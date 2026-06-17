#include <iostream>
#include <string>
#include <vector>
#include <deque>
#include <unordered_map>
#include <chrono>
#include <ctime>
#include <iomanip>
#include <cctype>
#include <algorithm>
#include <hiredis/hiredis.h>
#include <nlohmann/json.hpp>
#include <zlib.h>

using json = nlohmann::json;

enum EventType {
    EVENT_EXECVE = 1, EVENT_FORK = 2, EVENT_OPEN = 3, EVENT_UNLINK = 4,
    EVENT_CONNECT = 5, EVENT_SSL_READ = 6, EVENT_SSL_WRITE = 7,
    EVENT_AGENT_COMM = 9, EVENT_STDIO_READ = 10, EVENT_STDIO_WRITE = 11,
    EVENT_TCP_SEND = 12, EVENT_TCP_RECV = 13
};

// ================= 1. 强化的 Base64 解码器 =================
std::string base64_decode(const std::string &in) {
    std::string out;
    std::vector<int> T(256, -1);
    for (int i = 0; i < 64; i++) T["ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"[i]] = i;
    int val = 0, valb = -8;
    for (unsigned char c : in) {
        if (std::isspace(c)) continue; 
        if (T[c] == -1) break; 
        val = (val << 6) + T[c];
        valb += 6;
        if (valb >= 0) {
            out.push_back(char((val >> valb) & 0xFF));
            valb -= 8;
        }
    }
    return out;
}

// ================= 1.5 文本清洗器：滤除 AI 智能体的隐藏系统提示 =================
std::string clean_llm_text(std::string text) {
    size_t start;
    // 1. 剔除 <system-reminder> 标签及内部的背景记忆
    while ((start = text.find("<system-reminder>")) != std::string::npos) {
        size_t end = text.find("</system-reminder>", start);
        if (end != std::string::npos) text.erase(start, end + 18 - start);
        else text.erase(start);
    }
    
    // 2. 剔除大段的工具说明 [{The following skills...}]
    while ((start = text.find("[{The following skills")) != std::string::npos) {
        size_t end = text.find("}]", start);
        if (end != std::string::npos) text.erase(start, end + 2 - start);
        else text.erase(start);
    }

    // 3. 剔除常见的隐藏 API Header 及前缀
    std::vector<std::string> trash_tokens = {
        "x-anthropic-billing-header:",
        "You are Claude Code",
        "You are opencode",
        "[SUGGESTION MODE:"
    };
    for (const auto& token : trash_tokens) {
        while ((start = text.find(token)) != std::string::npos) {
            size_t end = text.find("\n", start); 
            if (end != std::string::npos) text.erase(start, end - start + 1);
            else text.erase(start); 
        }
    }
    return text;
}

// ================= 2. 状态机：双向语义上下文追踪 (多轮对话+请求ID维度) =================
struct ConversationTurn {
    std::string request_id;       
    std::string prompt;           
    std::string response;         
    uint64_t prompt_ts;
    uint64_t last_resp_ts;
};

class AgentContextTracker {
private:
    static const size_t MAX_TURNS    = 20;    
    static const size_t MAX_RESP_LEN = 16384;  

    struct AgentState {
        std::deque<ConversationTurn> turns;
    };
    std::unordered_map<uint32_t, AgentState> context_map;

    std::string extract_request_id(const std::string& payload) {
        size_t pos = payload.find("\"id\"");
        if (pos != std::string::npos) {
            pos += 4;
            while (pos < payload.length() && (payload[pos] == ' ' || payload[pos] == ':')) pos++;
            if (pos < payload.length() && payload[pos] == '"') {
                pos++;
                std::string id;
                while (pos < payload.length() && payload[pos] != '"' && payload[pos] != '\n') {
                    id += payload[pos++];
                }
                if (!id.empty()) return id;
            } else if (pos < payload.length() && std::isdigit(payload[pos])) {
                std::string id;
                while (pos < payload.length() && (std::isdigit(payload[pos]) || payload[pos] == '.')) {
                    id += payload[pos++];
                }
                if (!id.empty()) return id;
            }
        }
        pos = payload.find("x-request-id:");
        if (pos == std::string::npos) pos = payload.find("X-Request-Id:");
        if (pos == std::string::npos) pos = payload.find("request-id:");
        if (pos == std::string::npos) pos = payload.find("Request-Id:");
        if (pos != std::string::npos) {
            pos = payload.find(':', pos) + 1;
            while (pos < payload.length() && payload[pos] == ' ') pos++;
            std::string id;
            while (pos < payload.length() && payload[pos] != '\r' && payload[pos] != '\n') {
                id += payload[pos++];
            }
            if (!id.empty()) return id;
        }
        return ""; 
    }

public:
    void update_prompt(uint32_t agent_no, const std::string& prompt, uint64_t timestamp,
                       const std::string* raw_payload = nullptr) {
        auto& state = context_map[agent_no];
        std::string req_id = raw_payload ? extract_request_id(*raw_payload) : extract_request_id(prompt);
        if (req_id.empty()) {
            req_id = "req_" + std::to_string(agent_no) + "_" + std::to_string(timestamp);
        }

        if (!state.turns.empty()) {
            auto& last = state.turns.back();
            if (last.request_id == req_id) {
                last.prompt = prompt;
                last.prompt_ts = timestamp;
                return;
            }
        }

        ConversationTurn turn;
        turn.request_id = req_id;
        turn.prompt = prompt;
        turn.prompt_ts = timestamp;
        state.turns.push_back(turn);
        while (state.turns.size() > MAX_TURNS) state.turns.pop_front();

        std::cout << "\n\n[Prompt] Agent: " << agent_no << " | Request: " << req_id << "\n  -> " << prompt << "\n";
    }

    void append_response(uint32_t agent_no, const std::string& response_chunk) {
        auto it = context_map.find(agent_no);
        if (it == context_map.end()) return;
        auto& turns = it->second.turns;
        if (turns.empty()) return;

        auto& active = turns.back();
        
        // 打印流式头部，如果是新行则无缝追加
        if (active.response.empty()) {
            std::cout << "[Response] Agent: " << agent_no << "\n  <- ";
        }

        if (active.response.length() < MAX_RESP_LEN) {
            active.response += response_chunk;
            active.last_resp_ts = 0; 
        }
        
        std::cout << response_chunk << std::flush;
    }

    void update_response_ts(uint32_t agent_no, uint64_t timestamp) {
        auto it = context_map.find(agent_no);
        if (it == context_map.end()) return;
        auto& turns = it->second.turns;
        if (!turns.empty()) turns.back().last_resp_ts = timestamp;
    }

    std::string get_full_context(uint32_t agent_no) {
        auto it = context_map.find(agent_no);
        if (it == context_map.end() || it->second.turns.empty()) return "无明确语义上下文";
        auto& last = it->second.turns.back();
        std::string ctx = "Q: " + last.prompt;
        if (!last.response.empty()) ctx += " | A: " + last.response;
        return ctx;
    }
};

// ================= 3. 数据消费与 X-Ray 透视引擎 =================
class MainAnalyzer {
private:
    redisContext* redis_ctx;
    AgentContextTracker tracker;
    
    // 【新增】：TCP/TLS 流碎片重组缓冲区 (PID -> 未解析的半截字符串)
    std::unordered_map<uint32_t, std::string> stream_buffers;

    std::string format_time(uint64_t ns_timestamp) {
        auto t = (time_t)(ns_timestamp / 1000000000);
        auto tm = *std::localtime(&t);
        std::ostringstream oss;
        oss << std::put_time(&tm, "%H:%M:%S");
        return oss.str();
    }

    std::string decode_chunked(const std::string& chunked_data) {
        std::string result;
        size_t pos = 0;
        while (pos < chunked_data.size()) {
            size_t crlf = chunked_data.find("\r\n", pos);
            if (crlf == std::string::npos) {
                result.append(chunked_data.substr(pos));
                break;
            }
            std::string hex_len = chunked_data.substr(pos, crlf - pos);
            size_t len = 0;
            try { len = std::stoul(hex_len, nullptr, 16); } 
            catch (...) { result.append(chunked_data.substr(pos)); break; }
            if (len == 0) break; 

            pos = crlf + 2;
            if (pos + len > chunked_data.size()) {
                result.append(chunked_data.substr(pos));
                break;
            }
            result.append(chunked_data.substr(pos, len));
            pos += len + 2; 
        }
        return result;
    }

    std::string decompress_gzip(const std::string& compressed_data) {
        if (compressed_data.empty()) return "";
        z_stream zs;
        memset(&zs, 0, sizeof(zs));
        if (inflateInit2(&zs, 16 + MAX_WBITS) != Z_OK) return "";
        zs.next_in = (Bytef*)compressed_data.data();
        zs.avail_in = compressed_data.size();
        int ret;
        char outbuffer[32768];
        std::string outstring;
        do {
            zs.next_out = reinterpret_cast<Bytef*>(outbuffer);
            zs.avail_out = sizeof(outbuffer);
            ret = inflate(&zs, Z_NO_FLUSH);
            if (outstring.size() < zs.total_out) {
                outstring.append(outbuffer, zs.total_out - outstring.size());
            }
        } while (ret == Z_OK);
        inflateEnd(&zs);
        return outstring;
    }

    // 专门处理 WRITE(Prompt) 的 JSON 结构和降级提取
    std::string extract_prompt_text(const std::string& payload) {
        std::string result;
        // --- 方案 A: 标准 JSON 解析 ---
        try {
            json j = json::parse(payload);
            if (j.contains("messages") && j["messages"].is_array()) {
                for (auto& msg : j["messages"]) {
                    if (msg.contains("role") && msg["role"] == "user" && msg.contains("content")) {
                        result = ""; // 刷新，确保持有最新的用户输入
                        if (msg["content"].is_string()) {
                            result = msg["content"].get<std::string>();
                        } else if (msg["content"].is_array()) {
                            for (auto& block : msg["content"]) {
                                if (block.contains("text") && block["text"].is_string()) {
                                    result += block["text"].get<std::string>() + " ";
                                }
                            }
                        }
                    }
                }
            }
            if (!result.empty()) return clean_llm_text(result);
        } catch (...) {}

        // --- 方案 B: 降级暴力提取 (应对 64KB 截断) ---
        size_t last_user = payload.rfind("\"role\":\"user\"");
        if (last_user == std::string::npos) last_user = payload.rfind("\"role\": \"user\"");
        
        if (last_user != std::string::npos) {
            size_t text_pos = payload.find("\"text\"", last_user);
            size_t content_pos = payload.find("\"content\"", last_user);
            
            size_t target_pos = std::string::npos;
            if (text_pos != std::string::npos && content_pos != std::string::npos) {
                target_pos = std::min(text_pos, content_pos);
            } else if (text_pos != std::string::npos) { target_pos = text_pos; }
            else if (content_pos != std::string::npos) { target_pos = content_pos; }

            if (target_pos != std::string::npos) {
                target_pos += (target_pos == text_pos) ? 6 : 9; // 跳过 "text" 或 "content"
                while (target_pos < payload.length() && (payload[target_pos] == ' ' || payload[target_pos] == ':')) target_pos++;
                
                // 【核心修复】：必须是双引号开头，拒绝 [], 干扰
                if (target_pos < payload.length() && payload[target_pos] == '"') {
                    target_pos++; 
                    while (target_pos < payload.length() && payload[target_pos] != '"') {
                        if (payload[target_pos] == '\\' && target_pos + 1 < payload.length()) {
                            if (payload[target_pos+1] == 'n') result += '\n';
                            else result += payload[target_pos+1];
                            target_pos += 2;
                        } else {
                            result += payload[target_pos];
                            target_pos++;
                        }
                    }
                }
            }
        }

        if (!result.empty()) result = clean_llm_text(result);
        return result;
    }

    std::string clean_http2_payload(const std::string& raw_data) {
        std::string clean_str;
        for (unsigned char c : raw_data) {
            if (c >= 32 && c <= 126) clean_str += c;
            else if (c >= 128) clean_str += c; 
            else clean_str += '.';             
        }
        return clean_str;
    }

    void sniff_semantic_payload(uint32_t pid, uint32_t e_type, const std::string& raw_payload, uint64_t timestamp) {
        std::string actual_payload = raw_payload;

        // 仅对 HTTP/1 进行脱壳
        size_t header_end = raw_payload.find("\r\n\r\n");
        if (header_end != std::string::npos && raw_payload.find("HTTP/1.") != std::string::npos) {
            std::string headers = raw_payload.substr(0, header_end);
            std::string body = raw_payload.substr(header_end + 4);
            std::string lower_headers = headers;
            std::transform(lower_headers.begin(), lower_headers.end(), lower_headers.begin(), ::tolower);

            if (lower_headers.find("transfer-encoding: chunked") != std::string::npos) body = decode_chunked(body);
            if (lower_headers.find("content-encoding: gzip") != std::string::npos) {
                std::string decompressed = decompress_gzip(body);
                if (!decompressed.empty()) actual_payload = decompressed; 
            } else { actual_payload = body; }
        }

        std::string clean_str = clean_http2_payload(actual_payload);
        std::string lower_str = clean_str;
        std::transform(lower_str.begin(), lower_str.end(), lower_str.begin(), ::tolower);

        bool matched = false;

        // 处理用户提问 (Prompt)
        if (e_type == EVENT_SSL_WRITE || e_type == EVENT_STDIO_WRITE || e_type == EVENT_TCP_SEND) {
            if (lower_str.find("\"messages\"") != std::string::npos || 
                lower_str.find("\"model\"") != std::string::npos || 
                lower_str.find("\"system\"") != std::string::npos ||
                lower_str.find("anthropic") != std::string::npos) {
                
                std::string prompt_text = extract_prompt_text(actual_payload);
                if (prompt_text.empty()) {
                    prompt_text = "[解析失败或头部截断] 原始片段: " + clean_str.substr(0, 150) + "...";
                    matched = false; // 触发 X-Ray
                } else {
                    matched = true;
                }
                tracker.update_prompt(pid, prompt_text, timestamp, &actual_payload);
            }
        }
        // 处理 AI 响应 (Response / SSE 流)
        else if (e_type == EVENT_SSL_READ || e_type == EVENT_STDIO_READ || e_type == EVENT_TCP_RECV) {
            stream_buffers[pid] += actual_payload;
            std::string& buf = stream_buffers[pid];
            
            size_t pos = 0;
            while (true) {
                size_t nl = buf.find('\n', pos);
                if (nl == std::string::npos) break; // 当前行不完整，等待下一个网络包

                std::string line = buf.substr(pos, nl - pos);
                pos = nl + 1;

                size_t data_pos = line.find("data: ");
                if (data_pos != std::string::npos) {
                    std::string json_str = line.substr(data_pos + 6);
                    if (json_str.find("[DONE]") != std::string::npos) continue;

                    try {
                        json j = json::parse(json_str);
                        std::string chunk_text;
                        
                        // 兼容 Claude 格式
                        if (j.contains("type") && j["type"] == "content_block_delta" && j.contains("delta") && j["delta"].contains("text")) {
                            chunk_text = j["delta"]["text"].get<std::string>();
                        } 
                        // 兼容 Opencode / OpenAI / DeepSeek 格式
                        else if (j.contains("choices") && j["choices"].is_array() && j["choices"].size() > 0 && j["choices"][0].contains("delta") && j["choices"][0]["delta"].contains("content")) {
                            if (j["choices"][0]["delta"]["content"].is_string()) {
                                chunk_text = j["choices"][0]["delta"]["content"].get<std::string>();
                            }
                        }
                        
                        if (!chunk_text.empty()) {
                            tracker.append_response(pid, chunk_text);
                            tracker.update_response_ts(pid, timestamp);
                            matched = true;
                        }
                    } catch (...) {
                        // 解析失败忽略本行
                    }
                }
            }
            // 清理已成功解析拼接的行
            buf.erase(0, pos);
            // 防内存泄漏：如果超过 1MB 未见换行符（异常流），直接清空
            if (buf.length() > 1024 * 1024) buf.clear(); 
        }

        // ================= X-RAY 透视雷达 =================
        if (!matched && clean_str.length() > 20) {
            std::string type_str = (e_type == EVENT_SSL_WRITE || e_type == EVENT_STDIO_WRITE || e_type == EVENT_TCP_SEND) ? "[WRITE]" : "[READ]";
            std::cout << "\n[X-Ray] PID: " << pid << " " << type_str << " data:\n"
                      << "      " << clean_str.substr(0, 150) << "...\n";
        }
    }

public:
    MainAnalyzer(const char* host = "127.0.0.1", int port = 6379) {
        redis_ctx = redisConnect(host, port);
        if (!redis_ctx || redis_ctx->err) exit(1);
    }
    ~MainAnalyzer() { if (redis_ctx) redisFree(redis_ctx); }

    void process_event(const std::string& json_str) {
        try {
            json event = json::parse(json_str);
            uint32_t event_type = event.value("type", 0);  
            if (event_type == 0) event_type = event.value("behavior_no", 0);  
            uint64_t timestamp = event.value("timestamp", 0);

            uint32_t agent_no = 0;
            std::string agent_name = event.value("agent_name", "");
            if (agent_name.empty()) {
                if (event.contains("agent_id")) {
                    if (event["agent_id"].is_number()) agent_no = event["agent_id"].get<uint32_t>();
                    else if (event["agent_id"].is_string()) {
                        std::string aid = event["agent_id"].get<std::string>();
                        if (aid.rfind("agent_", 0) == 0) agent_no = (uint32_t)std::stoul(aid.substr(6));
                    }
                }
            } else { agent_no = event.value("agent_no", 0); }

            uint32_t pid = event.value("pid", 0);
            std::string comm = event.value("comm", "unknown");
            if (pid == 0) {
                auto op = event.value("operation", json::object());
                pid = op.value("pid", 0);
                comm = op.value("comm", "unknown");
            }
            if (agent_no == 0) agent_no = pid;

            if (event_type == EVENT_SSL_WRITE || event_type == EVENT_SSL_READ ||
                event_type == EVENT_STDIO_READ || event_type == EVENT_STDIO_WRITE ||
                event_type == EVENT_TCP_SEND || event_type == EVENT_TCP_RECV) {
                std::string b64_payload = event.value("network_payload", "");
                if (b64_payload.empty()) b64_payload = event.value("data", "");
                if (!b64_payload.empty()) {
                    std::string raw_payload = base64_decode(b64_payload);
                    sniff_semantic_payload(agent_no, event_type, raw_payload, timestamp);
                }
            }
            // 处理系统行为并在终端显示简要日志
            else if (event_type >= EVENT_EXECVE && event_type <= EVENT_AGENT_COMM) {
                std::string action_desc = "";
                if (event_type == EVENT_EXECVE) action_desc = "执行命令: " + event.value("filename", "");
                else if (event_type == EVENT_OPEN) action_desc = "访问文件: " + event.value("filename", "");
                else if (event_type == EVENT_UNLINK) action_desc = "删除文件: " + event.value("filename", "");
                else if (event_type == EVENT_FORK) action_desc = "创建子进程 (Fork)";
                else if (event_type == EVENT_CONNECT) action_desc = "网络连接至: " + event.value("dip", "") + ":" + std::to_string(event.value("dport", 0));
                else action_desc = "底层系统行为 (Type: " + std::to_string(event_type) + ")";
                
                // 让大段系统动作与对话剥离，保持清爽视觉
                std::cout << "\n[" << format_time(timestamp) << "] Agent Action (PID: " << pid << " / " << comm << ")\n"
                          << "  -> " << action_desc << "\n";
            }
        } catch (const json::parse_error& e) {
            std::cerr << "JSON parse error: " << e.what() << std::endl;
        } catch (const std::exception& e) {
            std::cerr << "Error processing event: " << e.what() << std::endl;
        }
    }
    
    void run() {
        std::cout << "C++ Trace Analyzer started, subscribing to ebpf_events\n";
        redisReply* reply = (redisReply*)redisCommand(redis_ctx, "SUBSCRIBE ebpf_events");
        if (reply) freeReplyObject(reply);

        while (redisGetReply(redis_ctx, (void**)&reply) == REDIS_OK) {
            if (reply->type == REDIS_REPLY_ARRAY && reply->elements == 3) {
                if (strcmp(reply->element[0]->str, "message") == 0) {
                    process_event(reply->element[2]->str);
                }
            }
            freeReplyObject(reply);
        }
    }
};

int main() {
    MainAnalyzer analyzer;
    analyzer.run();
    return 0;
}