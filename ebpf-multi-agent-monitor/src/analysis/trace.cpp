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
        if (std::isspace(c)) continue; // 【增强】免疫换行符与空格干扰
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

// ================= 2. 状态机：双向语义上下文追踪 (多轮对话+请求ID维度) =================
struct ConversationTurn {
    std::string request_id;       // 请求 ID（JSON-RPC id / HTTP x-request-id / 自生成）
    std::string prompt;           // 本轮用户输入
    std::string response;         // 本轮 AI 输出（SSE 流拼接）
    uint64_t prompt_ts;
    uint64_t last_resp_ts;
};

class AgentContextTracker {
private:
    static const size_t MAX_TURNS    = 20;    // 每 Agent 最多保留轮次
    static const size_t MAX_RESP_LEN = 8192;  // 单轮响应最大拼接长度

    struct AgentState {
        std::deque<ConversationTurn> turns;
    };
    std::unordered_map<uint32_t, AgentState> context_map;

    std::string extract_request_id(const std::string& payload) {
        // 1) JSON-RPC "id" 字段 (MCP 协议)
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
        // 2) HTTP x-request-id / request-id 头部
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
        return ""; // 返回空串，由调用方自生成
    }

public:
    void update_prompt(uint32_t agent_no, const std::string& prompt, uint64_t timestamp,
                       const std::string* raw_payload = nullptr) {
        auto& state = context_map[agent_no];
        // 从原始 payload 中提取 request_id（HTTP 头 / JSON-RPC id），
        // prompt 参数是已提取的纯文本，不含完整的 JSON 结构或 HTTP 头
        std::string req_id = raw_payload ? extract_request_id(*raw_payload) : extract_request_id(prompt);
        if (req_id.empty()) {
            // 自生成：Agent编号 + 时间戳
            req_id = "req_" + std::to_string(agent_no) + "_" + std::to_string(timestamp);
        }

        // 检查是否为同一请求的重传（相同 request_id 且上轮尚未有回复）
        if (!state.turns.empty()) {
            auto& last = state.turns.back();
            if (last.request_id == req_id) {
                // 重传：仅更新时间戳，保留已累积的响应
                last.prompt = prompt;
                last.prompt_ts = timestamp;
                std::cout << "\n[Prompt *retransmit*] Agent: " << agent_no
                          << " Request: " << req_id << "\n  -> " << prompt << "\n";
                return;
            }
        }

        // 新的一轮对话
        ConversationTurn turn;
        turn.request_id = req_id;
        turn.prompt = prompt;
        turn.prompt_ts = timestamp;
        state.turns.push_back(turn);
        while (state.turns.size() > MAX_TURNS) {
            state.turns.pop_front();
        }

        std::cout << "\n[Prompt] Agent: " << agent_no
                  << " Request: " << req_id << "\n  -> " << prompt << "\n";
    }

    void append_response(uint32_t agent_no, const std::string& response_chunk) {
        auto it = context_map.find(agent_no);
        if (it == context_map.end()) return;
        auto& turns = it->second.turns;
        if (turns.empty()) return;

        // 响应追加到最近一轮（SSE 流式响应按序到达）
        auto& active = turns.back();
        if (active.response.length() < MAX_RESP_LEN) {
            active.response += response_chunk;
            active.last_resp_ts = 0; // 将在外部更新
        }
        std::cout << "[Response] Agent: " << agent_no
                  << " Request: " << active.request_id << "\n  <- " << response_chunk << "\n";
    }

    void update_response_ts(uint32_t agent_no, uint64_t timestamp) {
        auto it = context_map.find(agent_no);
        if (it == context_map.end()) return;
        auto& turns = it->second.turns;
        if (!turns.empty()) {
            turns.back().last_resp_ts = timestamp;
        }
    }

    std::string get_full_context(uint32_t agent_no) {
        auto it = context_map.find(agent_no);
        if (it == context_map.end() || it->second.turns.empty()) {
            return "无明确语义上下文";
        }

        // 取最近一轮完整的 Q&A
        auto& last = it->second.turns.back();
        std::string ctx = "Q[" + last.request_id + "]: " + last.prompt;
        if (!last.response.empty()) {
            ctx += " | A: " + last.response;
        }
        return ctx;
    }

    // 获取最近 N 轮对话历史摘要
    std::string get_conversation_summary(uint32_t agent_no, size_t max_turns = 5) {
        auto it = context_map.find(agent_no);
        if (it == context_map.end() || it->second.turns.empty()) {
            return "无对话历史";
        }
        std::string summary = "对话历史(" + std::to_string(it->second.turns.size()) + "轮):\n";
        size_t start = it->second.turns.size() > max_turns
                           ? it->second.turns.size() - max_turns
                           : 0;
        for (size_t i = start; i < it->second.turns.size(); i++) {
            auto& t = it->second.turns[i];
            summary += "  [" + t.request_id + "] Q: " + t.prompt.substr(0, 80)
                       + (t.prompt.length() > 80 ? "..." : "") + "\n";
            if (!t.response.empty()) {
                summary += "       A: " + t.response.substr(0, 80)
                           + (t.response.length() > 80 ? "..." : "") + "\n";
            }
        }
        return summary;
    }

    void track_fork(uint32_t parent_pid, uint32_t child_pid) {
        if (context_map.find(parent_pid) != context_map.end()) {
            context_map[child_pid] = context_map[parent_pid];
        }
    }
};

// ================= 3. 数据消费与 X-Ray 透视引擎 =================
class MainAnalyzer {
private:
    redisContext* redis_ctx;
    AgentContextTracker tracker;

    std::string format_time(uint64_t ns_timestamp) {
        auto t = (time_t)(ns_timestamp / 1000000000);
        auto tm = *std::localtime(&t);
        std::ostringstream oss;
        oss << std::put_time(&tm, "%H:%M:%S");
        return oss.str();
    }

    // 【新增】: Chunked 传输解码器 (支持截断包)
    std::string decode_chunked(const std::string& chunked_data) {
        std::string result;
        size_t pos = 0;
        while (pos < chunked_data.size()) {
            size_t crlf = chunked_data.find("\r\n", pos);
            if (crlf == std::string::npos) {
                // 不完整的 chunk，直接把剩余部分塞进去
                result.append(chunked_data.substr(pos));
                break;
            }
            std::string hex_len = chunked_data.substr(pos, crlf - pos);
            size_t len = 0;
            try {
                len = std::stoul(hex_len, nullptr, 16);
            } catch (...) { 
                // 解析失败说明不是合法的 chunk 头，直接追加退出
                result.append(chunked_data.substr(pos));
                break; 
            }
            if (len == 0) break; // 数据流结束

            pos = crlf + 2;
            if (pos + len > chunked_data.size()) {
                // 遭遇 eBPF 截断的数据包
                result.append(chunked_data.substr(pos));
                break;
            }
            result.append(chunked_data.substr(pos, len));
            pos += len + 2; // 跳过 chunk 结尾的 \r\n
        }
        return result;
    }

    // 【新增】: Gzip 解压器 (支持截断解压)
    std::string decompress_gzip(const std::string& compressed_data) {
        if (compressed_data.empty()) return "";
        z_stream zs;
        memset(&zs, 0, sizeof(zs));
        // 16 + MAX_WBITS 让 zlib 自动识别并解析 Gzip 头
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
        // 注意：我们不检查 Z_STREAM_END，因为 eBPF 数据包很可能是截断的
        // 解压出内容就返回
        return outstring;
    }

    // 【修改后】: 极简且强壮的 JSON 文本提取器 (专治 eBPF 截断包与 SSE 数据流)
    std::string extract_pure_text(const std::string& payload, uint32_t e_type) {
        std::string result;
        
        // --- 方案 A: 尝试使用标准的 JSON 解析库 (完美处理中文 \uXXXX 和转义符) ---
        try {
            if (e_type == EVENT_SSL_READ || e_type == EVENT_STDIO_READ || e_type == EVENT_TCP_RECV) {
                // 读取 SSE 流 (Server-Sent Events)
                size_t pos = 0;
                while ((pos = payload.find("data: ", pos)) != std::string::npos) {
                    pos += 6;
                    size_t end = payload.find("\n", pos);
                    std::string json_line = payload.substr(pos, end - pos);
                    if (json_line.find("[DONE]") != std::string::npos) continue;
                    
                    try {
                        json j = json::parse(json_line);
                        // Claude 格式
                        if (j.contains("type") && j["type"] == "content_block_delta" && j.contains("delta") && j["delta"].contains("text")) {
                            result += j["delta"]["text"].get<std::string>();
                        }
                        // OpenAI 格式
                        else if (j.contains("choices") && j["choices"].is_array() && j["choices"].size() > 0 && j["choices"][0].contains("delta") && j["choices"][0]["delta"].contains("content")) {
                            if (j["choices"][0]["delta"]["content"].is_string()) {
                                result += j["choices"][0]["delta"]["content"].get<std::string>();
                            }
                        }
                    } catch (...) {} // 单行被截断解析失败，忽略本行，继续看下一行
                }
                if (!result.empty()) return result;
            } 
            else if (e_type == EVENT_SSL_WRITE || e_type == EVENT_STDIO_WRITE || e_type == EVENT_TCP_SEND) {
                // 解析完整的用户发包 JSON (包含整个聊天记录)
                json j = json::parse(payload);
                if (j.contains("messages") && j["messages"].is_array()) {
                    std::string last_user_msg = "";
                    for (auto& msg : j["messages"]) {
                        // 【关键】：只提取 user 的内容，并且只保留最新的一条（数组最后一条）
                        if (msg.contains("role") && msg["role"] == "user" && msg.contains("content")) {
                            last_user_msg = ""; // 刷新，确保最终留下的是刚刚输入的最新对话
                            if (msg["content"].is_string()) {
                                last_user_msg = msg["content"].get<std::string>();
                            } else if (msg["content"].is_array()) {
                                // 应对 Claude 复杂的 Content Block 结构
                                for (auto& block : msg["content"]) {
                                    if (block.contains("text") && block["text"].is_string()) {
                                        last_user_msg += block["text"].get<std::string>() + " ";
                                    }
                                }
                            }
                        }
                    }
                    if (!last_user_msg.empty()) return last_user_msg;
                }
            }
        } catch (...) {
            // JSON 解析失败（比如 Prompt 超过 16KB 导致 eBPF 截断了包尾）
            // 吞掉异常，向下走备用的字符串暴力匹配方案
        }

        // --- 方案 B: 降级使用字符串暴力提取 (应对截断包，兼容空格) ---
        std::vector<std::string> keys = {"\"text\"", "\"content\""};
        for (const auto& key : keys) {
            size_t pos = 0;
            while ((pos = payload.find(key, pos)) != std::string::npos) {
                pos += key.length();
                // 兼容 JSON 中的空格: 跳过冒号和周围的空格
                while (pos < payload.length() && (payload[pos] == ' ' || payload[pos] == ':')) pos++;
                if (pos < payload.length() && payload[pos] == '"') pos++; 
                
                std::string chunk;
                while (pos < payload.length()) {
                    if (payload[pos] == '"' && payload[pos - 1] != '\\') break;
                    chunk += payload[pos];
                    pos++;
                }
                
                std::string unescaped;
                for (size_t i = 0; i < chunk.length(); i++) {
                    if (chunk[i] == '\\' && i + 1 < chunk.length()) {
                        if (chunk[i+1] == 'n') { unescaped += ' '; i++; } 
                        else if (chunk[i+1] == '"') { unescaped += '"'; i++; }
                        else { unescaped += chunk[i]; }
                    } else {
                        unescaped += chunk[i];
                    }
                }
                if (unescaped.length() > 0 && unescaped.find("content_block_delta") == std::string::npos) {
                    result += unescaped;
                }
            }
        }
        return result;
    }

    // 【增强】：将二进制控制符替换为 '.'，让 HTTP/2 的底层结构显形
    std::string clean_http2_payload(const std::string& raw_data) {
        std::string clean_str;
        for (unsigned char c : raw_data) {
            if (c >= 32 && c <= 126) clean_str += c;
            else if (c >= 128) clean_str += c; // 保留中文字符
            else clean_str += '.';             // 二进制乱码全变成点
        }
        return clean_str;
    }

    void sniff_semantic_payload(uint32_t pid, uint32_t e_type, const std::string& raw_payload, uint64_t timestamp) {
        std::string actual_payload = raw_payload;

        // ================= HTTP 协议脱壳 =================
        size_t header_end = raw_payload.find("\r\n\r\n");
        if (header_end != std::string::npos && raw_payload.find("HTTP/1.") != std::string::npos) {
            std::string headers = raw_payload.substr(0, header_end);
            std::string body = raw_payload.substr(header_end + 4);

            std::string lower_headers = headers;
            std::transform(lower_headers.begin(), lower_headers.end(), lower_headers.begin(), ::tolower);

            // 1. 脱掉 Chunked 块传输壳
            if (lower_headers.find("transfer-encoding: chunked") != std::string::npos) {
                body = decode_chunked(body);
            }

            // 2. 脱掉 Gzip 压缩壳
            if (lower_headers.find("content-encoding: gzip") != std::string::npos) {
                std::string decompressed = decompress_gzip(body);
                if (!decompressed.empty()) {
                    actual_payload = decompressed; // 成功解压，替换原始乱码
                }
            } else {
                actual_payload = body; // 纯明文 Body
            }
        }

        // ================= 语义提取 =================
        // 1. 使用新增的协议脱壳机，提取纯人类自然语言
        // std::string pure_text = extract_pure_text(actual_payload);
        std::string pure_text = extract_pure_text(actual_payload, e_type);
        
        // 2. 如果纯文本提取失败，降级使用清洗后的原始数据进行判定
        std::string clean_str = clean_http2_payload(actual_payload);
        std::string lower_str = clean_str;
        std::transform(lower_str.begin(), lower_str.end(), lower_str.begin(), ::tolower);

        bool matched = false;

        if (e_type == EVENT_SSL_WRITE || e_type == EVENT_STDIO_WRITE || e_type == EVENT_TCP_SEND) {
            if (lower_str.find("\"messages\"") != std::string::npos || 
                lower_str.find("anthropic") != std::string::npos) {
                
                // 传入完整 payload 以提取 request_id，同时保留纯文本用于展示
                std::string prompt_text = pure_text.empty() ? clean_str : pure_text;
                tracker.update_prompt(pid, prompt_text, timestamp, &actual_payload);
                matched = true;
            }
        }
        else if (e_type == EVENT_SSL_READ || e_type == EVENT_STDIO_READ || e_type == EVENT_TCP_RECV) {
            if (lower_str.find("\"role\":\"assistant\"") != std::string::npos ||
                lower_str.find("content_block_delta") != std::string::npos) {
                
                // SSE 流式数据：拼接至当前活跃轮次
                if (!pure_text.empty()) {
                    tracker.append_response(pid, pure_text);
                    tracker.update_response_ts(pid, timestamp);
                }
                matched = true;
            }
        }

        // ================= X-RAY 透视雷达 =================
        if (!matched && clean_str.length() > 20) {
            std::string type_str = (e_type == EVENT_SSL_WRITE || e_type == EVENT_STDIO_WRITE || e_type == EVENT_TCP_SEND) ? "[WRITE]" : "[READ]";
            std::cout << "[X-Ray] PID: " << pid << " " << type_str << " data:\n"
                      << "      " << clean_str.substr(0, 100) << "\n";
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
            
            // 1. 获取外层通用身份字段 (兼容 ebpf_events channel 的 flat JSON 格式)
            uint32_t event_type = event.value("type", 0);  // flat JSON uses "type"
            if (event_type == 0) event_type = event.value("behavior_no", 0);  // fallback: behavior events
            uint64_t timestamp = event.value("timestamp", 0);

            // 2. agent_id 可能是 "agent_82817" (字符串) 或 82817 (数字)
            uint32_t agent_no = 0;
            std::string agent_name = event.value("agent_name", "");
            if (agent_name.empty()) {
                if (event.contains("agent_id")) {
                    if (event["agent_id"].is_number()) {
                        agent_no = event["agent_id"].get<uint32_t>();
                    } else if (event["agent_id"].is_string()) {
                        std::string aid = event["agent_id"].get<std::string>();
                        if (aid.rfind("agent_", 0) == 0) {
                            agent_no = (uint32_t)std::stoul(aid.substr(6));
                        }
                    }
                }
            } else {
                agent_no = event.value("agent_no", 0);
            }

            // 3. pid/comm 可能在顶层 (flat JSON) 或在 operation 子对象 (behavior JSON)
            uint32_t pid = event.value("pid", 0);
            std::string comm = event.value("comm", "unknown");
            if (pid == 0) {
                auto op = event.value("operation", json::object());
                pid = op.value("pid", 0);
                comm = op.value("comm", "unknown");
            }

            // 4. 用 pid 作为 agent_no 的兜底值
            if (agent_no == 0) agent_no = pid;

            if (event_type == EVENT_SSL_WRITE || event_type == EVENT_SSL_READ ||
                event_type == EVENT_STDIO_READ || event_type == EVENT_STDIO_WRITE ||
                event_type == EVENT_TCP_SEND || event_type == EVENT_TCP_RECV) {
                std::string b64_payload = event.value("network_payload", "");
                if (b64_payload.empty()) {
                    b64_payload = event.value("data", "");
                }
                if (!b64_payload.empty()) {
                    std::string raw_payload = base64_decode(b64_payload);
                    sniff_semantic_payload(agent_no, event_type, raw_payload, timestamp);
                }
            }
            // 5. 处理系统行为 (ebpf_events flat JSON 格式: filename/dip/dport 在顶层)
            else if (event_type >= EVENT_EXECVE && event_type <= EVENT_AGENT_COMM) {
                std::string action_desc = "";
                if (event_type == EVENT_EXECVE) action_desc = "执行命令: " + event.value("filename", "");
                else if (event_type == EVENT_OPEN) action_desc = "访问文件: " + event.value("filename", "");
                else if (event_type == EVENT_CONNECT) action_desc = "网络连接至: " + event.value("dip", "") + ":" + std::to_string(event.value("dport", 0));

                std::string motive = tracker.get_full_context(agent_no);

                std::cout << "[" << format_time(timestamp) << "] Agent: " << agent_name << " (ID: " << agent_no << ")\n"
                          << "  -> PID: " << pid << " (" << comm << ")\n"
                          << "  -> Action: " << action_desc << "\n"
                          << "  -> Context: " << motive << "\n\n";
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