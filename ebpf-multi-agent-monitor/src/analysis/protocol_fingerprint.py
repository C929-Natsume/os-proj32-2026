#!/usr/bin/env python3
"""
统一协议指纹识别与帧解析模块
支持: MCP (JSON-RPC), A2A (HTTP+SSE), ACP (REST+multipart), ANP (DIDs+JSON-LD)
"""
import json
import re

# 协议集
_PROTOCOL_MARKERS = {
    "MCP": ["jsonrpc", '"method"', '"params"', '"result"', '"id"'],
    "A2A": ["agent-card", "a2a/", "capabilities", '"task"', "event:", "data:"],
    "ACP": ["multipart", "boundary=", "content-type: multipart", "x-acp-"],
    "ANP": ['"@context"', '"@type"', "did:", "verifiableCredential", "agentGraph"],
}

# MCP
_MCP_CONTENT_LENGTH_RE = re.compile(
    r"Content-Length:\s*(\d+)\s*\r?\n", re.IGNORECASE
)

# SSE 行解析
_SSE_LINE_RE = re.compile(r"^(event|data|id|retry):\s?(.*)", re.MULTILINE)

# multipart boundary 提取
_BOUNDARY_RE = re.compile(
    r"boundary\s*=\s*\"?([^\";\r\n]+)\"?", re.IGNORECASE
)


def fingerprint_protocol(data, source=None, event_type=None):
    """
    基于阈值匹配: >=2 个标记命中即判定为该协议。
    """
    if isinstance(data, bytes):
        data = data.decode("utf-8", errors="replace")
    if not data or not data.strip():
        return None

    data_lower = data.lower()

    # 检查 HTTP 请求行中的 A2A 特有关键路径
    if data.startswith("GET ") or data.startswith("POST "):
        first_line = data.split("\r\n")[0] if "\r\n" in data else data.split("\n")[0]
        if "agent-card" in first_line or "a2a/" in first_line:
            return "A2A"

    best_proto = None
    best_score = 0
    for proto, markers in _PROTOCOL_MARKERS.items():
        score = sum(1 for m in markers if m.lower() in data_lower)
        if score >= 2 and score > best_score:
            best_proto = proto
            best_score = score

    if best_proto:
        return best_proto

    # 检测 text/event-stream Content-Type 但没有标准 SSE 字段
    if "text/event-stream" in data_lower:
        return "A2A"

    # 检测 chunked transfer encoding
    if "transfer-encoding: chunked" in data_lower:
        if "multipart" in data_lower or "boundary=" in data_lower:
            return "ACP"

    return None


# MCP 帧解析

def parse_mcp_frames(data):
    """
    从 Content-Length 帧中提取 MCP JSON-RPC 消息列表。
    返回 [(frame_json_str, consumed_bytes), ...]
    """
    if isinstance(data, bytes):
        data = data.decode("utf-8", errors="replace")
    frames = []
    offset = 0
    while offset < len(data):
        match = _MCP_CONTENT_LENGTH_RE.search(data, offset)
        if not match:
            break
        header_end = match.end()
        content_len = int(match.group(1))
        if content_len <= 0 or content_len > 10 * 1024 * 1024:
            break
        body_start = header_end
        while body_start < len(data) and data[body_start] in "\r\n":
            body_start += 1
        body_end = body_start + content_len
        if body_end > len(data):
            break
        frame = data[body_start:body_end]
        frames.append((frame, body_end - offset))
        offset = body_end
    return frames


def extract_mcp_fields(frame_str):
    """从 MCP JSON-RPC 帧提取 method, params, id。返回 dict 或 None。"""
    try:
        msg = json.loads(frame_str)
        if not isinstance(msg, dict):
            return None
        if msg.get("jsonrpc") != "2.0":
            return None
        return {
            "method": msg.get("method", ""),
            "params": msg.get("params"),
            "msg_id": msg.get("id"),
            "has_result": "result" in msg,
            "has_error": "error" in msg,
        }
    except (json.JSONDecodeError, TypeError):
        return None


# A2A SSE 解析

def parse_sse_events(data):
    """
    解析 SSE 文本流，提取 event type / id / data。
    返回 [{"event": ..., "data": ..., "id": ..., "retry": ...}, ...]
    """
    if isinstance(data, bytes):
        data = data.decode("utf-8", errors="replace")
    events = []
    current = {}
    for line in data.splitlines():
        line = line.strip()
        if not line:
            if current:
                events.append(current)
                current = {}
            continue
        match = _SSE_LINE_RE.match(line)
        if match:
            field, value = match.group(1), match.group(2).lstrip()
            if field == "data":
                prev = current.get("data", "")
                current["data"] = prev + value + "\n" if prev else value
            else:
                current[field] = value
    if current:
        events.append(current)
    return events


def extract_a2a_task_id(event_dict):
    """从 SSE event dict 的 data 字段提取 taskId """
    data_str = event_dict.get("data", "").strip()
    if not data_str:
        return None
    try:
        obj = json.loads(data_str)
        if isinstance(obj, dict):
            return obj.get("taskId") or obj.get("task_id")
        return None
    except (json.JSONDecodeError, TypeError):
        return data_str[:64]


def extract_a2a_agent_card(data):
    """尝试从数据中提取 agent-card JSON """
    if isinstance(data, bytes):
        data = data.decode("utf-8", errors="replace")
    for line in data.splitlines():
        line = line.strip()
        if line.startswith("{") and "capabilities" in line:
            try:
                return json.loads(line)
            except json.JSONDecodeError:
                pass
    # 尝试整段 JSON
    try:
        obj = json.loads(data)
        if isinstance(obj, dict) and "capabilities" in obj:
            return obj
    except json.JSONDecodeError:
        pass
    return None


# ACP 解析

def parse_acp_multipart(data, content_type_header=None):
    """
    解析 multipart MIME body。
    返回 [{"headers": {...}, "body": str}, ...]
    """
    if isinstance(data, bytes):
        data = data.decode("utf-8", errors="replace")

    # 提取 boundary
    boundary = None
    if content_type_header:
        match = _BOUNDARY_RE.search(content_type_header)
        if match:
            boundary = match.group(1)
    if not boundary:
        match = _BOUNDARY_RE.search(data[:4096])
        if match:
            boundary = match.group(1)

    if not boundary:
        return []

    parts = []
    delimiter = "--" + boundary
    sections = data.split(delimiter)
    for section in sections:
        section = section.strip()
        if not section or section == "--":
            continue
        # 分离 headers 与 body
        header_body = section.split("\r\n\r\n", 1)
        if len(header_body) < 2:
            header_body = section.split("\n\n", 1)
        headers_str = header_body[0] if len(header_body) >= 1 else ""
        body = header_body[1] if len(header_body) >= 2 else section

        headers = {}
        for line in headers_str.splitlines():
            if ":" in line:
                k, v = line.split(":", 1)
                headers[k.strip().lower()] = v.strip()

        parts.append({"headers": headers, "body": body.strip()})
    return parts


def extract_acp_headers(data):
    """提取 x-acp-* 自定义头。"""
    if isinstance(data, bytes):
        data = data.decode("utf-8", errors="replace")
    acp_headers = {}
    for line in data.splitlines():
        line_lower = line.lower()
        if line_lower.startswith("x-acp-"):
            if ":" in line:
                k, v = line.split(":", 1)
                acp_headers[k.strip()] = v.strip()
    return acp_headers


# ANP 解析

def extract_anp_graph(data):
    """从 JSON-LD 数据提取 @graph 节点列表 """
    if isinstance(data, bytes):
        data = data.decode("utf-8", errors="replace")
    try:
        obj = json.loads(data)
        if isinstance(obj, dict):
            graph = obj.get("@graph", [])
            if graph:
                return graph
        return [obj] if isinstance(obj, dict) else []
    except (json.JSONDecodeError, TypeError):
        return []


def extract_anp_dids(data):
    if isinstance(data, bytes):
        data = data.decode("utf-8", errors="replace")
    did_re = re.compile(r"did:[a-z0-9]+:[A-Za-z0-9._\-%]+")
    return did_re.findall(data)


# HTTP 工具

def split_http_message(data):
    """
    分离 HTTP 头部和 body。
    返回 {"headers": str, "body": str, "content_type": str|None}
    """
    if isinstance(data, bytes):
        data = data.decode("utf-8", errors="replace")
    parts = data.split("\r\n\r\n", 1)
    if len(parts) < 2:
        parts = data.split("\n\n", 1)
    headers = parts[0] if parts else ""
    body = parts[1] if len(parts) > 1 else ""

    content_type = None
    for line in headers.splitlines():
        if line.lower().startswith("content-type:"):
            content_type = line.split(":", 1)[1].strip()
            break

    return {"headers": headers, "body": body, "content_type": content_type}


def has_http_headers(data):
    if isinstance(data, bytes):
        data = data.decode("utf-8", errors="replace")
    first_line = data.split("\r\n")[0] if "\r\n" in data else data.split("\n")[0]
    return bool(re.match(r"^(GET|POST|PUT|DELETE|PATCH|HTTP/|HEAD|OPTIONS) ", first_line))
