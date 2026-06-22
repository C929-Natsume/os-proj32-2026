"""
JSON Schema Specification for Redis-backed multi-agent anomaly detection.

=================== REDIS KEY DESIGN ===================

All keys prefixed with "inter:" to namespace the inter_agent module.

----------------------------------------------------------------------
1. AGENT REGISTRY
----------------------------------------------------------------------
Key: inter:agents  (SET)
  set of agent_id strings, e.g. {"agent_0", "agent_1", "agent_2", "agent_3"}

Key: inter:agent:{agent_id}  (HASH)
  Field               Type     Description
  ─────────────────────────────────────────────────────────
  agent_id            str      Agent identifier (e.g. "agent_0")
  main_pid            int      Primary PID of this agent
  comm                str      Process name (from common.h event_header.comm)
  workspace           str      Working directory path
  status              str      "active" | "inactive" | "isolated"
  group               str      Agent group for multi-tenant

----------------------------------------------------------------------
2. PER-AGENT METRICS (Rolled-up intra_agent pid_stats)
----------------------------------------------------------------------
Key: inter:metric:{agent_id}  (HASH)
  Field                  Type     Unit    Description
  ──────────────────────────────────────────────────────────────────────
  cpu_usage              float    0.0-1.0 CPU usage ratio
  memory_usage           float    0.0-1.0 Memory usage ratio
  proc_exec_count        int      count   execve calls in current window
  proc_fork_count        int      count   fork/clone calls
  fs_open_count          int      count   open/openat calls
  fs_read_count          int      count   read calls
  fs_write_count         int      count   write calls
  fs_unlink_count        int      count   unlink calls
  fs_rename_count        int      count   rename calls
  fs_chmod_count         int      count   chmod calls
  fs_rmdir_count         int      count   rmdir calls
  net_connect_count      int      count   connect calls
  net_send_count         int      count   send/sendmsg calls
  net_recv_count         int      count   recv/recvmsg calls
  net_bind_count         int      count   bind calls
  net_listen_count       int      count   listen calls
  api_call_count         int      count   External API calls (LLM, etc.)
  msg_sent_count         int      count   Messages sent to other agents
  msg_recv_count         int      count   Messages from other agents
  unique_files_count     int      count   Distinct files accessed
  shell_exec_count       int      count   Shell binary executions
  sensitive_file_count   int      count   Sensitive path accesses
  workspace_violation    int      count   Out-of-workspace operations
  window_start_ns        int      ns      Start of current stats window
  last_active_ns         int      ns      Timestamp of last event

----------------------------------------------------------------------
3. INTER-AGENT INTERACTION EDGES
----------------------------------------------------------------------
Key: inter:edges  (SET)
  set of edge keys, e.g. "agent_0:agent_1" (src:dst format)

Key: inter:edge:{src}:{dst}  (HASH)
  Field                  Type     Description
  ─────────────────────────────────────────────────────────
  src                    str      Source agent_id
  dst                    str      Destination agent_id
  type                   str      "api_call" | "message" | "file_share"
  weight                 float    Normalized interaction strength (0-1)
  total_messages         int      Cumulative message count
  total_bytes            int      Cumulative data volume (bytes)
  first_seen_ns          int      First interaction timestamp (ns)
  last_seen_ns           int      Most recent timestamp (ns)

----------------------------------------------------------------------
4. RAW eBPF EVENTS (converted from common.h structs)
----------------------------------------------------------------------
Key: inter:events (STREAM)  --  append-only event stream

Each stream entry contains a JSON-encoded event dict.
Schema adapted from common.h:

  4a. PROCESS EVENTS (common.h: enum proc_event_type)
  ──────────────────────────────────────────────────────────────────────
  {
    "event_type": "proc",
    "subtype": "PROC_EXEC" | "PROC_FORK" | "PROC_EXIT" |
               "PROC_SIGNAL" | "PROC_SETUID",
    "timestamp_ns": 1234567890000,
    "pid": 12345,
    "tid": 12345,
    "comm": "python3",
    // for PROC_EXEC:
    "filename": "/bin/ls",
    "parent_pid": 12344,
    // for PROC_FORK:
    "child_pid": 12346,
    // for PROC_EXIT:
    "exit_code": 0,
    // for PROC_SIGNAL:
    "sig": 9,
    "target_pid": 12347,
    // for PROC_SETUID:
    "uid": 1000,
    "old_uid": 0
  }

  4b. FILE SYSTEM EVENTS (common.h: enum fs_event_type)
  ──────────────────────────────────────────────────────────────────────
  {
    "event_type": "fs",
    "subtype": "FS_OPEN" | "FS_CLOSE" | "FS_READ" | "FS_WRITE" |
               "FS_UNLINK" | "FS_RENAME" | "FS_CHMOD" |
               "FS_CREATE" | "FS_RMDIR",
    "timestamp_ns": 1234567890000,
    "pid": 12345,
    "tid": 12345,
    "comm": "python3",
    // for FS_OPEN:
    "filename": "/etc/passwd",
    "flags": 0,
    // for FS_READ:
    "fd": 3,
    "bytes": 4096,
    "filename": "/data/file.txt",
    // for FS_WRITE:
    "fd": 4,
    "bytes": 2048,
    "filename": "/tmp/out.txt",
    // for FS_UNLINK:
    "filename": "/tmp/tmpfile",
    // for FS_RENAME:
    "oldname": "/tmp/a",
    "newname": "/tmp/b",
    // for FS_CHMOD:
    "filename": "/tmp/script.sh",
    "mode": 511,
    // for FS_CREATE:
    "filename": "/tmp/new.txt",
    "flags": 577,
    "mode": 420,
    // for FS_RMDIR:
    "dirname": "/tmp/testdir"
  }

  4c. NETWORK EVENTS (common.h: enum net_event_type)
  ──────────────────────────────────────────────────────────────────────
  {
    "event_type": "net",
    "subtype": "NET_SOCKET" | "NET_CONNECT" | "NET_BIND" |
               "NET_LISTEN" | "NET_ACCEPT" | "NET_SEND" |
               "NET_RECV" | "NET_CLOSE" | "NET_TCP_STATE",
    "timestamp_ns": 1234567890000,
    "pid": 12345,
    "tid": 12345,
    "comm": "python3",
    // for NET_SOCKET:
    "domain": 2,
    "sock_type": 1,
    "protocol": 6,
    "fd": 3,
    // for NET_CONNECT:
    "fd": 3,
    "saddr": "16777343",       // decimal IP
    "sport": 45321,
    "family": 2,
    // for NET_BIND:
    "fd": 3,
    "saddr": "0",
    "sport": 8080,
    "family": 2,
    // for NET_LISTEN:
    "fd": 3,
    "backlog": 128,
    // for NET_ACCEPT:
    "fd": 3,
    "newfd": 4,
    "saddr": "16777343",
    "sport": 45322,
    "family": 2,
    // for NET_SEND:
    "fd": 4,
    "daddr": "2130706433",     // decimal IP (127.0.0.1)
    "dport": 80,
    "bytes": 512,
    // for NET_RECV:
    "fd": 4,
    "saddr": "2130706433",
    "sport": 80,
    "bytes": 1024,
    // for NET_CLOSE:
    "fd": 4,
    // for NET_TCP_STATE:
    "saddr": "2130706433",
    "sport": 45321,
    "daddr": "16777343",
    "dport": 80,
    "oldstate": 1,
    "newstate": 2
  }

----------------------------------------------------------------------
5. INTRA-AGENT ANOMALY ALERTS (from intra_analyzer audit output)
----------------------------------------------------------------------
Key: inter:anomalies  (STREAM)

Alert types produced by intra_agent (from intra_analyzer.c):
  - UNEXPECTED_SHELL_EXEC (HIGH)
  - SENSITIVE_FILE_ACCESS (HIGH)
  - OUT_OF_WORKSPACE_OPERATION (HIGH)
  - POSSIBLE_LOGIC_LOOP (MEDIUM)

{
    "anomaly_id": "anom_001234",
    "rule": "UNEXPECTED_SHELL_EXEC",
    "severity": "HIGH",          // "LOW" | "MEDIUM" | "HIGH" | "CRITICAL"
    "timestamp_ns": 1234567890000,
    "pid": 12345,
    "tid": 12345,
    "comm": "bash",
    "agent_id": "agent_0",
    "object": "/bin/sh",
    "reason": "Agent process launched shell interpreter",
    "details": {}
}

----------------------------------------------------------------------
6. INTER-AGENT MESSAGES (communication records)
----------------------------------------------------------------------
Key: inter:messages  (STREAM)

Inter-agent communication derived from network events + process topology.

{
    "msg_id": "msg_001234",
    "src_agent": "agent_0",
    "dst_agent": "agent_1",
    "msg_type": "request",       // "request" | "response" | "broadcast" | "error"
    "protocol": "HTTP",          // "HTTP" | "gRPC" | "IPC" | "FILE"
    "data_size": 2048,           // bytes
    "timestamp_ns": 1234567890000,
    "src_pid": 12345,
    "dst_pid": 12346,
    "src_port": 45321,
    "dst_port": 8080,
    "status_code": 200,
    "latency_us": 15000
}

----------------------------------------------------------------------
7. OBSERVATION DICT (what inter_agent.process_observation() consumes)
----------------------------------------------------------------------
This is the Python dict assembled by RedisCollector for the detection pipeline.

{
    "agents": {
        "agent_0": {
            "cpu_usage": 0.75,           # float 0-1
            "memory_usage": 0.65,         # float 0-1
            "api_call_count": 78,         # int
            "msg_sent": 34,               # int
            "msg_received": 29,           # int
            "proc_exec_count": 12,        # int
            "proc_fork_count": 2,         # int
            "fs_open_count": 45,          # int
            "fs_read_count": 234,         # int
            "fs_write_count": 156,        # int
            "fs_unlink_count": 3,         # int
            "net_connect_count": 89,      # int
            "net_send_count": 567,        # int
            "net_recv_count": 543,        # int
            "shell_exec_count": 0,        # int
            "sensitive_file_count": 0,    # int
            "unique_files_count": 8       # int
        },
        ...
    },
    "interactions": [
        {
            "src": "agent_0",
            "dst": "agent_1",
            "type": "api_call",           # "api_call"|"message"|"file_share"
            "weight": 0.5,                # float
            "timestamp_ns": 1234567990000
        },
        ...
    ],
    "messages": [
        {
            "src": "agent_0",
            "dst": "agent_1",
            "msg_type": "request",        # str
            "data_size": 2048,            # int bytes
            "timestamp_ns": 1234567890000
        },
        ...
    ],
    "anomalies": [
        {
            "agent_id": "agent_0",
            "rule": "UNEXPECTED_SHELL_EXEC",
            "severity": "HIGH",           # str
            "risk_score": 0.85,           # float 0-1
            "description": "...",
            "timestamp_ns": 1234567890000
        }
    ],
    "timestamp": 1234567990000,
    "window_start_ns": 1234567890000
}

=================== KEY RELATIONSHIP SUMMARY ===================

Redis SET:  inter:agents              -- discover all agents
Redis HASH: inter:agent:{id}          -- agent metadata
Redis HASH: inter:metric:{id}         -- per-agent performance counters
Redis SET:  inter:edges               -- discover all edges
Redis HASH: inter:edge:{src}:{dst}    -- edge attributes
Redis STREAM: inter:events            -- raw eBPF events (optional)
Redis STREAM: inter:anomalies         -- intra_agent alerts
Redis STREAM: inter:messages          -- inter-agent communications
"""
