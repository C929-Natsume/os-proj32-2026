AGENT_METRIC_FIELDS = {
    "cpu_usage": 0.0,
    "memory_usage": 0.0,
    "api_call_count": 0,
    "msg_sent": 0,
    "msg_received": 0,
    "proc_exec_count": 0,
    "proc_fork_count": 0,
    "fs_open_count": 0,
    "fs_read_count": 0,
    "fs_write_count": 0,
    "fs_unlink_count": 0,
    "net_connect_count": 0,
    "net_send_count": 0,
    "net_recv_count": 0,
    "shell_exec_count": 0,
    "sensitive_file_count": 0,
    "unique_files_count": 0,
    "workspace_violation": 0,
}


def empty_observation():
    return {
        "agents": {},
        "interactions": [],
        "messages": [],
        "anomalies": [],
        "timestamp": 0,
        "window_start_ns": 0,
    }
