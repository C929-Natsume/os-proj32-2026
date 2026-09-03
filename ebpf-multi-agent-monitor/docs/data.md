┌─────────────────────────────────────────────────────────────────────────────────────────────────────┐
│                                   第一层：应用层交互捕获 (eBPF uprobe/kprobe)                          │
│                                                                                                     │
│  ┌─ SSL/uprobe ───────────────────────────────────────┐  ┌─ 纯文本协议/kprobe ────────────────────┐ │
│  │  ssl_sniffer.bpf.c                                 │  │  sys_behavior.bpf.c (L570-869)          │ │
│  │                                                     │  │                                         │ │
│  │  [up/uret] SSL_read(ssl,buf,num)                    │  │  [kprobe] read(fd=0, buf, count)        │ │
│  │  [up/uret] SSL_write(ssl,buf,num)                   │  │     └→ pending_read[tid] = {buf,fd}     │ │
│  │  [up/uret] SSL_read_ex(ssl,buf,num,readbytes)       │  │  [trace] sys_exit_read(ctx->ret>0)      │ │
│  │  [up/uret] SSL_write_ex(ssl,buf,num,readbytes)      │  │     └→ submit_raw_event(ret bytes)       │ │
│  │  [up/uret] SSL_do_handshake(ssl)                    │  │                                         │ │
│  │  [up] go_tls_write(BX=buf, CX=len)                  │  │  [kprobe] write(fd=1/2, buf, count)     │ │
│  │  [up/uret] go_tls_read(BX=buf, CX=len)              │  │     └→ submit_raw_event (STDIO)         │ │
│  │                                                     │  │  [kprobe] write(fd≠1/2, buf, count)     │ │
│  │  数据输出 → ssl_rb (4MB ringbuf)                     │  │     └→ submit_raw_event (TCP)          │ │
│  │  struct probe_SSL_data_t {                          │  │                                         │ │
│  │    timestamp_ns, delta_ns,                          │  │  [kprobe] sendto(fd,buf,len,...)         │ │
│  │    pid, tid, uid,                                   │  │     └→ submit_raw_event (TCP SEND)      │ │
│  │    agent_id, agent_name,                            │  │                                         │ │
│  │    len, buf_size, buf_filled,                       │  │  [kprobe] recvfrom(fd,buf,len,...)       │ │
│  │    rw {0=READ,1=WRITE,2=HANDSHAKE},                 │  │     └→ pending_recv[tid] = {buf,fd}     │ │
│  │    is_handshake,                                    │  │  [trace] sys_exit_recvfrom(ctx->ret>0)  │ │
│  │    engine {1=OPENSSL,2=BORINGSSL,3=GO_TLS},         │  │     └→ submit_raw_event (TCP RECV)      │ │
│  │    comm[MAX_COMM_LEN],                              │  │                                         │ │
│  │    buf[65536]  ← 解密后的明文                           │  │  [kprobe] sendmsg(fd, msg, flags)       │ │
│  │  }                                                  │  │     └→ submit_msghdr_event             │ │
│  └─────────────────────────────────────────────────────┘  │  [kprobe] recvmsg(fd, msg, flags)       │ │
│                                                            │     └→ pending_msg[tid] = {msg_ptr}    │ │
│                                                            │  [trace] sys_exit_recvmsg(ctx->ret>0)  │ │
│                                                            │     └→ submit_msghdr_event (解引用iov) │ │
│                                                            │                                         │ │
│                                                            │  数据输出 → raw_rb (2MB ringbuf)          │ │
│                                                            │  struct raw_data_event {                 │ │
│                                                            │    timestamp_ns, pid, tid,               │ │
│                                                            │    agent_id, agent_name,                 │ │
│                                                            │    parent_agent_id, parent_agent_name,   │ │
│                                                            │    data_len, buf_size, buf_filled,       │ │
│                                                            │    direction {0=RECV,1=SEND},            │ │
│                                                            │    source {1=STDIO,2=TCP},               │ │
│                                                            │    fd, peer_pid, comm,                   │ │
│                                                            │    buf[16384]  ← 原始协议payload            │ │
│                                                            │  }                                       │ │
│                                                            └─────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────────────────────────────────────────────────┘
                                         │                                          │
                                         ▼                                          ▼
┌─────────────────────────────────────────────────────────────────────────────────────────────────────┐
│                                   第二层：系统调用行为捕获 (eBPF kprobe/tracepoint)                     │
│                                                                                                     │
│  sys_behavior.bpf.c                                                                                │
│  ┌─────────────────────────────────────────────────────────────────────────────────────────────┐    │
│  │  [ksyscall/execve]          → submit_sys_event(EVENT_EXECVE,   filename)                   │    │
│  │  [ksyscall/open/openat]     → submit_sys_event(EVENT_OPEN,     filename)                   │    │
│  │  [ksyscall/unlink/unlinkat] → submit_sys_event(EVENT_UNLINK,   filename)                   │    │
│  │  [ksyscall/fchmodat]        → submit_sys_event(EVENT_CHMOD,    filename)                   │    │
│  │  [ksyscall/connect]         → submit_connect_event()  ← 含 resolve_listen_peer() 检测       │    │
│  │                                   ├─ EVENT_CONNECT (普通连接)                               │    │
│  │                                   └─ EVENT_AGENT_COMM (对端是智能体，类型升格)                  │    │
│  │                               +→ fd_peer_map[fd] = {peer_pid, peer_agent_id, peer_name}    │    │
│  │  [ksyscall/bind]            → listen_map[{saddr,sport}] = pid                              │    │
│  │                               fd_peer_map[fd] = {self_pid, self_agent_id, self_name}       │    │
│  │  [ksyscall/close]           → fd_peer_map 清理对应 fd                                      │    │
│  │  [tracepoint/sched_fork]    → monitored_pids[child] = process_context{继承+候选标记}       │    │
│  │  [tp_btf/sched_switch]      → resource_map[{RES_LEVEL_PID,pid}].cpu_time_ns += delta        │    │
│  └─────────────────────────────────────────────────────────────────────────────────────────────┘    │
│                                                                                                     │
│  数据输出 → rb (256KB ringbuf)                                                                       │
│  struct sys_event {                                                                                │
│    event_type {1=EXECVE,2=FORK,3=OPEN,4=UNLINK,5=CONNECT,7=CHMOD,8=AGENT_COMM},                  │
│    pid, child_pid, uid, timestamp,                                                                  │
│    agent_id, agent_name,                                                                            │
│    parent_agent_id, parent_agent_name,                                                             │
│    peer_agent_id, peer_pid, peer_agent_name,                                                        │
│    comm, filename,                                                                                  │
│    union {                                                                                          │
│      execve { exit_code },                                                                          │
│      connect { family, dport, dip[46] },                                                           │
│      open   { mode }                                                                               │
│    }                                                                                                │
│  }                                                                                                  │
└─────────────────────────────────────────────────────────────────────────────────────────────────────┘
                                         │
                                         ▼
┌─────────────────────────────────────────────────────────────────────────────────────────────────────┐
│                                   第三层：智能体身份追踪 + 资源监控                                    │
│                                                                                                     │
│  身份注入 (loader.c):                                                                              │
│    扫描 /proc/*/cmdline → 匹配关键词 {claude,opencode,deepseek,...}                                 │
│    → 分配全局 agent_id (自1000递增)                                                                  │
│    → register_agent(monitored_pids, pid, agent_id, "Sys-Claude-1001")                              │
│    → register_agent(agent_info_map, pid, agent_id, "Sys-Claude-1001")  ← SSL 引擎专用               │
│                                                                                                     │
│  血缘树 (sys_behavior.bpf.c + agent_tracker.c):                                                    │
│    fork钩子: 子标记 CANDIDATE_SUB_AGENT → 连接443或协议指纹命中 → promote_to_sub_agent()           │
│    agent_tracker: 用户态维护 g_agents[] 数组, get_or_create_agent() 按 PID 查找/创建                │
│                                                                                                     │
│  资源四维聚合 (metrics_aggregator.c):                                                              │
│    [内核] sched_switch → resource_map 存 cpu_time_ns                                                │
│    [用户态] 每2秒遍历 resource_map:                                                                 │
│      ├─ 读 /proc/pid/statm → RSS bytes (resident*4096)                                             │
│      ├─ 读 /proc/pid/stat  → CPU ticks                                                              │
│      ├─ level=PID: 逐条 PUBLISH                                                                    │
│      ├─ level=AGENT: 按 agent_id 聚合后 PUBLISH                                                    │
│      ├─ level=CGROUP: 按 cgroup_id 聚合后 PUBLISH                                                  │
│      └─ level=SYS: 全局汇总后 PUBLISH                                                              │
│                                                                                                     │
│  拓扑构建 (topology_builder.c):                                                                    │
│    AGENT_COMM 事件 → SADD inter:edges + HSET inter:edge:{src}:{dst}                               │
│    消息流 → SADD inter:edges + HSET + HINCRBY total_messages/bytes                                 │
└─────────────────────────────────────────────────────────────────────────────────────────────────────┘
                                         │
                                         ▼
┌─────────────────────────────────────────────────────────────────────────────────────────────────────┐
│                           ringbuf_handler (用户态 C 守护进程, 单线程无锁轮询)                          │
│                                                                                                     │
│  1. bpf_obj_get("/sys/fs/bpf/sys_rb")  → sys_fd                                                   │
│  2. bpf_obj_get("/sys/fs/bpf/ssl_rb")  → ssl_fd                                                   │
│  3. bpf_obj_get("/sys/fs/bpf/raw_rb")  → raw_fd                                                   │
│  4. ring_buffer__new(sys_fd) + ring_buffer__add(ssl_fd) + ring_buffer__add(raw_fd)                 │
│  5. ring_buffer__poll(rb, 100ms)  ← 三合一轮询                                                      │
│                                                                                                     │
│  回调函数分发:                                                                                      │
│  ┌─────────────────────┬──────────────────────────────┬────────────────────────────────────────┐    │
│  │ handle_sys_event()  │ handle_ssl_event()           │ handle_raw_event()                     │    │
│  ├─────────────────────┼──────────────────────────────┼────────────────────────────────────────┤    │
│  │ 接收: sys_event     │ 接收: probe_SSL_data_t       │ 接收: raw_data_event                   │    │
│  │ 过滤: 无            │ 过滤: buf_size=0/buf_filled=0│ 过滤: 只推送元数据即使 buf=0           │    │
│  │ 动作: ship_sys_event│       /is_handshake/rw=2     │ 动作: ship_raw_event                   │    │
│  └─────────────────────┴──────────────────────────────┴────────────────────────────────────────┘    │
│                                                                                                     │
│  并行: fetch_and_ship_resources(res_fd) 每 2秒                                                      │
└─────────────────────────────────────────────────────────────────────────────────────────────────────┘
                                         │
                                         ▼
┌─────────────────────────────────────────────────────────────────────────────────────────────────────┐
│                              Redis 输出 (6 类数据通道)                                                │
│                                                                                                     │
│  ─── 通道1: PUBLISH ebpf_events (实时事件流, JSON) ─────                                            │
│                                                                                                     │
│  sys_event → JSON:                                                                                  │
│    {"type":1,"pid":1234,"ppid":0,"uid":1000,"timestamp":...,"comm":"claude",                        │
│     "filename":"/usr/bin/ls","agent_id":"Sys-Claude-1001","parent_agent_id":0,                      │
│     "parent_agent_name":"","main_pid":1234,"depth":0,"is_sub_agent":0}                              │
│                                                                                                     │
│  connect/agent_comm → JSON:                                                                        │
│    {"type":5,"pid":1234,..."dip":"127.0.0.1","dport":8080,                                         │
│     "agent_id":"Sys-Claude-1001",...                                                                │
│     "peer_agent_id":1002,"peer_pid":5678}                                                           │
│                                                                                                     │
│  ssl_event → JSON:                                                                                 │
│    {"type":44,"pid":1234,"ppid":1234,"timestamp":...,"comm":"python",                              │
│     "data_len":4096,"data":"<base64>","agent_id":"Sys-Claude-1001","main_pid":1234}                 │
│                                                                                                     │
│  raw_event → JSON:                                                                                 │
│    {"type":10,"pid":1234,"tid":1234,"timestamp":...,"comm":"claude",                               │
│     "data_len":256,"fd":1,"source":1,"direction":1,                                                │
│     "agent_id":1001,"agent_name":"Sys-Claude-1001",                                                │
│     "parent_agent_id":0,"parent_agent_name":"","peer_pid":0,                                       │
│     "data":"<base64>"}                                                                              │
│                                                                                                     │
│  ─── 通道2: XADD inter:events (持久化事件流) ────────                                               │
│                                                                                                     │
│  EXECVE/OPEN/UNLINK/CHMOD:                                                                         │
│    XADD inter:events * event_type proc subtype PROC_EXEC timestamp_ns ...                           │
│                          pid ... tid ... comm ... filename ... parent_pid ...                        │
│                          agent_id ... parent_agent_id ... parent_agent_name ...                      │
│                                                                                                     │
│  FORK:                                                                                             │
│    XADD inter:events * event_type proc subtype PROC_FORK ... child_pid ...                         │
│                                                                                                     │
│  CONNECT:                                                                                          │
│    XADD inter:events * event_type net subtype NET_CONNECT ... family daddr dport ...                │
│                                                                                                     │
│  AGENT_COMM:                                                                                       │
│    XADD inter:events * event_type net subtype AGENT_COMM ... family daddr dport ...                 │
│                          agent_id ... parent_agent_id ... parent_agent_name ...                     │
│                          peer_agent_id ... peer_pid ... peer_agent ...                              │
│                                                                                                     │
│  ─── 通道3: XADD inter:messages (应用层消息流, 含 payload) ───────                                  │
│                                                                                                     │
│  XADD inter:messages * msg_id msg_000001 src agent_1234 dst llm_api                                │
│        type prompt protocol ssl timestamp_ns ... pid ... tid ... main_pid ...                       │
│        comm python agent_id agent_1234 bytes 4096 data '<json_escaped>'                             │
│                                                                                                     │
│  (type: prompt/response/send/recv  |  protocol: ssl/stdio/tcp)                                     │
│                                                                                                     │
│  ─── 通道4: PUBLISH ebpf_resource_events (资源采样) ────                                           │
│                                                                                                     │
│  {"event":"RESOURCE_SAMPLE","timestamp":...,"level":4,"target_pid":1234,                           │
│   "total_rss_kb":45678,"total_cpu_user_ms":1234,"num_processes":1,                                │
│   "cgroup_memory_bytes":...,"cgroup_cpu_usage_usec":...}                                           │
│                                                                                                     │
│  ─── 通道5: HSET inter:metric:{agent_id} (30s窗口聚合指标) ─────                                   │
│                                                                                                     │
│  HSET inter:metric:agent_1234                                                                      │
│    cpu_usage 0.05 memory_usage 0.02                                                                │
│    proc_exec_count 3 proc_fork_count 1                                                              │
│    fs_open_count 15 fs_read_count 20 fs_write_count 10 fs_unlink_count 1 fs_chmod_count 0          │
│    net_connect_count 5 net_send_count 8 net_recv_count 12                                          │
│    api_call_count 25 msg_sent_count 8 msg_recv_count 12                                            │
│    unique_files_count 7 shell_exec_count 2 sensitive_file_count 0 workspace_violation 0            │
│    ssl_msg_count 10 ssl_total_bytes 20480                                                          │
│    window_start_ns ... last_active_ns ...                                                          │
│                                                                                                     │
│  ─── 通道6: SADD/HSET inter:edges / inter:agents (拓扑+注册) ────                                  │
│                                                                                                     │
│  SADD inter:agents agent_1234                                                                      │
│  HSET inter:agent:agent_1234 agent_id agent_1234 parent_agent_id agent_0 main_pid 1234             │
│       comm python workspace /home/user depth 0 is_sub_agent 0 status active group default          │
│                                                                                                     │
│  SADD inter:edges agent_1234:agent_5678                                                            │
│  HSET inter:edge:agent_1234:agent_5678 src agent_1234 dst agent_5678 type agent_comm               │
│       protocol tcp daddr 127.0.0.1 dport 8080 last_seen_ns ...                                     │
│       total_messages 5 total_bytes 4096                                                            │
└─────────────────────────────────────────────────────────────────────────────────────────────────────┘
                                         │
                                         ▼
┌─────────────────────────────────────────────────────────────────────────────────────────────────────┐
│                              Python 分析层 (main_analyzer.py)                                        │
│                                                                                                     │
│  ┌─ 订阅 ebpf_events (pub/sub JSON 实时) ────────────────────────────────────────┐                 │
│  │  反序列化 → 按 type 分发:                                                      │                 │
│  │    type 1-8  →  分析器: sys_event_anomaly_detection()                          │                 │
│  │    type 44-45 → 分析器: ssl_message_anomaly_detection()  ← prompt/response     │                 │
│  │    type 10-13 → 分析器: raw_protocol_anomaly_detection()                       │                 │
│  └───────────────────────────────────────────────────────────────────────────────┘                 │
│                                                                                                     │
│  ┌─ 读 XREAD inter:messages (流式) ────────────────────────────────────────────────┐                 │
│  │  protocol_fingerprint.py: 检测 MCP / A2A / ACP / ANP 协议类型                   │                 │
│  └───────────────────────────────────────────────────────────────────────────────┘                 │
│                                                                                                     │
│  ┌─ 结果输出 ──────────────────────────────────────────────────────────────────────┐                 │
│  │  intra_agent/main.py → 单智能体异常检测 → 输出 anomaly_{ts}.log                 │                 │
│  │  inter_agent/main.py → 多智能体关联分析 → 输出 SQLite + audit_log               │                 │
│  │  audit_engine.py    → 白/黑/灰名单 + LLM 复审                                   │                 │
│  └───────────────────────────────────────────────────────────────────────────────┘                 │
└─────────────────────────────────────────────────────────────────────────────────────────────────────┘