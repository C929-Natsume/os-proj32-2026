# Redis 新增数据接口规范

> **目的**：定义 C 端 `redis_shipper.c` 需要新增写入的所有 Redis key，使其输出与 Python 端 `RedisCollector` 读取格式对齐。
>
> **原则**：现有 `PUBLISH ebpf_events` 保持不变，新增 `inter:*` 命名空间下的 SET / HASH / STREAM 写入。

---

## 目录

1. [Agent 注册 — `inter:agents` / `inter:agent:{id}`](#1-agent-注册)
2. [窗口聚合指标 — `inter:metric:{agent_id}`](#2-窗口聚合指标)
3. [交互边 — `inter:edges` / `inter:edge:{src}:{dst}`](#3-交互边)
4. [事件流 — `inter:events`](#4-事件流)
5. [通信消息 — `inter:messages`](#5-通信消息)
6. [异常告警 — `inter:anomalies`](#6-异常告警)
7. [common.h 事件类型映射表](#7-commonh-事件类型映射表)
8. [关键约束](#8-关键约束)

---

## 1. Agent 注册

每个 agent 启动时写入一次。

### `inter:agents` (Redis SET)

```
SADD inter:agents "agent_0" "agent_1" "agent_2" "agent_3"
```

### `inter:agent:{agent_id}` (Redis HASH)

```bash
HSET inter:agent:agent_0 \
  agent_id   "agent_0" \
  main_pid   12345 \
  comm       "python3" \
  workspace  "/data/agent_0" \
  status     "active" \
  group      "default"
```

| Field | Type | Description |
|---|---|---|
| `agent_id` | string | Agent 标识，如 `"agent_0"` |
| `main_pid` | int | 主进程 PID |
| `comm` | string | 进程名（来自 `event_header.comm`） |
| `workspace` | string | 工作目录路径 |
| `status` | string | `"active"` / `"inactive"` / `"isolated"` |
| `group` | string | 多租户分组 |

---

## 2. 窗口聚合指标

**关键变化**：C 端不再只 PUBLISH 单条事件，还需在每个窗口周期（如 30s）结束时，将累计的计数器写入 HASH。

### `inter:metric:{agent_id}` (Redis HASH)

```bash
HSET inter:metric:agent_0 \
  cpu_usage            0.32 \
  memory_usage         0.41 \
  proc_exec_count      3 \
  proc_fork_count      1 \
  fs_open_count        12 \
  fs_read_count        234 \
  fs_write_count       156 \
  fs_unlink_count      0 \
  net_connect_count    8 \
  api_call_count       78 \
  msg_sent_count       15 \
  msg_recv_count       12 \
  unique_files_count   7 \
  shell_exec_count     0 \
  sensitive_file_count 0 \
  workspace_violation  0 \
  window_start_ns      1717400000000000000 \
  last_active_ns       1717400030000000000
```

### 字段一览

| Field | Type | 单位 | 对应 common.h 事件 |
|---|---|---|---|
| `cpu_usage` | float | 0.0–1.0 | 从 `/proc/pid/stat` 计算 |
| `memory_usage` | float | 0.0–1.0 | 从 `/proc/pid/status` 计算 |
| `proc_exec_count` | int | count | `EVENT_EXECVE` 计数 |
| `proc_fork_count` | int | count | `EVENT_FORK` 计数 |
| `fs_open_count` | int | count | `EVENT_OPEN` 计数 |
| `fs_read_count` | int | count | `EVENT_SSL_READ` 次数 |
| `fs_write_count` | int | count | `EVENT_SSL_WRITE` 次数 |
| `fs_unlink_count` | int | count | `EVENT_UNLINK` 计数 |
| `net_connect_count` | int | count | `EVENT_CONNECT` 计数 |
| `api_call_count` | int | count | SSL READ/WRITE 中外部 API 请求数（需业务标记） |
| `msg_sent_count` | int | count | 本 agent 发送到其他 agent 的消息数 |
| `msg_recv_count` | int | count | 本 agent 从其他 agent 接收的消息数 |
| `unique_files_count` | int | count | 窗口内去重的 filename 数 |
| `shell_exec_count` | int | count | `EVENT_EXECVE` 且 filename 含 `sh`/`bash`/`zsh` |
| `sensitive_file_count` | int | count | `EVENT_OPEN` 且 filename 匹配敏感路径 |
| `workspace_violation` | int | count | 文件操作超出 `workspace` 路径的次数 |
| `window_start_ns` | int | ns | 当前窗口起始时间戳 |
| `last_active_ns` | int | ns | 窗口内最近一次事件时间戳 |

---

## 3. 交互边

检测到 agent A 向 agent B 发起 connect / send 时，记录边关系。

### `inter:edges` (Redis SET)

```
SADD inter:edges "agent_0:agent_1"
```

SET 元素格式为 `"{src}:{dst}"`。

### `inter:edge:{src}:{dst}` (Redis HASH)

```bash
HSET inter:edge:agent_0:agent_1 \
  src              "agent_0" \
  dst              "agent_1" \
  type             "api_call" \
  weight           0.5 \
  total_messages   34 \
  total_bytes      20480 \
  first_seen_ns    1717400000000000000 \
  last_seen_ns     1717400030000000000
```

| Field | Type | Description |
|---|---|---|
| `src` | string | 源 agent_id |
| `dst` | string | 目标 agent_id |
| `type` | string | `"api_call"` / `"message"` / `"file_share"` |
| `weight` | float | 规范化交互强度 0–1 |
| `total_messages` | int | 累计消息数 |
| `total_bytes` | int | 累计数据量（bytes） |
| `first_seen_ns` | int | 首次交互时间戳 (ns) |
| `last_seen_ns` | int | 最近交互时间戳 (ns) |

---

## 4. 事件流

每条 eBPF 事件按 JSON 格式 `XADD` 到流中。此流为**可选**，供离线回放和调试使用。

### `inter:events` (Redis STREAM)

```bash
XADD inter:events * \
  event_type   "proc" \
  subtype      "PROC_EXEC" \
  timestamp_ns 1717400000000000000 \
  pid          12345 \
  tid          12345 \
  comm         "python3" \
  filename     "/bin/sh" \
  parent_pid   12344
```

### 各子类型示例

#### PROC_EXEC（原 `EVENT_EXECVE`）

```bash
XADD inter:events * \
  event_type   "proc" \
  subtype      "PROC_EXEC" \
  timestamp_ns 1717400000000000000 \
  pid          12345 \
  tid          12345 \
  comm         "python3" \
  filename     "/bin/sh" \
  parent_pid   12344
```

#### PROC_FORK（原 `EVENT_FORK`）

```bash
XADD inter:events * \
  event_type   "proc" \
  subtype      "PROC_FORK" \
  timestamp_ns 1717400000000000000 \
  pid          12345 \
  tid          12345 \
  comm         "python3" \
  child_pid    12346
```

#### FS_OPEN（原 `EVENT_OPEN`）

```bash
XADD inter:events * \
  event_type   "fs" \
  subtype      "FS_OPEN" \
  timestamp_ns 1717400001000000000 \
  pid          12345 \
  tid          12345 \
  comm         "python3" \
  filename     "/etc/passwd" \
  flags        0
```

#### FS_UNLINK（原 `EVENT_UNLINK`）

```bash
XADD inter:events * \
  event_type   "fs" \
  subtype      "FS_UNLINK" \
  timestamp_ns 1717400001500000000 \
  pid          12345 \
  tid          12345 \
  comm         "python3" \
  filename     "/tmp/tmpfile"
```

#### NET_CONNECT（原 `EVENT_CONNECT`）

```bash
XADD inter:events * \
  event_type   "net" \
  subtype      "NET_CONNECT" \
  timestamp_ns 1717400002000000000 \
  pid          12345 \
  tid          12345 \
  comm         "python3" \
  fd           3 \
  saddr        "16777343" \
  sport        45321 \
  family       2
```

#### NET_SEND（原 `EVENT_SSL_WRITE`）

```bash
XADD inter:events * \
  event_type   "net" \
  subtype      "NET_SEND" \
  timestamp_ns 1717400003000000000 \
  pid          12345 \
  tid          12345 \
  comm         "python3" \
  fd           4 \
  daddr        "2130706433" \
  dport        443 \
  bytes        512
```

#### NET_RECV（原 `EVENT_SSL_READ`）

```bash
XADD inter:events * \
  event_type   "net" \
  subtype      "NET_RECV" \
  timestamp_ns 1717400004000000000 \
  pid          12345 \
  tid          12345 \
  comm         "python3" \
  fd           4 \
  saddr        "2130706433" \
  sport        443 \
  bytes        1024
```

---

## 5. 通信消息

当检测到 agent 间通信（通过 connect 端口或 SSL 流量识别）时写入。

### `inter:messages` (Redis STREAM)

```bash
XADD inter:messages * \
  msg_id       "msg_000001" \
  src_agent    "agent_0" \
  dst_agent    "agent_1" \
  msg_type     "request" \
  protocol     "HTTP" \
  data_size    2048 \
  timestamp_ns 1717400005000000000 \
  src_pid      12345 \
  dst_pid      12346 \
  src_port     45321 \
  dst_port     8080 \
  status_code  200 \
  latency_us   15000
```

| Field | Type | Description |
|---|---|---|
| `msg_id` | string | 消息唯一 ID |
| `src_agent` | string | 源 agent |
| `dst_agent` | string | 目标 agent |
| `msg_type` | string | `"request"` / `"response"` / `"broadcast"` / `"error"` |
| `protocol` | string | `"HTTP"` / `"gRPC"` / `"IPC"` / `"FILE"` |
| `data_size` | int | 消息体大小 (bytes) |
| `timestamp_ns` | int | 时间戳 (ns) |
| `src_pid` | int | 源 PID |
| `dst_pid` | int | 目标 PID |
| `src_port` | int | 源端口 |
| `dst_port` | int | 目标端口 |
| `status_code` | int | HTTP 状态码或等价 |
| `latency_us` | int | 延迟 (微秒) |

---

## 6. 异常告警

C 端 intra_agent 检测到异常时写入（shell 执行、敏感文件访问等）。

### `inter:anomalies` (Redis STREAM)

```bash
XADD inter:anomalies * \
  anomaly_id   "anom_000001" \
  rule         "UNEXPECTED_SHELL_EXEC" \
  severity     "HIGH" \
  timestamp_ns 1717400006000000000 \
  pid          12345 \
  tid          12345 \
  comm         "bash" \
  agent_id     "agent_0" \
  object       "/bin/sh" \
  reason       "Agent process launched shell interpreter" \
  details      "{}"
```

| Field | Type | Description |
|---|---|---|
| `anomaly_id` | string | 告警唯一 ID |
| `rule` | string | 规则名：`UNEXPECTED_SHELL_EXEC` / `SENSITIVE_FILE_ACCESS` / `OUT_OF_WORKSPACE_OPERATION` / `POSSIBLE_LOGIC_LOOP` |
| `severity` | string | `"LOW"` / `"MEDIUM"` / `"HIGH"` / `"CRITICAL"` |
| `timestamp_ns` | int | 时间戳 (ns) |
| `pid` | int | 触发进程 PID |
| `tid` | int | 触发线程 TID |
| `comm` | string | 进程名 |
| `agent_id` | string | 所属 agent |
| `object` | string | 操作对象（文件路径 / 端口等） |
| `reason` | string | 可读的异常原因 |
| `details` | string | 补充信息的 JSON 字符串 |

---

## 7. common.h 事件类型映射表

| C enum | 值 | `inter:events` 中的 `event_type` | `subtype` |
|---|---|---|---|
| `EVENT_EXECVE` | 1 | `"proc"` | `"PROC_EXEC"` |
| `EVENT_FORK` | 2 | `"proc"` | `"PROC_FORK"` |
| `EVENT_OPEN` | 3 | `"fs"` | `"FS_OPEN"` |
| `EVENT_UNLINK` | 4 | `"fs"` | `"FS_UNLINK"` |
| `EVENT_CONNECT` | 5 | `"net"` | `"NET_CONNECT"` |
| `EVENT_SSL_READ` | 6 | `"net"` | `"NET_RECV"` |
| `EVENT_SSL_WRITE` | 7 | `"net"` | `"NET_SEND"` |

---

## 8. 关键约束

1. **时间窗口**：Python 方 `RedisCollector` 默认 30s 窗口，`window_start_ns` 和 `last_active_ns` 对齐此窗口
2. **计数器重置**：每次 `HSET inter:metric:{id}` 后，C 端必须清零内存计数器，开始下一窗口
3. **agent_id 分配**：C 端需维护 PID → agent_id 映射（如配置文件 `/etc/agent_id.conf` 或启动参数传入）
4. **字段命名一致性**：HASH field 名必须与本文表格完全一致（下划线命名，全小写），Python 方 `collector.py:86-99` 硬编码了这些字段名
5. **首次启动**：建议先执行 `ship_register_agent()` 完成注册，再开始写入其他 key
6. **错误处理**：所有 Redis 命令调用失败不应影响 eBPF 主流程，建议 `void` 返回 + 日志打印
