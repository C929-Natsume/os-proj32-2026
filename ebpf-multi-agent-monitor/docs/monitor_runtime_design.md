# eBPF Multi-Agent Monitor 运行链路说明

本文档概述本轮改动范围、异常类型、Redis 数据规范与 SQLite 持久化方案。整体链路为：

```text
loader/eBPF -> ringbuf_handler -> Redis -> main_analyzer -> SQLite
```

## 1. 修改文件

| 文件 | 说明 |
| --- | --- |
| `src/user/redis_shipper.c` | 增强 Redis 推送逻辑，新增 `inter:messages` Stream 写入；补充 `pid/tid/main_pid/comm/agent_id` 等归因字段；修复 `XADD` 参数格式。 |
| `src/analysis/main_analyzer.py` | 主分析器同时支持 Redis pub/sub 与 Stream；默认只消费新事件；增加非 UTF-8 安全解码、SSL 降噪、异常入库逻辑。 |
| `src/analysis/sqlite_store.py` | 新增 SQLite 持久化模块，保存原始事件、异常记录和审计结果。 |
| `src/analysis/inter_agent/main.py` | 增强跨智能体关联分析，包括短 SSL 会话、重复 payload、提示注入、资源竞争等规则。 |
| `src/config/app_config.yaml` | 新增 SQLite 存储配置。 |
| `src/config/rules.yaml` | 统一配置单体分析和跨智能体分析规则阈值。 |
| `src/user/Makefile` | 修正用户态程序构建与链接配置。 |


## 2. 五类异常

| 类型 | 代表规则 | 说明 |
| --- | --- | --- |
| 进程执行异常 | `UNEXPECTED_SHELL_EXEC`、`PRIVILEGE_ESCALATION_ATTEMPT` | 检测 shell 执行、sudo 提权、下载后执行等危险进程行为。 |
| 文件越界异常 | `SENSITIVE_FILE_ACCESS`、`OUT_OF_WORKSPACE_OPERATION` | 检测访问敏感文件、删除工作区外文件、读取凭据等行为。 |
| 网络流量异常 | `UNUSUAL_NETWORK_CONNECTION`、`FREQUENT_SHORT_SSL_SESSIONS` | 检测非标准端口外连、短 SSL 分片爆发、重复 SSL payload。 |
| Prompt 注入异常 | `PROMPT_INJECTION_SIGNAL`、`PROMPT_INJECTION_TO_DANGEROUS_ACTION` | 检测忽略指令、泄露系统提示、诱导危险动作等语义风险。 |
| 循环与资源异常 | `POSSIBLE_LOGIC_LOOP`、`RESOURCE_CONTENTION_SPIKE` | 检测高频 IO/网络循环、资源竞争、进程风暴等系统级异常。 |

## 3. Redis 规范

### Pub/Sub

| Channel | 用途 |
| --- | --- |
| `ebpf_events` | 实时事件通道，兼容系统事件与 SSL 事件。 |
| `ebpf_behavior_events` | 行为语义事件通道。 |
| `ebpf_resource_events` | 资源采样事件通道。 |

### Stream

| Stream/Key | 用途 |
| --- | --- |
| `inter:messages` | LLM/SSL 消息流，分析器主要消费该 Stream。 |
| `inter:events` | 系统行为事件流，用于跨智能体关联。 |
| `inter:anomalies` | 分析器输出的异常结果流。 |
| `inter:agents` | 已发现智能体集合。 |
| `inter:agent:<agent_id>` | 单个智能体元信息。 |
| `inter:edges`、`inter:edge:<src>:<dst>` | 智能体通信边与边属性。 |
| `inter:metric:<agent_id>` | 智能体聚合指标。 |

### `inter:messages` 字段

| 字段 | 说明 |
| --- | --- |
| `msg_id` | 消息 ID。 |
| `src` / `dst` | 源智能体与目标组件。 |
| `type` | `prompt` 或 `response`。 |
| `protocol` | 当前为 `ssl`。 |
| `timestamp_ns` | 事件时间戳。 |
| `pid` / `tid` / `main_pid` | 进程、线程与母体进程归因。 |
| `comm` / `agent_id` | 进程名与智能体 ID。 |
| `bytes` / `data` | payload 长度与截断预览。 |

### Analyzer 控制项

| 环境变量 | 说明 |
| --- | --- |
| `ANALYZER_REPLAY_HISTORY=1` | 从历史开头回放 `inter:messages`。默认只看新事件。 |
| `ANALYZER_LOG_SSL_EVENTS=1` | 打印 SSL 事件摘要。默认关闭。 |
| `ANALYZER_VERBOSE_EVENTS=1` | 打印完整事件内容。默认关闭。 |
| `ANALYZER_PROCESS_SSL_PUBSUB=1` | 同时处理 pub/sub 中的 SSL 事件。默认关闭，避免重复。 |

## 4. 持久化保存

SQLite 默认开启，路径：

```text
logs/alerts/analysis.db
```

配置位置：

```yaml
storage:
  sqlite:
    enabled: true
    path: ../../logs/alerts/analysis.db
```

### 数据表

| 表 | 内容 |
| --- | --- |
| `events` | 保存分析器接收到的原始事件。 |
| `anomalies` | 保存规则命中的异常记录。 |
| `audit_results` | 保存审计请求与审计结果。 |

### 常用查询

查看最近异常：

```bash
sqlite3 logs/alerts/analysis.db \
  "select anomaly_id, rule, severity, pid, comm from anomalies order by id desc limit 5;"
```

查看最近审计结果：

```bash
sqlite3 logs/alerts/analysis.db \
  "select rule, severity, pid, comm, result_json from audit_results order by id desc limit 5;"
```

## 5. 终端命令

### 挂载 bpffs

```bash
sudo mkdir -p /sys/fs/bpf
mount | grep ' /sys/fs/bpf ' || sudo mount -t bpf bpf /sys/fs/bpf
```

### 启动 loader

```bash
cd /mnt/e/os2026/ebpf-multi-agent-monitor/src/user
sudo ./loader
```

### 启动 ringbuf_handler

```bash
cd /mnt/e/os2026/ebpf-multi-agent-monitor/src/user
sudo ./ringbuf_handler
```

### 启动 analyzer

```bash
cd /mnt/e/os2026/ebpf-multi-agent-monitor
PYTHONUNBUFFERED=1 ./.venv/bin/python src/analysis/main_analyzer.py
```

### 测试 Claude 流量

```bash
redis-cli XLEN inter:messages
claude -p "只回复四个字：测试成功" --output-format json
redis-cli XLEN inter:messages
```

### 查看 Redis 最新消息

```bash
redis-cli XREVRANGE inter:messages + - COUNT 3
```

### 查看 SQLite 异常

```bash
cd /mnt/e/os2026/ebpf-multi-agent-monitor
sqlite3 logs/alerts/analysis.db \
  "select anomaly_id, rule, severity, pid, comm from anomalies order by id desc limit 5;"
```
