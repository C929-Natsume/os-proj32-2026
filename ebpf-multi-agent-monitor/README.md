# eBPF Multi-Agent Monitor

基于 eBPF 的多智能体系统行为监控与分析平台，通过内核态探针捕获系统调用和 SSL 加密流量，结合 Redis 消息队列和 Python 分析模块实现跨层安全审计。

## 架构概览

```
┌─────────────────────────────────────────────────────────────────────┐
│                     eBPF Multi-Agent Monitor                        │
├─────────────────────────────────────────────────────────────────────┤
│                                                                     │
│  ┌─────────────┐    ┌──────────────┐    ┌─────────────┐             │
│  │    BPF      │    │ Ring Buffer  │    │    Redis    │             │
│  │ Kernel      │───▶│   Handler    │───▶│   Shipper   │             │
│  │ (bpf/)      │    │ (user/)      │    │  (user/)    │             │
│  └─────────────┘    └──────────────┘    └──────┬──────┘             │
│                                                │                    │
│                                                ▼                    │
│                   ┌─────────────────────────────────────┐           │
│                   │        Analysis Layer               │           │
│                   │  ┌───────────┐ ┌─────────────────┐  │           │
│                   │  │   Audit   │ │ Intra/Inter     │  │           │
│                   │  │  Engine   │ │ Agent Analyzer  │  │           │
│                   │  └───────────┘ └─────────────────┘  │           │
│                   └─────────────────────────────────────┘           │
│                                                                     │
└─────────────────────────────────────────────────────────────────────┘
```

## 目录结构

```
ebpf-multi-agent-monitor/
├── src/
│   ├── bpf/                           # eBPF 内核态程序 (libbpf)
│   │   ├── vmlinux.h                  # bpftool 生成的内核数据结构
│   │   ├── sys_behavior.bpf.c         # 系统调用监控 (execve/fork/open/...)
│   │   ├── ssl_sniffer.bpf.c          # SSL 流量监控 (SSL_read/write/...)
│   │   └── common.h                   # 共享结构体定义
│   │
│   ├── user/                          # 用户态程序
│   │   ├── loader.c                   # BPF 程序加载器
│   │   ├── ringbuf_handler.c          # Ring Buffer 事件读取
│   │   ├── redis_shipper.c            # Redis 数据推送
│   │   └── Makefile                   # 构建脚本
│   │
│   ├── analysis/                      # Python 分析模块
│   │   ├── main_analyzer.py           # 分析入口，消费 Redis 数据
│   │   ├── audit_engine.py            # 审计引擎，黑白名单 + LLM
│   │   ├── intra_agent/               # 单智能体行为分析
│   │   │   └── main.py
│   │   └── inter_agent/               # 多智能体协同分析
│   │       └── main.py
│   │
│   └── config/                        # 配置文件
│       ├── rules.yaml                 # 黑白名单、告警规则
│       └── app_config.yaml            # Redis、LLM、监控目标配置
│
├── build/                             # 编译输出目录
├── logs/                              # 日志输出目录
├── requirements.txt                   # Python 依赖
└── README.md
```

## 文件详细说明

### BPF 内核态 (src/bpf/)

#### common.h
定义用户态与内核态共享的事件结构体：
- `sys_event`: 系统调用事件（execve/fork/open/unlink/connect）
- `ssl_event`: SSL 加密流量事件（SSL_read/SSL_write）

#### sys_behavior.bpf.c
通过 kprobes/tracepoints 监控系统调用：
| 探针 | 说明 |
|------|------|
| `tracepoint/raw_syscalls/sys_enter` | 系统调用入口 |
| `tracepoint/raw_syscalls/sys_exit` | 系统调用出口 |
| `kprobe/do_execve` | execve 执行 |
| `kprobe/__x64_sys_fork` | fork 系统调用 |
| `kprobe/__x64_sys_open` | open 系统调用 |
| `kprobe/__x64_sys_unlink` | unlink 系统调用 |
| `kprobe/__x64_sys_connect` | connect 系统调用 |

打印示例：
```
[BPF] execve detected: filename=/bin/ls
[BPF] connect syscall: sockfd=3, addrlen=110
```

#### ssl_sniffer.bpf.c
通过 uprobes/uretprobes 监控 OpenSSL 函数：
| 探针 | 说明 |
|------|------|
| `uprobe/SSL_read` | SSL 读操作入口 |
| `uretprobe/SSL_read` | SSL 读操作返回 |
| `uprobe/SSL_write` | SSL 写操作入口 |
| `uretprobe/SSL_write` | SSL 写操作返回 |
| `uprobe/SSL_connect` | SSL 连接建立 |
| `uprobe/SSL_accept` | SSL 接受连接 |

使用 `PT_REGS_PARM*` 宏从 `struct pt_regs *ctx` 提取函数参数。

打印示例：
```
[BPF] SSL_read uprobe triggered: ssl=0xffff, num=1024
[BPF] SSL_write uretprobe: ret=256
```

---

### 用户态 (src/user/)

#### loader.c
BPF 程序加载器，负责：
1. 调用 `*_bpf__open_and_load()` 加载 BPF 骨架
2. 调用 `*_bpf__attach()` 挂载探针
3. 处理 SIGINT/SIGTERM 信号退出

打印示例：
```
[LOADER] eBPF Multi-Agent Monitor Loader starting...
[LOADER] Step 1: Loading sys_behavior BPF skeleton...
[LOADER] Step 2: Attaching sys_behavior probes...
[LOADER] sys_behavior BPF program attached successfully
[LOADER] Step 3: Loading ssl_sniffer BPF skeleton...
[LOADER] All BPF programs loaded and attached successfully
```

#### ringbuf_handler.c
Ring Buffer 事件轮询器：
1. 创建 `ring_buffer__new()` 监听 BPF 环形缓冲区
2. 注册回调函数处理 `sys_event` 和 `ssl_event`
3. 调用 `ring_buffer__poll()` 轮询新事件

打印示例：
```
[RINGBUF] Received sys_event: type=1, pid=1234, comm=bash
[RINGBUF]   -> execve: filename=/bin/ls
[RINGBUF] Received ssl_event: type=6, pid=5678, comm=curl, data_len=512
[RINGBUF]   -> SSL_read: 512 bytes
```

#### redis_shipper.c
Redis 数据推送模块：
1. 连接 Redis (`redisConnect`)
2. 将事件序列化为 JSON
3. 使用 `SET` 存储 + `PUBLISH` 发布到 `ebpf_events` 频道

打印示例：
```
[REDIS] Connecting to Redis at 127.0.0.1:6379...
[REDIS] Connected to Redis successfully
[REDIS] Shipped sys_event: key=sys_event:1234:1234567890
[REDIS] Published sys_event to channel ebpf_events
```

#### Makefile
构建脚本，完成：
1. 使用 `clang` 编译 `.bpf.c` 生成 `.bpf.o`
2. 使用 `bpftool gen skeleton` 生成 `.skel.h` 骨架头文件

```bash
make            # 编译所有
make skeletons  # 仅生成骨架文件
make clean      # 清理
```

---

### 分析模块 (src/analysis/)

#### main_analyzer.py
分析层入口：
1. 连接 Redis 订阅 `ebpf_events` 频道
2. 根据事件类型分发到不同处理函数
3. 调用 `AuditEngine` 进行审计
4. 捕获 KeyboardInterrupt 退出

打印示例：
```
[ANALYZER] Initializing Main Analyzer...
[ANALYZER] Connecting to Redis at 127.0.0.1:6379...
[ANALYZER] Connected to Redis successfully
[ANALYZER] Received event: {'type': 1, 'pid': 1234, 'comm': 'ls'}
[ANALYZER] Processing system event: {...}
[ANALYZER]   Audit result: {'status': 'allowed', 'reason': 'whitelist_match'}
```

#### audit_engine.py
审计引擎：
1. 加载 `rules.yaml` 中的黑白名单
2. `check_blacklist()`: 匹配黑名单返回 BLOCKED
3. `check_whitelist()`: 匹配白名单返回 ALLOWED
4. `call_llm()`: LLM 接口调用（可选）

打印示例：
```
[AUDIT] Auditing event: {...}
[AUDIT] Checking blacklist...
[AUDIT]   No blacklist match
[AUDIT] Checking whitelist...
[AUDIT]   Match found in whitelist: /bin/ls
[AUDIT] Result: ALLOWED (whitelist match)
```

#### intra_agent/main.py
单智能体行为分析：
- 跟踪每个 PID 的 exec_count、file_count、network_count
- 检测异常：高频率 exec、文件访问、网络连接

打印示例：
```
[INTRA] Analyzing single agent behavior for event: {...}
[INTRA] New agent detected: PID=1234, Comm=curl
[INTRA]   Agent 1234 made a network connection (network_count=1)
[INTRA] Checking for anomalies in agent PID=1234...
```

#### inter_agent/main.py
多智能体协同分析：
- 构建父子进程关系图（fork 事件）
- 统计网络连接相关性
- 检测 fork bomb、port scanning 等跨进程异常

打印示例：
```
[INTER] Analyzing multi-agent correlation for event: {...}
[INTER]   Detected fork: parent=1234, child=5678
[INTER]   Updated agent graph: parent 1234 -> child 5678
[INTER] Checking for cross-agent anomalies...
```

---

### 配置文件 (src/config/)

#### rules.yaml
```yaml
whitelist:        # 白名单路径
  - /bin/ls
  - /bin/bash
blacklist:        # 黑名单路径
  - /tmp/malware
  - /bin/sh
alert_rules:      # 告警规则
  - name: high_exec_count
    condition: exec_count > 50
    severity: medium
```

#### app_config.yaml
```yaml
redis:
  host: 127.0.0.1
  port: 6379
  channel: ebpf_events

llm:
  enabled: false
  api_key: your_api_key_here

monitor:
  target_processes:
    - python
    - bash
```

---

## 启动命令

### 前置条件

```bash
# 安装依赖
sudo apt install redis-server libhiredis-dev

# Python 依赖
pip install -r requirements.txt

# 生成 BPF 骨架
cd src/user && make
```

### 启动顺序

```bash
# 1. 启动 Redis
redis-server --daemonize yes

# 2. 启动 BPF Loader (终端1)
sudo ./src/user/loader

# 3. 启动 Ring Buffer Handler (终端2) - 读取 BPF 事件并推送到 Redis
sudo ./src/user/ringbuf_handler

# 4. 启动 Python 分析模块 (终端3)
cd src/analysis && python3 main_analyzer.py
```

### 分步验证

```bash
# 验证 Redis 连接
redis-cli ping
# 应返回: PONG

# 验证 BPF 编译
cd src/user && ls -la *.skel.h
# 应看到: sys_behavior.skel.h  ssl_sniffer.skel.h

# 查看 BPF 探针
sudo bpftool prog list
sudo bpftool perf
```

---

## 数据流

```
┌──────────────┐
│  用户进程     │  execve / open / SSL_read
└──────┬───────┘
       ▼
┌─────────────────────────────────────────┐
│         BPF Kernel Probes               │
│  sys_behavior.bpf.c                     │
│  ssl_sniffer.bpf.c                      │
│         printk() 输出到 ring buffer      │
└──────────────────┬──────────────────────┘
                   ▼
┌─────────────────────────────────────────┐
│      ringbuf_handler (用户态)            │
│      读取 ring buffer 事件               │
│      打印事件详情                         │
└──────────────────┬──────────────────────┘
                   ▼
┌─────────────────────────────────────────┐
│      redis_shipper (用户态)              │
│      发布事件到 Redis ebpf_events 频道    │
└──────────────────┬──────────────────────┘
                   ▼
┌─────────────────────────────────────────┐
│      main_analyzer.py                   │
│      订阅 Redis 频道                     │
│      分发事件到审计引擎                    │
└──────────────────┬──────────────────────┘
                   ▼
┌─────────────────────────────────────────┐
│      audit_engine.py                    │
│      黑白名单检查                         │
│      LLM 分析 (可选)                     │
└─────────────────────────────────────────┘
```

---

## print 信息标签

| 模块 | 标签 | 说明 |
|------|------|------|
| BPF 内核态 | `[BPF]` | 系统调用/SSL 探针触发 |
| Loader | `[LOADER]` | BPF 骨架加载过程 |
| Ring Buffer | `[RINGBUF]` | 事件读取处理 |
| Redis | `[REDIS]` | Redis 连接和发布 |
| Analyzer | `[ANALYZER]` | 分析层入口 |
| Audit | `[AUDIT]` | 审计引擎 |
| Intra-Agent | `[INTRA]` | 单智能体分析 |
| Inter-Agent | `[INTER]` | 多智能体分析 |
