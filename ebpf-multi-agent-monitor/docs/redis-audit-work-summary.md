# Redis 接口与审计异常工作说明

## 目标



1. Redis 接口规范化
2. 审计异常结果回写

本次工作基于 [Redis数据接口规范.md](/mnt/e/os2026/ebpf-multi-agent-monitor/Redis数据接口规范.md) 推进，目标是把 `ebpf -> Redis -> analysis` 这一条链路补成统一接口，而不是只做临时测试输出。

---

## 一、Redis 接口规范化

### 1. 做了什么

在 `src/user/redis_shipper.c` 中，保留原有：

- `PUBLISH ebpf_events`

新增并补齐了规范中的 `inter:*` Redis 接口：

- `inter:agents`
- `inter:agent:{agent_id}`
- `inter:metric:{agent_id}`
- `inter:events`
- `inter:edges`
- `inter:edge:{src}:{dst}`
- `inter:messages`

同时新增了 Python 侧消费模块：

- `src/data/schema.py`
- `src/data/collector.py`

用于把 Redis 中的 `inter:*` 数据还原成统一的 observation dict。

### 2. 现在能做什么

- 记录 agent 注册信息
- 按窗口写入聚合指标
- 记录交互边关系
- 写入事件流
- 写入消息流
- 给 Python 分析侧提供统一读取入口

### 3. 相关文件

- [redis_shipper.c](/mnt/e/os2026/ebpf-multi-agent-monitor/src/user/redis_shipper.c)
- [collector.py](/mnt/e/os2026/ebpf-multi-agent-monitor/src/data/collector.py)
- [schema.py](/mnt/e/os2026/ebpf-multi-agent-monitor/src/data/schema.py)

---

## 二、审计异常结果回写

### 1. 做了什么

在 `src/analysis/main_analyzer.py` 中补了异常回写逻辑，把分析结果统一写入：

- `inter:anomalies`

这里包含两类来源：

1. `intra_agent` 单体异常
2. `inter_agent` 协同异常

写入字段包括：

- `anomaly_id`
- `rule`
- `severity`
- `timestamp_ns`
- `pid`
- `tid`
- `comm`
- `agent_id`
- `object`
- `reason`
- `details`

### 2. 现在能做什么

- 单体分析命中后可统一回写异常流
- 协同分析命中后可统一回写异常流
- 后续 Python/前端/审计模块可以直接消费同一套异常接口

### 3. 当前已支持的具体异常

当前这些规则已经在代码里实现，并且命中后会回写到 `inter:anomalies`。

#### 3.1 进程执行类

- `UNEXPECTED_SHELL_EXEC`
  单体检测到进程执行 `sh`、`bash` 等 shell 解释器
- `UNEXPECTED_SHELL_EXEC_CHAIN`
  协同检测到异常 shell 启动链路
- `PRIVILEGE_ESCALATION_ATTEMPT`
  检测到执行 `sudo`，疑似权限提升尝试
- `SUSPICIOUS_DOWNLOAD_EXEC_CHAIN`
  检测到下载后执行链路，如 `curl` / `wget` 后紧接解释器执行
- `POTENTIAL_FORK_BOMB`
  检测到异常 fork 速率或异常子进程扩张，疑似 fork bomb

#### 3.2 文件系统类

- `SENSITIVE_FILE_ACCESS`
  单体检测到访问或删除敏感路径，如 `/etc/shadow`、`~/.ssh/`、`.env`
- `SENSITIVE_FILE_OUT_OF_SCOPE`
  检测到越界访问敏感文件
- `OUT_OF_WORKSPACE_OPERATION`
  单体检测到工作区外删除行为
- `OUT_OF_WORKSPACE_ACCESS`
  检测到工作区外文件访问
- `OUT_OF_WORKSPACE_DELETE`
  检测到工作区外文件删除
- `PATH_TRAVERSAL_ATTEMPT`
  检测到 `../` 等路径遍历尝试
- `FILE_IO_STORM`
  检测到同一路径高频文件操作，疑似 I/O 风暴

#### 3.3 网络连接类

- `UNUSUAL_NETWORK_CONNECTION`
  单体检测到非标准端口外连
- `HIGH_FREQUENCY_API_CALLS`
  检测到短时间内高频网络/API 连接
- `NON_WHITELIST_INTERNAL_CONNECTION`
  检测到连接非白名单内网地址
- `UNUSUAL_EXTERNAL_CONNECTION`
  检测到连接异常端口
- `POTENTIAL_PORT_SCAN`
  检测到异常高频连接，疑似端口扫描

#### 3.4 语义与明文类

- `PROMPT_INJECTION_SIGNAL`
  检测到 SSL 明文中存在提示注入特征
- `HIGH_RISK_INSTRUCTION_IN_SSL`
  检测到 SSL 明文中存在高危操作指令
- `PROMPT_INJECTION_TO_DANGEROUS_ACTION`
  检测到高危提示后，紧跟 shell、文件操作或网络外联
- `HALLUCINATION_INDUCED_LOOP`
  检测到重复语义信号或重复 SSL 文本，并伴随无进展循环
- `POSSIBLE_LOGIC_LOOP`
  单体检测到文件与网络操作高频且对象集中，疑似逻辑循环
- `FREQUENT_SHORT_SSL_SESSIONS`
  检测到高频短 SSL 明文片段，疑似异常短会话或重试
- `SUSPICIOUS_REPETITIVE_SSL_PAYLOAD`
  检测到超长重复 SSL 明文
- `FUNCTION_MISUSE_MINING_SIGNAL`
  检测到 SSL 明文中存在疑似挖矿或功能滥用指令

#### 3.5 资源争抢类

- `RESOURCE_CONTENTION_SPIKE`
  检测到多个活跃 agent/进程同时产生高密度事件，疑似资源争抢

### 4. 相关文件

- [main_analyzer.py](/mnt/e/os2026/ebpf-multi-agent-monitor/src/analysis/main_analyzer.py)
- [intra_agent/main.py](/mnt/e/os2026/ebpf-multi-agent-monitor/src/analysis/intra_agent/main.py)
- [inter_agent/main.py](/mnt/e/os2026/ebpf-multi-agent-monitor/src/analysis/inter_agent/main.py)

---

## 三、当前结论


1. Redis 从“只发一条事件”扩展为“规范化 `inter:*` 接口”
2. 审计结果从“只在分析器里打印”扩展为“统一回写 `inter:anomalies`”

这两部分结合起来，形成了比较完整的链路：

`eBPF 事件 -> redis_shipper -> inter:* -> RedisCollector / analyzer -> inter:anomalies`

---

## 四、和 fix/trace 分支的区别

`fix/trace` 分支更偏向：

- 底层采集增强
- Redis Pub/Sub 测试输出
- `trace.cpp` 演示分析

而我这次做的是：

- 面向规范的 Redis 存储接口
- 面向分析模块的异常回写接口

所以两边重点不同：

1. `fix/trace` 不是把这套 `inter:*` 接口全部补全
2. 我这次工作也没有合并 `trace.cpp` 那套测试链路

---

## 五、当前状态

已完成：

1. `src/user` 编译通过
2. `src/analysis` 与 `src/data` 的 Python 语法检查通过
3. Redis 规范接口和异常回写逻辑已落代码

未做：

1. 没有合并 `fix/trace` 分支
2. 没有把 `trace.cpp` 接入当前主分析链路
3. 没有把 `fix/trace` 的 Redis Pub/Sub 格式替换当前 `inter:*` 规范

---

## 六、启动与验证命令

下面这组命令用于启动当前这条链路：

`loader -> ringbuf_handler -> Redis -> main_analyzer -> inter:* / SQLite`

建议开 4 个终端。

### 1. 终端一：准备环境

```bash
cd /mnt/e/os2026/ebpf-multi-agent-monitor

redis-cli ping

rm -f logs/alerts/analysis.db

redis-cli DEL inter:events inter:anomalies inter:messages inter:edges inter:agents
redis-cli --scan --pattern 'inter:agent:*' | xargs -r redis-cli DEL
redis-cli --scan --pattern 'inter:edge:*' | xargs -r redis-cli DEL
redis-cli --scan --pattern 'inter:metric:*' | xargs -r redis-cli DEL
```

如果 Redis 没启动：

```bash
redis-server --daemonize yes
redis-cli ping
```

### 2. 终端二：启动 eBPF loader

```bash
cd /mnt/e/os2026/ebpf-multi-agent-monitor
./scripts/run_loader.sh
```

看到下面这句说明挂载成功：

```text
[LOADER] BPF programs attached and Maps pinned successfully.
```

### 3. 终端三：启动 ringbuf handler

```bash
cd /mnt/e/os2026/ebpf-multi-agent-monitor
./scripts/run_ringbuf.sh
```

### 4. 终端四：启动 analyzer

```bash
cd /mnt/e/os2026/ebpf-multi-agent-monitor
./scripts/run_analyzer.sh
```

### 5. 终端五：触发真实 agent

先配置 CLI 路径：

```bash
export PATH="/home/jiang12333/.npm-global/bin:$PATH"
```

用 `Claude` 触发一次：

```bash
claude -p "用一句中文介绍你自己" --output-format json
```

如果要测 `Codex`：

```bash
codex exec "用一句中文介绍你自己"
```

如果要测 `Gemini`：

```bash
GEMINI_CLI_TRUST_WORKSPACE=true \
gemini --skip-trust --model gemini-3.1-flash-lite \
  -p 'Reply with exactly: agentsight-smoke' \
  --output-format json
```

### 6. 查看 Redis 结果

查看 agent 注册：

```bash
redis-cli SMEMBERS inter:agents
```

查看事件流：

```bash
redis-cli XRANGE inter:events - + COUNT 10
```

查看异常流：

```bash
redis-cli XRANGE inter:anomalies - + COUNT 10
```

查看消息流：

```bash
redis-cli XRANGE inter:messages - + COUNT 10
```

### 7. 查看 SQLite 落库结果

```bash
python3 - <<'PY'
import sqlite3
db='/mnt/e/os2026/ebpf-multi-agent-monitor/logs/alerts/analysis.db'
conn=sqlite3.connect(db)
cur=conn.cursor()
for table in ['events', 'anomalies', 'audit_results']:
    n = cur.execute(f'select count(*) from {table}').fetchone()[0]
    print(table, n)
PY
```
