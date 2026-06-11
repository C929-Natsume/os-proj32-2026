# eBPF Multi-Agent Monitor 演示说明

## 演示目标

本次演示的目标不是单纯展示 eBPF 探针触发，而是展示：

1. 可以对真实大模型 Agent 进行底层行为采集
2. 可以捕获 `Claude Code` 的系统行为与 SSL/HTTP 相关事件
3. 可以拿到 Prompt、LLM 调用次数、Token 统计等高层信息
4. 现有项目的分析层仍然保留，后续可以继续接入审计和多智能体分析

## 演示思路


1. `AgentSight`：负责真实 Agent 的底层采集
2. `ebpf-multi-agent-monitor`：负责上层审计、单体分析、协同分析

## 架构讲解


> 我们把系统拆成两层。底层采集层仍然基于 eBPF，但为了适配 `Claude Code` 这类主流 Agent，我们引入了 `AgentSight` 作为稳定采集组件，专门解决进程树归因、SSL 明文捕获和 HTTP/SSE 重组问题。上层仍保留我们自己的分析框架，用于审计、单智能体行为分析和多智能体协同分析。

## Inter-Agent 可扩展异常类型

`inter-agent` 不只可以看 fork 关系和端口扫描，它更适合作为跨 agent 关联分析层，后续可以接入下面五类异常：

1. 网络异常检测：高频/高代价 API 调用、非法外联、解密后可疑 Prompt/指令、SSL/TLS 握手异常。
2. 文件系统异常检测：敏感文件越权访问、工作区外异常删除/写入、无意义 I/O 风暴、路径遍历逃逸。
3. 进程与执行异常检测：非预期 shell 启动、异常下载执行链、fork 炸弹、权限提升尝试。
4. 内存与 CPU 资源异常检测：CPU 空转、无进展死循环、内存泄漏、多个 agent 之间的资源争抢。
5. 应用层语义逻辑异常：幻觉诱导死循环、提示注入导致高危操作、功能滥用。

当前代码里已经落地的是父子进程图、网络连接频次、`POTENTIAL_PORT_SCAN`、`POTENTIAL_FORK_BOMB`。其余几类可以继续基于 `AgentSight` 提供的 Prompt、`llm_calls`、文件事件、进程树和网络目标往上做关联分析。

## 演示前准备

建议提前确认以下内容：

```bash
claude --version
```

应看到类似：

```text
2.1.162 (Claude Code)
```

确认 `AgentSight` 可执行文件存在：

```bash
cd /mnt/e/agentsight
ls ./collector/target/release/agentsight
```

## 现场演示命令

### 1. 进入 AgentSight

```bash
cd /mnt/e/agentsight
```

### 2. 运行一次真实采集

推荐直接使用已经验证通过的命令：

```bash
sudo env PATH="$PATH" HOME="/home/jiang12333" \
  ./collector/target/release/agentsight record \
  --db /home/jiang12333/.local/share/agentsight/sessions/demo-claude.db \
  -- /home/jiang12333/.npm-global/lib/node_modules/@anthropic-ai/claude-code/bin/claude.exe \
  -p "请用一句话介绍你自己" \
  --output-format json
```

### 3. 展示 Prompt 数据

```bash
./collector/target/release/agentsight db prompts \
  --db /home/jiang12333/.local/share/agentsight/sessions/demo-claude.db
```

### 4. 展示审计/事件摘要

```bash
./collector/target/release/agentsight db audit \
  --db /home/jiang12333/.local/share/agentsight/sessions/demo-claude.db
```

### 5. 展示数据库统计

```bash
python3 - <<'PY'
import sqlite3
db="/home/jiang12333/.local/share/agentsight/sessions/demo-claude.db"
conn=sqlite3.connect(db)
cur=conn.cursor()
print("raw_events", cur.execute("select count(*) from raw_events").fetchone()[0])
print("llm_calls", cur.execute("select count(*) from llm_calls").fetchone()[0])
print("sources", list(cur.execute("select source,count(*) from raw_events group by source order by count(*) desc")))
PY
```

## 演示时应该强调什么


1. 抓到了真实 `Claude Code`
2. 抓到了 `ssl` 事件
3. 抓到了 `http_parser` / `sse_processor`
4. 能看到 Prompt
5. 能看到 `llm_calls`
6. 能看到 Token 统计


> 这说明我们不是只抓到了底层系统调用，而是已经拿到了真实 Agent 的完整请求链路。

## 已验证结果

当前机器上已经验证通过的一组结果如下：

```text
raw_events: 82
llm_calls: 2
sources:
  ssl: 69
  http_parser: 4
  sse_processor: 2
  system: 6
  diagnostic: 1
```

录制摘要中还可以看到：

- `2 API calls`
- `22650 tokens`
- `deepseek-v4-pro`
- `deepseek-v4-flash`
- `api.deepseek.com/anthropic/v1/messages`

## 


> 原始链路适合展示基础 eBPF 能力，但 `Claude Code` 这类主流 Agent 在真实环境里不仅有系统调用，还涉及进程树归因、SSL 明文捕获和 HTTP/SSE 数据重组。为了保证比赛演示稳定，我们先用已经验证通过的采集层跑通真实链路，再把数据接回我们现有的分析层。

## 

可以这样回答：

> 本质上仍然是基于 eBPF 的底层采集，只是我们没有停留在基础 syscall 监控，而是进一步解决了真实 Agent 在运行时的适配问题。

## 


> 采集层解决的是数据拿不拿得到的问题，而我们的分析层解决的是这些数据如何转化成审计结果、异常检测和协同行为分析的问题。

## 结束

> 当前我们已经跑通了真实 Agent 的底层采集链路，下一步就是把这些已经验证可用的采集结果接回现有的 `intra-agent` / `inter-agent` 分析模块，形成完整的多智能体安全审计闭环。
