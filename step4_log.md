### Step 4 完成情况

本步骤的目标是：对识别出的异常行为进行归因定位与告警，并输出包含时间戳、PID/TID、操作对象等关键上下文的用户可读日志；同时在多智能体场景下补充语义关联与交互链路，形成跨层因果说明。

当前结果可以分为 `solo` 和 `multi` 两部分。

---

#### solo

`solo` 部分已经完成，并已落地为真实日志输出。

已实现内容：

1. 异常行为类型输出
- 直接记录规则名与风险等级，例如 `SENSITIVE_FILE_ACCESS`、`UNEXPECTED_SHELL_EXEC`、`POSSIBLE_LOGIC_LOOP` 等。

2. 触发异常行为的事件序列输出
- 日志中保留异常请求编号、规则名、严重级别、操作对象、触发原因。
- 同时补充异常前最近命中的 prompt/response 预览，形成用户可读的事件链。

3. 语义关联
- `MainAnalyzer` 会从 `inter:messages` 回查异常发生前 30 秒内的最近 prompt/response。
- 这些语义上下文会被注入到审计请求中，并写入用户友好日志。

4. 根因定位
- 若 LLM 审计返回 `reasoning`，则优先将其作为根因解释。
- 若无 LLM 解释，则回退到规则层给出的异常原因。

5. 分析报告
- 若 LLM 返回 `summary`，则作为最终分析报告写入日志。
- 若无 LLM 结果，则输出规则审计得到的 `decision/status` 摘要。

当前 `solo` 日志结构如下：

```text
[solo] <异常类型> (<风险等级>)
time=<时间>  pid=<PID>  tid=<TID>
agent=<agent_id>  comm=<进程名>  object=<操作对象>
[event sequence]
  - req#...
  - object=...  reason=...
  - prompt/response ...
[semantic association]
  ...
[root cause]
  ...
[analysis report]
  ...
[evidence]
  ...
```

对应实现：

- `ebpf-multi-agent-monitor/src/analysis/main_analyzer.py`
  `MainAnalyzer._enrich_semantic_context()` 负责回查最近语义上下文。
- `ebpf-multi-agent-monitor/src/analysis/main_analyzer.py`
  `MainAnalyzer._handle_intra_results()` 负责在审计完成后写用户日志。
- `ebpf-multi-agent-monitor/src/analysis/intra_agent/user_log.py`
  `IntraUserLogger` 负责格式化并落盘 `solo` 日志。

当前日志落盘路径：

```text
ebpf-multi-agent-monitor/logs/intra_agent/anomaly_YYYYMMDD_HHMMSS.log
```

---

#### multi

`multi` 部分已经具备可用的日志与展示样例，但当前更偏向“交互异常归因日志”和“展示链路输出”，不是单独再做一套完全独立于现有链路的日志系统。

已实现内容：

1. 异常行为类型输出
- 多智能体异常日志中已经记录异常类型与风险等级，例如 `stale_state (HIGH)`。

2. 触发异常行为事件输出
- 日志中包含异常时间、涉及的 agent、eBPF 侧 agent 标识。
- 事件序列中记录消息方向、发送者、接收者以及关键文本片段。

3. 智能体交互关系
- 日志中已经显式记录 `sender -> receiver`。
- 同时保留全局视图信息，例如拓扑类型、agent 数量、边数量。

4. prompt/response 与异常事件关联
- 事件序列和语义关联部分已经能体现发送方、接收方和消息内容。
- 当前样例中可以看到由上层任务指令触发的异常链。

5. 根因定位
- 日志中已有 `[root cause]` 字段，用于概括多智能体异常的直接原因。

6. 全局视图
- 日志中已有 `[view]` 段，记录：
  - `topology`
  - `agents`
  - `edges`
  - agent 列表

当前 `multi` 日志结构如下：

```text
[node] <异常类型> (<风险等级>)
risk=<风险分数>  time=<时间>
agent=<agent_id>  ebpf=<内核侧标识>
[event sequence]
  - <发送方> -> <接收方>  "<消息内容>"
[semantic association]
  sender: ...
  content: ...
[root cause]
  ...
[view]
  topology=...  agents=...  edges=...
  agents: ...
```

当前可用样例：

- `/mnt/e/os2026/anomaly_20260626.log`

该样例已经覆盖：

1. 异常类型
2. 事件序列
3. 交互方向
4. 语义关联
5. 根因定位
6. 全局拓扑视图

---

#### 对题目要求的对应关系

基础要求：

- 已完成
- `solo` 与 `multi` 日志中都已经输出时间戳、Agent/进程标识、操作对象或交互对象、根因说明等关键上下文。

进阶要求：

- 基本完成
- `solo` 链路已实现“系统调用异常 -> 最近 prompt/response -> LLM 审计解释”的跨层关联。
- `multi` 链路已实现“异常节点 -> agent 间交互 -> 消息语义 -> 全局拓扑”的关联说明。

---

#### 当前边界

1. `solo`
- 已形成稳定的用户友好日志格式，可直接用于展示和答辩。

2. `multi`
- 当前已经有样例日志和前端展示链路。
- 如果后续需要“完全统一的正式日志规范”，可以继续把 `multi` 输出也收敛成与 `solo` 类似的固定块结构，并增加图结构序列化输出。

---

#### 运行方式与命令

`single / interactive / all` 三种模式不是写在 `intra_agent` 子目录中，而是由总控入口 `src/analysis/main_analyzer.py` 统一调度。

命令行参数定义：

```text
--mode single
--mode interactive
--mode all
```

对应含义：

1. `single`
- 仅开启 `intra-agent` 单体异常检测与单体审计日志链路。

2. `interactive`
- 仅开启 `inter-agent` 多智能体交互异常分析链路。

3. `all`
- 同时开启 `intra-agent` 与 `inter-agent` 两条链路。

终端启动命令如下：

```bash
cd /mnt/e/os2026/ebpf-multi-agent-monitor
python3 src/analysis/main_analyzer.py --mode single
```

```bash
cd /mnt/e/os2026/ebpf-multi-agent-monitor
python3 src/analysis/main_analyzer.py --mode interactive
```

```bash
cd /mnt/e/os2026/ebpf-multi-agent-monitor
python3 src/analysis/main_analyzer.py --mode all
```

如果需要完整展示前端中的三种流程图模式，则可在启动展示系统后，通过对话框直接输入以下命令：

1. `单点模式 single intra-agent 审计链路展示`
2. `交互模式 interactive inter-agent 交互异常展示`
3. `全量模式 all 单点与交互联合展示`

展示系统启动命令：

```bash
cd /mnt/e/os2026/ebpf-monitor-showcase
npm run dev
```

浏览器访问：

```text
http://127.0.0.1:3000
```

---

#### 结论

`step4` 已经从“设计要求”推进到“可运行结果”：

1. `solo` 日志链路已完成并落盘。
2. `multi` 已具备异常归因、语义关联和全局拓扑说明能力。
3. `main_analyzer.py` 已支持 `single / interactive / all` 三种模式切换。
4. `CoreSight` 前端已支持通过三条展示命令触发对应流程图链路。
