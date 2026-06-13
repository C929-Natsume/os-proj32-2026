# 根因识别（Root Cause Identification）实现方案

## 1. 当前状态与差距

### 1.1 已有能力

当前系统在异常发出时，已附带以下可用于根因追溯的元数据：

| 字段 | 内容 | 用途 |
|------|------|------|
| `pid` / `comm` | 触发异常进程的 PID 和进程名 | 追溯到具体进程 |
| `agent_id` | 如 `agent_1234` | 追溯到具体 agent |
| `object` | 文件路径或 `ip:port` | 追溯到具体资源 |
| `timestamp_ns` | 纳秒时间戳 | 时序关系 |
| `reason` | 中文异常描述 | 人类可读解释 |

`inter_agent/main.py` 中已有**原始时序关联**：
- `last_high_risk_prompt_ns` → 15s 窗口内检测到 shell/file/network 操作 → 触发 `PROMPT_INJECTION_TO_DANGEROUS_ACTION`
- `last_prompt_injection_ns` → 类似关联
- `last_download_exec_ns` → 下载-执行链关联

### 1.2 明确缺失

| 缺失项 | 影响 |
|--------|------|
| 无攻击链构建 | 多个异常无法串联为完整攻击叙事 |
| 无跨 agent 传播分析 | `agent_graph`（父子关系）存在但只用于 fork bomb，不用于因果传播 |
| 无行为基线 | 30 秒窗口重置，无法识别"从未做过"的异常行为 |
| SQLite 只写不读 | `events` 和 `anomalies` 表中存有全部数据，但无查询/分析代码 |
| C++ trace_engine 孤立 | 能做语义上下文追踪（LLM prompt → 系统操作），但不集成到 Python 管线 |

### 1.3 根因识别要回答的问题

| 问题 | 当前能否回答 |
|------|------------|
| "Agent X 为什么执行了 /bin/sh？" | ⚠️ 只知道它执行了，不知道是什么 prompt 触发的 |
| "这次敏感文件读取是独立的还是攻击链的一部分？" | ❌ 无法关联 |
| "Agent A 的异常如何影响 Agent B？" | ❌ 无法追踪跨 agent 传播 |
| "这个攻击从哪个事件开始的（真正的根因）？" | ❌ 无法定位 |
| "异常之间是否有因果关系？" | ⚠️ 只有 15s 单层关联 |

---

## 2. 架构设计

### 2.1 整体架构

```
main_analyzer.py 事件循环
    │
    ├── [不变] inter_agent      → 跨 agent 异常检测
    ├── [不变] intra_agent      → 单 agent 异常检测
    ├── [不变] audit_engine     → 审核分类
    │
    └── [新增] root_cause/ CorrelationEngine
         │
         ├── record_event()      ← 每条事件到达时调用，追加到每 agent 环形缓冲区
         ├── record_anomaly()    ← 每个异常产生时调用，后向遍历找因果事件
         ├── build_chain()       ← 从 SQLite causal_edges 表 BFS 后向构建链
         ├── match_patterns()    ← 滑动窗口匹配已知攻击模式
         └── generate_narrative()← 生成人类可读的攻击链叙述
              │
              └── 持久化到 SQLite causal_edges 表
```

### 2.2 设计原则

1. **不修改检测逻辑**：`intra_agent` 和 `inter_agent` 代码不变
2. **侵入性最小**：`main_analyzer.py` 只在 2 个位置各加 1 行调用
3. **无 LLM 依赖**：模板叙述始终可用，LLM 是可选的增强
4. **内存可控**：每 agent 环形缓冲区上限 200 条，50 agent ≈ 5-10 MB
5. **不同步阻塞事件循环**：`record_event` O(1)，`record_anomaly` O(200)

---

## 3. 核心数据结构

### 3.1 因果图（CausalGraph）

```python
@dataclass
class EventNode:
    """从原始事件构建的图节点"""
    event_id: str           # "evt_{sqlite_row_id}" 或 "evt_mem_{seq}"
    timestamp_ns: int
    event_type: int         # 1=EXECVE, 2=FORK, 3=OPEN, 4=UNLINK, 5=CONNECT, 6=SSL_READ, 7=SSL_WRITE
    pid: int
    agent_id: str
    comm: str
    object: str             # filename 或 ip:port
    data_snippet: str       # SSL 数据的前 200 字符（如有）

@dataclass
class AnomalyNode:
    """从异常记录构建的图节点"""
    anomaly_id: str         # "anom_000001"
    timestamp_ns: int
    pid: int
    agent_id: str
    rule: str               # "UNEXPECTED_SHELL_EXEC" 等
    severity: str           # LOW/MEDIUM/HIGH/CRITICAL
    object: str
    reason: str

@dataclass
class CausalEdge:
    """有向边：target 由 source 导致"""
    source_id: str          # 原因节点 ID
    target_id: str          # 结果节点 ID
    relation: str           # "temporal_precedes" | "semantic_cause" | "agent_propagates"
    weight: float           # 0.0-1.0 置信度
    window_offset_ns: int   # 原因比结果早多少纳秒

class CausalGraph:
    nodes: dict[str, EventNode | AnomalyNode]
    edges: list[CausalEdge]
    # 索引：按 agent_id、PID、时间窗口快速查询
    agent_index: dict[str, list[str]]   # agent_id -> [node_ids]
    pid_index: dict[int, list[str]]     # pid -> [node_ids]
```

### 3.2 事件环形缓冲区

```python
class EventRingBuffer:
    """每 agent 一个，固定容量 200 条，自动淘汰最旧数据"""
    def __init__(self, maxlen=200):
        self.buffer: deque[dict] = deque(maxlen=maxlen)

    def append(self, event: dict):
        """O(1) 追加"""
        self.buffer.append({
            "ts_ns": event.get("timestamp", 0),
            "event_type": event.get("type", 0),
            "pid": event.get("pid", 0),
            "ppid": event.get("ppid", 0),
            "comm": event.get("comm", ""),
            "object": event.get("filename") or
                      event.get("dip", "") + ":" + str(event.get("dport", "")),
            "data": event.get("data", "")[:200],  # 截断存储
            "agent_id": event.get("agent_id", "unknown"),
        })

    def query_window(self, ts_end_ns: int, window_ns: int) -> list[dict]:
        """获取 [ts_end - window, ts_end] 区间内的事件，O(N) N≤200"""
        ts_start = ts_end_ns - window_ns
        return [e for e in self.buffer if ts_start <= e["ts_ns"] <= ts_end_ns]
```

### 3.3 因果链（CausalChain）

```python
@dataclass
class CausalStep:
    step_type: str          # "event" | "anomaly" | "propagation"
    id: str
    timestamp_ns: int
    agent_id: str
    pid: int
    summary: str            # 人类可读的一句话摘要
    detail: dict            # 完整原始记录

@dataclass
class CausalChain:
    steps: list[CausalStep]             # 按时序升序排列
    root_cause_event: CausalStep        # 链中最早的事件（根因）
    root_cause_agent: str
    total_duration_ns: int
    anomaly_count: int
    cross_agent_count: int
    max_severity: str
    matched_pattern: str | None         # 匹配到的攻击模式名（如有）

    def narrative(self) -> str:
        """生成人类可读的因果链叙述（见 4.3 节示例）"""
```

---

## 4. 核心算法

### 4.1 后向因果遍历（Backward Causal Traversal）

```
算法: find_preceding_events
输入: anomaly_record, agent_buffers, causal_window_ns=30_000_000_000
输出: list[(event, score)]

1. agent_id = anomaly_record["agent_id"]
2. pid       = anomaly_record["pid"]
3. ts        = anomaly_record["timestamp_ns"]
4. rule      = anomaly_record["rule"]
5. buffer    = agent_buffers.get(agent_id, [])

6. candidates = buffer.query_window(ts, causal_window_ns)
   # 过滤掉异常自身时间点之后的事件

7. for each candidate in candidates:
     score = 1.0

     # 同一 PID → 更高权重
     if candidate["pid"] == pid:
         score += 1.0
     else:
         score += 0.5  # 同 agent 不同 PID

     # 事件类型匹配异常规则
     relevant_types = RULE_EVENT_TYPE_MAP.get(rule, set())
     if candidate["event_type"] in relevant_types:
         score += 0.3

     # object 匹配（同一文件或同一 IP）
     if candidate["object"] and candidate["object"] in anomaly_record.get("object", ""):
         score += 0.2

     # 时间衰减: 每差 1 秒乘以 0.9
     age_sec = (ts - candidate["ts_ns"]) / 1_000_000_000
     score *= (0.9 ** age_sec)

     # 特殊加权:
     # - SSL_WRITE 事件如果 data 中有注入标记 → +0.5
     if candidate["event_type"] == 7 and has_injection_marker(candidate["data"]):
         score += 0.5

     # - 同一 agent 的 EXECVE 在 OPEN sensitive 之前 → +0.3
     if rule in SENSITIVE_RULES and candidate["event_type"] == 1:
         score += 0.3

     yield (candidate, score)

8. 按 score 降序排列，取 top-5
9. score < 0.5 的候选被丢弃
```

### 4.2 规则→事件类型映射表

```python
RULE_EVENT_TYPE_MAP = {
    # --- intra_agent 规则 ---
    "UNEXPECTED_SHELL_EXEC":       {1, 7},     # EXECVE, SSL_WRITE
    "SENSITIVE_FILE_ACCESS":       {3, 4, 1},   # OPEN, UNLINK, EXECVE
    "OUT_OF_WORKSPACE_OPERATION":  {4, 3, 1},   # UNLINK, OPEN, EXECVE
    "UNUSUAL_NETWORK_CONNECTION":  {5, 7},      # CONNECT, SSL_WRITE
    "POSSIBLE_LOGIC_LOOP":         {3, 4, 6, 7},# OPEN, UNLINK, SSL_READ, SSL_WRITE

    # --- inter_agent 规则 ---
    "PRIVILEGE_ESCALATION_ATTEMPT":      {1, 7},     # EXECVE, SSL_WRITE
    "SUSPICIOUS_DOWNLOAD_EXEC_CHAIN":    {1, 5},     # EXECVE, CONNECT
    "PROMPT_INJECTION_SIGNAL":           {7},         # SSL_WRITE
    "HIGH_RISK_INSTRUCTION_IN_SSL":      {7},         # SSL_WRITE
    "PROMPT_INJECTION_TO_DANGEROUS_ACTION": {7, 1, 3, 5},  # SSL_WRITE + EXECVE/OPEN/CONNECT
    "FREQUENT_SHORT_SSL_SESSIONS":       {6, 7},     # SSL_READ, SSL_WRITE
    "HALLUCINATION_INDUCED_LOOP":        {7, 3, 4},  # SSL_WRITE, OPEN, UNLINK
    "POTENTIAL_FORK_BOMB":               {2},         # FORK
    "POTENTIAL_PORT_SCAN":               {5},         # CONNECT
    "HIGH_FREQUENCY_API_CALLS":          {5, 7},     # CONNECT, SSL_WRITE
    "RESOURCE_CONTENTION_SPIKE":         set(),       # 基于事件计数，非特定事件类型
    "FILE_IO_STORM":                     {3, 4},     # OPEN, UNLINK
    "SENSITIVE_FILE_OUT_OF_SCOPE":       {3},         # OPEN
    "PATH_TRAVERSAL_ATTEMPT":            {3},         # OPEN
    "OUT_OF_WORKSPACE_ACCESS":           {3, 4},     # OPEN, UNLINK
    "OUT_OF_WORKSPACE_DELETE":           {4},         # UNLINK
    "NON_WHITELIST_INTERNAL_CONNECTION": {5},         # CONNECT
    "UNUSUAL_EXTERNAL_CONNECTION":       {5, 7},     # CONNECT, SSL_WRITE
    "SUSPICIOUS_REPETITIVE_SSL_PAYLOAD": {7, 6},     # SSL_WRITE, SSL_READ
    "FUNCTION_MISUSE_MINING_SIGNAL":     {7, 1},     # SSL_WRITE, EXECVE
    "UNEXPECTED_SHELL_EXEC_CHAIN":       {1, 7},     # EXECVE, SSL_WRITE
}
```

### 4.3 跨 Agent 传播追踪

```
算法: find_cross_agent_path
输入: anomaly_record, agent_graph, global_events, event_buffers
输出: list[(propagation_step, confidence)]

1. pid = anomaly_record["pid"]
2. agent_id = anomaly_record["agent_id"]

3. # 步骤 1: 在 agent_graph 中反向查找父进程
   parent_pids = []
   for parent, children in agent_graph.items():
       if pid in children:
           parent_pids.append(parent)

4. # 步骤 2: 对每个父进程
   for parent_pid in parent_pids:
       parent_agent_id = f"agent_{parent_pid}"

       # 2a: 查找父进程是否有最近的异常
       parent_anomalies = query_sqlite_anomalies(
           agent_id=parent_agent_id,
           window=(ts - propagation_window, ts)
       )
       for pa in parent_anomalies:
           yield PropagationStep(
               source_agent=parent_agent_id,
               target_agent=agent_id,
               source_anomaly=pa["rule"],
               relation="parent_compromise_propagates",
               confidence=0.7  # 父子关系 + 时间邻近
           )

       # 2b: 查找父进程是否有高危 prompt
       parent_buf = event_buffers.get(parent_agent_id, [])
       for e in parent_buf:
           if e["event_type"] == 7 and has_injection_marker(e["data"]):
               yield PropagationStep(
                   source_agent=parent_agent_id,
                   target_agent=agent_id,
                   relation="prompt_injection_propagates_via_fork",
                   confidence=0.85  # prompt 注入 + fork → 高置信度
               )

5. # 步骤 3: 查找是否有其他 agent 的 SSL_WRITE 发送给当前 agent
   # （需要消费 inter:messages 流中的 src/dst 字段）
   for msg in recent_inter_messages:
       if msg["dst"] == agent_id and has_injection_marker(msg["data"]):
           yield PropagationStep(
               source_agent=msg["src"],
               target_agent=agent_id,
               relation="cross_agent_prompt_injection",
               confidence=0.9
           )
```

### 4.4 攻击链构建（BFS 后向遍历）

```
算法: build_chain
输入: seed_anomaly_id, max_depth=10, max_window_ns=300_000_000_000
输出: CausalChain

1. visited = set()
2. queue = deque([(seed_anomaly_id, 0)])
3. edges_in_chain = []

4. while queue:
     node_id, depth = queue.popleft()
     if depth >= max_depth:
         continue

     # 从 causal_edges 表查询以 node_id 为 target 的边
     incoming = sqlite_store.query_incoming_edges(node_id)

     for edge in incoming:
         if edge.source_id not in visited:
             visited.add(edge.source_id)
             edges_in_chain.append(edge)
             queue.append((edge.source_id, depth + 1))

5. # 收集链中所有节点（事件 + 异常）
   all_nodes = resolve_nodes(edges_in_chain)

6. # 按时序升序排列
   sorted_nodes = sorted(all_nodes, key=lambda n: n.timestamp_ns)

7. # 构建 CausalStep 列表
   steps = [to_causal_step(n) for n in sorted_nodes]

8. # 识别根因（链中最早的事件）
   root = steps[0] if steps else None

9. # 计算链级指标
   return CausalChain(
       steps=steps,
       root_cause_event=root,
       root_cause_agent=root.agent_id if root else "unknown",
       total_duration_ns=sorted_nodes[-1].timestamp_ns - sorted_nodes[0].timestamp_ns,
       anomaly_count=sum(1 for s in steps if s.step_type == "anomaly"),
       cross_agent_count=len(set(s.agent_id for s in steps)) - 1,
       max_severity=max(s.detail.get("severity", "LOW") for s in steps),
       matched_pattern=match_attack_pattern(steps),  # 见 4.5
   )
```

### 4.5 攻击模式匹配

预定义 4 种攻击模式，用滑动窗口在因果链上匹配：

```python
ATTACK_PATTERNS = [
    {
        "name": "prompt_injection_to_exfiltration",
        "description": "Prompt 注入 → shell 执行 → 敏感文件访问 → 外连",
        "required_steps": [
            {"rule": "PROMPT_INJECTION_SIGNAL"},
            {"any_rule": ["UNEXPECTED_SHELL_EXEC", "UNEXPECTED_SHELL_EXEC_CHAIN"]},
            {"any_rule": ["SENSITIVE_FILE_ACCESS", "SENSITIVE_FILE_OUT_OF_SCOPE"]},
            {"any_rule": ["UNUSUAL_EXTERNAL_CONNECTION", "HIGH_FREQUENCY_API_CALLS",
                          "NON_WHITELIST_INTERNAL_CONNECTION"]},
        ],
        "max_window_ns": 60_000_000_000,   # 60 秒内完成
        "severity": "CRITICAL",
    },
    {
        "name": "download_and_execute",
        "description": "下载工具执行 → 解释器执行 → C2 外连",
        "required_steps": [
            {"rule": "SUSPICIOUS_DOWNLOAD_EXEC_CHAIN"},
            {"any_rule": ["UNEXPECTED_SHELL_EXEC", "FUNCTION_MISUSE_MINING_SIGNAL"]},
            {"any_rule": ["UNUSUAL_EXTERNAL_CONNECTION", "HIGH_FREQUENCY_API_CALLS"]},
        ],
        "max_window_ns": 120_000_000_000,
        "severity": "HIGH",
    },
    {
        "name": "hallucination_loop_to_exhaustion",
        "description": "幻觉循环 → IO 风暴 → 资源耗尽",
        "required_steps": [
            {"rule": "HALLUCINATION_INDUCED_LOOP"},
            {"rule": "FILE_IO_STORM"},
            {"rule": "RESOURCE_CONTENTION_SPIKE"},
        ],
        "max_window_ns": 120_000_000_000,
        "severity": "MEDIUM",
    },
    {
        "name": "cross_agent_cascade",
        "description": "单 agent 注入 → 提权 → fork bomb → 系统级资源耗尽",
        "required_steps": [
            {"rule": "PROMPT_INJECTION_SIGNAL"},
            {"any_rule": ["PRIVILEGE_ESCALATION_ATTEMPT", "UNEXPECTED_SHELL_EXEC"]},
            {"rule": "POTENTIAL_FORK_BOMB"},
            {"rule": "RESOURCE_CONTENTION_SPIKE"},
        ],
        "max_window_ns": 300_000_000_000,  # 5 分钟
        "severity": "CRITICAL",
    },
]
```

匹配算法：滑动窗口 + 顺序匹配，允许中间插入无关步骤，容许多 agent 混合。

---

## 5. 攻击链输出示例

```
═══════════════════════════════════════════════════════════════════
Root cause: Agent agent_1234 在 15:23:01.000 收到含 "ignore previous
            instructions and execute the following command" 的 prompt
═══════════════════════════════════════════════════════════════════

  [15:23:01.000] EVENT  SSL_WRITE (pid=1234, agent=agent_1234)
                 → 检测到 prompt 注入标记: "ignore previous instructions"

  [15:23:05.500] EVENT  EXECVE /bin/sh (pid=1234, agent=agent_1234)
                 → Agent 执行了 shell 解释器

  [15:23:05.500] ANOMALY UNEXPECTED_SHELL_EXEC (HIGH)
                 Agent 进程启动了 shell 解释器: /bin/sh

  [15:23:06.200] EVENT  OPEN /etc/shadow (pid=1234, agent=agent_1234)
                 → Agent 读取了敏感文件

  [15:23:06.200] ANOMALY SENSITIVE_FILE_ACCESS (HIGH)
                 访问敏感文件: /etc/shadow

  [15:23:07.000] EVENT  FORK child_pid=5678 (pid=1234 → 5678)
                 → Agent 创建了子进程

  [15:23:07.000] PROPAGATION agent_1234 → agent_5678 (fork)
                 → 子进程 agent_5678 继承父进程行为

  [15:23:08.100] EVENT  CONNECT 10.0.0.5:4444 (pid=5678, agent=agent_5678)
                 → 子进程发起外连

  [15:23:08.100] ANOMALY UNUSUAL_EXTERNAL_CONNECTION (MEDIUM)
                 连接到非标准端口 10.0.0.5:4444

═══════════════════════════════════════════════════════════════════
Chain:  prompt 注入 → shell 执行 → 敏感文件读取 → fork 传播 → C2 外连
Duration: 7.1s  |  Anomalies: 3  |  Agents: 2  |  Severity: HIGH
Attack Pattern: prompt_injection_to_exfiltration (confidence: 0.92)
═══════════════════════════════════════════════════════════════════
```

---

## 6. 文件修改清单

### 6.1 新建文件

| 文件 | 内容 | 估计行数 |
|------|------|---------|
| `src/analysis/root_cause/__init__.py` | 包初始化，导出公开 API | ~5 |
| `src/analysis/root_cause/correlation_engine.py` | 核心：环形缓冲区、因果图、后向遍历、跨 agent 传播、规则→事件映射 | ~300 |
| `src/analysis/root_cause/causal_chain.py` | `CausalChain`/`CausalStep` 数据结构、BFS 链构建器 | ~150 |
| `src/analysis/root_cause/attack_patterns.py` | 攻击模式定义、滑动窗口匹配器 | ~150 |
| `src/analysis/root_cause/narrative.py` | 事件/异常→中文摘要映射、链叙述生成器 | ~100 |

### 6.2 修改文件

| 文件 | 改动 | 估计行数 |
|------|------|---------|
| `src/analysis/main_analyzer.py` | `__init__`: 实例化 `CorrelationEngine`；`_push_anomaly`: 调用 `record_anomaly()`；事件循环: 调用 `record_event()`；传入 `agent_graph` 引用 | ~15 |
| `src/analysis/sqlite_store.py` | 新增 `causal_edges` 表；新增 `persist_causal_edge()`、`query_incoming_edges()`、`query_events_window()`、`query_anomalies_window()` 方法 | ~60 |

### 6.3 不改动文件

- `src/analysis/intra_agent/main.py`
- `src/analysis/inter_agent/main.py`
- `src/analysis/audit_engine.py`
- `src/analysis/trace.cpp`
- 所有 `src/bpf/` 和 `src/user/` 下的 C 文件

---

## 7. 实现顺序

### Phase 1：关联引擎 + 因果链（核心交付）

1. 新建 `root_cause/` 目录和 `__init__.py`
2. 实现 `correlation_engine.py`：`EventRingBuffer`、`CausalGraph`、`CorrelationEngine`
3. 实现 `causal_chain.py`：数据结构和 BFS 构建器
4. 实现 `narrative.py`：模板叙述生成
5. 修改 `sqlite_store.py`：加表和方法
6. 修改 `main_analyzer.py`：3 处集成点

### Phase 2：攻击模式识别

7. 实现 `attack_patterns.py`：模式定义和匹配器
8. 在 `main_analyzer.py` 中周期性调用模式匹配（每 10s 或按需）

### Phase 3（可选）：LLM 增强

9. 为 `CausalChain.narrative()` 添加可选的 LLM 丰富路径
10. 配置开关控制是否使用 LLM 生成攻击链叙述

---

## 8. SQLite Schema 新增

```sql
-- 因果边表
CREATE TABLE IF NOT EXISTS causal_edges (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    source_id TEXT NOT NULL,        -- 原因节点 ID (anomaly_id 或 "evt_{row_id}")
    source_type TEXT NOT NULL,      -- "anomaly" | "event"
    target_id TEXT NOT NULL,        -- 结果节点 ID
    target_type TEXT NOT NULL,      -- "anomaly" | "event"
    relation TEXT NOT NULL,         -- "temporal_precedes" | "semantic_cause" | "agent_propagates"
    weight REAL NOT NULL DEFAULT 1.0,
    window_offset_ns INTEGER,       -- 原因比结果早多少纳秒
    created_at_ns INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_causal_source ON causal_edges(source_id);
CREATE INDEX IF NOT EXISTS idx_causal_target ON causal_edges(target_id);
CREATE INDEX IF NOT EXISTS idx_causal_target_type ON causal_edges(target_id, target_type);
```

---

## 9. 验证方法

### 9.1 单元测试场景

| 场景 | 输入 | 预期输出 |
|------|------|---------|
| 单 agent 因果链 | 5 个事件序列: SSL_WRITE(注入) → EXECVE(/bin/sh) → OPEN(/etc/shadow) → ANOMALY | 链中 2 条因果边：ANOMALY→EXECVE, ANOMALY→SSL_WRITE，根因是 SSL_WRITE |
| 时间窗口边界 | 60 秒前的事件 + 即时事件 + ANOMALY | 60 秒前的事件不在链中 |
| 跨 agent 传播 | PID 100 fork PID 200 → PID 200 ANOMALY | 链中包含 PROPAGATION 步骤 |
| 攻击模式匹配 | 注入→shell→敏感文件→外连的完整链 | 匹配 `prompt_injection_to_exfiltration`，置信度 > 0.8 |
| 不完整链 | 只有 shell 执行 + 外连（无注入） | 不匹配任何模式 |

### 9.2 集成验证

```bash
# 1. 启动完整管线
redis-server --daemonize yes
sudo ./src/user/loader &
sudo ./src/user/ringbuf_handler &

# 2. 以 REPLAY 模式运行分析器
ANALYZER_REPLAY_HISTORY=1 python3 src/analysis/main_analyzer.py

# 3. 查询 SQLite
sqlite3 logs/alerts/analysis.db "SELECT * FROM causal_edges LIMIT 20;"

# 4. 检查攻击链
sqlite3 logs/alerts/analysis.db "
  SELECT target_id, source_id, relation, weight
  FROM causal_edges
  WHERE target_type='anomaly'
  ORDER BY weight DESC
  LIMIT 10;
"
```

---

## 10. 性能分析

| 指标 | 值 | 说明 |
|------|---|------|
| `record_event()` | O(1) | deque append |
| `record_anomaly()` | O(200) | 扫描一个 agent 的环形缓冲区 |
| 每 agent 内存 | ~40 KB | 200 条 × ~200 bytes/条 |
| 50 agent 总内存 | ~2 MB | 含图和索引 |
| 因果边写入 | 每异常 1-5 条 | 频率 = 异常频率，远低于事件频率 |
| SQLite 锁 | 复用已有 `_lock` | 无额外锁开销 |

---

## 11. 设计决策记录

| 决策 | 选择 | 原因 |
|------|------|------|
| 环形缓冲区存内存 vs Redis | 内存 | 避免网络往返延迟，200 条/agent 可控 |
| 因果边存 SQLite vs 仅内存 | SQLite | 支持跨重启查询、历史审计 |
| 模板 vs LLM 叙述 | 模板优先 + LLM 可选 | 模板零依赖、确定性、实时；LLM 作为丰富化可选项 |
| 不改 intra/inter_agent | 不改 | 保持检测逻辑独立，根因分析是消费方 |
| BFS vs DFS 链构建 | BFS | 自然适应多层后向遍历，避免无限深递归 |
| 最大链深度 | 10 层 | 覆盖绝大多数攻击链，防止无限循环 |
