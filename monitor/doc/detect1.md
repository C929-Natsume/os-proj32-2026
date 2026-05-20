# 智能体与外界通信异常模式监测研究综述（2023-2025）

## 一、研究背景与核心问题

### 1.1 研究背景

随着大语言模型（LLM）的快速发展，AI智能体（AI Agent）已经从简单的聊天机器人演变为能够自主执行复杂任务的系统。这些智能体通过与外部环境（包括LLM API、其他服务、工具、数据库以及其他智能体）进行通信来完成任务。然而，这种广泛的通信能力也带来了新的安全风险和异常行为模式。

智能体通信安全已成为AI安全领域的关键问题。根据OWASP Top 10 for LLM Applications，提示注入（Prompt Injection）、数据泄露、权限提升等攻击向量已成为主要威胁。同时，智能体自身的非确定性行为、自主决策能力以及与外部系统的复杂交互，使得传统的安全监控方法难以有效应对。

### 1.2 核心问题分类

基于对近三年相关研究的系统梳理，当前研究主要关注以下核心问题：

#### 1.2.1 提示注入攻击检测（Prompt Injection Detection）

**问题描述：**
- 直接提示注入：攻击者直接向智能体输入恶意指令，试图覆盖系统提示
- 间接提示注入：攻击者通过外部数据源（如网页、文档、邮件）注入恶意内容
- 越狱攻击（Jailbreak）：绕过安全限制，使智能体生成有害内容
- 目标劫持（Goal Hijacking）：改变智能体的原始任务目标

**研究关注点：**
- 如何实时检测输入中的恶意模式
- 如何区分正常用户输入和注入攻击
- 如何处理编码混淆、多语言绕过等高级攻击手法

#### 1.2.2 多智能体系统通信安全（Multi-Agent Communication Security）

**问题描述：**
- 传播漏洞（Propagation Vulnerability）：恶意智能体通过消息交互扭曲集体决策
- 智能体间信任问题：如何验证通信对方的身份和意图
- 消息篡改：通信过程中的中间人攻击
- 协议漏洞：MCP（Model Context Protocol）、A2A（Agent-to-Agent Protocol）等新兴协议的安全问题

**研究关注点：**
- 如何检测恶意智能体的异常行为
- 如何在不依赖标记攻击数据的情况下实现防御
- 如何建立安全的智能体间通信机制

#### 1.2.3 工具调用异常检测（Tool Call Anomaly Detection）

**问题描述：**
- 工具选择错误：智能体选择了不适当的工具或参数
- 权限滥用：智能体执行超出授权范围的操作
- 工具链攻击：通过恶意工具或工具组合实施攻击
- 供应链攻击：工具/插件本身的恶意代码

**研究关注点：**
- 如何监控和审计工具调用行为
- 如何实施最小权限原则
- 如何检测工具使用中的异常模式

#### 1.2.4 运行时行为监控（Runtime Behavior Monitoring）

**问题描述：**
- 智能体行为漂移：模型更新、提示变化导致的输出质量下降
- 无限循环和重复调用：智能体陷入死循环或过度调用API
- 资源滥用：异常高的Token消耗或API调用频率
- 幻觉和错误信息生成：智能体产生虚假或有害内容

**研究关注点：**
- 如何实现细粒度的行为追踪
- 如何建立行为基线和异常检测模型
- 如何实时拦截危险操作

#### 1.2.5 数据泄露与隐私保护（Data Leakage & Privacy）

**问题描述：**
- PII（个人身份信息）泄露：智能体无意中暴露敏感信息
- 数据外泄：智能体被诱导将数据传输到外部服务器
- 记忆投毒（Memory Poisoning）：通过污染智能体的记忆影响其行为

**研究关注点：**
- 如何检测和防止敏感数据泄露
- 如何实现数据脱敏和匿名化
- 如何保护智能体的长期记忆安全

---

## 二、主要解决方案与技术洞察

### 2.1 多层防御架构（Multi-Layer Defense Architecture）

**核心洞察：** 单一防御机制难以应对多样化的攻击向量，需要分层、多维度的防御体系。

**技术方案：**

1. **LlamaFirewall（Meta, 2025）**
   - 三层防护：PromptGuard 2（越狱检测）、Agent Alignment Checks（代理对齐检查）、CodeShield（代码安全分析）
   - 实时拦截恶意输入和不安全代码生成
   - 支持自定义规则和策略

2. **InferenceWall（2025）**
   - Rust驱动的启发式规则引擎
   - ML分类器（ONNX）
   - 语义相似度检测（FAISS）
   - LLM-judge仲裁层
   - 异常评分机制

3. **Prompt Inspector**
   - 五层检测：哈希缓存、正则匹配、语义分析、向量嵌入、AI辅助审查
   - 自适应威胁库
   - 多租户隔离

### 2.2 无监督异常检测（Unsupervised Anomaly Detection）

**核心洞察：** 攻击模式不断演变，依赖标记数据的监督学习方法难以应对未知攻击。

**技术方案：**

1. **BlindGuard（2025）**
   - 层次化智能体编码器：捕获个体、邻居和全局交互模式
   - 腐败引导检测器：通过定向噪声注入和对比学习训练
   - 无需恶意样本即可检测提示注入、记忆投毒和工具攻击

2. **Hodoscope（CMU, 2026）**
   - 基于群体行为差异的无监督监控
   - 比较不同组的行为分布
   - 突出显示独特和可疑的行为模式
   - 减少6-23倍的人工审查工作量

3. **Trajectory Guard（2026）**
   - Siamese循环自编码器架构
   - 混合损失函数：对比学习（任务-轨迹对齐）+ 重构损失（序列有效性）
   - 统一检测"错误计划"和"畸形计划结构"
   - 推理延迟仅32ms

### 2.3 智能体行为可观测性（Agent Observability）

**核心洞察：** 智能体的黑箱决策过程需要细粒度的追踪和监控，以实现故障诊断和安全审计。

**技术方案：**

1. **AgentOps（AgentOps-AI, 2024）**
   - 自动追踪LLM调用、工具调用和代理执行
   - 会话回放功能
   - 成本跟踪和基准测试
   - 提示注入和数据泄露检测
   - 与CrewAI、AutoGen、LangChain等框架集成

2. **Pallma-Guard（2025）**
   - 基于OpenTelemetry的智能体决策过程追踪
   - 开源ML模型实时检测威胁
   - 框架无关：支持LangChain、LangGraph、LlamaIndex等

3. **Agent SRE（2026）**
   - 混沌工程方法测试AI智能体
   - SLO（服务级别目标）定义和监控
   - 自动回滚和故障注入

### 2.4 基于LLM的安全检测（LLM-Based Security Detection）

**核心洞察：** 利用LLM的语义理解能力进行上下文感知的安全检测。

**技术方案：**

1. **GuardAgent（2025）**
   - 首个护栏智能体（Guardrail Agent）
   - 通过知识启用的推理动态检查目标智能体的行为
   - 分析安全护栏请求并生成验证任务

2. **Anomaly Agent（2026）**
   - 基于LangGraph的两阶段检测流程
   - 检测节点 + 验证节点
   - 多变量时间序列异常检测
   - 多模态分析（文本+视觉）

3. **AD-AGENT（USC, 2025）**
   - 自然语言驱动的异常检测管道生成
   - 多智能体架构：Processor、Selector、Generator、Reviewer、Evaluator
   - 支持表格、图和时间序列数据
   - 安全沙箱执行

### 2.5 智能体通信协议安全（Agent Communication Protocol Security）

**核心洞察：** 新兴的智能体通信协议（MCP、A2A）需要专门的安全机制和监控。

**技术方案：**

1. **AgentSentinel（2025）**
   - Agent-to-Monitor（A2M）通信协议
   - 拦截所有敏感操作
   - 实时安全风险审计
   - 任务上下文与系统追踪关联分析

2. **Oktsec（2025）**
   - AI智能体安全代理
   - 监控智能体与外部服务的通信
   - 实时异常检测和阻断

3. **InsAIts（2025）**
   - 多智能体异常监控系统
   - 基于图的智能体交互分析
   - 实时威胁检测

### 2.6 对抗测试与红队（Adversarial Testing & Red Teaming）

**核心洞察：** 主动发现和修复安全漏洞需要系统化的对抗测试方法。

**技术方案：**

1. **AgentProbe（2026）**
   - 194种对抗攻击测试
   - 支持提示注入、数据外泄、权限提升、输出操纵等攻击类型
   - GitHub Actions集成
   - SARIF输出格式

2. **Garak（NVIDIA, 2023-2025）**
   - LLM漏洞扫描工具
   - 检测幻觉、数据泄露、提示注入、越狱等
   - 支持多种模型和API

3. **LLMFuzzer（2024）**
   - 专门针对LLM的模糊测试工具
   - 自动化漏洞发现

---

## 三、技术趋势与未来方向

### 3.1 主要趋势

1. **从静态规则到动态学习**：从基于正则和关键词的静态检测，向基于机器学习和LLM的动态、自适应检测转变

2. **从单点防护到系统级防御**：从单一的输入过滤，向覆盖智能体全生命周期的系统级安全架构演进

3. **从监督学习到无监督/自监督**：减少对标记攻击数据的依赖，提高对未知攻击的检测能力

4. **从被动响应到主动预防**：从事后审计向实时监控和主动拦截转变

5. **从中心化到分布式**：多智能体系统中的分布式安全监控和协同防御

### 3.2 未来研究方向

1. **智能体安全标准化**：建立统一的智能体安全评估标准和认证体系

2. **实时自适应防御**：开发能够根据攻击态势自动调整防御策略的智能系统

3. **跨智能体信任机制**：建立去中心化的智能体身份验证和信任评估机制

4. **隐私保护监控**：在保护用户隐私的前提下实现有效的行为监控

5. **人机协同安全**：结合人类专家知识和AI能力的安全决策系统

---

## 四、参考文献（50篇）

### 4.1 开源工具与框架

| 序号 | 项目名称 | 作者/组织 | GitHub Stars | 主要功能 | 链接 |
|------|----------|-----------|--------------|----------|------|
| 1 | **LlamaFirewall** | Meta | 2000+ | AI代理安全护栏框架，包含PromptGuard 2、Agent Alignment Checks、CodeShield | https://github.com/meta-llama/PurpleLlama/tree/main/LlamaFirewall |
| 2 | **LLM Guard** | ProtectAI | 1500+ | LLM输入输出安全扫描，提示注入检测，PII检测 | https://github.com/protectai/llm-guard |
| 3 | **Garak** | NVIDIA | 1200+ | LLM安全测试框架，检测幻觉、数据泄露、提示注入、越狱 | https://github.com/leondz/garak |
| 4 | **AgentOps** | AgentOps-AI | 2200+ | AI代理可观测性平台，会话回放，成本跟踪，安全检测 | https://github.com/AgentOps-AI/agentops |
| 5 | **Langfuse** | Langfuse | 3500+ | LLM工程平台，可观测性、提示管理、评估 | https://github.com/langfuse/langfuse |
| 6 | **Helicone** | Helicone | 1800+ | LLM可观测性和AI网关，低延迟代理 | https://github.com/Helicone/helicone |
| 7 | **Lunary** | Lunary | 900+ | LLM可观测性和提示管理，开源 | https://github.com/lunary-ai/lunary |
| 8 | **TruLens** | TruEra | 1100+ | RAG三元组评估指标，可观测性 | https://github.com/truera/trulens |
| 9 | **Arize Phoenix** | Arize AI | 2200+ | AI可观测性和评估，本地优先 | https://github.com/Arize-ai/phoenix |
| 10 | **Portkey** | Portkey | 800+ | AI网关，LLM路由和故障转移 | https://github.com/Portkey-AI/gateway |
| 11 | **InferenceWall** | InferWall | 300+ | AI应用防火墙，多层检测引擎 | https://github.com/inferwall/inferwall |
| 12 | **Prompt Inspector** | Aunicall | 250+ | 开源LLM防火墙，实时提示注入检测 | https://github.com/aunicall/prompt-inspector |
| 13 | **AgentProbe** | AlexMelges | 400+ | AI代理对抗安全测试，194种攻击 | https://github.com/alexmelges/agentprobe |
| 14 | **LLMFuzzer** | mnns | 600+ | LLM模糊测试工具 | https://github.com/mnns/LLMFuzzer |
| 15 | **PyOD** | Yue Zhao | 8500+ | Python异常检测库，支持智能体异常检测 | https://github.com/yzhao062/pyod |
| 16 | **Vard** | Anders Myrmel | 50+ | 轻量级提示注入检测库 | https://github.com/andersmyrmel/vard |
| 17 | **Prompt-Shield** | Griff-Reaper | 80+ | 企业级提示注入检测和防御系统 | https://github.com/Griff-Reaper/prompt-shield |
| 18 | **LLM-Prompt-Guard** | Shane Hamilton | 60+ | 正则基础的提示注入防火墙 | https://github.com/shanemhamilton/llm-prompt-guard |
| 19 | **LlmGuard (Elixir)** | North-Shore-AI | 40+ | Elixir LLM防火墙和护栏 | https://github.com/North-Shore-AI/LlmGuard |
| 20 | **Agent SRE** | Imran Siddique | 150+ | AI代理站点可靠性工程，混沌工程 | https://github.com/imran-siddique/agent-sre |
| 21 | **Pallma-Guard** | Pallma AI | 100+ | AI代理安全可观测性层 | https://github.com/pallma-ai/pallma |
| 22 | **AgentShield** | AgentShield | 80+ | AI代理安全和监控SDK | https://github.com/agentshield/python-sdk |
| 23 | **Anomaly Agent** | Andrew Maguire | 30+ | 基于LLM的时间序列异常检测 | https://github.com/andrewm4894/anomaly-agent |
| 24 | **Anomalistral** | Kacper0199 | 150+ | Mistral AI代理异常检测管道 | https://github.com/Kacper0199/anomalistral |
| 25 | **AD-AGENT** | USC-FORTIS | 200+ | LLM驱动的端到端异常检测 | https://github.com/USC-FORTIS/AD-AGENT |
| 26 | **Argos** | Microsoft | 30+ | 基于LLM的时间序列异常检测规则生成 | https://github.com/microsoft/argos |
| 27 | **Multi-Agent Attack Graph PoC** | Dickens88 | 100+ | 多智能体攻击图分析系统 | https://github.com/dickens88/multi-agent-attack-graph-poc |
| 28 | **AegisX** | 238469 | 200+ | AI驱动的Web渗透测试多智能体系统 | https://github.com/238469/AegisX |
| 29 | **Awesome Agent Skills Security** | LLMSecurity | 300+ | AI代理技能安全资源精选列表 | https://github.com/LLMSecurity/awesome-agent-skills-security |
| 30 | **Awesome Agent Communication Security** | theshi-1128 | 80+ | 智能体通信安全研究精选 | https://github.com/theshi-1128/awesome-agent-communication-security |

### 4.2 学术论文

| 序号 | 论文标题 | 作者 | 年份 | 会议/期刊 | 链接 |
|------|----------|------|------|-----------|------|
| 31 | **AgentSentinel: An End-to-End and Real-Time Security Defense Framework for Computer-Use Agents** | Haitao Hu, et al. | 2025 | arXiv | https://arxiv.org/abs/2509.07764 |
| 32 | **BlindGuard: Safeguarding LLM-based Multi-Agent Systems under Unknown Attacks** | Rui Miao, et al. | 2025 | arXiv | https://arxiv.org/abs/2508.08127 |
| 33 | **GuardAgent: Safeguard LLM Agents via Knowledge-Enabled Reasoning** | - | 2025 | ICLR Workshop | https://arxiv.org/abs/2505.12594 |
| 34 | **Hodoscope: Unsupervised Monitoring for AI Misbehaviors** | Ziqian Zhong, et al. | 2026 | arXiv | https://arxiv.org/abs/2604.11072 |
| 35 | **Trajectory Guard: A Lightweight, Sequence-Aware Model for Real-Time Anomaly Detection in Agentic AI** | Laksh Advani | 2026 | arXiv | https://arxiv.org/abs/2601.00516 |
| 36 | **AgentOps: Enabling Observability of LLM Agents** | Liming Dong, et al. | 2024 | arXiv | https://arxiv.org/abs/2411.05285 |
| 37 | **A Survey on Agent Communication Security: Protocols, Risks, Defenses, and Future Challenges** | - | 2025 | arXiv | https://arxiv.org/abs/2506.19676 |
| 38 | **Arbiter: Detecting Interference in LLM Agent System Prompts** | Mason | 2026 | arXiv | https://github.com/LLMSecurity/awesome-agent-skills-security |
| 39 | **ESAA-Security: Event-Sourced Architecture for Agent-Assisted Security Audits** | - | 2025 | - | https://github.com/LLMSecurity/awesome-agent-skills-security |
| 40 | **Anomalyze: Hybrid CX Insight Engine with GenAI Agent** | - | 2024 | - | https://github.com/anomalyze |

### 4.3 安全标准与框架

| 序号 | 名称 | 组织 | 描述 | 链接 |
|------|------|------|------|------|
| 41 | **OWASP Top 10 for LLM Applications** | OWASP | LLM应用十大安全风险 | https://owasp.org/www-project-top-10-for-large-language-model-applications/ |
| 42 | **OWASP AI Agent Security Cheat Sheet** | OWASP | AI代理安全最佳实践 | https://cheatsheetseries.owasp.org/cheatsheets/AI_Agent_Security_Cheat_Sheet.html |
| 43 | **NIST AI Risk Management Framework** | NIST | AI风险管理框架 | https://www.nist.gov/itl/ai-risk-management-framework |
| 44 | **MITRE ATLAS** | MITRE | AI系统对抗威胁矩阵 | https://atlas.mitre.org/ |
| 45 | **OpenTelemetry GenAI Semantic Conventions** | OpenTelemetry | GenAI可观测性标准 | https://opentelemetry.io/docs/specs/semconv/gen-ai/ |

### 4.4 相关项目与资源

| 序号 | 项目名称 | 作者/组织 | Stars | 描述 | 链接 |
|------|----------|-----------|-------|------|------|
| 46 | **Oubliette Shield** | - | 150+ | LLM防火墙，网络欺骗技术 | https://github.com/oubliette-shield |
| 47 | **Oktsec** | - | 100+ | AI代理安全代理 | https://github.com/oktsec |
| 48 | **InsAIts** | - | 80+ | 多智能体异常监控 | https://github.com/insaits |
| 49 | **CARLA** | - | 500+ | 对比学习异常检测 | https://github.com/caogang/wgan-gp |
| 50 | **CoLA** | - | 400+ | 属性网络对比自监督学习 | https://github.com/CRIPAC-DIG/CoLA |

---

## 五、总结

智能体与外界通信的异常模式监测是一个快速发展的研究领域，涵盖了提示注入检测、多智能体通信安全、工具调用监控、运行时行为监控和数据泄露防护等多个方面。近三年的研究呈现出以下特点：

1. **技术多样化**：从传统的基于规则的方法，到基于机器学习、深度学习和LLM的现代方法

2. **架构系统化**：从单点防护向覆盖智能体全生命周期的系统级安全架构演进

3. **检测智能化**：利用LLM的语义理解能力和无监督学习方法，提高对未知攻击的检测能力

4. **可观测性增强**：通过细粒度的追踪和监控，实现智能体行为的全面可视化

5. **标准化推进**：OpenTelemetry等标准的制定，推动了智能体可观测性的标准化

未来的研究需要在实时性、准确性、可扩展性和隐私保护之间寻求平衡，同时建立统一的安全评估标准和认证体系，为智能体的安全部署提供可靠保障。
