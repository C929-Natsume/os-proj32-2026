# 代理式人工智能网络通信异常检测研究报告

## 摘要

本报告系统梳理了近三年来（2023-2026）代理式人工智能（AI Agent）网络通信异常检测领域的开源研究进展。通过对50余个高质量开源项目（GitHub Stars > 20）的深入分析，总结了该领域关注的核心问题、技术洞察与解决方案，为AI安全研究者和工程实践者提供全面参考。

---

## 一、研究背景与核心问题

### 1.1 AI Agent网络通信异常的定义

AI Agent网络通信异常是指智能体在与外部系统（LLM API、工具服务、其他Agent）交互过程中，出现的偏离预期行为模式或安全策略的通信活动。这类异常包括但不限于：

- **LLM API通信异常**：异常API调用、成本超支、敏感数据外泄
- **工具调用异常**：恶意工具链组合、权限越界、命令注入
- **Agent间通信异常**：消息篡改、身份伪造、协作冲突
- **外部服务通信异常**：数据外泄、SSRF攻击、恶意端点访问

### 1.2 领域关注的核心问题

根据对开源项目的分析，当前研究主要聚焦以下五大核心问题：

#### 问题1：Agent与LLM API通信的可观测性

**问题描述**：AI Agent与LLM API的通信是核心交互路径，但传统监控工具无法理解LLM特有的通信模式（如流式响应、Token计费、提示词结构）。

**关键挑战**：
- 跨框架的统一追踪（LangChain、CrewAI、AutoGen等）
- 实时成本监控与预算控制
- 敏感提示词的审计与合规
- 多租户环境下的隔离与追踪

#### 问题2：数据外泄与敏感信息保护

**问题描述**：Agent可能在不知情的情况下将敏感数据（PII、凭证、商业机密）发送到外部LLM服务或工具端点。

**关键挑战**：
- 实时PII检测与脱敏
- 凭证泄露的预防与检测
- 数据流向的可视化追踪
- 合规性要求（GDPR、HIPAA等）

#### 问题3：提示注入与恶意指令攻击

**问题描述**：攻击者可能通过提示注入劫持Agent行为，诱导其执行恶意操作或泄露敏感信息。

**关键挑战**：
- 直接/间接提示注入检测
- 工具投毒攻击（Tool Poisoning Attack）防护
- 多轮对话中的攻击检测
- 零日攻击的防御能力

#### 问题4：多Agent系统通信安全

**问题描述**：多Agent系统中，Agent间通信可能被窃听、篡改或伪造，协作过程可能产生冲突或死锁。

**关键挑战**：
- Agent身份认证与授权
- 消息完整性与机密性保护
- 协作冲突检测与解决
- Agent网络拓扑的安全管理

#### 问题5：Agent行为审计与合规

**问题描述**：企业需要审计Agent的所有操作，以满足安全合规和内部治理要求。

**关键挑战**：
- 完整的审计日志记录
- 防篡改的日志存储
- 行为基线与异常检测
- 合规报告的自动生成

---

## 二、技术洞察与解决方案

### 2.1 Agent通信可观测性技术

#### 洞察1：OpenTelemetry成为Agent追踪的标准

OpenTelemetry作为云原生可观测性标准，被广泛采用于Agent追踪场景，实现跨框架、跨服务的统一追踪。

**代表性方案**：
- **Langfuse**（Stars 14,400+）：开源LLM工程平台，基于OpenTelemetry实现LLM调用追踪，支持自托管，提供提示词管理、评估、成本分析等功能。
- **Phoenix**（Arize AI，Stars 9,400+）：开源AI可观测性平台，基于OpenTelemetry的追踪系统，支持LangGraph、CrewAI、LlamaIndex等框架。
- **OpenLLMetry**（Stars 6,500+）：基于OpenTelemetry的LLM可观测性工具集，支持OpenAI、Anthropic、Cohere等50+ LLM提供商。

#### 洞察2：代理网关实现透明监控

通过在Agent与LLM API之间部署代理网关，实现透明的通信监控、审计和安全控制。

**代表性方案**：
- **LiteLLM**（Stars 20,000+）：开源AI网关，统一调用100+ LLM提供商，提供虚拟密钥、成本追踪、负载均衡、速率限制、审计日志等功能。
- **Helicone**（Stars 4,600+）：开源LLM可观测性平台，一行代码即可监控OpenAI、Anthropic、LangChain等，提供追踪、会话管理、成本分析。
- **LLMTrace**（Stars 100+）：透明代理用于OpenAI兼容API，提供实时安全检测（Prompt注入检测、PII扫描、数据泄露防护），使用Rust构建。

#### 洞察3：会话回放与执行图分析

通过记录Agent的完整执行过程，支持会话回放和执行图分析，帮助理解Agent行为和诊断问题。

**代表性方案**：
- **AgentOps**（Stars 5,100+）：Python SDK用于AI Agent监控、LLM成本追踪、基准测试，支持会话回放、执行图分析、成本管理，与CrewAI、LangChain、AutoGen等主流框架集成。
- **AgentNeo**（Stars 884+）：AI Agent可观测性、监控和评估框架，支持LLM调用追踪、Agent/工具追踪、交互监控、执行图可视化。

### 2.2 数据外泄防护技术

#### 洞察4：多层PII检测与脱敏

采用规则匹配、NER模型、LLM分类器等多层方法检测和脱敏敏感信息。

**代表性方案**：
- **LLM-Guard**（Protect AI，Stars 2,100+）：LLM交互安全工具包，提供30+扫描器，包括匿名化、PII检测、敏感词过滤、毒性检测等。
- **PII Masker**（HydroXai）：开源PII脱敏工具，使用DeBERTa-v3自动检测和脱敏敏感数据，高精度检测，可扩展性能。
- **ZugaShield**：7层AI Agent安全系统，阻止提示注入、数据外泄和AI特定攻击，延迟<15ms，150+签名。

#### 洞察5：凭证集中管理与代理

Agent不直接持有API Key或OAuth Token，通过代理服务发起调用，实现凭证的集中管理和审计。

**代表性方案**：
- **agent-auth-broker**：AI Agent集中式凭证管理与授权代理服务，Agent不直接持有API Key或OAuth Token，通过Broker发起调用，实现凭证隔离。
- **LiteLLM**：提供虚拟密钥管理，支持API Key轮换、预算限制、租户隔离。

#### 洞察6：数据流向可视化

通过追踪数据在Agent系统中的流动，识别潜在的数据外泄路径。

**代表性方案**：
- **LangSight**：AI Agent调用的完整可观测性，追踪、成本、健康检查、MCP服务器安全扫描、CVE/OWASP MCP Top 10检测。
- **agent-discover-scanner**：多层AI Agent检测，包括静态代码分析、网络监控、Kubernetes运行时可见性（eBPF），识别向AI提供商的出站连接。

### 2.3 提示注入防护技术

#### 洞察7：多层防御架构

提示注入防护采用多层防御：规则过滤、模型检测、行为分析，形成纵深防御。

**代表性方案**：
- **NeMo Guardrails**（NVIDIA，Stars 5,200+）：可编程护栏工具包，支持输入/输出/对话/检索/执行护栏，防护越狱和提示注入攻击。附带论文 arXiv:2310.10501。
- **Purple Llama**（Meta，Stars 3,700+）：LLM安全工具集，包含Llama Guard（内容安全模型）、Prompt Guard（提示注入检测）、Code Shield（不安全代码过滤）、LlamaFirewall（Agent护栏系统）。附带多篇论文。
- **Rebuff**（Protect AI，Stars 1,300+）：开源LLM提示注入检测系统，采用四层防御：启发式过滤、LLM检测、向量数据库、金丝雀令牌。

#### 洞察8：工具投毒攻击检测

工具投毒攻击（Tool Poisoning Attack）是针对Agent的新型攻击，通过篡改工具描述诱导Agent执行恶意操作。

**代表性方案**：
- **LlamaFirewall**（Meta）：AI Agent安全护栏框架，检测直接和间接提示注入、工具投毒攻击、数据外泄等。
- **sentinel-mcp**：MCP服务器安全扫描器，检测硬编码凭证、工具描述投毒、工具影子攻击、SSRF风险、命令注入等。
- **ZIRAN**（Taoq-AI，Stars 100+）：AI Agent安全测试框架，通过知识图谱分析发现危险工具链组合，覆盖565个攻击向量。

#### 洞察9：AI驱动的安全检测

使用AI模型检测AI攻击，实现"以AI治AI"的安全范式。

**代表性方案**：
- **Prompt Shield**：自学习提示注入检测引擎，包含25个输入检测器（支持10种语言）、5个输出扫描器，F1达96.0%。
- **Open Guard Engine**：AI编码助手的Agent无关安全引擎，三层检测：快速模式匹配、Agent分析检测新型注入、LLM安全分类。

### 2.4 多Agent系统通信安全

#### 洞察10：标准化通信协议的兴起

Google A2A、MCP等标准化协议的出现，为Agent间通信提供了互操作性和安全保障。

**代表性方案**：
- **A2A (Agent2Agent Protocol)**（Google，Stars 7,200+）：开放协议，实现不同框架和供应商的AI Agent之间的通信和互操作，支持Agent发现、能力协商、安全认证。
- **MCP (Model Context Protocol)**（Anthropic，Stars 5,000+）：开放标准，为LLM与外部数据源、工具之间建立标准化双向通信链路，包含完整的安全最佳实践文档。
- **AMP (Agent Messaging Protocol)**：AI Agent通信开放标准，提供联邦式架构、Ed25519加密签名、本地优先存储。

#### 洞察11：Agent身份认证与授权

Agent需要可信的身份认证机制，防止身份伪造和未授权访问。

**代表性方案**：
- **Human Verified AI Agent**：基于A2A协议的AI Agent开源实现，实现HTTP消息签名进行请求认证。
- **APort Agent Guardrails**：AI Agent预执行授权护栏，在工具调用前检查身份和能力限制。

#### 洞察12：Agent沙箱隔离

通过沙箱隔离Agent的执行环境，限制其对系统资源的访问。

**代表性方案**：
- **Agent Sandbox**：企业级AI Agent沙箱运行时，基于Kubernetes和容器隔离，完全兼容E2B协议，支持代码执行、浏览器使用。
- **Agent Guard**：AI Agent开源防火墙，提供策略执行、MCP安全扫描、零信任身份、沙箱隔离。

### 2.5 安全审计与合规技术

#### 洞察13：防篡改审计日志

使用哈希链、数字签名等技术确保审计日志的完整性和不可篡改性。

**代表性方案**：
- **Traceprompt**（Stars 50+）：Node.js SDK，为LLM应用提供审计就绪、防篡改日志，支持客户端加密、哈希链完整性，符合FINRA、HIPAA、EU AI Act合规要求。
- **Codesteward Audit Proxy**（Stars 50+）：代理服务器，位于AI编码Agent和上游LLM API之间，异步提取结构化审计数据到ClickHouse。

#### 洞察14：安全基准测试与红队测试

系统化的安全基准测试和红队测试帮助发现Agent的安全漏洞。

**代表性方案**：
- **garak**（NVIDIA，Stars 3,500+）：LLM漏洞扫描器，检测幻觉、数据泄露、提示注入、错误信息生成、毒性生成、越狱等多种弱点。附带论文。
- **PyRIT**（Microsoft，Stars 2,700+）：生成式AI风险识别工具，用于红队测试，支持多种攻击向量、自动化风险评估。附带论文 arXiv:2410.02828。
- **Agent Security Bench (ASB)**（Stars 144）：ICLR 2025论文官方代码，系统评估LLM Agent的攻击和防御策略，覆盖10个场景、398个对抗环境。

#### 洞察15：威胁检测规则化

将Agent威胁检测规则化，支持与现有SIEM/SOC工具集成。

**代表性方案**：
- **agent-threat-rules**：29个AI Agent威胁检测规则，覆盖9个攻击类别，类似Sigma规则但针对提示注入、工具投毒、MCP攻击。
- **AgentShield Sigma Rules**：AI Agent的Sigma规则集，实时监控Agent行为，检测提示注入、数据窃取、工具投毒、权限提升等攻击。

---

## 三、开源项目详细参考

### 3.1 Agent可观测性与监控平台

| 序号 | 项目名称 | GitHub链接 | Stars | 核心功能 | 论文/文章 |
|------|----------|------------|-------|----------|-----------|
| 1 | LiteLLM | https://github.com/BerriAI/litellm | 20,000+ | AI网关，统一调用100+ LLM，虚拟密钥、成本追踪、审计日志 | 否 |
| 2 | Langfuse | https://github.com/langfuse/langfuse | 14,400+ | LLM工程平台，可观测性、追踪、评估、提示管理 | 否 |
| 3 | Phoenix | https://github.com/Arize-ai/phoenix | 9,400+ | AI可观测性平台，OpenTelemetry追踪，评估 | 否 |
| 4 | OpenLLMetry | https://github.com/traceloop/openllmetry | 6,500+ | OpenTelemetry原生LLM可观测性工具集 | 否 |
| 5 | AgentOps | https://github.com/AgentOps-AI/agentops | 5,100+ | Agent监控、成本追踪、会话回放、执行图分析 | 否 |
| 6 | Helicone | https://github.com/Helicone/helicone | 4,600+ | LLM可观测性平台，追踪、成本分析、提示管理 | 否 |
| 7 | OpenLIT | https://github.com/openlit/openlit | 1,800+ | OpenTelemetry原生AI工程平台，Guardrails、GPU监控 | 否 |
| 8 | AgentNeo | https://github.com/raga-ai-hub/AgentNeo | 884+ | Agent可观测性、监控、评估，执行图可视化 | 否 |

### 3.2 Agent安全护栏框架

| 序号 | 项目名称 | GitHub链接 | Stars | 核心功能 | 论文/文章 |
|------|----------|------------|-------|----------|-----------|
| 9 | NeMo Guardrails | https://github.com/NVIDIA-NeMo/Guardrails | 5,200+ | 可编程护栏，输入/输出/对话/检索/执行护栏 | arXiv:2310.10501 |
| 10 | Purple Llama | https://github.com/meta-llama/PurpleLlama | 3,700+ | LLM安全工具集，Llama Guard、Prompt Guard、LlamaFirewall | 多篇论文 |
| 11 | LLM-Guard | https://github.com/protectai/llm-guard | 2,100+ | LLM交互安全工具包，30+扫描器 | 否 |
| 12 | Agentic Security | https://github.com/msoedov/agentic_security | 1,600+ | LLM漏洞扫描器，AI红队工具包 | 否 |
| 13 | Rebuff | https://github.com/protectai/rebuff | 1,300+ | 提示注入检测，四层防御架构 | 否 |

### 3.3 Agent漏洞扫描与红队测试

| 序号 | 项目名称 | GitHub链接 | Stars | 核心功能 | 论文/文章 |
|------|----------|------------|-------|----------|-----------|
| 14 | garak | https://github.com/NVIDIA/garak | 3,500+ | LLM漏洞扫描器，检测幻觉、数据泄露、提示注入 | garak-paper.pdf |
| 15 | PyRIT | https://github.com/Azure/PyRIT | 2,700+ | 生成式AI风险识别工具，红队测试 | arXiv:2410.02828 |
| 16 | Agent Security Bench | https://github.com/agiresearch/ASB | 144 | Agent安全基准测试，ICLR 2025 | ICLR 2025论文 |
| 17 | ZIRAN | https://github.com/Taoq-AI/Ziran | 100+ | Agent安全测试框架，知识图谱分析危险工具链 | 是 |
| 18 | HackMyAgent | https://github.com/opena2a-org/hackmyagent | - | Agent安全工具包，209个安全检查 | 否 |

### 3.4 多Agent系统通信框架

| 序号 | 项目名称 | GitHub链接 | Stars | 核心功能 | 论文/文章 |
|------|----------|------------|-------|----------|-----------|
| 19 | AutoGen | https://github.com/microsoft/autogen | 50,000+ | 多Agent AI应用框架，事件驱动通信 | 多篇论文 |
| 20 | LangGraph | https://github.com/langchain-ai/langgraph | 16,900+ | 有状态Agent工作流框架，持久执行 | 否 |
| 21 | A2A Protocol | https://github.com/google/A2A | 7,200+ | Agent间通信开放协议，安全认证 | 协议规范 |
| 22 | MCP | https://github.com/modelcontextprotocol/modelcontextprotocol | 5,000+ | LLM与工具通信标准，安全最佳实践 | 规范文档 |
| 23 | CrewAI | https://github.com/crewAIInc/crewAI | - | 多Agent协作框架，企业级安全 | 否 |

### 3.5 AI安全网关与防火墙

| 序号 | 项目名称 | GitHub链接 | Stars | 核心功能 | 论文/文章 |
|------|----------|------------|-------|----------|-----------|
| 24 | AI Security Gateway | https://github.com/syphon1c/ai-security-gateway | - | 统一安全平台，250+检测规则，数据脱敏 | 否 |
| 25 | Trylon Gateway | https://github.com/trylonai/gateway | 89 | LLM防火墙，PII检测脱敏、内容过滤 | 否 |
| 26 | LLMTrace | https://github.com/geopolitis/llmtrace | 100+ | 透明代理，安全检测、PII扫描、数据泄露防护 | 否 |
| 27 | LLM Audit Gateway | https://github.com/almaz-go/llm-audit-gateway | 50+ | Go语言高性能代理，监控、审计、速率限制 | 否 |

### 3.6 MCP安全扫描器

| 序号 | 项目名称 | GitHub链接 | Stars | 核心功能 | 论文/文章 |
|------|----------|------------|-------|----------|-----------|
| 28 | mcpsec | https://github.com/pfrederiksen/mcpsec | - | OWASP MCP Top 10扫描器，YAML规则引擎 | 否 |
| 29 | MCP Security Framework | https://github.com/JoKFA/mcp-security-framework | - | MCP服务器安全测试框架，5阶段流水线 | 否 |
| 30 | sentinel-mcp | https://github.com/robdtaylor/sentinel-mcp | - | MCP服务器扫描器，工具投毒检测 | 否 |
| 31 | LangSight | https://github.com/LangSight/langsight | - | Agent可观测性，MCP安全扫描，CVE检测 | 否 |

### 3.7 Agent安全扫描器

| 序号 | 项目名称 | GitHub链接 | Stars | 核心功能 | 论文/文章 |
|------|----------|------------|-------|----------|-----------|
| 32 | AgentShield | https://github.com/elliotllliu/agent-shield | - | 多引擎安全扫描器，13个独立扫描引擎 | 否 |
| 33 | agent-discover-scanner | https://github.com/Defend-AI-Tech-Inc/agent-discover-scanner | - | 多层Agent检测，静态分析、网络监控、eBPF | 否 |
| 34 | Agent Risk Analyzer | https://github.com/Prnvlol/agent-risk-analyzer | - | 静态安全扫描器，20种漏洞类别，MITRE ATLAS映射 | 否 |

### 3.8 威胁检测规则与框架

| 序号 | 项目名称 | GitHub链接 | Stars | 核心功能 | 论文/文章 |
|------|----------|------------|-------|----------|-----------|
| 35 | agent-threat-rules | https://github.com/panguard-ai/agent-threat-rules | - | 29个Agent威胁检测规则，9个攻击类别 | 否 |
| 36 | Sigma-AI | https://github.com/agentshield-ai/sigma-ai | - | Agent Sigma规则集，实时行为监控 | 否 |
| 37 | OWASP Agentic AI Top 10 | https://github.com/precize/OWASP-Agentic-AI | - | Agent十大安全风险框架 | 框架文档 |

### 3.9 数据泄露防护

| 序号 | 项目名称 | GitHub链接 | Stars | 核心功能 | 论文/文章 |
|------|----------|------------|-------|----------|-----------|
| 38 | ZugaShield | https://github.com/Zuga-Technologies/ZugaShield | - | 7层Agent安全系统，150+签名，延迟<15ms | 否 |
| 39 | Superagent | https://github.com/superagent-ai/superagent | - | Agent安全SDK，提示注入防护、PII脱敏 | 否 |
| 40 | PII Masker | https://github.com/HydroXai/pii-masker-v1 | - | PII脱敏工具，DeBERTa-v3模型 | 否 |

### 3.10 审计与合规工具

| 序号 | 项目名称 | GitHub链接 | Stars | 核心功能 | 论文/文章 |
|------|----------|------------|-------|----------|-----------|
| 41 | Traceprompt | https://github.com/traceprompt/traceprompt-node | 50+ | 防篡改审计日志，哈希链完整性，合规支持 | 否 |
| 42 | Codesteward Audit Proxy | https://github.com/Codesteward/codesteward-audit-proxy | 50+ | AI编码Agent审计代理，ClickHouse存储 | 否 |
| 43 | LLM Authz Audit | https://github.com/aiauthz/llm-authz-audit | 50+ | LLM应用授权漏洞扫描 | 否 |

### 3.11 Agent沙箱与隔离

| 序号 | 项目名称 | GitHub链接 | Stars | 核心功能 | 论文/文章 |
|------|----------|------------|-------|----------|-----------|
| 44 | Agent Sandbox | https://github.com/agent-sandbox/agent-sandbox | - | 企业级沙箱运行时，K8s容器隔离，E2B兼容 | 否 |
| 45 | Agent Guard | https://github.com/Aveerayy/agent-guard | - | Agent防火墙，策略执行、零信任、沙箱隔离 | 否 |
| 46 | APort Agent Guardrails | https://github.com/APortHQ/aport-agent-guardrails | - | 预执行授权护栏，身份和能力检查 | 否 |

### 3.12 安全资源汇总

| 序号 | 项目名称 | GitHub链接 | Stars | 核心功能 | 论文/文章 |
|------|----------|------------|-------|----------|-----------|
| 47 | Awesome Agent Skills Security | https://github.com/LLMSecurity/awesome-agent-skills-security | - | Agent技能安全资源精选列表 | 汇总多篇论文 |
| 48 | Awesome LLM Security Tool | https://github.com/d1pakda5/awesome-llm-security-tool | - | LLM安全工具精选列表 | 汇总多篇论文 |
| 49 | MCP Security Cheat Sheet | https://github.com/OWASP/CheatSheetSeries | OWASP项目 | MCP安全最佳实践速查表 | 否 |

### 3.13 其他相关工具

| 序号 | 项目名称 | GitHub链接 | Stars | 核心功能 | 论文/文章 |
|------|----------|------------|-------|----------|-----------|
| 50 | LLM-IDS-Agent | https://github.com/888585544/LLM-IDS-Agent | 50+ | 基于LLM的网络入侵检测框架 | 是 |
| 51 | ferret-scan | https://github.com/fubak/ferret-scan | - | LLM CLI安全扫描器，提示注入、凭证泄露检测 | 否 |
| 52 | agent-auth-broker | https://github.com/worsher/agent-auth-broker | - | Agent凭证管理与授权代理 | 否 |

---

## 四、技术趋势与展望

### 4.1 当前技术趋势

1. **OpenTelemetry标准化**：OpenTelemetry成为Agent追踪的事实标准，实现跨框架、跨服务的统一可观测性。
2. **代理网关普及**：LiteLLM、Helicone等代理网关成为企业部署LLM应用的标配，提供透明监控和安全控制。
3. **护栏框架成熟**：NeMo Guardrails、LlamaFirewall等护栏框架日趋成熟，提供可编程的安全控制能力。
4. **协议标准化加速**：A2A、MCP等标准化协议推动Agent间通信的互操作性和安全性。
5. **红队测试工具化**：garak、PyRIT等红队测试工具帮助企业系统化评估Agent安全性。

### 4.2 未来研究方向

1. **实时威胁检测**：基于流式学习的实时Agent威胁检测，应对快速演进的攻击手法。
2. **联邦式Agent安全**：跨组织的安全情报共享，协同防御新型攻击。
3. **自适应护栏**：根据上下文动态调整安全策略的自适应护栏系统。
4. **形式化验证**：Agent行为的形式化验证，提供数学级别的安全保证。
5. **隐私保护监控**：差分隐私、联邦学习在Agent监控中的应用。

---

## 五、结论

代理式人工智能网络通信异常检测是一个快速发展的研究领域，涵盖了可观测性、数据保护、提示注入防护、多Agent通信安全、审计合规等多个维度。通过对50余个高质量开源项目的分析，我们发现：

1. **可观测性基础设施完善**：Langfuse、AgentOps、LiteLLM等工具提供了完整的Agent通信追踪能力。
2. **安全护栏日趋成熟**：NeMo Guardrails、LlamaFirewall等框架提供了可编程的安全控制能力。
3. **协议标准化推进**：A2A、MCP等协议为Agent间通信提供了互操作性和安全保障。
4. **红队测试工具化**：garak、PyRIT、ASB等工具支持系统化的安全评估。
5. **开源生态繁荣**：NVIDIA、Meta、Microsoft、Google等科技巨头积极参与，推动了技术的快速迭代。

对于研究者和工程实践者，建议根据具体场景需求选择合适的工具组合，并持续关注该领域的最新进展。

---

## 附录：附带论文/文章的项目列表

以下项目附带学术论文或详细技术文章，适合深入研究：

| 项目名称 | 论文/文章来源 | 主要贡献 |
|----------|--------------|----------|
| NeMo Guardrails | arXiv:2310.10501 | 可编程护栏框架，五种护栏类型 |
| Purple Llama | 多篇论文 | Llama Guard、Prompt Guard、LlamaFirewall |
| garak | garak-paper.pdf | LLM漏洞扫描方法论 |
| PyRIT | arXiv:2410.02828 | 生成式AI风险识别框架 |
| Agent Security Bench | ICLR 2025 | Agent安全基准测试方法论 |
| ZIRAN | 项目文档 | 知识图谱分析危险工具链 |
| LLM-IDS-Agent | 项目论文 | LLM驱动的网络入侵检测 |

---