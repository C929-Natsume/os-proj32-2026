# 监测进程与执行引起的异常模式——研究综述（2023-2026）

## 一、研究背景与核心问题

### 1.1 研究背景

进程是操作系统资源分配和调度的基本单位，几乎所有恶意活动和安全事件最终都会体现为进程层面的异常行为。从传统的恶意软件执行、权限提升，到现代的容器逃逸、进程注入、Living-off-the-Land（LotL）攻击，进程行为异常检测一直是网络安全和系统运维的核心议题。

近三年来，随着eBPF（Extended Berkeley Packet Filter）技术的成熟和普及，进程监控领域发生了革命性变化。eBPF允许在内核空间安全地运行自定义程序，实现了低开销、高可见性、无侵入的进程行为监控。同时，云原生环境的普及也推动了容器进程安全监控的快速发展。

### 1.2 核心问题分类

#### 1.2.1 恶意进程执行检测（Malicious Process Execution Detection）

**问题描述：**
- 未知/可疑进程的启动和执行
- 恶意软件在内存中的解密和执行
- 无文件攻击（Fileless Malware）：直接在内存中执行恶意代码
- LotL攻击：利用系统自带工具（PowerShell、WMI、cmd）执行恶意操作
- 加壳/混淆恶意软件的动态分析

**研究关注点：**
- 如何在进程执行的第一时间检测恶意行为
- 如何处理加壳和混淆的恶意软件
- 如何区分合法系统工具的正常使用和恶意滥用

#### 1.2.2 进程注入与隐藏检测（Process Injection & Concealment Detection）

**问题描述：**
- DLL注入：将恶意DLL注入到合法进程中
- 进程挖空（Process Hollowing）：替换合法进程的内存映像
- APC注入：通过异步过程调用注入代码
- 反射式DLL注入：无需LoadLibrary的内存注入
- Rootkit隐藏进程：通过Hook系统调用隐藏恶意进程

**研究关注点：**
- 如何检测各种进程注入技术
- 如何发现被Rootkit隐藏的进程
- 如何对比不同数据源（VAD vs PEB）发现不一致

#### 1.2.3 容器与云原生进程安全（Container & Cloud-Native Process Security）

**问题描述：**
- 容器逃逸：从容器内获取宿主机权限
- 特权容器滥用：以特权模式运行容器访问宿主机资源
- 异常进程树：容器内出现不符合预期的父子进程关系
- Kubernetes Pod内的横向移动

**研究关注点：**
- 如何在容器环境中实现细粒度的进程监控
- 如何将进程事件与Kubernetes元数据关联
- 如何检测容器逃逸行为

#### 1.2.4 系统调用异常检测（System Call Anomaly Detection）

**问题描述：**
- 异常的系统调用序列：偏离正常行为的syscall模式
- 异常的系统调用参数：可疑的参数值
- 高频系统调用：异常的系统调用频率
- 特权系统调用滥用：mount、setuid、ptrace等敏感调用的滥用

**研究关注点：**
- 如何建立正常系统调用行为的基线
- 如何在保证低延迟的前提下实现实时检测
- 如何处理系统调用序列的上下文依赖

#### 1.2.5 进程资源与行为异常（Process Resource & Behavioral Anomaly）

**问题描述：**
- CPU/内存/I/O资源异常消耗
- 僵尸进程和孤儿进程
- 异常的网络连接行为（进程发起的可疑外连）
- 进程间通信异常（IPC、Pipe、共享内存）

**研究关注点：**
- 如何区分正常负载峰值和恶意资源消耗
- 如何建立进程行为的正常基线
- 如何实现多维度的关联分析

---

## 二、主要解决方案与技术洞察

### 2.1 基于eBPF的内核级进程监控

**核心洞察：** eBPF技术允许在内核空间安全地运行自定义监控程序，实现零侵入、低开销的进程行为监控，是当前进程异常检测的主流技术方向。

**技术方案：**

1. **BCC - BPF Compiler Collection（IOVisor, 2023-2025）**
   - eBPF领域最经典的工具包，22,000+ Stars
   - 包含execsnoop（进程执行追踪）、exitsnoop（进程退出）、killsnoop（信号追踪）、opensnoop（文件打开追踪）等
   - **Insight：** 提供模块化的单功能工具，每个工具专注一种事件类型，通过管道组合实现复杂的监控逻辑

2. **eCapture - 旁观者（gojue, 2023-2025）**
   - 基于eBPF uprobe技术，14,700+ Stars
   - 无需CA证书捕获SSL/TLS明文通信
   - Bash/Zsh命令审计、MySQL/PostgreSQL查询审计
   - **Insight：** 通过uprobe（用户空间探针）而非kprobe监控用户态程序，实现了对加密通信的透明解密，解决了恶意进程使用加密通道的检测难题

3. **Tracee（Aqua Security, 2023-2025）**
   - eBPF运行时安全与取证工具，4,000+ Stars
   - 内置丰富的检测签名，覆盖进程注入、反调试、容器逃逸等
   - 事件引擎从底层事实事件到高级安全事件的分层架构
   - **Insight：** 将原始eBPF事件抽象为分层的安全事件模型，使安全分析人员可以直接使用高层语义事件而非底层系统调用

4. **Tetragon（Cilium/Isovalent, 2023-2025）**
   - eBPF安全可观测性与执行策略引擎，4,300+ Stars
   - 默认生成process_exec和process_exit事件
   - TracingPolicy机制定义细粒度的异常检测规则
   - **Insight：** 将安全策略与Kubernetes身份信息关联，实现了基于身份的进程行为控制，而非仅基于IP/端口

5. **Falco（Falco Security/CNCF, 2023-2025）**
   - CNCF毕业项目，云原生运行时安全工具，8,700+ Stars
   - 基于自定义规则实时检测系统调用异常
   - 支持容器运行时和Kubernetes元数据集成
   - **Insight：** 通过声明式规则语言将安全知识编码为检测规则，使安全团队无需编程即可定义检测策略

### 2.2 内存取证与进程注入检测

**核心洞察：** 进程注入和Rootkit技术最终都会在内存中留下痕迹，内存取证是检测这些高级威胁的最有效手段。

**技术方案：**

1. **Volatility 3（Volatility Foundation, 2023-2026）**
   - 全球最广泛使用的内存取证框架，9,300+ Stars
   - 从RAM样本中提取进程、网络连接、加载模块等
   - 内置hollowprocesses、malfind等恶意软件检测插件
   - **Insight：** 通过分析物理内存而非依赖操作系统API，可以发现Rootkit隐藏的进程和被注入的代码

2. **PE-sieve（hasherezade, 2023-2025）**
   - 轻量级进程内存扫描引擎，3,500+ Stars
   - 检测进程中的替换PE、shellcode、hooks、内存补丁
   - 支持Process Hollowing、Process Doppelgang-ing、Reflective DLL Injection等
   - **Insight：** 通过对比VAD（Virtual Address Descriptor）和PEB（Process Environment Block）中的模块信息发现不一致，这是检测进程注入的核心技术

3. **Hollows Hunter（hasherezade, 2023-2025）**
   - 基于PE-sieve的全系统进程注入扫描工具，2,300+ Stars
   - 批量扫描所有运行中的进程
   - 支持ETW事件监听模式实现实时检测
   - **Insight：** 将单进程的内存扫描扩展到全系统批量扫描，并通过ETW实现事件驱动的实时监控

4. **Qiling Framework（2023-2025）**
   - 高级二进制仿真框架，5,700+ Stars
   - 支持多平台（Windows/Linux/macOS/Android/UEFI）和多架构
   - 指令级/内存级/系统调用级的细粒度插桩
   - **Insight：** 通过仿真技术在隔离环境中动态分析恶意进程行为，避免了真实系统被感染的风险

### 2.3 Rootkit检测与反分析

**核心洞察：** Rootkit通过修改操作系统内核或用户态API来隐藏自身，检测需要从多个数据源交叉验证。

**技术方案：**

1. **OpenArk（BlackINT3, 2023-2025）**
   - 下一代Windows反Rootkit工具，11,900+ Stars
   - 进程管理、内核分析（内存、驱动、回调、过滤器）
   - DLL注入/卸载、内存扫描、PPL支持
   - **Insight：** 提供从用户态到内核态的全栈分析能力，通过对比不同数据源发现Rootkit的隐藏行为

2. **Unhide（YJesus, 2023-2025）**
   - 发现被隐藏的进程和端口，185+ Stars
   - 六种检测技术：对比/proc与/bin/ps、系统调用扫描、PID暴力枚举等
   - **Insight：** 通过多种独立技术的交叉验证提高检测准确性，单一技术可能被Rootkit绕过，但多种技术同时被绕过的概率极低

3. **RkHunter（2023-2025）**
   - POSIX系统Rootkit检测工具，2,200+ Stars
   - SHA256哈希校验、文件权限检查、内核模块可疑字符串扫描
   - **Insight：** 通过文件完整性校验和已知特征匹配检测Rootkit，适合作为定期扫描的补充手段

### 2.4 系统调用审计与结构化分析

**核心洞察：** Linux Audit框架提供了最基础的系统调用审计能力，但原始日志格式不利于分析，需要结构化处理。

**技术方案：**

1. **Linux Audit（audit-userspace, 2023-2025）**
   - Linux审计系统的官方用户空间实现，666+ Stars
   - 通过拦截系统调用并序列化审计日志
   - 满足Common Criteria、PCI-DSS等安全标准
   - **Insight：** 作为操作系统内核的一部分，审计框架具有最高的可靠性和最完整的系统调用覆盖

2. **LAUREL（ThreatHunters.io, 2023-2025）**
   - auditd事件后处理插件，798+ Stars
   - 将原始审计日志转换为结构化JSON
   - 自动解码十六进制编码的EXECVE参数
   - **Insight：** 通过结构化和丰富化处理，将难以分析的原始审计日志转换为安全分析人员可直接使用的结构化数据

3. **Sysmon for Linux（Microsoft, 2023-2025）**
   - Sysinternals Sysmon的Linux版本，1,900+ Stars
   - 基于eBPF收集进程生命周期、网络连接、文件写入等事件
   - 事件格式与MITRE ATT&CK框架高度契合
   - **Insight：** 将Windows生态成熟的Sysmon事件模型引入Linux，实现了跨平台的统一进程事件格式

### 2.5 端点检测与响应（EDR）

**核心洞察：** 现代EDR平台需要整合进程监控、文件完整性、网络分析、日志审计等多维度数据，实现关联分析。

**技术方案：**

1. **Wazuh（2023-2026）**
   - 开源SIEM+EDR平台，10,000+ Stars
   - Rootkit检测、隐藏进程检测、异常系统调用响应检测
   - 日志分析、漏洞检测、合规性管理
   - **Insight：** 将进程监控与其他安全数据源（日志、文件、网络）关联分析，通过多维度关联提高检测精度

2. **osquery + Fleet（Meta/Fleetdm, 2023-2025）**
   - osquery：SQL驱动OS检测框架，22,600+ Stars
   - Fleet：集中式osquery管理平台，5,700+ Stars
   - 通过SQL查询进程、内核模块、网络连接等
   - **Insight：** 将操作系统状态抽象为关系数据库，使安全检测从"编写脚本"变为"编写SQL查询"，大幅降低了使用门槛

3. **Velociraptor（Velocidex, 2023-2026）**
   - 端点可见性与事件响应工具，3,500+ Stars
   - VQL查询语言定义和收集端点数据
   - 丰富的预构建Artifact生态系统
   - **Insight：** 通过自定义查询语言（VQL）实现了灵活的端点数据收集，使取证人员可以快速编写自定义收集逻辑

4. **GRR Rapid Response（Google, 2023-2025）**
   - 远程实时取证框架，4,900+ Stars
   - 远程进程列举、网络连接监控、内存分析
   - Python客户端+服务器端基础设施
   - **Insight：** 将取证能力从"离线分析"推进到"在线实时响应"，支持远程浏览文件系统和收集进程信息

### 2.6 反分析技术检测

**核心洞察：** 了解恶意软件使用的反分析技术，有助于构建更有效的分析环境。

**技术方案：**

1. **al-khaser（2023-2025）**
   - 最全面的恶意软件反分析技术PoC集合，6,400+ Stars
   - 涵盖反调试、反虚拟机、反沙箱、反注入、反转储等
   - **Insight：** 通过系统化收集反分析技术，帮助安全研究人员构建更隐蔽的分析环境

---

## 三、技术趋势与未来方向

### 3.1 主要趋势

1. **eBPF成为主流**：BCC、Tracee、Tetragon、Falco、Sysmon for Linux等核心工具均基于eBPF，体现了eBPF在进程监控领域的主导地位

2. **从检测到响应**：从单纯的异常检测向"检测+响应+取证"全流程演进，如Tetragon支持实时执行策略

3. **云原生适配**：Falco、Tracee、Tetragon等原生支持Kubernetes和容器环境

4. **声明式规则**：Falco的规则语言、Tetragon的TracingPolicy等使安全策略声明式化

5. **跨平台统一**：Sysmon for Linux将Windows生态的事件模型引入Linux

### 3.2 未来研究方向

1. **AI驱动的异常检测**：利用机器学习分析系统调用序列，自动发现未知攻击模式

2. **eBPF + LLM**：结合大语言模型的语义理解能力和eBPF的底层可见性

3. **零信任进程执行**：基于持续验证的进程执行控制

4. **联邦学习**：在保护隐私的前提下跨组织共享进程行为威胁情报

---

## 四、参考文献（50篇）

> **说明：** 以下所有项目均为真实存在的开源项目，GitHub链接已验证。Star数量基于2025-2026年的搜索结果，标记"~"为近似值。

### 4.1 eBPF进程监控工具

| 序号 | 项目名称 | 组织 | GitHub Stars | 主要功能 | 链接 |
|------|----------|------|--------------|----------|------|
| 1 | **BCC** | IOVisor | ~22,000 | eBPF工具集，execsnoop/exitsnoop/opensnoop等进程监控工具 | https://github.com/iovisor/bcc |
| 2 | **eCapture** | gojue | ~14,700 | eBPF uprobe，TLS明文捕获，Bash/Zsh命令审计 | https://github.com/gojue/ecapture |
| 3 | **bpftrace** | IOVisor | ~7,600 | 高级eBPF追踪语言，自定义进程监控脚本 | https://github.com/iovisor/bpftrace |
| 4 | **libbpf** | libbpf | ~2,500 | eBPF C库，BPF CO-RE基础库 | https://github.com/libbpf/libbpf |

### 4.2 容器与云原生运行时安全

| 序号 | 项目名称 | 组织 | GitHub Stars | 主要功能 | 链接 |
|------|----------|------|--------------|----------|------|
| 5 | **Falco** | Falco Security / CNCF | ~8,700 | 云原生运行时安全，系统调用规则驱动异常检测 | https://github.com/falcosecurity/falco |
| 6 | **Tetragon** | Cilium / Isovalent | ~4,300 | eBPF安全可观测性引擎，TracingPolicy进程执行策略 | https://github.com/cilium/tetragon |
| 7 | **Tracee** | Aqua Security | ~4,000 | eBPF运行时安全与取证，内置检测签名 | https://github.com/aquasecurity/tracee |
| 8 | **ThreatMapper** | Deepfence | ~5,200 | 云原生应用保护平台，运行时威胁管理 | https://github.com/deepfence/ThreatMapper |

### 4.3 内存取证与进程注入检测

| 序号 | 项目名称 | 组织 | GitHub Stars | 主要功能 | 链接 |
|------|----------|------|--------------|----------|------|
| 9 | **Volatility 3** | Volatility Foundation | ~9,300 | 内存取证框架，进程分析/网络连接/恶意软件检测 | https://github.com/volatilityfoundation/volatility3 |
| 10 | **PE-sieve** | hasherezade | ~3,500 | 进程内存扫描引擎，检测注入PE/shellcode/hooks | https://github.com/hasherezade/pe-sieve |
| 11 | **Hollows Hunter** | hasherezade | ~2,300 | 全系统进程注入扫描，ETW实时监听 | https://github.com/hasherezade/hollows_hunter |
| 12 | **MalUnpack** | hasherezade | ~500+ | 动态脱壳工具，运行时内存监控 | https://github.com/hasherezade/mal_unpack |
| 13 | **Qiling Framework** | Qiling | ~5,700 | 二进制仿真框架，恶意软件动态行为分析 | https://github.com/qilingframework/qiling |

### 4.4 Rootkit检测与反分析

| 序号 | 项目名称 | 组织 | GitHub Stars | 主要功能 | 链接 |
|------|----------|------|--------------|----------|------|
| 14 | **OpenArk** | BlackINT3 | ~11,900 | Windows反Rootkit工具，内核分析/进程管理/DLL注入 | https://github.com/BlackINT3/OpenArk |
| 15 | **al-khaser** | ayoubfaouzi | ~6,400 | 恶意软件反分析技术PoC集合 | https://github.com/ayoubfaouzi/al-khaser |
| 16 | **Pafish** | a0rtega | ~3,800 | 虚拟机和分析环境检测测试工具 | https://github.com/a0rtega/pafish |
| 17 | **RkHunter** | Rootkit-Hunter | ~2,200 | POSIX Rootkit检测，哈希校验/隐藏文件检测 | https://github.com/Rootkit-Hunter/rkhunter |
| 18 | **Unhide** | YJesus | ~185 | 隐藏进程和端口检测，六种检测技术 | https://github.com/YJesus/Unhide |
| 19 | **GoDefender** | KiExitDispatcher | ~200+ | Go安全工具包，反VM/反调试/反注入 | https://github.com/KiExitDispatcher/GoDefender |
| 20 | **mabj/anti** | mabj | ~100+ | 72种真实恶意软件反分析技术PoC | https://github.com/mabj/anti |

### 4.5 系统调用审计与结构化分析

| 序号 | 项目名称 | 组织 | GitHub Stars | 主要功能 | 链接 |
|------|----------|------|--------------|----------|------|
| 21 | **Sysmon for Linux** | Microsoft | ~1,900 | Sysmon Linux版，eBPF进程/网络/文件事件监控 | https://github.com/microsoft/SysmonForLinux |
| 22 | **LAUREL** | ThreatHunters.io | ~798 | auditd事件后处理，结构化JSON输出 | https://github.com/threathunters-io/laurel |
| 23 | **audit-userspace** | Linux Audit Project | ~666 | Linux审计系统官方实现 | https://github.com/linux-audit/audit-userspace |

### 4.6 端点检测与响应（EDR）

| 序号 | 项目名称 | 组织 | GitHub Stars | 主要功能 | 链接 |
|------|----------|------|--------------|----------|------|
| 24 | **osquery** | Meta (Facebook) | ~22,600 | SQL驱动OS检测框架，进程/内核/网络查询 | https://github.com/osquery/osquery |
| 25 | **Wazuh** | Wazuh Inc. | ~10,000+ | SIEM+EDR平台，rootkit检测/入侵检测/漏洞检测 | https://github.com/wazuh/wazuh |
| 26 | **Fleet** | Fleetdm | ~5,700 | osquery集中管理平台，检测工程/CIS基准 | https://github.com/fleetdm/fleet |
| 27 | **GRR Rapid Response** | Google | ~4,900 | 远程实时取证框架，远程进程/内存分析 | https://github.com/google/grr |
| 28 | **Velociraptor** | Velocidex | ~3,500+ | 端点可见性工具，VQL查询语言 | https://github.com/Velocidex/velociraptor |

### 4.7 进程行为基线与检测工程

| 序号 | 项目名称 | 组织 | GitHub Stars | 主要功能 | 链接 |
|------|----------|------|--------------|----------|------|
| 29 | **osquery-defense-kit** | Chainguard | ~500+ | 生产级osquery检测查询集 | https://github.com/chainguard-dev/osquery-defense-kit |
| 30 | **Sigma** | SigmaHQ | ~8,500 | 通用SIEM签名格式，3000+检测规则 | https://github.com/SigmaHQ/sigma |
| 31 | **Elastic Detection Rules** | Elastic | ~2,400 | Elastic Security检测规则 | https://github.com/elastic/detection-rules |
| 32 | **Zircolite** | wagga40 | ~750 | 独立SIGMA检测工具，支持Auditd/Sysmon日志 | https://github.com/wagga40/Zircolite |
| 33 | **sysmon-ai** | oashraff | ~100+ | AI异常检测系统监控，资源预测 | https://github.com/oashraff/sysmon-ai |

### 4.8 进程树分析与取证

| 序号 | 项目名称 | 组织 | GitHub Stars | 主要功能 | 链接 |
|------|----------|------|--------------|----------|------|
| 34 | **process-forest** | williballenthin | ~147 | 从EVTX重建历史进程层次结构 | https://github.com/williballenthin/process-forest |
| 35 | **HistoricProcessTree** | IllusiveNetworks-Labs | ~100+ | Windows安全事件日志进程树可视化 | https://github.com/IllusiveNetworks-Labs/HistoricProcessTree |
| 36 | **BPFView** | jnesss | ~34 | eBPF进程与网络活动关联，Sigma规则匹配 | https://github.com/jnesss/bpfview |

### 4.9 Volatility插件（进程注入检测）

| 序号 | 项目名称 | 组织 | GitHub Stars | 主要功能 | 链接 |
|------|----------|------|--------------|----------|------|
| 37 | **HollowFind** | monnappa22 | ~142 | Volatility插件，进程挖空检测 | https://github.com/monnappa22/HollowFind |
| 38 | **ProcInjectionsFind** | darshantank | ~50+ | Volatility插件，8种进程注入检测 | https://github.com/darshantank/ProcInjectionsFind |

### 4.10 综合安全平台与资源

| 序号 | 项目名称 | 组织 | GitHub Stars | 主要功能 | 链接 |
|------|----------|------|--------------|----------|------|
| 39 | **OSSEC HIDS** | OSSEC Community | ~4,800 | 开源HIDS，日志分析/FIM/rootkit检测 | https://github.com/ossec/ossec-hids |
| 40 | **Fail2ban** | Fail2ban Community | ~16,700 | 入侵防御框架，异常登录进程检测 | https://github.com/fail2ban/fail2ban |
| 41 | **Suricata** | OISF | ~5,800 | 网络IDS/IPS，文件提取/进程检测 | https://github.com/OISF/suricata |
| 42 | **Zeek** | Zeek Project | ~7,500 | 网络流量分析，进程网络行为检测 | https://github.com/zeek/zeek |
| 43 | **Arkime** | Arkime Community | ~7,300 | 全包捕获和索引，网络文件提取 | https://github.com/arkime/arkime |
| 44 | **YARA** | VirusTotal | ~7,900 | 模式匹配引擎，恶意进程特征描述 | https://github.com/VirusTotal/yara |
| 45 | **ClamAV** | Cisco Talos | ~5,400 | 开源杀毒引擎，恶意进程检测 | https://github.com/Cisco-Talos/clamav |
| 46 | **Loki** | Neo23x0 | ~3,700 | IOC/YARA扫描器，进程异常检查 | https://github.com/Neo23x0/Loki |
| 47 | **chkrootkit** | scorpiondefense | ~200+ | 本地rootkit检测，隐藏进程/目录 | https://github.com/scorpiondefense/chkrootkit |
| 48 | **linuxprivchecker** | sleventyeleven | ~1,500 | Linux特权提升检查 | https://github.com/sleventyeleven/linuxprivchecker |
| 49 | **OpenDR** | opendr-io | ~50+ | Python EDR替代方案，进程行为监控 | https://github.com/opendr-io/opendr |
| 50 | **awesome-ebpf** | zoidbergwill | ~200+ | eBPF工具和资源精选列表 | https://github.com/zoidbergwill/awesome-ebpf |

---

## 五、总结

进程与执行异常模式监测是一个涵盖内核安全、恶意软件分析、云原生安全、内存取证等多个领域的综合性研究方向。近三年的研究呈现出以下特点：

1. **eBPF成为绝对主流**：排名前列的项目中，绝大多数直接基于eBPF技术。eBPF以其低开销、高可见性、安全性的优势，已成为进程监控的事实标准技术

2. **分层事件模型**：从原始系统调用（BCC）到结构化事件（LAUREL）再到安全语义事件（Tracee/Falco），形成了清晰的事件抽象层次

3. **从单点到平台**：从单一功能的监控工具（execsnoop）向集成平台（Wazuh、ThreatMapper）演进

4. **内存取证不可替代**：Volatility 3、PE-sieve等项目证明了内存分析在检测进程注入和Rootkit方面的不可替代性

5. **声明式安全策略**：Falco规则、Tetragon TracingPolicy、Sigma规则等使安全知识可编码、可共享、可版本控制

6. **CNCF生态推动标准化**：Falco（CNCF毕业）和Tetragon（CNCF项目）代表了云原生进程安全监控的最佳实践
