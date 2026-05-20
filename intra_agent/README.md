# Intra-Agent 审计链路

该目录实现了单智能体审计链路：

1. `intra_analyzer.c`：从 `proc/fs/net` 事件提取异常候选（规则检测）。
2. `intra_audit.c`：对白名单/黑名单/灰名单进行判定。
3. 黑名单事件进入 LLM 复核（可选，`MONITOR_LLM_JUDGE_CMD`）。
4. 统一输出中文审计日志：`[请求][单体审计]` 与 `[告警][单体审计]`。
5. 运行中自动热重载规则文件（默认每 5 秒检查一次变更）。

## 文件作用说明

- `intra_agent/intra_analyzer.c`：单体行为检测核心。接收 `proc/fs/net` 事件，做规则判断（敏感路径、工作区越界、异常 shell、疑似循环），生成审计请求。
- `intra_agent/intra_analyzer.h`：`intra_analyzer` 对外接口声明（初始化与事件入口）。
- `intra_agent/intra_audit.c`：审计决策核心。对白/黑/灰分类，执行 LLM 复核，输出最终中文请求/告警日志，并支持规则热重载。
- `intra_agent/intra_audit.h`：审计请求结构体与审计模块接口声明。
- `intra_agent/audit_rules.conf`：审计规则配置文件（白名单路径、黑名单路径、规则分类、LLM 可抑制规则）。
- `intra_agent/llm_judge.sh`：LLM 复核脚本（当前接 DeepSeek），输入审计 prompt，输出 `CONFIRM/SUPPRESS/UNSURE`。
- `intra_agent/deepseek.env`：DeepSeek 私有配置（API Key、模型、可选 Base URL）。
- `intra_agent/run_demo.sh`：一键演示脚本（启动 monitor、触发用例、汇总请求/告警日志）。

## monitor 接入点（与 intra-agent 关联）

- `monitor/src/user/main.c`：初始化 `intra_init()`，启动整体事件循环。
- `monitor/src/user/proc_events.c`：接收进程事件并调用 `intra_on_proc_event()`。
- `monitor/src/user/fs_events.c`：接收文件事件并调用 `intra_on_fs_event()`。
- `monitor/src/user/net_events.c`：接收网络事件并调用 `intra_on_net_event()`。
- `monitor/src/ebpf/fs.bpf.c`：文件系统 eBPF 采集逻辑（含 `openat/openat2` 等），为文件类单体审计提供底层事件来源。

## 执行原则

- 审计链路始终执行，不提供“关闭审计”开关。
- 事件流必须经过 `intra_analyzer -> intra_audit`。
- LLM 仅用于复核，不替代本地审计策略。

## 环境变量

- `MONITOR_WORKSPACE`：工作区根目录，默认 `/mnt/e/os2026`
- `MONITOR_LLM_JUDGE_CMD`：LLM 判定命令。命令会接收一个参数（审计 prompt），并输出以下 token 之一：
  - `CONFIRM`
  - `SUPPRESS`
  - `UNSURE`
- `MONITOR_AUDIT_RULES`：审计规则配置文件路径；默认 `${MONITOR_WORKSPACE}/intra_agent/audit_rules.conf`

## 规则配置

默认配置文件：`intra_agent/audit_rules.conf`

支持键：

- `white_path_prefixes`：白名单路径前缀，逗号分隔
- `black_path_markers`：黑名单路径关键片段，逗号分隔
- `white_rules`：直接判白的规则名，逗号分隔
- `black_rules`：直接判黑的规则名，逗号分隔
- `gray_rules`：直接判灰的规则名，逗号分隔
- `llm_allow_suppress_rules`：允许被 LLM suppress 的规则名，逗号分隔（默认空）

## 热重载

- 无需重启 `monitor`。
- 修改 `audit_rules.conf` 并保存后，模块会自动检查并重载。
- 重载成功会打印 `RULES_RELOAD` 的 `[请求][单体审计]` 日志。

## 示例

```bash
export MONITOR_WORKSPACE=/mnt/e/os2026
export MONITOR_LLM_JUDGE_CMD="/mnt/e/os2026/intra_agent/llm_judge.sh"
export MONITOR_AUDIT_RULES="/mnt/e/os2026/intra_agent/audit_rules.conf"
cd /mnt/e/os2026/monitor
sudo ./monitor
```

## 一键演示

```bash
cd /mnt/e/os2026
./intra_agent/run_demo.sh
```

也可以直接整段 root 运行：

```bash
cd /mnt/e/os2026
sudo ./intra_agent/run_demo.sh
```

脚本会自动：

1. 启动 `monitor`
2. 构造 `claude` 相关进程
3. 触发敏感文件读取、越界写入、子 shell 启动
4. 汇总打印“请求/告警”关键日志



## DeepSeek 配置

- 脚本会优先读取 `intra_agent/deepseek.env`（已支持）
- 建议该文件权限为 `600`
- 可配置项：
  - `DEEPSEEK_API_KEY`
  - `DEEPSEEK_MODEL`（默认 `deepseek-chat`）
  - `DEEPSEEK_BASE_URL`（默认 `https://api.deepseek.com`）

## 安全默认策略

- 黑名单事件会进入 LLM 复核。
- 但默认情况下，黑名单事件的 `SUPPRESS` 会被策略阻断并告警（防止误抑制高危事件）。
- 若确实需要允许某些规则被 suppress，请在 `llm_allow_suppress_rules` 中显式配置。
- 当 `MONITOR_LLM_JUDGE_CMD` 未配置或调用失败时，黑名单事件走本地兜底策略并继续告警，不会静默放过。
