# LLM 审计模块说明

## 1. 模块定位

LLM 审计模块位于单体审计阶段，用于对高风险或语义型异常进行二次判断，提升误报抑制能力与语义解释能力。

整体位置：

```text
intra/inter analyzer -> AuditEngine -> LLM review -> audit result -> SQLite
```

## 2. 当前已完成内容

| 项 | 说明 |
| --- | --- |
| DeepSeek 接入 | `audit_engine.py` 已接入 DeepSeek Chat Completions API。 |
| 安全配置 | API Key 通过环境变量 `DEEPSEEK_API_KEY` 注入，不写入仓库。 |
| 结构化输出 | LLM 输出统一为 JSON，包含 `decision`、`risk_level`、`summary`、`reasoning`、`evidence`、`suggested_action`。 |
| 兜底策略 | 当 LLM 不可用、超时或返回异常时，系统退回规则兜底告警。 |
| 模板分流 | 不同异常类型进入不同审计模板，而不是共用单一提示词。 |

## 3. 审计流程

```text
规则命中 -> 分类为 WHITE / GRAY / BLACK ->
BLACK 事件进入 LLM 审计 ->
LLM 返回结构化结果 ->
生成 ALLOW / CORRELATE / ALERT / FORCE_ALERT
```

说明：

- `WHITE`：直接放行。
- `GRAY`：进入关联分析，不强依赖 LLM。
- `BLACK`：进入 LLM 审计，由模型做二次确认或抑制判断。

## 4. 当前模板划分

| 模板 | 代表规则 | 关注点 |
| --- | --- | --- |
| `sensitive_file` | `SENSITIVE_FILE_ACCESS` | 敏感文件、凭据、越权读取、后续外传风险 |
| `shell_exec` | `UNEXPECTED_SHELL_EXEC` | shell 执行、下载执行、提权、破坏性命令 |
| `workspace_violation` | `OUT_OF_WORKSPACE_OPERATION` | 工作区外访问、删除、覆盖、越界写入 |
| `prompt_injection_signal` | `PROMPT_INJECTION_SIGNAL` | 忽略指令、泄露秘密、上下文污染、外部恶意输入 |
| `prompt_injection_action` | `PROMPT_INJECTION_TO_DANGEROUS_ACTION` | 注入后触发 shell、文件、网络等危险动作 |
| `logic_loop` | `POSSIBLE_LOGIC_LOOP` | 高频重试、循环调用、短会话风暴、资源消耗 |
| `short_ssl_burst` | `FREQUENT_SHORT_SSL_SESSIONS` | 短 SSL 爆发、异常重试、探测式请求 |

## 5. Prompt Injection 模板强化

当前已对 Prompt Injection 两类异常做额外强化：

- 区分“仅有可疑文本”与“已驱动危险动作”
- 增加 `confirm_when` 与 `suppress_when` 条件
- 强调事件链判断：

```text
文本诱导 -> 工具调用 -> 危险动作
```

这使 LLM 可以更好地区分：

- 安全测试样本
- 普通文本分析任务
- 已经进入执行链路的真实注入攻击

## 6. 输出格式

LLM 返回示例：

```json
{
  "decision": "CONFIRM",
  "risk_level": "HIGH",
  "summary": "进程尝试访问敏感文件，符合高风险规则",
  "reasoning": "访问对象为系统敏感文件，且与当前任务无关，存在越权读取风险",
  "evidence": [
    "path=/etc/passwd",
    "rule=SENSITIVE_FILE_ACCESS"
  ],
  "suggested_action": "ALERT"
}
```

## 7. 当前验证结果

已完成的验证包括：

- DeepSeek API 实际调用成功
- `AuditEngine` 可解析结构化 JSON 结果
- 黑名单事件可触发 `LLM确认风险`
- 返回结果中已包含 `llm_review` 字段
- 不同规则可进入不同模板

## 8. 下一步工作

| 方向 | 说明 |
| --- | --- |
| 完整链路联调 | 验证真实事件经 Redis/analyzer 后落入 SQLite。 |
| 提示词继续细化 | 针对更多规则补充模板和判断条件。 |
| 结果展示优化 | 将 `llm_review` 做更方便查询与展示的持久化视图。 |
| 根因识别扩展 | 在 LLM 审计之上继续做根因总结与多事件语义缝合。 |
