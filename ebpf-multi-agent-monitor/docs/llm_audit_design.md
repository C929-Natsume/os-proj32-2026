# LLM 审计模块说明

## 1. 模块定位

LLM 审计模块位于单体审计阶段，对高风险和语义型异常进行二次判断，用于降低误报并补充语义解释。

```text
intra/inter analyzer -> AuditEngine -> LLM review -> audit result -> SQLite
```

## 2. 已完成能力

- 已接入 DeepSeek Chat Completions API。
- API Key 通过环境变量 `DEEPSEEK_API_KEY` 注入，不写入仓库。
- LLM 输出统一为结构化 JSON，包含 `decision`、`risk_level`、`summary`、`reasoning`、`evidence`、`suggested_action`。
- LLM 超时、异常或不可用时自动回退到规则兜底。
- 不同异常进入不同审计模板，不使用单一提示词。

## 3. 审计流程

```text
规则命中 -> WHITE / GRAY / BLACK 分类 -> BLACK 进入 LLM 审计 -> 返回结构化结果 -> 生成审计动作
```

- `WHITE`：直接放行
- `GRAY`：进入关联分析
- `BLACK`：进入 LLM 二次审计

## 4. 五类异常与模板映射

项目层面保持 5 类顶层异常；实现层面使用 8 个业务模板，另有 `generic`、`generic_black` 作为兜底模板。

| 异常大类 | 代表规则 | 审计模板 |
| --- | --- | --- |
| 文件与资源访问异常 | `SENSITIVE_FILE_ACCESS`、`OUT_OF_WORKSPACE_OPERATION` | `sensitive_file`、`workspace_violation` |
| 命令与执行异常 | `UNEXPECTED_SHELL_EXEC` | `shell_exec` |
| 提示注入异常 | `PROMPT_INJECTION_SIGNAL`、`PROMPT_INJECTION_TO_DANGEROUS_ACTION` | `prompt_injection_signal`、`prompt_injection_action` |
| 流程与控制异常 | `POSSIBLE_LOGIC_LOOP`、`TASK_SPEC_VIOLATION`、`ROLE_SPEC_VIOLATION`、`STEP_REPETITION`、`CONTEXT_LOSS`、`TERMINATION_FAILURE` | `logic_loop`、`task_control` |
| 网络与通信异常 | `FREQUENT_SHORT_SSL_SESSIONS` | `short_ssl_burst` |

新增的 5 个规则没有扩成第六类，而是并入“流程与控制异常”：

- `TASK_SPEC_VIOLATION` / `ROLE_SPEC_VIOLATION` / `CONTEXT_LOSS` -> `task_control`
- `STEP_REPETITION` / `TERMINATION_FAILURE` -> `logic_loop`

这样既保留了规则粒度，便于 benchmark 和统计，也控制了模板数量，便于维护。

## 5. 输出格式

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

## 6. 当前结论

- LLM 审计接入已完成。
- 新增 5 个流程控制类规则已完成。
- `rules.yaml`、`audit_engine.py`、设计文档已对齐。
- `AuditEngine` 可正常返回 `llm_review` 结构化结果。
- 黑名单事件可完成真实 LLM 二次确认。

## 7. 后续重点

- 完整链路联调：验证真实事件从 analyzer 到 SQLite 的全流程落库。
- benchmark：对比 baseline 与当前 LLM 审计架构的误报率、命中率和解释能力。
- 展示优化：将 `llm_review` 结果做前端可视化展示。
