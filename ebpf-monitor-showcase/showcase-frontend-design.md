# 基于 Assistant-UI 的 SQL Optimize 前端页面设计

> 为方便用户测试SQL 优化效果，我们采用Assistant-UI搭建前端，提供类似Chat-GPT风格的对话页面。用户可以在此网站页面上创建账户，加载配置数据库和模型，查看SQL的优化效果

## 概述

SQL Optimize 前端以 Assistant-UI 作为的 UI 框架，使用React + Next构建前端项目，实现从“输入 SQL → 后端执行优化 → 前端流式渲染”的流程。

## SQL优化页面

优化主页面由 `app/assistant.tsx` 的 `<Assistant />` 组件承载，核心运行方式如下：

- 运行时与传输

  - 使用 `AssistantRuntimeProvider` 提供 Assistant-UI 运行时。
  - 通过 `useChatRuntime` + `AssistantChatTransport` 指定后端入口为 `"/api/forward-chat"`。
  - 请求头按需注入 `Authorization: Bearer <token>`，Token 由 `getToken()` 从 `localStorage` 读取。
- 布局结构

  - 左侧：`<ThreadListSidebar />` 展示与管理对话列表（新建、归档、登录入口）。
  - 右侧：`<Thread />` 展示对话消息与输入区（Composer）。
  - 头部：`Shadcn` 组件与 `SidebarTrigger` 便于切换侧栏。
- 交互细节（`components/assistant-ui/thread.tsx`）

  - 空态欢迎：根据时间段动态问候，展示示例建议；点击建议会填充并自动发送。
  - 消息区：
    - 用户消息（UserMessage）与助手消息（AssistantMessage）分开渲染。
    - 助手消息支持复制、刷新；用户消息支持编辑并“更新”。
    - 分支回溯（BranchPicker）：在多分支回复时可切换历史分支。
  - 输入器（Composer）：
    - 支持附件（图片/文件）添加、预览与移除。
    - 生成中可一键“停止”；底部提供“滚动到底部”快速回到最新回复。
  - Markdown 渲染（`MarkdownText`）：启用 GFM，代码块带“复制”按钮与样式化标题栏。
- 鉴权与错误回退

  - 全局 `GlobalAuthFetch`：任何前端请求若收到 401/403，则清理本地登录态（`SQLopt.auth` 与 `SQLOPT_SERVICE_TOKEN`）。
  - 消息级错误以红色提示框展示（`MessageError`）。
  - 侧栏 `LoginModal` 负责登录/注册/登出；登录成功后 Token 会被持久化，随即影响后续请求头注入。

## 其他功能（含接口封装）

围绕使用端需求，提供以下功能模块；每个功能都集成了对应的接口封装与本地持久化策略。

### 登录 / 注册 / 登出

- 入口组件：`components/assistant-ui/login-modal.tsx`（在侧栏底部触发）。
- 接口封装：`lib/auth/authService.ts`
  - `registerUser(payload)` → POST `${NEXT_PUBLIC_API_BASE}/api/auth/register`
  - `loginUser(payload)` → POST `${NEXT_PUBLIC_API_BASE}/api/auth/login`
  - 成功后 `saveAuth()` 将 Token 同步保存到 `SQLopt.auth` 与 `SQLOPT_SERVICE_TOKEN`，供传输层读取。
- 统一失败处理：
  - `components/GlobalAuthFetch.tsx` 拦截所有前端 `fetch` 的 401/403 并执行 `clearAuth()`；
  - `lib/auth/authFetch.ts` 的 `fetchWithAuth()` 也会在 401/403 触发登出（可通过 `autoLogout` 关闭）。

### 模型切换（LLM 连接）

- UI 集成：可放在顶部或侧栏的选择器（自定义实现），数据由 service 提供。
- 数据与接口：`lib/model/*`
  - 列表与活跃态：`modelApi.list()`、`modelApi.getActive()`、`modelApi.setActive()`（路径前缀 `${NEXT_PUBLIC_SQLOPT_SERVICE_URL}/api/models/*`）。
  - 本地状态：`modelService.init()/refresh()/select(id)`；`selectedId` 会持久化到 `localStorage(SELECTED_MODEL_ID)`，并尽量与后端 active 对齐。
- 典型交互：初始化时读取后端 active → 若无则用本地/首项 → 用户切换时调用 `setActive` 并更新本地。

### 数据库切换（连接）

- 数据与接口：`lib/database/*`
  - 列表与活跃态：`databaseApi.list()`、`databaseApi.getActive()`、`databaseApi.setActive()`（`${NEXT_PUBLIC_SQLOPT_SERVICE_URL}/api/databases/*`）。
  - 本地状态：`databaseService.init()/refresh()/select(id)`；选择持久化到 `localStorage(SELECTED_DB_ID)`。
- 注意事项：切换数据库后，模型/模式等上下文可能需要重新加载（按需调用对应 service 的 `refresh`）。

### 模式切换（数据库模式 Schema）

- 数据与接口：`lib/schema/*`
  - 列表与活跃态：`schemaApi.list()`、`schemaApi.getActive()`、`schemaApi.setActive()`（`${NEXT_PUBLIC_SQLOPT_SERVICE_URL}/api/schemas/*`）。
  - 本地状态：`schemaService.init()/refresh()/select(id)`；选择持久化到 `localStorage(SELECTED_SCHEMA_ID)`。
- 使用方式：在 SQL 优化前选择合适的 Schema，便于后端进行更准确的分析与改写。

### 对话切换与新建

- UI 组件：
  - `components/assistant-ui/thread-list.tsx` 的 `ThreadList` 提供“新建对话”“归档”等基础交互；
  - `components/assistant-ui/threadlist-sidebar.tsx` 将 `ThreadList` 放入侧栏，并附带登录入口。
- 运行机制：
  - 会话管理由 Assistant-UI 的 `ThreadListPrimitive`/`ThreadPrimitive` 在前端内存管理；当前实现未持久化到后端。
  - 若需要云端持久化，可在此基础上对接自有存储（例如在 `ThreadList` 的事件回调里调用后端接口保存/加载会话）。

### SQL 优化请求（对话消息 → 后端优化）

- 统一入口：`app/api/forward-chat/route.ts`
  - 解析并校验来自 Assistant-UI 的 `messages`，仅提取必要字段转发到后端 `/api/optimize`；
  - 将后端的 SSE/NDJSON 转换为 Assistant-UI 事件流（`text-delta` 等）返回给前端；
  - 401/403 直接以 JSON 错误透传（触发登出），其它错误以标准错误流返回。
- 辅助工具：`app/api/forward-chat/externalPayload.ts`
  - `buildOptimizeRequestPayload()`、`toAssistantUIResponse()`、`createAssistantUIErrorStream()` 等。
