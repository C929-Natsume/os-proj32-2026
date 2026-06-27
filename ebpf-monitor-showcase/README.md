# CoreSight

CoreSight 是一个用于展示 eBPF 多智能体监控项目的独立 Next.js 展示系统。

## 项目用途

本项目用于比赛演示和项目展示，主要覆盖：

- 系统架构展示
- 实时告警与审计结果展示
- LLM 审计结果展示
- Benchmark 对比展示
- 从主监控项目 SQLite 数据库读取真实监控数据

## 技术栈

- Next.js 15
- React 19
- Tailwind CSS 4
- Radix UI
- Lucide Icons
- Framer Motion

## 前后端说明

本项目的前端和后端都集成在同一个 Next.js 项目中：

- 前端：浏览器中的展示页面
- 后端：Next.js API Routes，位于 `app/api/*`

因此，展示系统不需要单独启动 FastAPI 或 Flask 服务。

展示系统后端会读取主监控项目中的真实数据：

```text
/mnt/e/os2026/ebpf-multi-agent-monitor/logs/alerts/analysis.db
```

同时会读取主监控项目中的 LLM 配置：

```text
/mnt/e/os2026/ebpf-multi-agent-monitor/src/config/app_config.yaml
```

## 开发模式启动

如果依赖还没有安装，先执行：

```bash
cd /mnt/e/os2026/ebpf-monitor-showcase
npm install
```

启动集成的前端和后端：

```bash
cd /mnt/e/os2026/ebpf-monitor-showcase
npm run dev
```

说明：

- 默认 `dev` 已启用轮询监听，适合 `/mnt/e/...` 这类挂载目录，代码修改后刷新页面即可看到更新。
- 这次改完脚本后，需要先手动重启一次 `npm run dev`，之后才会按新的热重载方式工作。

浏览器访问：

```text
http://127.0.0.1:3000
```

如果 `3000` 端口已经被占用，可以指定其他端口：

```bash
cd /mnt/e/os2026/ebpf-monitor-showcase
PORT=3001 npm run dev
```

浏览器访问：

```text
http://127.0.0.1:3001
```

## 接口检查

健康检查：

```bash
curl http://127.0.0.1:3000/api/health
```

模型配置：

```bash
curl http://127.0.0.1:3000/api/models
```

概览数据：

```bash
curl http://127.0.0.1:3000/api/overview
```

异常列表：

```bash
curl http://127.0.0.1:3000/api/anomalies
```

## 生产模式启动

```bash
cd /mnt/e/os2026/ebpf-monitor-showcase
npm run build
npm run start
```

## 注意事项

- 当前目录已经与原 SQL 项目的 Git 历史解耦。
- 展示系统本身是一个独立的 Next.js 应用，但会读取主监控项目中的真实数据。
- 如果需要展示最新监控结果，需要先更新主监控项目中的 `analysis.db`。
