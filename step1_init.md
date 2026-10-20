```txt
ebpf-multi-agent-monitor/
├── src/
│   ├── bpf/                           # eBPF 内核态程序 (基于 libbpf)
│   │   ├── vmlinux.h                  # bpftool 生成的内核数据结构头文件
│   │   ├── sys_behavior.bpf.c         # kprobes/tracepoints 监控 execve, fork, open, unlink, connect 等
│   │   ├── ssl_sniffer.bpf.c          # uprobes 监控 OpenSSL (SSL_read/SSL_write) 提取明文
│   │   └── common.h                   # BPF 程序与用户态共享的结构体定义 (如事件 event 结构)
│   │
│   ├── user/                          # 用户态 eBPF 加载器与数据转发
│   │   ├── loader.c                   # 加载 BPF 字节码，挂载探针
│   │   ├── ringbuf_handler.c          # 轮询 BPF Ring Buffer，解析内核传递的事件
│   │   ├── redis_shipper.c            # 将解析后的应用层语义和系统层行为数据推送到 Redis
│   │   └── Makefile                   # 构建脚本：包含利用 bpftool 生成 *.skel.h 骨架文件的指令
│   │
│   ├── analysis/                      # 跨层分析与图计算模块
│   │   ├── main_analyzer.py           # 分析模块入口，消费 Redis 数据
│   │   ├── audit_engine.py            # 审计模块：黑白名单判定与 LLM 接口调用
│   │   ├── intra_agent/               # 单智能体行为分析规则与检测
│   │   └── inter_agent/               # 多智能体协同异常/关联分析
│   │
│   └── config/                        # 配置文件
│       ├── rules.yaml                 # 告警规则、黑白名单配置
│       └── app_config.yaml            # Redis 连接、LLM API 密钥、监控目标进程名/路径等配置
│
├── build/                             # 编译输出目录 (包含生成的 .o 和 .skel.h 文件)
├── docs/                              # 架构文档、流程图与部署说明
├── logs/                              # Alert / Log 告警输出目录
│   ├── ebpf_log/                      # ebpf捕获原始内容（用于程序开发调试阶段）
│   └── llm_log/                       # 经过LLM优化的用户报告
├── requirements.txt                   # 分析模块依赖 (如 redis, networkx, openai 等)
└── README.md
```