monitor/
├── include/
│   ├── common.h          # 所有模块共享的数据结构 (枚举、事件体)
│   └── vmlinux.h         # 由 bpftool 生成的内核类型
├── src/
│   ├── ebpf/
│   │   ├── proc.bpf.c    # 进程管理探头 (fork/exec/exit/signal 等)
│   │   ├── fs.bpf.c      # 文件系统探头 (open/read/write/unlink 等)
│   │   └── net.bpf.c     # 网络探头 (socket/connect/tcp_state 等)
│   └── user/
│       ├── main.c        # 入口、初始化、事件循环
│       ├── proc_events.c # 进程事件回调、进程树维护
│       ├── fs_events.c   # 文件事件回调
│       ├── net_events.c  # 网络事件回调
│       ├── proc_tree.c   # 进程树数据结构实现
│       └── proc_tree.h
├── Makefile / CMakeLists.txt
└── .gitignore