# 启动 loader（自动发现模式）
sudo ./src/user/loader &
LOADER_PID=$!
sleep 3
# 检查 BPF 探针
sudo bpftool prog list | grep -E "sys_behavior|ssl_sniffer"
sudo bpftool perf list | grep -E "uprobe|kprobe"
# 终止
sudo kill -INT $LOADER_PID
# 确认清理干净
sudo bpftool prog list | grep -E "sys_behavior|ssl_sniffer"  # 应该为空