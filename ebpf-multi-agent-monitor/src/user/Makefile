BPF_SRCS = ../bpf/sys_behavior.bpf.c ../bpf/ssl_sniffer.bpf.c
SKEL_SRCS = sys_behavior.skel.h ssl_sniffer.skel.h
USER_SRCS = loader.c ringbuf_handler.c redis_shipper.c
COMMON_HDR = ../bpf/common.h
VMLINUX_H = ../bpf/vmlinux.h

BPF_CLANG = clang
BPF_FLAGS = -target bpf -D__TARGET_ARCH_x86 -I../bpf \
            -I/home/gabriel/comp/project3136859-387615/libbpf/include \
            -I/home/gabriel/comp/project3136859-387615/libbpf/src
BPFTOOL = /home/gabriel/comp/project3136859-387615/bpftool/src/bpftool

CC = gcc
CFLAGS = -Wall -Wextra \
         -I../bpf \
         -I/home/gabriel/comp/project3136859-387615/libbpf/include \
         -I/home/gabriel/comp/project3136859-387615/libbpf/src \
         -I/home/gabriel/comp/project3136859-387615/bpftool/src/libbpf/include
LDFLAGS = -L/home/gabriel/comp/project3136859-387615/libbpf/src -lbpf -lelf -lz

all: skeletons user_programs

%.skel.h: ../bpf/%.bpf.c $(COMMON_HDR) $(VMLINUX_H)
	@echo "[MAKE] Compiling $< to BPF object..."
	$(BPF_CLANG) $(BPF_FLAGS) -O2 -g -c $< -o $(basename $(notdir $<)).bpf.o
	@echo "[MAKE] Fixing .rodata.str1.1 section for compatibility..."
	@llvm-objcopy --rename-section .rodata.str1.1=.rodata $(basename $(notdir $<)).bpf.o 2>/dev/null || true
	@echo "[MAKE] Generating skeleton $@..."
	$(BPFTOOL) gen skeleton $(basename $(notdir $<)).bpf.o > $@

skeletons: $(SKEL_SRCS)
	@echo "[MAKE] BPF skeleton generation complete"

# 修改点 1：loader 现在负责加载 BPF，因此依赖骨架 $(SKEL_SRCS)，且需要链接 $(LDFLAGS)
loader: loader.c $(SKEL_SRCS)
	@echo "[MAKE] Compiling loader (eBPF Loader & Map Pinner)..."
	$(CC) $(CFLAGS) -o loader loader.c $(LDFLAGS)

# 修改点 2：ringbuf_handler 不再依赖骨架，但需要链接 redis_shipper, libbpf 和 hiredis
ringbuf_handler: ringbuf_handler.c redis_shipper.c
	@echo "[MAKE] Compiling ringbuf_handler (Event Consumer & Redis Shipper)..."
	$(CC) $(CFLAGS) -o ringbuf_handler ringbuf_handler.c redis_shipper.c $(LDFLAGS) -lhiredis

user_programs: loader ringbuf_handler
	@echo "[MAKE] User programs built successfully"

clean:
	@echo "[MAKE] Cleaning build artifacts..."
	@rm -f *.bpf.o *.skel.h
	@rm -f loader ringbuf_handler
	@echo "[MAKE] Clean complete"

.PHONY: all skeletons user_programs clean