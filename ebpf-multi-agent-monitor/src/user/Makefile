BPF_SRCS = ../bpf/sys_behavior.bpf.c ../bpf/ssl_sniffer.bpf.c
SKEL_SRCS = sys_behavior.skel.h ssl_sniffer.skel.h
USER_SRCS = loader.c ringbuf_handler.c redis_shipper.c
COMMON_HDR = ../bpf/common.h
VMLINUX_H = ../bpf/vmlinux.h

BPF_CLANG = clang-15
BPF_FLAGS = -target bpf -D__TARGET_ARCH_x86 -I../bpf -I/home/gabriel/os2026/libbpf/include/uapi -I/home/gabriel/os2026/libbpf/include
BPFTOOL = /home/gabriel/os2026/bpftool/src/bpftool

CC = gcc
CFLAGS = -Wall -Wextra -I/home/gabriel/os2026/libbpf/include -I/home/gabriel/os2026/libbpf/include/uapi -I../bpf
LDFLAGS = -L/home/gabriel/os2026/libbpf/build/lib -lbpf -lelf -lz

all: skeletons user_programs

%.skel.h: ../bpf/%.bpf.c $(COMMON_HDR) $(VMLINUX_H)
	@echo "[MAKE] Compiling $< to BPF object..."
	$(BPF_CLANG) $(BPF_FLAGS) -g -c $< -o $(basename $(notdir $<)).bpf.o
	@echo "[MAKE] Fixing .rodata.str1.1 section for compatibility..."
	@llvm-objcopy --rename-section .rodata.str1.1=.rodata $(basename $(notdir $<)).bpf.o 2>/dev/null || true
	@echo "[MAKE] Generating skeleton $@..."
	$(BPFTOOL) gen skeleton $(basename $(notdir $<)).bpf.o > $@

skeletons: $(SKEL_SRCS)
	@echo "[MAKE] BPF skeleton generation complete"

loader: loader.c $(SKEL_SRCS)
	@echo "[MAKE] Compiling loader..."
	$(CC) $(CFLAGS) -o loader loader.c $(LDFLAGS)

ringbuf_handler: ringbuf_handler.c $(SKEL_SRCS)
	@echo "[MAKE] Compiling ringbuf_handler..."
	$(CC) $(CFLAGS) -o ringbuf_handler ringbuf_handler.c $(LDFLAGS)

redis_shipper: redis_shipper.c $(SKEL_SRCS)
	@echo "[MAKE] Compiling redis_shipper..."
	$(CC) $(CFLAGS) -o redis_shipper redis_shipper.c $(LDFLAGS) -lhiredis

user_programs: loader ringbuf_handler redis_shipper
	@echo "[MAKE] User programs built successfully"

clean:
	@echo "[MAKE] Cleaning build artifacts..."
	@rm -f *.bpf.o *.skel.h
	@rm -f loader ringbuf_handler redis_shipper
	@echo "[MAKE] Clean complete"

.PHONY: all skeletons user_programs clean