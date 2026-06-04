BPF_DIR = ../bpf
USER_DIR = .

BPF_SRCS = $(BPF_DIR)/sys_behavior.bpf.c $(BPF_DIR)/ssl_sniffer.bpf.c
SKEL_SRCS = $(BPF_DIR)/sys_behavior.skel.h $(BPF_DIR)/ssl_sniffer.skel.h
BPF_OBJS = $(BPF_DIR)/sys_behavior.bpf.o $(BPF_DIR)/ssl_sniffer.bpf.o

COMMON_HDR = $(BPF_DIR)/common.h
VMLINUX_H = $(BPF_DIR)/vmlinux.h

MODULE_SRCS = $(BPF_DIR)/sys_behavior.c $(BPF_DIR)/ssl_sniffer.c

BPF_CLANG = clang
BPF_FLAGS = -target bpf -D__TARGET_ARCH_x86 -I$(BPF_DIR) \
            -I/home/gabriel/comp/project3136859-387615/libbpf/include \
            -I/home/gabriel/comp/project3136859-387615/libbpf/src
BPFTOOL = /home/gabriel/comp/project3136859-387615/bpftool/src/bpftool

CC = gcc
CFLAGS = -Wall -Wextra \
         -I$(BPF_DIR) \
         -I/home/gabriel/comp/project3136859-387615/libbpf/include \
         -I/home/gabriel/comp/project3136859-387615/libbpf/src \
         -I/home/gabriel/comp/project3136859-387615/bpftool/src/libbpf/include
LDFLAGS = -L/home/gabriel/comp/project3136859-387615/libbpf/src -lbpf -lelf -lz

all: skeletons user_programs

$(BPF_DIR)/%.skel.h: $(BPF_DIR)/%.bpf.c $(COMMON_HDR) $(VMLINUX_H)
	@echo "[MAKE] Compiling $< to BPF object..."
	$(BPF_CLANG) $(BPF_FLAGS) -O2 -g -c $< -o $(BPF_DIR)/$*.bpf.o
	@echo "[MAKE] Fixing .rodata.str1.1 section for compatibility..."
	@llvm-objcopy --rename-section .rodata.str1.1=.rodata $(BPF_DIR)/$*.bpf.o 2>/dev/null || true
	@echo "[MAKE] Generating skeleton $@..."
	$(BPFTOOL) gen skeleton $(BPF_DIR)/$*.bpf.o name $*_bpf > $@

skeletons: $(SKEL_SRCS)
	@echo "[MAKE] BPF skeleton generation complete in $(BPF_DIR)/"

loader: loader.c $(MODULE_SRCS) $(SKEL_SRCS)
	@echo "[MAKE] Compiling loader (eBPF Loader & Map Pinner)..."
	$(CC) $(CFLAGS) -o loader loader.c $(MODULE_SRCS) $(LDFLAGS)

ringbuf_handler: ringbuf_handler.c redis_shipper.c
	@echo "[MAKE] Compiling ringbuf_handler (Event Consumer & Redis Shipper)..."
	$(CC) $(CFLAGS) -o ringbuf_handler ringbuf_handler.c redis_shipper.c $(LDFLAGS) -lhiredis

user_programs: loader ringbuf_handler
	@echo "[MAKE] User programs built successfully"

clean:
	@echo "[MAKE] Cleaning build artifacts..."
	@rm -f $(BPF_OBJS) $(SKEL_SRCS)
	@rm -f loader ringbuf_handler
	@echo "[MAKE] Clean complete"

.PHONY: all skeletons user_programs clean