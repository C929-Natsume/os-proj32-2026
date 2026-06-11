BPF_SRCS = ../bpf/sys_behavior.bpf.c ../bpf/ssl_sniffer.bpf.c
SKEL_SRCS = sys_behavior.skel.h ssl_sniffer.skel.h
USER_SRCS = loader.c ringbuf_handler.c redis_shipper.c
COMMON_HDR = ../bpf/common.h
VMLINUX_H = ../bpf/vmlinux.h

ROOT_DIR := $(abspath ../../..)
LIBBPF_DIR := $(ROOT_DIR)/libbpf
LIBBPF_SRC := $(LIBBPF_DIR)/src
LIBBPF_BUILD_DIR ?= $(LIBBPF_DIR)/build
LIBBPF_STATIC := $(LIBBPF_BUILD_DIR)/libbpf.a
BPFTOOL_BIN := $(ROOT_DIR)/bpftool/src/bpftool

BPF_CLANG = clang
BPF_FLAGS = -target bpf -D__TARGET_ARCH_x86 -I../bpf \
            -I$(LIBBPF_DIR)/include \
            -I$(LIBBPF_SRC)
BPFTOOL = $(BPFTOOL_BIN)

CC = gcc
CFLAGS = -Wall -Wextra \
         -I../bpf \
         -I$(LIBBPF_DIR)/include \
         -I$(LIBBPF_SRC)
LDFLAGS = $(LIBBPF_STATIC) -lelf -lz

all: skeletons user_programs

%.skel.h: ../bpf/%.bpf.c $(COMMON_HDR) $(VMLINUX_H)
	@echo "[MAKE] Compiling $< to BPF object..."
	$(BPF_CLANG) $(BPF_FLAGS) -O2 -g -c $< -o $(basename $(notdir $<)).bpf.o
	@echo "[MAKE] Fixing .rodata.str1.1 section for compatibility..."
	@llvm-objcopy --rename-section .rodata.str1.1=.rodata $(basename $(notdir $<)).bpf.o 2>/dev/null || true
	@echo "[MAKE] Generating skeleton $@..."
	$(BPFTOOL) gen skeleton $(basename $(notdir $<)).bpf.o > $@
	@sed -i 's#<bpf/libbpf.h>#"libbpf.h"#g' $@

skeletons: $(SKEL_SRCS)
	@echo "[MAKE] BPF skeleton generation complete"

$(LIBBPF_STATIC):
	@echo "[MAKE] Building local libbpf..."
	$(MAKE) -C $(LIBBPF_SRC) OBJDIR=$(LIBBPF_BUILD_DIR) EXTRA_CFLAGS='-Wno-error=discarded-qualifiers'

# 修改点 1：loader 现在负责加载 BPF，因此依赖骨架 $(SKEL_SRCS)，且需要链接 $(LDFLAGS)
loader: loader.c $(SKEL_SRCS) $(LIBBPF_STATIC)
	@echo "[MAKE] Compiling loader (eBPF Loader & Map Pinner)..."
	$(CC) $(CFLAGS) -o loader loader.c $(LDFLAGS)

# 修改点 2：ringbuf_handler 使用 redis-cli 发布，不依赖 hiredis 开发包
ringbuf_handler: ringbuf_handler.c redis_shipper.c $(LIBBPF_STATIC)
	@echo "[MAKE] Compiling ringbuf_handler (Event Consumer & Redis-CLI Shipper)..."
	$(CC) $(CFLAGS) -o ringbuf_handler ringbuf_handler.c redis_shipper.c $(LDFLAGS)

user_programs: loader ringbuf_handler
	@echo "[MAKE] User programs built successfully"

clean:
	@echo "[MAKE] Cleaning build artifacts..."
	@rm -f *.bpf.o *.skel.h
	@rm -f loader ringbuf_handler
	@echo "[MAKE] Clean complete"

.PHONY: all skeletons user_programs clean
