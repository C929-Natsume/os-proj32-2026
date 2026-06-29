BPF_DIR = ../bpf
USER_DIR = .
BUILD_DIR = ../../build

SKEL_SRCS = $(BUILD_DIR)/sys_behavior.skel.h $(BUILD_DIR)/ssl_sniffer.skel.h
BPF_OBJS = $(BUILD_DIR)/sys_behavior.bpf.o $(BUILD_DIR)/ssl_sniffer.bpf.o
USER_BINS = $(BUILD_DIR)/loader $(BUILD_DIR)/ringbuf_handler

COMMON_HDR = $(BPF_DIR)/common.h
VMLINUX_H = $(BPF_DIR)/vmlinux.h

MODULE_SRCS = $(BPF_DIR)/sys_behavior.c $(BPF_DIR)/ssl_sniffer.c $(BPF_DIR)/agent_registry.c

BPF_CLANG = clang
BPF_FLAGS = -target bpf -D__TARGET_ARCH_x86 -I$(BPF_DIR) \
            -I/home/gabriel/comp/project3136859-387615/libbpf/include \
            -I/home/gabriel/comp/project3136859-387615/libbpf/src
BPFTOOL = /home/gabriel/comp/project3136859-387615/bpftool/src/bpftool
HIREDIS_ROOT ?= /home/gabriel/comp/project3136859-387615/hiredis
LIBBPF_LIB_DIR ?= /usr/lib/x86_64-linux-gnu

CC = gcc
CFLAGS = -Wall -Wextra \
         -I$(BPF_DIR) \
         -I$(BUILD_DIR) \
         -I/home/gabriel/comp/project3136859-387615/libbpf/include \
         -I/home/gabriel/comp/project3136859-387615/libbpf/src \
         -I/home/gabriel/comp/project3136859-387615/bpftool/src/libbpf/include \
         -I/mnt/e/os2026
LDFLAGS = -L$(LIBBPF_LIB_DIR) -l:libbpf.so.1 -lelf -lz
HIREDIS_LDFLAGS = $(HIREDIS_ROOT)/libhiredis.a

all: $(BUILD_DIR) skeletons user_programs

$(BUILD_DIR):
	@mkdir -p $(BUILD_DIR)

$(BUILD_DIR)/%.skel.h: $(BPF_DIR)/%.bpf.c $(COMMON_HDR) $(VMLINUX_H) | $(BUILD_DIR)
	@echo "[MAKE] Compiling $< to BPF object..."
	$(BPF_CLANG) $(BPF_FLAGS) -O2 -g -c $< -o $(BUILD_DIR)/$*.bpf.o
	@echo "[MAKE] Fixing .rodata.str1.1 section for compatibility..."
	@llvm-objcopy --rename-section .rodata.str1.1=.rodata $(BUILD_DIR)/$*.bpf.o 2>/dev/null || true
	@echo "[MAKE] Generating skeleton $@..."
	$(BPFTOOL) gen skeleton $(BUILD_DIR)/$*.bpf.o name $*_bpf > $@

skeletons: $(SKEL_SRCS)
	@echo "[MAKE] BPF skeleton generation complete in $(BUILD_DIR)/"

$(BUILD_DIR)/loader: loader.c $(MODULE_SRCS) $(SKEL_SRCS) | $(BUILD_DIR)
	@echo "[MAKE] Compiling loader (eBPF Loader & Map Pinner)..."
	$(CC) $(CFLAGS) -o $@ loader.c $(MODULE_SRCS) $(LDFLAGS)

REDIS_SHIPPER_SRCS = redis_client.c agent_tracker.c metrics_aggregator.c topology_builder.c event_serializer.c

$(BUILD_DIR)/ringbuf_handler: ringbuf_handler.c $(REDIS_SHIPPER_SRCS) | $(BUILD_DIR)
	@echo "[MAKE] Compiling ringbuf_handler (Event Consumer & Redis Shipper)..."
	$(CC) $(CFLAGS) -o $@ ringbuf_handler.c $(REDIS_SHIPPER_SRCS) $(LDFLAGS) $(HIREDIS_LDFLAGS)

user_programs: $(USER_BINS)
	@echo "[MAKE] User programs built successfully"

clean:
	@echo "[MAKE] Cleaning build artifacts..."
	@rm -rf $(BUILD_DIR)/*.bpf.o $(BUILD_DIR)/*.skel.h $(BUILD_DIR)/loader $(BUILD_DIR)/ringbuf_handler
	@echo "[MAKE] Clean complete"

.PHONY: all skeletons user_programs clean
