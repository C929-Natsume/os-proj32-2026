# SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
OUTPUT := .output
CLANG ?= clang
CC ?= gcc

LIBBPF_SRC := $(abspath ../libbpf/src)
LIBBPF_DIR := $(abspath ../libbpf)
BPFTOOL_SRC := $(abspath ../bpftool/src)
LIBBPF_OBJ := $(abspath $(OUTPUT)/libbpf.a)
BPFTOOL_OUTPUT ?= $(abspath $(OUTPUT)/bpftool)
BPFTOOL ?= $(BPFTOOL_OUTPUT)/bootstrap/bpftool

ARCH := $(shell uname -m | sed 's/x86_64/x86/' | sed 's/aarch64/arm64/' | sed 's/arm.*/arm/')
VMLINUX := include/vmlinux.h

# eBPF 编译包含路径（使用 -nostdinc 避免用户空间标准头文件）
BPF_INCLUDES := -Iinclude -I. -I$(OUTPUT) -I$(LIBBPF_DIR)/include/uapi
BPF_FLAGS := -g -O2 -target bpf -D__TARGET_ARCH_$(ARCH) -nostdinc $(BPF_INCLUDES)

# 用户态包含路径
USER_INCLUDES := -I$(OUTPUT) -Iinclude -I. -I$(LIBBPF_DIR)/include -I$(LIBBPF_DIR)/include/uapi
CFLAGS := -g -Wall

ALL_LDFLAGS := -lelf -lz

APPS = monitor

EBPF_SRCS := src/ebpf/proc.bpf.c src/ebpf/fs.bpf.c src/ebpf/net.bpf.c src/ebpf/ssl.bpf.c
EBPF_OBJS := $(patsubst src/ebpf/%.bpf.c,$(OUTPUT)/%.bpf.o,$(EBPF_SRCS))
SKEL_HDRS := $(patsubst $(OUTPUT)/%.bpf.o,$(OUTPUT)/%.skel.h,$(EBPF_OBJS))

USER_SRCS := src/user/main.c src/user/proc_events.c src/user/fs_events.c \
             src/user/net_events.c src/user/proc_tree.c src/user/log.c src/user/ssl_events.c
USER_OBJS := $(patsubst src/user/%.c,$(OUTPUT)/%.o,$(USER_SRCS))

ifeq ($(V),1)
	Q =
	msg =
else
	Q = @
	msg = @printf '  %-8s %s\n' "$(1)" "$(2)"
endif

.PHONY: all clean

all: $(APPS)

$(OUTPUT) $(OUTPUT)/libbpf $(BPFTOOL_OUTPUT):
	$(call msg,MKDIR,$@)
	$(Q)mkdir -p $@

$(LIBBPF_OBJ): $(wildcard $(LIBBPF_SRC)/*.[ch] $(LIBBPF_SRC)/Makefile) | $(OUTPUT)/libbpf
	$(call msg,LIB,$@)
	$(Q)$(MAKE) -C $(LIBBPF_SRC) BUILD_STATIC_ONLY=1 \
		OBJDIR=$(dir $@)/libbpf DESTDIR=$(dir $@) \
		INCLUDEDIR= LIBDIR= UAPIDIR= \
		install

$(BPFTOOL): | $(BPFTOOL_OUTPUT)
	$(call msg,BPFTOOL,$@)
	$(Q)$(MAKE) ARCH= CROSS_COMPILE= OUTPUT=$(BPFTOOL_OUTPUT)/ -C $(BPFTOOL_SRC) bootstrap

$(VMLINUX):
	$(call msg,GEN-VMLINUX,$@)
	$(Q)mkdir -p $(dir $@)
	$(Q)$(BPFTOOL) btf dump file /sys/kernel/btf/vmlinux format c > $@

# eBPF 编译规则（关键修改）
$(OUTPUT)/%.bpf.o: src/ebpf/%.bpf.c $(LIBBPF_OBJ) include/common.h $(VMLINUX) | $(OUTPUT) $(BPFTOOL)
	$(call msg,BPF,$@)
	$(Q)$(CLANG) $(BPF_FLAGS) -c $< -o $@

# 生成骨架头文件
$(OUTPUT)/%.skel.h: $(OUTPUT)/%.bpf.o | $(OUTPUT) $(BPFTOOL)
	$(call msg,GEN-SKEL,$@)
	$(Q)$(BPFTOOL) gen skeleton $< > $@

# 用户态编译
$(OUTPUT)/%.o: src/user/%.c $(SKEL_HDRS) include/common.h | $(OUTPUT)
	$(call msg,CC,$@)
	$(Q)$(CC) $(CFLAGS) $(USER_INCLUDES) -c $< -o $@

# 链接
$(APPS): $(USER_OBJS) $(LIBBPF_OBJ) | $(OUTPUT)
	$(call msg,BINARY,$@)
	$(Q)$(CC) $(CFLAGS) $^ $(ALL_LDFLAGS) -o $@

clean:
	$(call msg,CLEAN)
	$(Q)rm -rf $(OUTPUT) $(APPS)

.DELETE_ON_ERROR:
.SECONDARY: