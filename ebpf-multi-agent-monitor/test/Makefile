BPF_DIR = ../src/bpf
USER_DIR = ../src/user
BUILD_DIR = ../build

TEST_BINS = test_unit test_functional

LIBBPF_LIB_DIR ?= /usr/lib/x86_64-linux-gnu

CC = gcc
CFLAGS = -Wall -Wextra -Wno-unused-parameter -Wno-unused-result -g -O2 \
         -I$(BPF_DIR) \
         -I$(USER_DIR) \
         -I$(BUILD_DIR) \
         -I/home/gabriel/comp/project3136859-387615/libbpf/include \
         -I/home/gabriel/comp/project3136859-387615/libbpf/src \
         -I/home/gabriel/comp/project3136859-387615/bpftool/src/libbpf/include \
         -I/mnt/e/os2026

LDFLAGS = -lm
BPF_LDFLAGS = -L$(LIBBPF_LIB_DIR) -l:libbpf.so.1 -lelf -lz

.PHONY: all clean test_all test_functional test_integration test_perf

all: $(TEST_BINS)

test_unit: test_unit.c $(USER_DIR)/event_serializer.c
	$(CC) $(CFLAGS) -o $@ test_unit.c $(USER_DIR)/event_serializer.c $(LDFLAGS)

test_functional: test_functional.c $(BPF_DIR)/sys_behavior.c $(BPF_DIR)/agent_registry.c
	$(CC) $(CFLAGS) -o $@ test_functional.c \
		$(BPF_DIR)/sys_behavior.c \
		$(BPF_DIR)/agent_registry.c \
		$(LDFLAGS) $(BPF_LDFLAGS)

test_functional_run: test_functional
	@echo "Running functional tests (requires root, sudo)..."
	@sudo ./test_functional

test_integration:
	@echo "Running integration tests (requires root + redis-server)..."
	@sudo bash test_integration.sh

test_perf:
	@echo "Running performance benchmark (requires root)..."
	@sudo bash test_perf.sh

test_all: all
	@echo "================================================"
	@echo "  Running ALL tests..."
	@echo "================================================"
	@echo ""
	@echo "--- Unit Tests (no root needed) ---"
	./test_unit || true
	@echo ""
	@echo "--- Functional Tests (requires root) ---"
	-sudo ./test_functional || echo "  SKIP: no root for functional tests"
	@echo ""
	@echo "--- Performance Tests (requires root) ---"
	-sudo bash test_perf.sh || echo "  SKIP: no root for perf tests"
	@echo ""
	@echo "--- Integration Tests (requires root + redis) ---"
	-sudo bash test_integration.sh || echo "  SKIP: no root for integration tests"
	@echo ""
	@echo "================================================"
	@echo "  All tests completed."
	@echo "================================================"

clean:
	rm -f $(TEST_BINS)
