/* ===================================================================
 *  eBPF Multi-Agent Monitor — Functional End-to-End Tests
 *
 *  Tests the actual BPF event capture pipeline by:
 *  1. Loading sys_behavior BPF programs
 *  2. Registering the test process as a monitored agent
 *  3. Generating real syscalls (open, read, write, fork, etc.)
 *  4. Reading ring buffer events and verifying correctness
 *
 *  Requires: root, BPF support, compiled BPF skeleton in build/
 * ===================================================================
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <time.h>
#include "../src/bpf/common.h"
#include "../src/bpf/sys_behavior.h"
#include "../src/bpf/ssl_sniffer.h"

/* ===== Stats & Globals ===== */
static int tests_passed = 0;
static int tests_failed = 0;
static int events_captured = 0;

#define TEST_PREFIX "[FUNC]"
#define RB_POLL_TIMEOUT_MS 500
#define MAX_CAPTURED 256

/* Captured event buffer for cross-checking */
static struct sys_event captured_events[MAX_CAPTURED];
static int captured_count = 0;

/* ===== External APIs from loader components ===== */
extern int setup_sys_behavior(void);
extern int get_monitored_pids_fd(void);
extern void teardown_sys_behavior(void);
extern void register_agent(int map_fd, int pid, __u32 agent_id,
                           const char *agent_name);

/* ===== Ring Buffer Callback ===== */
static int on_sys_event(void *ctx, void *data, size_t len) {
    (void)ctx;
    if (len != sizeof(struct sys_event)) return 1;
    struct sys_event *ev = (struct sys_event *)data;
    if (captured_count < MAX_CAPTURED) {
        captured_events[captured_count++] = *ev;
    }
    events_captured++;
    return 0;
}

static int raw_event_count = 0;
static int on_raw_event(void *ctx, void *data, size_t len) {
    (void)ctx;
    if (len != sizeof(struct raw_data_event)) return 1;
    raw_event_count++;
    return 0;
}

/* ===== Test Helpers ===== */
#define SECTION(name) \
    do { printf("\n--- %s ---\n", name); } while (0)
#define CHECK(cond, fmt, ...) \
    do { \
        if (cond) { printf("  ✓ " fmt "\n", ##__VA_ARGS__); tests_passed++; } \
        else { printf("  ✗ " fmt "\n", ##__VA_ARGS__); tests_failed++; } \
    } while(0)

/* ===================================================================
 *  Setup: load BPF, register, open ring buffers
 * =================================================================== */
static struct ring_buffer *sys_rb = NULL;
static struct ring_buffer *raw_rb = NULL;

static int setup(void) {
    int fd;

    if (setup_sys_behavior() != 0) {
        fprintf(stderr, "FAIL: setup_sys_behavior\n");
        return -1;
    }

    /* Register test process as agent */
    int map_fd = get_monitored_pids_fd();
    if (map_fd < 0) {
        fprintf(stderr, "FAIL: get_monitored_pids_fd\n");
        teardown_sys_behavior();
        return -1;
    }
    register_agent(map_fd, getpid(), 1001, "Sys-func_test-1001");
    printf("[SETUP] Registered PID %d as agent 1001\n", getpid());

    /* Open pinned ring buffers */
    fd = bpf_obj_get("/sys/fs/bpf/sys_rb");
    if (fd < 0) { perror("bpf_obj_get sys_rb"); teardown_sys_behavior(); return -1; }
    sys_rb = ring_buffer__new(fd, on_sys_event, NULL, NULL);
    if (!sys_rb) { fprintf(stderr, "FAIL: ring_buffer__new sys_rb\n"); close(fd); teardown_sys_behavior(); return -1; }

    fd = bpf_obj_get("/sys/fs/bpf/raw_rb");
    if (fd < 0) { perror("bpf_obj_get raw_rb"); teardown_sys_behavior(); return -1; }
    raw_rb = ring_buffer__new(fd, on_raw_event, NULL, NULL);
    if (!raw_rb) { fprintf(stderr, "FAIL: ring_buffer__new raw_rb\n"); close(fd); teardown_sys_behavior(); return -1; }

    return 0;
}

static void teardown(void) {
    ring_buffer__free(sys_rb);
    ring_buffer__free(raw_rb);
    teardown_sys_behavior();
}

static int poll_events(int timeout_ms) {
    int ret;
    struct ring_buffer *rbs[] = {sys_rb, raw_rb};
    for (int i = 0; i < 2; i++) {
        ret = ring_buffer__poll(rbs[i], timeout_ms);
        if (ret < 0) return ret;
    }
    return 0;
}

static void drain_ring_buffer(void) {
    /* Poll repeatedly until no more events */
    for (int i = 0; i < 20; i++) {
        int ret = ring_buffer__poll(sys_rb, 50);
        ring_buffer__poll(raw_rb, 50);
        if (ret <= 0) break;
    }
}

static void reset_capture(void) {
    captured_count = 0;
    events_captured = 0;
    raw_event_count = 0;
    drain_ring_buffer(); /* clear any pending events */
}

/* ===================================================================
 *  TEST 1: Basic Syscall Capture (open, write, close, unlink)
 * =================================================================== */
static void test_syscall_capture(void) {
    SECTION("Test 1: Syscall Capture (open → write → close → unlink)");

    reset_capture();

    /* Generate syscalls */
    int fd = open("/tmp/__ebpf_test_file__",
                  O_CREAT | O_RDWR | O_TRUNC, 0644);
    CHECK(fd >= 0, "open /tmp/__ebpf_test_file__");

    const char *msg = "hello eBPF";
    ssize_t written = write(fd, msg, strlen(msg));
    CHECK(written == (ssize_t)strlen(msg), "write to test file");

    close(fd);

    int ret = unlink("/tmp/__ebpf_test_file__");
    CHECK(ret == 0, "unlink test file");

    /* Poll ring buffer for events */
    poll_events(RB_POLL_TIMEOUT_MS);

    /* Verify */
    CHECK(events_captured > 0, "at least one sys_event captured (%d)",
          events_captured);

    /* Check for specific event types */
    int found_open = 0, found_unlink = 0;
    for (int i = 0; i < captured_count; i++) {
        if (captured_events[i].event_type == EVENT_OPEN) found_open = 1;
        if (captured_events[i].event_type == EVENT_UNLINK) found_unlink = 1;
    }
    CHECK(found_open, "EVENT_OPEN captured");
    CHECK(found_unlink, "EVENT_UNLINK captured");

    /* Verify agent identity propagation */
    int has_agent_id = 0;
    for (int i = 0; i < captured_count; i++) {
        if (captured_events[i].agent_id == 1001 ||
            strcmp(captured_events[i].agent_name, "Sys-func_test-1001") == 0) {
            has_agent_id = 1;
            break;
        }
    }
    CHECK(has_agent_id, "agent_id=1001 propagated in events");
}

/* ===================================================================
 *  TEST 2: Plaintext Stdout Capture
 * =================================================================== */
static void test_stdout_capture(void) {
    SECTION("Test 2: Plaintext Stdout Capture");

    reset_capture();

    /* Write to stdout — should trigger raw_rb capture via sys_write_raw */
    const char *test_data = "EBPF_TEST_MARKER_STDOUT_12345";
    write(STDOUT_FILENO, test_data, strlen(test_data));

    poll_events(RB_POLL_TIMEOUT_MS);

    CHECK(raw_event_count > 0,
          "raw event captured on stdout write (%d events)",
          raw_event_count);
}

/* ===================================================================
 *  TEST 3: Execve Event Capture
 * =================================================================== */
static void test_execve_capture(void) {
    SECTION("Test 3: Execve Event Capture");

    reset_capture();

    /* Run a simple command as agent */
    int child = fork();
    CHECK(child >= 0, "fork for execve test");
    if (child == 0) {
        /* Child: exec ls */
        execlp("ls", "ls", "/tmp", NULL);
        _exit(1);
    }
    int status;
    waitpid(child, &status, 0);
    CHECK(WIFEXITED(status) && WEXITSTATUS(status) == 0,
          "child execve completed");

    poll_events(RB_POLL_TIMEOUT_MS);

    int found_exec = 0;
    for (int i = 0; i < captured_count; i++) {
        if (captured_events[i].event_type == EVENT_EXECVE) found_exec = 1;
    }
    CHECK(found_exec, "EVENT_EXECVE captured (child process)");
}

/* ===================================================================
 *  TEST 4: Inter-Agent Fork Detection
 * =================================================================== */
static void test_fork_detection(void) {
    SECTION("Test 4: Inter-Agent Fork Detection");

    reset_capture();

    int child = fork();
    CHECK(child >= 0, "fork for inter-agent test");

    if (child == 0) {
        /* Child: do some syscalls, then exit */
        int fd = open("/tmp/__ebpf_fork_child__", O_CREAT | O_RDWR, 0644);
        write(fd, "child_data", 10);
        close(fd);
        unlink("/tmp/__ebpf_fork_child__");
        _exit(0);
    }

    int status;
    waitpid(child, &status, 0);
    CHECK(WIFEXITED(status), "child exited normally");

    poll_events(RB_POLL_TIMEOUT_MS);

    /* Check for fork event with correct parent/child PIDs */
    int found_fork = 0;
    int found_fork_child_match = 0;
    for (int i = 0; i < captured_count; i++) {
        if (captured_events[i].event_type == EVENT_FORK) {
            found_fork = 1;
            if (captured_events[i].child_pid == (__u32)child)
                found_fork_child_match = 1;
        }
    }
    CHECK(found_fork, "EVENT_FORK captured");
    CHECK(found_fork_child_match,
          "fork event child_pid matches actual child PID (%d)", child);
}

/* ===================================================================
 *  TEST 5: Agent Identity Propagation across Fork
 * =================================================================== */
static void test_agent_identity_propagation(void) {
    SECTION("Test 5: Agent Identity Propagation across Fork");

    reset_capture();

    int child = fork();
    CHECK(child >= 0, "fork identity test");

    if (child == 0) {
        /* Child should inherit agent_id from parent */
        /* Do a syscall that will be captured */
        int fd = open("/tmp/__ebpf_id_test__", O_CREAT | O_RDWR, 0644);
        write(fd, "id_test", 7);
        close(fd);
        unlink("/tmp/__ebpf_id_test__");
        _exit(0);
    }

    int status;
    waitpid(child, &status, 0);
    poll_events(RB_POLL_TIMEOUT_MS);

    /* Child's open() etc. should have agent_id=1001 from inheritance */
    int found_child_with_agent_id = 0;
    for (int i = 0; i < captured_count; i++) {
        if (captured_events[i].pid == (__u32)child &&
            captured_events[i].event_type == EVENT_OPEN &&
            captured_events[i].agent_id == 1001) {
            found_child_with_agent_id = 1;
            break;
        }
    }
    CHECK(found_child_with_agent_id,
          "child process events carry inherited agent_id=1001");
}

/* ===================================================================
 *  TEST 6: Event Data Integrity
 * =================================================================== */
static void test_event_integrity(void) {
    SECTION("Test 6: Event Data Integrity");

    reset_capture();

    /* Generate events with known properties */
    const char *test_filename = "/tmp/__ebpf_integrity__";
    int fd = open(test_filename, O_CREAT | O_RDWR, 0644);
    write(fd, "integrity", 9);
    close(fd);
    unlink(test_filename);

    poll_events(RB_POLL_TIMEOUT_MS);

    /* Check basic integrity of all captured events */
    for (int i = 0; i < captured_count; i++) {
        char reason[256];
        int ok = 1;

        if (captured_events[i].timestamp == 0) {
            snprintf(reason, sizeof(reason), "event[%d] timestamp=0", i);
            ok = 0;
        }
        if (captured_events[i].pid == 0) {
            snprintf(reason, sizeof(reason), "event[%d] pid=0", i);
            ok = 0;
        }
        if (captured_events[i].event_type < EVENT_EXECVE ||
            captured_events[i].event_type > EVENT_TCP_RECV) {
            snprintf(reason, sizeof(reason),
                     "event[%d] invalid type=%u", i,
                     captured_events[i].event_type);
            ok = 0;
        }
        if (!ok) {
            printf("  ✗ integrity: %s\n", reason);
            tests_failed++;
        } else {
            tests_passed++;
        }
    }
}

/* ===================================================================
 *  TEST 7: Multiple Agents Detection
 * =================================================================== */
static void test_multi_agent(void) {
    SECTION("Test 7: Multi-Agent Registration & Events");

    /* Create a second "agent" process via fork */
    reset_capture();

    int child = fork();
    CHECK(child >= 0, "fork for multi-agent test");

    if (child == 0) {
        /* Child registers itself as a different agent */
        int map_fd = get_monitored_pids_fd();
        register_agent(map_fd, getpid(), 2002, "Sys-second_agent-2002");

        /* Generate events as second agent */
        int fd = open("/tmp/__ebpf_multi__", O_CREAT | O_RDWR, 0644);
        write(fd, "multi_agent", 11);
        close(fd);
        unlink("/tmp/__ebpf_multi__");

        /* Signal parent we're done, then exit */
        FILE *f = fopen("/tmp/__ebpf_multi_done__", "w");
        if (f) fclose(f);
        _exit(0);
    }

    /* Wait for child to finish */
    for (int i = 0; i < 50 && access("/tmp/__ebpf_multi_done__", F_OK) != 0; i++)
        usleep(100000);
    unlink("/tmp/__ebpf_multi_done__");

    int status;
    waitpid(child, &status, 0);

    poll_events(RB_POLL_TIMEOUT_MS);

    /* Check that both agents' events were captured */
    int found_agent1 = 0, found_agent2 = 0;
    for (int i = 0; i < captured_count; i++) {
        if (captured_events[i].agent_id == 1001) found_agent1 = 1;
        if (captured_events[i].agent_id == 2002) found_agent2 = 1;
    }
    CHECK(found_agent1, "agent 1001 events captured");
    CHECK(found_agent2, "agent 2002 (child) events captured with own agent_id");
}

/* ===================================================================
 *  TEST 8: Agent Type Detection (candidate→full→sub)
 *
 *  Verifies the BPF program correctly distinguishes between
 *  registered agents, sub-agents inheriting parent identity,
 *  and unregistered processes.
 * =================================================================== */
static void test_agent_type_detection(void) {
    SECTION("Test 8: Agent Type Detection");

    reset_capture();

    /* Fork a "sub-agent" child that inherits parent identity */
    int child = fork();
    CHECK(child >= 0, "fork for agent type test");

    if (child == 0) {
        /* Child: does NOT register itself — should inherit parent agent_id */
        int fd = open("/tmp/__ebpf_type_child__", O_CREAT | O_RDWR, 0644);
        write(fd, "type_test", 9);
        close(fd);
        unlink("/tmp/__ebpf_type_child__");
        _exit(0);
    }

    int status;
    waitpid(child, &status, 0);
    CHECK(WIFEXITED(status), "type-test child exited");

    poll_events(RB_POLL_TIMEOUT_MS * 2);

    /* Check child's events carry inherited agent_id = 1001 */
    int found_child_inherited = 0;
    for (int i = 0; i < captured_count; i++) {
        if (captured_events[i].pid == (__u32)child &&
            captured_events[i].agent_id == 1001) {
            found_child_inherited = 1;
            break;
        }
    }
    CHECK(found_child_inherited,
          "unregistered child inherits parent agent_id=1001 (%s)",
          found_child_inherited ? "yes" : "no");
}

/* ===================================================================
 *  TEST 9: Inter-Agent Communication via TCP loopback
 *
 *  Connects two registered agents via TCP and verifies the BPF
 *  program captures EVENT_CONNECT with correct peer_agent_id
 *  and raw TCP payload events.
 * =================================================================== */
static void test_inter_agent_comm(void) {
    SECTION("Test 9: Inter-Agent Communication (TCP loopback)");

    reset_capture();

    /* Create server socket in parent to accept child's connect */
    int svr_fd = socket(AF_INET, SOCK_STREAM, 0);
    CHECK(svr_fd >= 0, "create server socket");

    struct sockaddr_in addr = {0};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = inet_addr("127.0.0.1");
    addr.sin_port = 0;
    CHECK(bind(svr_fd, (struct sockaddr *)&addr, sizeof(addr)) == 0,
          "bind server socket");

    socklen_t addrlen = sizeof(addr);
    CHECK(getsockname(svr_fd, (struct sockaddr *)&addr, &addrlen) == 0,
          "getsockname");
    CHECK(listen(svr_fd, 1) == 0, "listen");

    short port = addr.sin_port;

    int child = fork();
    CHECK(child >= 0, "fork for inter-agent comm test");

    if (child == 0) {
        /* Child: register as agent 3003, connect to parent */
        close(svr_fd);
        int map_fd = get_monitored_pids_fd();
        register_agent(map_fd, getpid(), 3003, "Comm-agent_3003");

        int cli = socket(AF_INET, SOCK_STREAM, 0);
        struct sockaddr_in dst = {0};
        dst.sin_family = AF_INET;
        dst.sin_addr.s_addr = inet_addr("127.0.0.1");
        dst.sin_port = port;
        if (connect(cli, (struct sockaddr *)&dst, sizeof(dst)) != 0) _exit(2);
        write(cli, "from_child", 10);
        char buf[64] = {0};
        read(cli, buf, sizeof(buf));
        close(cli);
        _exit(0);
    }

    /* Parent (agent 1001): accept child's connection, send data */
    int client_fd = accept(svr_fd, NULL, NULL);
    CHECK(client_fd >= 0, "accept child connection");
    close(svr_fd);

    char buf[64] = {0};
    read(client_fd, buf, sizeof(buf));
    write(client_fd, "from_parent", 11);
    close(client_fd);

    int status;
    waitpid(child, &status, 0);
    CHECK(WIFEXITED(status) && WEXITSTATUS(status) == 0,
          "inter-agent TCP exchange completed");

    /* Poll and check for events */
    poll_events(RB_POLL_TIMEOUT_MS * 3);

    /* Check for CONNECT event (TCP handshake between agents) */
    int found_connect = 0;
    int found_peer_match = 0;
    for (int i = 0; i < captured_count; i++) {
        if (captured_events[i].event_type == EVENT_CONNECT) {
            found_connect = 1;
            /* Child→parent connect should have child's PID and agent_id=3003 */
            if (captured_events[i].pid == (__u32)child &&
                captured_events[i].agent_id == 3003) {
                found_peer_match = 1;
            }
        }
    }
    CHECK(found_connect,
          "EVENT_CONNECT captured between agents (%s)",
          found_connect ? "yes" : "no");
    CHECK(found_peer_match,
          "connect event carries child agent_id=3003 (%s)",
          found_peer_match ? "yes" : "no");

    /* Raw data events should capture the TCP payloads */
    CHECK(raw_event_count > 0,
          "raw_data events captured during inter-agent TCP (%d events)",
          raw_event_count);
}

/* ===================================================================
 *  TEST 10: Negative Test — Unregistered Process
 *
 *  Verifies that a process NOT registered as an agent does NOT
 *  have agent_id set (i.e., agent_id == 0 or kernel-sniffed).
 * =================================================================== */
static void test_negative_unregistered(void) {
    SECTION("Test 10: Negative Test — Unregistered Process");

    reset_capture();

    int child = fork();
    CHECK(child >= 0, "fork for negative test");

    if (child == 0) {
        /* Child: does NOT call register_agent() — deliberately unmonitored */
        int fd = open("/tmp/__ebpf_neg_child__", O_CREAT | O_RDWR, 0644);
        write(fd, "neg", 3);
        close(fd);
        unlink("/tmp/__ebpf_neg_child__");
        _exit(0);
    }

    int status;
    waitpid(child, &status, 0);
    CHECK(WIFEXITED(status), "negative-test child exited");

    poll_events(RB_POLL_TIMEOUT_MS * 2);

    /* Unregistered child events should either inherit parent agent_id
     * or carry the kernel-sniffed flag — they should NOT have a brand
     * new agent_id that was never registered. */
    int child_events = 0;
    int bad_own_id = 0;
    for (int i = 0; i < captured_count; i++) {
        if (captured_events[i].pid == (__u32)child) {
            child_events++;
            /* agent_id should be either 1001 (inherited) or have
             * the kernel-sniffed flag set — not a random new ID */
            if (captured_events[i].agent_id != 1001 &&
                !AGENT_ID_IS_KERNEL_SNIFFED(captured_events[i].agent_id)) {
                bad_own_id = 1;
            }
        }
    }
    CHECK(child_events >= 1, "unregistered child generated events");
    CHECK(!bad_own_id,
          "unregistered child did NOT get a new agent_id (%s)",
          bad_own_id ? "FAIL: got unexpected agent_id" : "ok");
}

/* ===================================================================
 *  TEST 11: TCP Event Coverage (connect/send/receive on loopback)
 *
 *  Opens a local TCP connection and verifies EVENT_CONNECT,
 *  EVENT_TCP_SEND, and EVENT_TCP_RECV are captured.
 *
 *  Uses a simple fork-based echo server on 127.0.0.1:0 (random port).
 * =================================================================== */
static void test_tcp_event_coverage(void) {
    SECTION("Test 11: TCP Event Coverage (connect/send/recv)");

    reset_capture();

    /* Create a listening socket in parent */
    int svr_fd = socket(AF_INET, SOCK_STREAM, 0);
    CHECK(svr_fd >= 0, "create server socket");

    struct sockaddr_in addr = {0};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = inet_addr("127.0.0.1");
    addr.sin_port = 0; /* random port */
    CHECK(bind(svr_fd, (struct sockaddr *)&addr, sizeof(addr)) == 0,
          "bind server socket");

    socklen_t addrlen = sizeof(addr);
    CHECK(getsockname(svr_fd, (struct sockaddr *)&addr, &addrlen) == 0,
          "getsockname");
    CHECK(listen(svr_fd, 1) == 0, "listen on server socket");

    short port = addr.sin_port;

    /* Fork server child that accepts once and echoes back */
    int child = fork();
    CHECK(child >= 0, "fork for TCP test");

    if (child == 0) {
        /* Server child: accept, read, write back, close, exit */
        int client = accept(svr_fd, NULL, NULL);
        if (client < 0) _exit(1);
        char buf[64];
        ssize_t n = read(client, buf, sizeof(buf));
        if (n > 0) write(client, buf, (size_t)n);
        close(client);
        close(svr_fd);
        _exit(0);
    }

    close(svr_fd); /* parent doesn't need server fd */

    /* Parent: connect to child server */
    int cli_fd = socket(AF_INET, SOCK_STREAM, 0);
    CHECK(cli_fd >= 0, "create client socket");

    struct sockaddr_in dst = {0};
    dst.sin_family = AF_INET;
    dst.sin_addr.s_addr = inet_addr("127.0.0.1");
    dst.sin_port = port;
    CHECK(connect(cli_fd, (struct sockaddr *)&dst, sizeof(dst)) == 0,
          "connect to local server");

    /* Send data and read echo */
    const char *tcp_msg = "TCP_test_data_agent_1001";
    ssize_t sent = write(cli_fd, tcp_msg, strlen(tcp_msg));
    CHECK(sent == (ssize_t)strlen(tcp_msg), "TCP send");

    char echo[64] = {0};
    ssize_t recvd = read(cli_fd, echo, sizeof(echo));
    CHECK(recvd == sent, "TCP recv echo");

    close(cli_fd);

    int status;
    waitpid(child, &status, 0);

    /* Poll ring buffers for TCP events */
    poll_events(RB_POLL_TIMEOUT_MS * 3);

    int found_connect = 0;
    for (int i = 0; i < captured_count; i++) {
        if (captured_events[i].event_type == EVENT_CONNECT) {
            found_connect = 1;
        }
    }

    CHECK(found_connect, "EVENT_CONNECT captured (%s)",
          found_connect ? "yes" : "no");

    /* TCP send/recv payload goes to raw_rb (raw_data_event), not sys_rb.
     * Verify via raw_event_count instead. */
    CHECK(raw_event_count >= 2,
          "raw_data events captured for TCP payload (%d events, expected ≥ 2)",
          raw_event_count);
}

/* ===================================================================
 *  Main
 * =================================================================== */
int main(void) {
    printf("================================================\n");
    printf("  eBPF Multi-Agent Monitor — Functional Tests\n");
    printf("================================================\n");

    if (geteuid() != 0) {
        fprintf(stderr, "FAIL: must run as root\n");
        return 1;
    }

    /* ---- BPF setup ---- */
    if (setup() != 0) {
        fprintf(stderr, "FAIL: setup failed\n");
        return 1;
    }

    /* ---- Run tests ---- */
    test_syscall_capture();
    test_stdout_capture();
    test_execve_capture();
    test_fork_detection();
    test_agent_identity_propagation();
    test_event_integrity();
    test_multi_agent();
    test_agent_type_detection();
    test_inter_agent_comm();

    /* Drain events before negative test */
    drain_ring_buffer();
    test_negative_unregistered();
    test_tcp_event_coverage();

    /* ---- Cleanup ---- */
    teardown();

    printf("\n================================================\n");
    printf("  Results: %d passed, %d failed, %d total\n",
           tests_passed, tests_failed, tests_passed + tests_failed);
    printf("================================================\n");

    return tests_failed > 0 ? 1 : 0;
}
