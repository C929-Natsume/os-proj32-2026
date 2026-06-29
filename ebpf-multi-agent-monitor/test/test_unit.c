#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "event_serializer.h"

static int tests_passed = 0;
static int tests_failed = 0;

#define TEST(name)   do { printf("  %-60s ... ", name); } while(0)
#define PASS()       do { printf("PASS\n"); tests_passed++; } while(0)
#define FAIL(fmt, ...) do { printf("FAIL: " fmt "\n", ##__VA_ARGS__); tests_failed++; } while(0)

/* ===== Agent Detection (replicate loader.c logic for testability) ===== */
static const char *g_agent_keywords[] = {
    "claude", "opencode", "openclaw", "anthropic", "codex",
    "gemini", "openai", "deepseek", "aider", "cursor", "qwen",
};
#define AGENT_KEYWORD_COUNT (sizeof(g_agent_keywords) / sizeof(g_agent_keywords[0]))

static const char *detect_agent_name(const char *cmdline) {
    if (!cmdline) return NULL;
    for (size_t k = 0; k < AGENT_KEYWORD_COUNT; k++) {
        if (strstr(cmdline, g_agent_keywords[k]) != NULL)
            return g_agent_keywords[k];
    }
    return NULL;
}

static void test_agent_detection(void) {
    printf("\n--- Agent Detection ---\n");

    TEST("claude in cmdline string");
    if (strcmp(detect_agent_name("node /usr/bin/claude"), "claude") == 0)
        PASS(); else FAIL("expected 'claude', got '%s'", detect_agent_name("node /usr/bin/claude"));

    TEST("opencode desktop");
    if (strcmp(detect_agent_name("/opt/OpenCode/ai.opencode.desktop"), "opencode") == 0)
        PASS(); else FAIL("expected 'opencode'");

    TEST("openclaw agent");
    if (strcmp(detect_agent_name("openclaw-cli"), "openclaw") == 0)
        PASS(); else FAIL("expected 'openclaw'");

    TEST("anthropic in path");
    if (strcmp(detect_agent_name(".anthropic/agent"), "anthropic") == 0)
        PASS(); else FAIL("expected 'anthropic'");

    TEST("codex CLI");
    if (strcmp(detect_agent_name("codex"), "codex") == 0)
        PASS(); else FAIL("expected 'codex'");

    TEST("gemini agent");
    if (strcmp(detect_agent_name("gemini-cli"), "gemini") == 0)
        PASS(); else FAIL("expected 'gemini'");

    TEST("bash is NOT an agent");
    if (detect_agent_name("bash /tmp/script.sh") == NULL)
        PASS(); else FAIL("bash should not match");

    TEST("python3 is NOT an agent");
    if (detect_agent_name("python3 /usr/bin/pip install") == NULL)
        PASS(); else FAIL("python3 should not match");

    TEST("empty string is NOT an agent");
    if (detect_agent_name("") == NULL)
        PASS(); else FAIL("empty string should not match");

    TEST("NULL is NOT an agent");
    if (detect_agent_name(NULL) == NULL)
        PASS(); else FAIL("NULL should not match");

    TEST("git is NOT an agent (should be excluded)");
    if (detect_agent_name("git push origin main") == NULL)
        PASS(); else FAIL("git should not match");

    TEST("count of agent keywords >= 10");
    if (AGENT_KEYWORD_COUNT >= 10)
        PASS(); else FAIL("only %zu keywords", AGENT_KEYWORD_COUNT);
}

/* ===== Path Utility Tests ===== */
static void test_path_utilities(void) {
    printf("\n--- Path Utilities ---\n");

    TEST("path_starts_with exact match");
    if (path_starts_with("/home/user/project", "/home/user/project"))
        PASS(); else FAIL("exact match failed");

    TEST("path_starts_with parent dir prefix");
    if (path_starts_with("/home/user/project/src", "/home/user/project"))
        PASS(); else FAIL("prefix match failed");

    TEST("path_starts_with no match");
    if (!path_starts_with("/tmp/other", "/home/user"))
        PASS(); else FAIL("should not match different path");

    TEST("path_starts_with root prefix");
    if (path_starts_with("/etc/passwd", "/"))
        PASS(); else FAIL("root prefix match failed");

    TEST("path_is_sensitive /etc/shadow");
    if (path_is_sensitive("/etc/shadow"))
        PASS(); else FAIL("shadow should be sensitive");

    TEST("path_is_sensitive /etc/passwd");
    if (path_is_sensitive("/etc/passwd"))
        PASS(); else FAIL("passwd should be sensitive");

    TEST("path_is_sensitive SSH private key");
    if (path_is_sensitive("/home/user/.ssh/id_rsa"))
        PASS(); else FAIL("ssh key should be sensitive");

    TEST("path_is_sensitive normal file");
    if (!path_is_sensitive("/home/user/test.txt"))
        PASS(); else FAIL("normal file should not be sensitive");

    TEST("path_is_sensitive /tmp file");
    if (!path_is_sensitive("/tmp/hello.c"))
        PASS(); else FAIL("/tmp file should not be sensitive");

    TEST("path_is_workspace_violation outside workspace");
    if (path_is_workspace_violation("/etc/shadow"))
        PASS(); else FAIL("/etc/shadow should be violation");

    TEST("path_is_workspace_violation inside workspace");
    if (!path_is_workspace_violation("/mnt/e/os2026/test.txt"))
        PASS(); else FAIL("workspace file should not be violation");
}

/* ===== JSON Escaping Tests ===== */
static void test_json_escaping(void) {
    printf("\n--- JSON Escaping ---\n");
    char buf[512];

    TEST("json_escape plain text");
    json_escape("hello world", buf, sizeof(buf));
    if (strcmp(buf, "hello world") == 0)
        PASS(); else FAIL("got '%s'", buf);

    TEST("json_escape double quote");
    json_escape("say \"hello\"", buf, sizeof(buf));
    if (strcmp(buf, "say \\\"hello\\\"") == 0)
        PASS(); else FAIL("got '%s'", buf);

    TEST("json_escape backslash");
    json_escape("a\\b", buf, sizeof(buf));
    if (strcmp(buf, "a\\\\b") == 0)
        PASS(); else FAIL("got '%s'", buf);

    TEST("json_escape newline");
    json_escape("line1\nline2", buf, sizeof(buf));
    if (strcmp(buf, "line1\\nline2") == 0)
        PASS(); else FAIL("got '%s'", buf);

    TEST("json_escape tab");
    json_escape("col1\tcol2", buf, sizeof(buf));
    if (strcmp(buf, "col1\\tcol2") == 0)
        PASS(); else FAIL("got '%s'", buf);

    TEST("json_escape control char (replaced with space)");
    {
        const char input[] = {'a', 0x01, 'b', '\0'};
        json_escape(input, buf, sizeof(buf));
        if (strcmp(buf, "a b") == 0)
            PASS(); else FAIL("got '%s'", buf);
    }

    TEST("json_escape empty string");
    json_escape("", buf, sizeof(buf));
    if (strcmp(buf, "") == 0)
        PASS(); else FAIL("got '%s'", buf);

    TEST("json_escape_bytes binary with null");
    {
        const unsigned char bin[] = {'A', 0x00, 'B', '\n'};
        json_escape_bytes((const char *)bin, 4, buf, sizeof(buf));
        if (strlen(buf) > 2)
            PASS(); else FAIL("got '%s'", buf);
    }
}

/* ===== Lowercase Tests ===== */
static void test_lowercase(void) {
    printf("\n--- Lowercase Conversion ---\n");
    char buf[256];

    TEST("lowercase_copy ALL CAPS");
    lowercase_copy("HELLO WORLD", buf, sizeof(buf));
    if (strcmp(buf, "hello world") == 0)
        PASS(); else FAIL("got '%s'", buf);

    TEST("lowercase_copy Mixed Case");
    lowercase_copy("OpenCode Agent", buf, sizeof(buf));
    if (strcmp(buf, "opencode agent") == 0)
        PASS(); else FAIL("got '%s'", buf);

    TEST("lowercase_copy already lowercase");
    lowercase_copy("hello", buf, sizeof(buf));
    if (strcmp(buf, "hello") == 0)
        PASS(); else FAIL("got '%s'", buf);

    TEST("lowercase_copy empty string");
    lowercase_copy("", buf, sizeof(buf));
    if (strcmp(buf, "") == 0)
        PASS(); else FAIL("got '%s'", buf);

    TEST("lowercase_copy with numbers");
    lowercase_copy("Agent42", buf, sizeof(buf));
    if (strcmp(buf, "agent42") == 0)
        PASS(); else FAIL("got '%s'", buf);
}

/* ===== Event Type Tests ===== */
static void test_event_types(void) {
    printf("\n--- Event Type Names ---\n");

    TEST("event_stream_type EXECVE(1)");
    if (event_stream_type(1) != NULL)
        PASS(); else FAIL("returned NULL");

    TEST("event_stream_type FORK(2)");
    if (event_stream_type(2) != NULL)
        PASS(); else FAIL("returned NULL");

    TEST("event_stream_type CONNECT(5)");
    if (event_stream_type(5) != NULL)
        PASS(); else FAIL("returned NULL");

    TEST("event_stream_type STDIO_READ(10)");
    if (event_stream_type(10) != NULL)
        PASS(); else FAIL("returned NULL");

    TEST("event_stream_type unknown");
    if (event_stream_type(99) != NULL)
        PASS(); else FAIL("returned NULL");

    TEST("get_behavior_name EXECVE");
    if (get_behavior_name(1) != NULL)
        PASS(); else FAIL("returned NULL");

    TEST("get_behavior_name CONNECT");
    if (get_behavior_name(5) != NULL)
        PASS(); else FAIL("returned NULL");
}

/* ===== bounded_strnlen Tests ===== */
static void test_bounded_strnlen(void) {
    printf("\n--- Bounded String Length ---\n");

    TEST("shorter than max");
    if (bounded_strnlen_local("hello", 10) == 5)
        PASS(); else FAIL("got %zu", bounded_strnlen_local("hello", 10));

    TEST("exactly max");
    if (bounded_strnlen_local("hello", 5) == 5)
        PASS(); else FAIL("got %zu", bounded_strnlen_local("hello", 5));

    TEST("truncated by max");
    if (bounded_strnlen_local("hello world", 5) == 5)
        PASS(); else FAIL("got %zu", bounded_strnlen_local("hello world", 5));

    TEST("empty string");
    if (bounded_strnlen_local("", 10) == 0)
        PASS(); else FAIL("got %zu", bounded_strnlen_local("", 10));

    TEST("NULL pointer");
    if (bounded_strnlen_local(NULL, 10) == 0)
        PASS(); else FAIL("got %zu", bounded_strnlen_local(NULL, 10));

    TEST("max = 0");
    if (bounded_strnlen_local("hello", 0) == 0)
        PASS(); else FAIL("got %zu", bounded_strnlen_local("hello", 0));
}

/* ===== Format IPv4 Tests ===== */
static void test_format_ipv4(void) {
    printf("\n--- IPv4 Formatting ---\n");
    char buf[64];

    TEST("format_ipv4 loopback");
    {
        const char raw[46] = {127, 0, 0, 1};
        format_ipv4(raw, buf, sizeof(buf));
        if (strcmp(buf, "127.0.0.1") == 0)
            PASS(); else FAIL("got '%s'", buf);
    }

    TEST("format_ipv4 local network");
    {
        const char raw[46] = {192, 168, 1, 100};
        format_ipv4(raw, buf, sizeof(buf));
        if (strcmp(buf, "192.168.1.100") == 0)
            PASS(); else FAIL("got '%s'", buf);
    }
}

/* ===== Sanitize Component Tests ===== */
static void test_sanitize(void) {
    printf("\n--- Sanitize Component ---\n");
    char buf[128];

    TEST("sanitize_component (hyphen->underscore, no lowercase)");
    sanitize_component("Claude-1001", buf, sizeof(buf));
    if (strcmp(buf, "Claude_1001") == 0)
        PASS(); else FAIL("got '%s'", buf);

    TEST("sanitize_component with special chars");
    sanitize_component("Sys/Agent:test", buf, sizeof(buf));
    if (strstr(buf, "_") != NULL)
        PASS(); else FAIL("got '%s'", buf);
}

/* ===== Main ===== */
int main(void) {
    printf("============================================\n");
    printf("  eBPF Multi-Agent Monitor — Unit Tests\n");
    printf("============================================\n");

    test_agent_detection();
    test_path_utilities();
    test_json_escaping();
    test_lowercase();
    test_event_types();
    test_bounded_strnlen();
    test_format_ipv4();
    test_sanitize();

    printf("\n============================================\n");
    printf("  Results: %d passed, %d failed, %d total\n",
           tests_passed, tests_failed, tests_passed + tests_failed);
    printf("============================================\n");

    return tests_failed > 0 ? 1 : 0;
}
