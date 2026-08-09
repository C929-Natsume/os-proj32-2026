#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <ctype.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <linux/types.h>
#include "../bpf/common.h"
#include "event_serializer.h"

const char *workspace_root(void)
{
    static const char *g_workspace_root = NULL;
    if (g_workspace_root && g_workspace_root[0]) {
        return g_workspace_root;
    }
    g_workspace_root = getenv("MONITOR_WORKSPACE");
    if (!g_workspace_root || !g_workspace_root[0]) {
        g_workspace_root = "/mnt/e/os2026";
    }
    return g_workspace_root;
}

size_t bounded_strnlen_local(const char *src, size_t max_len)
{
    size_t si = 0;
    if (!src) return 0;
    while (si < max_len && src[si] != '\0') si++;
    return si;
}

void json_escape_bytes(const char *src, size_t src_len, char *dst, size_t dst_len)
{
    size_t si = 0, di = 0;
    if (!dst || dst_len == 0) return;
    if (!src) { dst[0] = '\0'; return; }

    while (si < src_len && di + 1 < dst_len) {
        unsigned char c = (unsigned char)src[si++];
        if (c == '\\' || c == '"') {
            if (di + 2 >= dst_len) break;
            dst[di++] = '\\'; dst[di++] = (char)c;
            continue;
        }
        if (c == '\n') { if (di + 2 >= dst_len) break; dst[di++] = '\\'; dst[di++] = 'n'; continue; }
        if (c == '\r') { if (di + 2 >= dst_len) break; dst[di++] = '\\'; dst[di++] = 'r'; continue; }
        if (c == '\t') { if (di + 2 >= dst_len) break; dst[di++] = '\\'; dst[di++] = 't'; continue; }
        if (iscntrl(c)) { dst[di++] = ' '; continue; }
        if (c > 127) { dst[di++] = '.'; continue; }
        dst[di++] = (char)c;
    }
    dst[di] = '\0';
}

void json_escape(const char *src, char *dst, size_t dst_len)
{
    json_escape_bytes(src, src ? strlen(src) : 0, dst, dst_len);
}

void shell_escape_bytes(const char *src, size_t src_len, char *dst, size_t dst_len)
{
    size_t si = 0, di = 0;
    if (!dst || dst_len == 0) return;
    if (!src) { dst[0] = '\0'; return; }

    while (si < src_len && di + 1 < dst_len) {
        unsigned char c = (unsigned char)src[si++];
        if (c == '\\' || c == '"' || c == '$' || c == '`') {
            if (di + 2 >= dst_len) break;
            dst[di++] = '\\'; dst[di++] = (char)c;
            continue;
        }
        if (c == '\n' || c == '\r' || c == '\t' || iscntrl(c)) { dst[di++] = ' '; continue; }
        dst[di++] = (char)c;
    }
    dst[di] = '\0';
}

void shell_escape(const char *src, char *dst, size_t dst_len)
{
    shell_escape_bytes(src, src ? strlen(src) : 0, dst, dst_len);
}

void lowercase_copy(const char *src, char *dst, size_t dst_len)
{
    size_t i = 0;
    if (!dst || dst_len == 0) return;
    if (!src) { dst[0] = '\0'; return; }
    while (src[i] != '\0' && i + 1 < dst_len) {
        dst[i] = (char)tolower((unsigned char)src[i]);
        i++;
    }
    dst[i] = '\0';
}

void sanitize_component(const char *src, char *dst, size_t dst_len)
{
    size_t si = 0, di = 0;
    if (!dst || dst_len == 0) return;
    while (src && src[si] != '\0' && di + 1 < dst_len) {
        unsigned char c = (unsigned char)src[si++];
        dst[di++] = isalnum(c) ? (char)c : '_';
    }
    dst[di] = '\0';
}

void format_ipv4(const char raw[46], char *out, size_t out_len)
{
    const unsigned char *ip = (const unsigned char *)raw;
    if (!out || out_len == 0) return;
    snprintf(out, out_len, "%u.%u.%u.%u", ip[0], ip[1], ip[2], ip[3]);
}

void base64_encode(const unsigned char *src, size_t len, char *out)
{
    const char b64chars[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    size_t i, j = 0;
    for (i = 0; i < len; i += 3) {
        uint32_t n = ((uint32_t)src[i] << 16) |
                     ((i + 1 < len ? (uint32_t)src[i + 1] : 0) << 8) |
                     (i + 2 < len ? (uint32_t)src[i + 2] : 0);
        out[j++] = b64chars[(n >> 18) & 0x3F];
        out[j++] = b64chars[(n >> 12) & 0x3F];
        out[j++] = (i + 1 < len) ? b64chars[(n >> 6) & 0x3F] : '=';
        out[j++] = (i + 2 < len) ? b64chars[n & 0x3F] : '=';
    }
    out[j] = '\0';
}

int path_starts_with(const char *path, const char *prefix)
{
    size_t prefix_len;
    if (!path || !prefix) return 0;
    prefix_len = strlen(prefix);
    if (prefix_len == 0) return 0;
    return strncmp(path, prefix, prefix_len) == 0;
}

int path_is_sensitive(const char *path)
{
    static const char *markers[] = {
        "/etc/shadow", "/etc/passwd", "/etc/sudoers",
        "/var/run/docker.sock", "/.ssh/", "/.aws/credentials",
        "/.kube/config", ".env",
    };
    size_t i;
    if (!path || !path[0]) return 0;
    for (i = 0; i < sizeof(markers) / sizeof(markers[0]); i++) {
        if (strstr(path, markers[i]) != NULL) return 1;
    }
    return 0;
}

int path_is_workspace_violation(const char *path)
{
    if (!path || !path[0] || path[0] != '/') return 0;
    if (path_starts_with(path, workspace_root())) return 0;
    if (path_starts_with(path, "/tmp/") || path_starts_with(path, "/var/tmp/")) return 0;
    return 1;
}

void remember_unique_file(struct agent_metrics *metrics, const char *path)
{
    unsigned int i;
    if (!metrics || !path || !path[0]) return;
    for (i = 0; i < metrics->unique_files_count && i < MAX_UNIQUE_FILES; i++) {
        if (strncmp(metrics->unique_files[i], path, 512) == 0) return;
    }
    if (metrics->unique_files_count < MAX_UNIQUE_FILES) {
        strncpy(metrics->unique_files[metrics->unique_files_count], path, 511);
        metrics->unique_files[metrics->unique_files_count][511] = '\0';
        metrics->unique_files_count++;
    }
}

const char *event_stream_type(unsigned int event_type)
{
    switch (event_type) {
    case EVENT_EXECVE:
    case EVENT_FORK:
        return "proc";
    case EVENT_OPEN:
    case EVENT_UNLINK:
    case EVENT_CHMOD:
        return "fs";
    case EVENT_CONNECT:
    case EVENT_SSL_READ:
    case EVENT_SSL_WRITE:
    case EVENT_AGENT_COMM:
    case EVENT_TCP_SEND:
    case EVENT_TCP_RECV:
        return "net";
    case EVENT_STDIO_READ:
    case EVENT_STDIO_WRITE:
        return "proc";
    default:
        return "unknown";
    }
}

const char *event_stream_subtype(unsigned int event_type)
{
    switch (event_type) {
    case EVENT_EXECVE:  return "PROC_EXEC";
    case EVENT_FORK:    return "PROC_FORK";
    case EVENT_OPEN:    return "FS_OPEN";
    case EVENT_UNLINK:  return "FS_UNLINK";
    case EVENT_CONNECT: return "NET_CONNECT";
    case EVENT_AGENT_COMM: return "AGENT_COMM";
    case EVENT_SSL_READ: return "NET_RECV";
    case EVENT_SSL_WRITE: return "NET_SEND";
    case EVENT_CHMOD:   return "FS_CHMOD";
    case EVENT_STDIO_READ: return "STDIO_READ";
    case EVENT_STDIO_WRITE: return "STDIO_WRITE";
    case EVENT_TCP_SEND: return "TCP_SEND";
    case EVENT_TCP_RECV: return "TCP_RECV";
    default: return "UNKNOWN";
    }
}

const char *get_behavior_name(uint32_t type)
{
    switch (type) {
    case EVENT_EXECVE:    return "PROCESS_EXECUTE";
    case EVENT_FORK:      return "PROCESS_FORK";
    case EVENT_OPEN:      return "FILE_OPEN";
    case EVENT_UNLINK:    return "FILE_DELETE";
    case EVENT_CONNECT:   return "NETWORK_CONNECT";
    case EVENT_AGENT_COMM: return "AGENT_COMMUNICATION";
    case EVENT_SSL_READ:  return "SSL_RECEIVE_RESPONSE";
    case EVENT_SSL_WRITE: return "SSL_SEND_PROMPT";
    case EVENT_CHMOD:     return "PERMISSION_CHANGE";
    case EVENT_STDIO_READ: return "STDIO_READ";
    case EVENT_STDIO_WRITE: return "STDIO_WRITE";
    case EVENT_TCP_SEND:  return "TCP_PLAINTEXT_SEND";
    case EVENT_TCP_RECV:  return "TCP_PLAINTEXT_RECV";
    case EVENT_AGENT_DISCOVERY: return "AGENT_BEHAVIORAL_DISCOVERY";
    default: return "UNKNOWN_BEHAVIOR";
    }
}
