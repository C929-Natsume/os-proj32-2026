#ifndef EVENT_SERIALIZER_H
#define EVENT_SERIALIZER_H

#include <stddef.h>
#include <linux/types.h>

#define MAX_UNIQUE_FILES 64

struct agent_metrics {
    double cpu_usage;
    double memory_usage;
    unsigned int proc_exec_count;
    unsigned int proc_fork_count;
    unsigned int fs_open_count;
    unsigned int fs_read_count;
    unsigned int fs_write_count;
    unsigned int fs_unlink_count;
    unsigned int net_connect_count;
    unsigned int net_send_count;
    unsigned int net_recv_count;
    unsigned int api_call_count;
    unsigned int msg_sent_count;
    unsigned int msg_recv_count;
    unsigned int shell_exec_count;
    unsigned int sensitive_file_count;
    unsigned int workspace_violation;
    unsigned int unique_files_count;
    unsigned int fs_chmod_count;
    unsigned int ssl_msg_count;
    unsigned long long ssl_total_bytes;
    unsigned long long window_start_ns;
    unsigned long long last_active_ns;
    char unique_files[MAX_UNIQUE_FILES][512];
};

void json_escape_bytes(const char *src, size_t src_len, char *dst, size_t dst_len);
void json_escape(const char *src, char *dst, size_t dst_len);
void shell_escape_bytes(const char *src, size_t src_len, char *dst, size_t dst_len);
void shell_escape(const char *src, char *dst, size_t dst_len);
void lowercase_copy(const char *src, char *dst, size_t dst_len);
void sanitize_component(const char *src, char *dst, size_t dst_len);
void format_ipv4(const char raw[46], char *out, size_t out_len);
void base64_encode(const unsigned char *src, size_t len, char *out);
size_t bounded_strnlen_local(const char *src, size_t max_len);
int path_starts_with(const char *path, const char *prefix);
int path_is_sensitive(const char *path);
int path_is_workspace_violation(const char *path);
void remember_unique_file(struct agent_metrics *metrics, const char *path);

const char *event_stream_type(unsigned int event_type);
const char *event_stream_subtype(unsigned int event_type);
const char *get_behavior_name(uint32_t type);
const char *workspace_root(void);

#endif
