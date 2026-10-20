#ifndef PROC_TREE_H
#define PROC_TREE_H

#include <stdint.h>
#include "common.h"

struct proc_node
{
    uint32_t pid;
    uint32_t ppid;
    char comm[TASK_COMM_LEN];
    char exec_path[MAX_FILENAME];
    
    char last_file_created[MAX_FILENAME];
    char last_file_deleted[MAX_FILENAME];
    char last_file_read[MAX_FILENAME];
    char last_file_written[MAX_FILENAME];
    char last_file_chmod[MAX_FILENAME];
    char last_file_exec[MAX_FILENAME];
    
    __u64 bytes_read;
    __u64 bytes_written;
    __u32 last_chmod_mode;
    
    __u32 files_created_count;
    __u32 files_deleted_count;
    __u32 files_read_count;
    __u32 files_written_count;
    __u32 files_chmod_count;
    __u32 files_exec_count;
    
    struct proc_node *sibling;
    struct proc_node *child;
    struct proc_node *next_child;
};

struct proc_node *find_or_create_node(uint32_t pid);
void add_child(uint32_t parent_pid, uint32_t child_pid);
void update_exec(uint32_t pid, const char *filename, const char *comm);
void remove_node(uint32_t pid);
void update_file_create(uint32_t pid, const char *filename);
void update_file_delete(uint32_t pid, const char *filename);
void update_file_read(uint32_t pid, const char *filename, __u64 bytes);
void update_file_write(uint32_t pid, const char *filename, __u64 bytes);
void update_file_chmod(uint32_t pid, const char *filename, __u32 mode);
void update_file_exec(uint32_t pid, const char *filename);
void print_tree(struct proc_node *node, int depth);
void print_all_tree(void);
void scan_proc_directory(void);

// claude
void print_claude_tree(void);
int is_claude_related(uint32_t pid);

extern struct proc_node *proc_list;

#endif