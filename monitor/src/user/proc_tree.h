#ifndef PROC_TREE_H
#define PROC_TREE_H

#include <stdint.h>
#include "common.h"

struct proc_node
{
    uint32_t pid;
    uint32_t ppid;
    int alive;
    char comm[TASK_COMM_LEN];
    char exec_path[MAX_FILENAME];
    struct proc_node *sibling;
    struct proc_node *child;
    struct proc_node *next_child;
};

struct proc_node *find_or_create_node(uint32_t pid);
void add_child(uint32_t parent_pid, uint32_t child_pid);
void update_exec(uint32_t pid, const char *filename);
void remove_node(uint32_t pid);
void print_tree(struct proc_node *node, int depth);
void print_all_tree(void);
void scan_proc_directory(void);

// claude
void print_claude_tree(void);
int is_claude_related(uint32_t pid);

extern struct proc_node *proc_list;

#endif
