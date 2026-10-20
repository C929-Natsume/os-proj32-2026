#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <dirent.h>
#include <unistd.h>
#include "proc_tree.h"
#include "common.h"

// 使用固定大小缓冲区，避免 PATH_MAX 未定义问题
#define PROC_PATH_BUF 4096

struct proc_node *proc_list = NULL;

struct proc_node *find_or_create_node(uint32_t pid)
{
    struct proc_node *cur;
    for (cur = proc_list; cur; cur = cur->sibling)
        if (cur->pid == pid)
            return cur;
    struct proc_node *n = calloc(1, sizeof(*n));
    if (!n)
        return NULL;
    n->pid = pid;
    n->sibling = proc_list;
    proc_list = n;
    return n;
}

void add_child(uint32_t parent_pid, uint32_t child_pid)
{
    struct proc_node *parent = find_or_create_node(parent_pid);
    struct proc_node *child = find_or_create_node(child_pid);
    if (!parent || !child)
        return;
    child->ppid = parent_pid;
    if (parent->comm[0] != '\0') {
        snprintf(child->comm, TASK_COMM_LEN, "%s", parent->comm);
    }
    child->next_child = parent->child;
    parent->child = child;
}

void update_exec(uint32_t pid, const char *filename, const char *comm)
{
    struct proc_node *node = find_or_create_node(pid);
    if (!node)
        return;
    snprintf(node->exec_path, MAX_FILENAME, "%s", filename);
    const char *base = strrchr(filename, '/');
    snprintf(node->comm, TASK_COMM_LEN, "%s", base ? base + 1 : filename);
}

void update_file_create(uint32_t pid, const char *filename)
{
    struct proc_node *node = find_or_create_node(pid);
    if (!node || !filename)
        return;
    snprintf(node->last_file_created, MAX_FILENAME, "%s", filename);
    node->files_created_count++;
}

void update_file_delete(uint32_t pid, const char *filename)
{
    struct proc_node *node = find_or_create_node(pid);
    if (!node || !filename)
        return;
    snprintf(node->last_file_deleted, MAX_FILENAME, "%s", filename);
    node->files_deleted_count++;
}

void update_file_read(uint32_t pid, const char *filename, __u64 bytes)
{
    struct proc_node *node = find_or_create_node(pid);
    if (!node)
        return;
    if (filename && filename[0] != '\0') {
        snprintf(node->last_file_read, MAX_FILENAME, "%s", filename);
    }
    node->bytes_read += bytes;
    node->files_read_count++;
}

void update_file_write(uint32_t pid, const char *filename, __u64 bytes)
{
    struct proc_node *node = find_or_create_node(pid);
    if (!node)
        return;
    if (filename && filename[0] != '\0') {
        snprintf(node->last_file_written, MAX_FILENAME, "%s", filename);
    }
    node->bytes_written += bytes;
    node->files_written_count++;
}

void update_file_chmod(uint32_t pid, const char *filename, __u32 mode)
{
    struct proc_node *node = find_or_create_node(pid);
    if (!node || !filename)
        return;
    snprintf(node->last_file_chmod, MAX_FILENAME, "%s", filename);
    node->last_chmod_mode = mode;
    node->files_chmod_count++;
}

void update_file_exec(uint32_t pid, const char *filename)
{
    struct proc_node *node = find_or_create_node(pid);
    if (!node || !filename)
        return;
    snprintf(node->last_file_exec, MAX_FILENAME, "%s", filename);
    node->files_exec_count++;
}

void remove_node(uint32_t pid)
{
    // 简单置标志，不释放（防止悬空指针），实际可标记为 dead
}

void scan_proc_directory(void)
{
    DIR *dir = opendir("/proc");
    if (!dir)
        return;

    struct dirent *entry;
    while ((entry = readdir(dir)) != NULL)
    {
        // 只处理数字目录（PID）
        if (!isdigit(entry->d_name[0]))
            continue;

        uint32_t pid = atoi(entry->d_name);
        if (pid == 0)
            continue;

        char stat_path[PROC_PATH_BUF];
        snprintf(stat_path, PROC_PATH_BUF, "/proc/%u/stat", pid);

        FILE *stat_file = fopen(stat_path, "r");
        if (!stat_file)
            continue;

        char comm[TASK_COMM_LEN] = {0};
        uint32_t ppid = 0;

        // 读取 stat 文件格式：pid (comm) state ppid ...
        if (fscanf(stat_file, "%*d (%[^)]) %*c %u", comm, &ppid) == 2)
        {
            // 创建或更新进程节点
            struct proc_node *node = find_or_create_node(pid);
            if (node)
            {
                node->ppid = ppid;
                snprintf(node->comm, TASK_COMM_LEN, "%s", comm);

                // 读取执行路径
                char exe_link[PROC_PATH_BUF];
                snprintf(exe_link, PROC_PATH_BUF, "/proc/%u/exe", pid);
                ssize_t len = readlink(exe_link, node->exec_path, MAX_FILENAME - 1);
                if (len > 0)
                {
                    node->exec_path[len] = '\0';
                }

                // 建立父子关系
                if (ppid != 0)
                {
                    struct proc_node *parent = find_or_create_node(ppid);
                    if (parent)
                    {
                        // 检查是否已存在子节点关系
                        int exists = 0;
                        for (struct proc_node *c = parent->child; c; c = c->next_child)
                        {
                            if (c->pid == pid)
                            {
                                exists = 1;
                                break;
                            }
                        }
                        if (!exists)
                        {
                            node->next_child = parent->child;
                            parent->child = node;
                        }
                    }
                }
            }
        }

        fclose(stat_file);
    }

    closedir(dir);
}

void print_tree(struct proc_node *node, int depth)
{
    if (!node)
        return;
    char prefix[64] = {0};
    for (int i = 0; i < depth && i < 31; i++)
        strcat(prefix, "  ");
    print_tree_log("%s├─ PID %-6d (%.15s)", prefix, node->pid, node->comm);
    if (node->exec_path[0])
        print_tree_log(" → %.255s", node->exec_path);
    
    if (node->last_file_created[0])
        print_tree_log(" [CREATE: %.63s]", node->last_file_created);
    if (node->last_file_deleted[0])
        print_tree_log(" [DELETE: %.63s]", node->last_file_deleted);
    if (node->last_file_read[0])
        print_tree_log(" [READ: %.63s (%llu bytes)]", node->last_file_read, node->bytes_read);
    else if (node->bytes_read > 0)
        print_tree_log(" [READ: %llu bytes]", node->bytes_read);
    if (node->last_file_written[0])
        print_tree_log(" [WRITE: %.63s (%llu bytes)]", node->last_file_written, node->bytes_written);
    else if (node->bytes_written > 0)
        print_tree_log(" [WRITE: %llu bytes]", node->bytes_written);
    if (node->last_file_chmod[0])
        print_tree_log(" [CHMOD: %.63s (0%o)]", node->last_file_chmod, node->last_chmod_mode);
    if (node->last_file_exec[0])
        print_tree_log(" [EXEC: %.63s]", node->last_file_exec);
    
    if (node->files_created_count > 0 || node->files_deleted_count > 0 || 
        node->files_read_count > 0 || node->files_written_count > 0 ||
        node->files_chmod_count > 0 || node->files_exec_count > 0) {
        print_tree_log(" [cnt: C=%u D=%u R=%u W=%u M=%u X=%u]",
            node->files_created_count, node->files_deleted_count,
            node->files_read_count, node->files_written_count,
            node->files_chmod_count, node->files_exec_count);
    }
    
    print_tree_log("\n");
    for (struct proc_node *c = node->child; c; c = c->next_child)
        print_tree(c, depth + 1);
}

void print_all_tree(void)
{
    print_tree_log("\n=== Full Process Tree ===\n");
    for (struct proc_node *p = proc_list; p; p = p->sibling)
    {
        int is_root = 1;
        for (struct proc_node *q = proc_list; q; q = q->sibling)
            if (q->pid == p->ppid)
            {
                is_root = 0;
                break;
            }
        if (is_root)
            print_tree(p, 0);
    }
}

// claude

static int str_contains_claude(const char *str)
{
    if (!str)
        return 0;
    char buf[MAX_FILENAME] = {0};
    for (int i = 0; str[i] && i < MAX_FILENAME - 1; i++) {
        buf[i] = tolower((unsigned char)str[i]);
    }
    return strstr(buf, "claude") != NULL;
}

// void print_claude_tree(void)
// {
//     printf("\n=== Agent Process Tree (Claude only) ===\n");
//     int found = 0;
//     for (struct proc_node *p = proc_list; p; p = p->sibling)
//     {
//         if (is_claude_in_tree(p))
//         {
//             print_tree(p, 0);
//             found = 1;
//         }
//     }
//     if (!found)
//     {
//         printf("No claude process found.\n");
//     }
// }
void print_claude_tree(void)
{
    print_tree_log("\n=== Agent Process Tree (Claude only) ===\n");
    int found = 0;
    for (struct proc_node *p = proc_list; p; p = p->sibling)
    {
        if (is_claude_related(p->pid))
        {
            int is_claude_root = 1;
            for (struct proc_node *q = proc_list; q; q = q->sibling)
                if (q->pid == p->ppid && is_claude_related(q->pid))
                {
                    is_claude_root = 0;
                    break;
                }
            if (is_claude_root)
                print_tree(p, 0);
            found = 1;
        }
    }
    if (!found)
    {
        print_tree_log("No claude process found.\n");
    }
}
static struct proc_node *find_node_by_pid(uint32_t pid)
{
    for (struct proc_node *p = proc_list; p; p = p->sibling)
        if (p->pid == pid)
            return p;
    return NULL;
}

int is_claude_related(uint32_t pid)
{
    struct proc_node *node = find_node_by_pid(pid);
    if (!node)
        return 0;

    if (str_contains_claude(node->comm) || str_contains_claude(node->exec_path))
        return 1;

    struct proc_node *parent = find_node_by_pid(node->ppid);
    while (parent && parent->pid != 0)
    {
        if (str_contains_claude(parent->comm) || str_contains_claude(parent->exec_path))
            return 1;
        parent = find_node_by_pid(parent->ppid);
    }

    return 0;
}