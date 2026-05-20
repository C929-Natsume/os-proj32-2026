#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <dirent.h>
#include <unistd.h>
#include "proc_tree.h"

// 使用固定大小缓冲区，避免 PATH_MAX 未定义问题
#define PROC_PATH_BUF 4096

struct proc_node *proc_list = NULL;

static struct proc_node *find_node_by_pid(uint32_t pid)
{
    for (struct proc_node *p = proc_list; p; p = p->sibling)
        if (p->pid == pid && p->alive)
            return p;
    return NULL;
}

static void unlink_child_from_parent(struct proc_node *parent, struct proc_node *child)
{
    if (!parent || !child)
        return;

    struct proc_node **slot = &parent->child;
    while (*slot)
    {
        if (*slot == child)
        {
            *slot = child->next_child;
            child->next_child = NULL;
            return;
        }
        slot = &(*slot)->next_child;
    }
}

static void link_child_once(struct proc_node *parent, struct proc_node *child)
{
    if (!parent || !child)
        return;

    for (struct proc_node *c = parent->child; c; c = c->next_child)
    {
        if (c == child)
            return;
    }

    child->next_child = parent->child;
    parent->child = child;
}

struct proc_node *find_or_create_node(uint32_t pid)
{
    struct proc_node *cur;
    for (cur = proc_list; cur; cur = cur->sibling)
    {
        if (cur->pid != pid)
            continue;

        if (!cur->alive)
        {
            cur->ppid = 0;
            cur->comm[0] = '\0';
            cur->exec_path[0] = '\0';
            cur->child = NULL;
            cur->next_child = NULL;
        }
        cur->alive = 1;
        return cur;
    }
    struct proc_node *n = calloc(1, sizeof(*n));
    if (!n)
        return NULL;
    n->pid = pid;
    n->alive = 1;
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

    if (child->ppid != 0 && child->ppid != parent_pid)
    {
        struct proc_node *old_parent = find_node_by_pid(child->ppid);
        unlink_child_from_parent(old_parent, child);
    }

    child->ppid = parent_pid;
    link_child_once(parent, child);
}

void update_exec(uint32_t pid, const char *filename)
{
    struct proc_node *node = find_or_create_node(pid);
    if (!node)
        return;
    snprintf(node->exec_path, MAX_FILENAME, "%s", filename);
    const char *base = strrchr(filename, '/');
    snprintf(node->comm, TASK_COMM_LEN, "%s", base ? base + 1 : filename);
}

void remove_node(uint32_t pid)
{
    struct proc_node *node = find_node_by_pid(pid);
    if (!node)
        return;

    if (node->ppid != 0)
    {
        struct proc_node *parent = find_node_by_pid(node->ppid);
        unlink_child_from_parent(parent, node);
    }

    for (struct proc_node *c = node->child; c;)
    {
        struct proc_node *next = c->next_child;
        c->ppid = 0;
        c->next_child = NULL;
        c = next;
    }

    node->child = NULL;
    node->next_child = NULL;
    node->ppid = 0;
    node->comm[0] = '\0';
    node->exec_path[0] = '\0';
    node->alive = 0;
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
                if (node->ppid != 0 && node->ppid != ppid)
                {
                    struct proc_node *old_parent = find_node_by_pid(node->ppid);
                    unlink_child_from_parent(old_parent, node);
                }
                node->ppid = ppid;
                node->alive = 1;
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
                            link_child_once(parent, node);
                        }
                    }
                }
            }
        }

        fclose(stat_file);
    }

    closedir(dir);
}

static int is_claude_in_tree(struct proc_node *node)
{
    if (!node || !node->alive)
        return 0;
    if (strstr(node->comm, "claude") || strstr(node->exec_path, "claude"))
        return 1;
    for (struct proc_node *c = node->child; c; c = c->next_child)
        if (is_claude_in_tree(c))
            return 1;
    return 0;
}

void print_tree(struct proc_node *node, int depth)
{
    if (!node || !node->alive)
        return;
    for (int i = 0; i < depth; i++)
        printf("  ");
    printf("├─ PID %-6d (%.15s)", node->pid, node->comm);
    if (node->exec_path[0])
        printf(" → %.255s", node->exec_path);
    printf("\n");
    for (struct proc_node *c = node->child; c; c = c->next_child)
        print_tree(c, depth + 1);
}

void print_all_tree(void)
{
    printf("\n=== Full Process Tree ===\n");
    for (struct proc_node *p = proc_list; p; p = p->sibling)
    {
        if (!p->alive)
            continue;
        int is_root = 1;
        for (struct proc_node *q = proc_list; q; q = q->sibling)
            if (q->alive && q->pid == p->ppid)
            {
                is_root = 0;
                break;
            }
        if (is_root)
            print_tree(p, 0);
    }
}

// claude

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
    printf("\n=== Agent Process Tree (Claude only) ===\n");
    int found = 0;
    for (struct proc_node *p = proc_list; p; p = p->sibling)
    {
        if (!p->alive)
            continue;
        // 只关心自身就是 claude 的节点
        if (strstr(p->comm, "claude") || strstr(p->exec_path, "claude"))
        {
            print_tree(p, 0);
            found = 1;
        }
    }
    if (!found)
    {
        printf("No claude process found.\n");
    }
}
int is_claude_related(uint32_t pid)
{
    struct proc_node *node = find_node_by_pid(pid);
    if (!node)
        return 0;

    // 如果当前进程本身是 claude
    if (strstr(node->comm, "claude") || strstr(node->exec_path, "claude"))
        return 1;

    // 如果是 claude 进程的子进程
    if (is_claude_in_tree(node))
        return 1;

    // 如果祖先节点是 claude
    struct proc_node *parent = find_node_by_pid(node->ppid);
    while (parent && parent->pid != 0)
    {
        if (strstr(parent->comm, "claude") || strstr(parent->exec_path, "claude"))
            return 1;
        parent = find_node_by_pid(parent->ppid);
    }

    return 0;
}
