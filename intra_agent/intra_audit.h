#ifndef INTRA_AUDIT_H
#define INTRA_AUDIT_H

#include "common.h"

enum audit_severity
{
    AUDIT_SEV_LOW = 1,
    AUDIT_SEV_MEDIUM = 2,
    AUDIT_SEV_HIGH = 3,
};

struct audit_req
{
    unsigned long long req_id;
    __u64 timestamp_ns;
    __u32 pid;
    __u32 tid;
    const char *comm;
    const char *rule;
    const char *object;
    const char *reason;
    enum audit_severity severity;
};

void intra_audit_init(const char *workspace_root);
void intra_audit_submit(const struct audit_req *req);

#endif
