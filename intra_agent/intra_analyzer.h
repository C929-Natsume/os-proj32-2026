#ifndef INTRA_ANALYZER_H
#define INTRA_ANALYZER_H

#include "common.h"

void intra_init(void);
void intra_on_proc_event(const struct proc_event *e);
void intra_on_fs_event(const struct fs_event *e);
void intra_on_net_event(const struct net_event *e);

#endif
