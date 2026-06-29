#ifndef REDIS_CLIENT_H
#define REDIS_CLIENT_H

#include <hiredis/hiredis.h>
#include "../bpf/common.h"

extern redisContext *redis_ctx;

void finish_redis_command(const char *op_name, redisReply *reply);

int redis_shipper_init(void);
void redis_shipper_close(void);
int ship_sys_event(struct sys_event *event);
int ship_ssl_event(struct probe_SSL_data_t *event);
int ship_raw_event(struct raw_data_event *event);

#endif
