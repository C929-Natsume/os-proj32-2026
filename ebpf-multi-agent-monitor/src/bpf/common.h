#ifndef COMMON_H
#define COMMON_H

#define MAX_COMM_LEN 16
#define MAX_PATH_LEN 512

enum event_type {
    EVENT_EXECVE = 1,
    EVENT_FORK,
    EVENT_OPEN,
    EVENT_UNLINK,
    EVENT_CONNECT,
    EVENT_SSL_READ,
    EVENT_SSL_WRITE,
    EVENT_CHMOD
};

#include "sys_behavior.h"
#include "ssl_sniffer.h"

#endif