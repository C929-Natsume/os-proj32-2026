#include <stdio.h>
#include <stdarg.h>
#include <time.h>
#include <string.h>
#include "common.h"

FILE *log_file = NULL;
int enable_log = 0;

void log_print(const char *format, ...)
{
    va_list args;
    va_start(args, format);

    if (enable_log && log_file)
    {
        time_t now = time(NULL);
        struct tm *tm = localtime(&now);
        char timestamp[32];
        strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S", tm);
        
        fprintf(log_file, "[%s] ", timestamp);
        vfprintf(log_file, format, args);
        fflush(log_file);
    }

    va_end(args);
}

void print_tree_log(const char *format, ...)
{
    va_list args;
    va_start(args, format);

    if (enable_log && log_file)
    {
        time_t now = time(NULL);
        struct tm *tm = localtime(&now);
        char timestamp[32];
        strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S", tm);
        
        fprintf(log_file, "[%s] ", timestamp);
        vfprintf(log_file, format, args);
        fflush(log_file);
    }
    else
    {
        vprintf(format, args);
        fflush(stdout);
    }

    va_end(args);
}

int open_log_file(const char *filename)
{
    if (!enable_log)
        return 0;

    log_file = fopen(filename, "a");
    if (!log_file)
    {
        fprintf(stderr, "Failed to open log file: %s\n", filename);
        return -1;
    }
    return 0;
}

void close_log_file(void)
{
    if (log_file)
    {
        fclose(log_file);
        log_file = NULL;
    }
}