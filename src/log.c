#include "log.h"

#include <stdarg.h>
#include <stdio.h>
#include <time.h>

static void vlog_with_level(const char *level, const char *fmt, va_list ap) {
    time_t now = time(NULL);
    struct tm tm_now;
    localtime_r(&now, &tm_now);
    char buf[32];
    strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M:%S", &tm_now);
    fprintf(stderr, "[%s] %s ", buf, level);
    vfprintf(stderr, fmt, ap);
    fputc('\n', stderr);
}

void log_info(const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    vlog_with_level("INFO", fmt, ap);
    va_end(ap);
}

void log_error(const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    vlog_with_level("ERROR", fmt, ap);
    va_end(ap);
}
