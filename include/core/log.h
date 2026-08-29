#ifndef CORE_LOG_H
#define CORE_LOG_H

#include <stdio.h>
#include <stdbool.h>

extern int g_verbose;

/* ANSI Color Codes */
#define ANSI_COLOR_RED     "\x1b[31m"
#define ANSI_COLOR_GREEN   "\x1b[32m"
#define ANSI_COLOR_YELLOW  "\x1b[33m"
#define ANSI_COLOR_BLUE    "\x1b[34m"
#define ANSI_COLOR_MAGENTA "\x1b[35m"
#define ANSI_COLOR_CYAN    "\x1b[36m"
#define ANSI_COLOR_BOLD    "\x1b[1m"
#define ANSI_COLOR_RESET   "\x1b[0m"

void log_init(int verbose);
void log_info(const char *fmt, ...);
void log_success(const char *fmt, ...);
void log_warn(const char *fmt, ...);
void log_error(const char *fmt, ...);
void log_debug(const char *fmt, ...);
void log_raw(const char *fmt, ...);

#define LOG_INFO(...)    log_info(__VA_ARGS__)
#define LOG_SUCCESS(...) log_success(__VA_ARGS__)
#define LOG_WARN(...)    log_warn(__VA_ARGS__)
#define LOG_ERROR(...)   log_error(__VA_ARGS__)
#define LOG_DEBUG(...)   log_debug(__VA_ARGS__)

#endif /* CORE_LOG_H */
