#include "core/log.h"
#include <stdarg.h>
#include <time.h>

int g_verbose = 0;

void log_init(int verbose)
{
    g_verbose = verbose;
}

static void print_prefix(const char *color, const char *level_tag)
{
    time_t rawtime;
    struct tm *timeinfo;
    char time_str[16];

    time(&rawtime);
    timeinfo = localtime(&rawtime);
    strftime(time_str, sizeof(time_str), "%H:%M:%S", timeinfo);

    printf("[%s] %s[%s]%s ", time_str, color, level_tag, ANSI_COLOR_RESET);
}

void log_info(const char *fmt, ...)
{
    va_list args;
    print_prefix(ANSI_COLOR_BLUE, "INFO");
    va_start(args, fmt);
    vprintf(fmt, args);
    va_end(args);
    printf("\n");
    fflush(stdout);
}

void log_success(const char *fmt, ...)
{
    va_list args;
    print_prefix(ANSI_COLOR_GREEN, "SUCCESS");
    va_start(args, fmt);
    vprintf(fmt, args);
    va_end(args);
    printf("\n");
    fflush(stdout);
}

void log_warn(const char *fmt, ...)
{
    va_list args;
    print_prefix(ANSI_COLOR_YELLOW, "WARN");
    va_start(args, fmt);
    vprintf(fmt, args);
    va_end(args);
    printf("\n");
    fflush(stdout);
}

void log_error(const char *fmt, ...)
{
    va_list args;
    print_prefix(ANSI_COLOR_RED, "ERROR");
    va_start(args, fmt);
    vfprintf(stderr, fmt, args);
    va_end(args);
    fprintf(stderr, "\n");
    fflush(stderr);
}

void log_debug(const char *fmt, ...)
{
    if (!g_verbose) return;
    va_list args;
    print_prefix(ANSI_COLOR_CYAN, "DEBUG");
    va_start(args, fmt);
    vprintf(fmt, args);
    va_end(args);
    printf("\n");
    fflush(stdout);
}

void log_raw(const char *fmt, ...)
{
    va_list args;
    va_start(args, fmt);
    vprintf(fmt, args);
    va_end(args);
    fflush(stdout);
}
