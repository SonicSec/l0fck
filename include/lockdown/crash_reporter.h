#ifndef CRASH_REPORTER_H
#define CRASH_REPORTER_H

#include "l0fck.h"

typedef struct {
    char incident_id[64];
    char process_name[64];
    int pid;
    char exception_type[64];
    char termination_signal[64];
    uint64_t fault_address;
    char faulting_symbol[128];
    char backtrace[2048];
    bool is_objc_exception;
    bool is_memory_corruption;
    bool parsed_successfully;
} crash_triage_info_t;

typedef struct l0fck_session_s l0fck_session_t;

int crash_reporter_fetch_latest(idevice_t dev, lockdownd_client_t ld, const char *process_filter, char **out_ips, size_t *out_len);
int crash_reporter_fetch_latest_session(l0fck_session_t *sess, const char *process_filter, char **out_ips, size_t *out_len);
int crash_reporter_parse_ips(const char *ips_data, size_t len, crash_triage_info_t *out_info);
void crash_reporter_print_triage(const crash_triage_info_t *info);

#endif /* CRASH_REPORTER_H */
