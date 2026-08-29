#include "l0fck.h"
#include "lockdown/crash_reporter.h"
#include "lockdown/afc_manager.h"
#include "lockdown/session_manager.h"
#include "core/log.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int crash_reporter_parse_ips(const char *ips_data, size_t len, crash_triage_info_t *out_info)
{
    if (!ips_data || len == 0 || !out_info) return -1;
    memset(out_info, 0, sizeof(crash_triage_info_t));

    /* Search for Incident ID */
    const char *p = strstr(ips_data, "\"incident_id\":\"");
    if (p) {
        p += 15;
        const char *end = strchr(p, '"');
        if (end) {
            size_t n = end - p;
            if (n >= sizeof(out_info->incident_id)) n = sizeof(out_info->incident_id) - 1;
            strncpy(out_info->incident_id, p, n);
        }
    }

    /* Search for Process Name */
    p = strstr(ips_data, "\"procName\":\"");
    if (!p) p = strstr(ips_data, "\"procName\" : \"");
    if (!p) p = strstr(ips_data, "\"app_name\":\"");
    if (p) {
        p = strchr(p, ':');
        if (p) {
            p = strchr(p, '"');
            if (p) {
                p++;
                const char *end = strchr(p, '"');
                if (end) {
                    size_t n = end - p;
                    if (n >= sizeof(out_info->process_name)) n = sizeof(out_info->process_name) - 1;
                    strncpy(out_info->process_name, p, n);
                }
            }
        }
    }

    /* Search for PID */
    p = strstr(ips_data, "\"pid\" : ");
    if (!p) p = strstr(ips_data, "\"pid\":");
    if (p) {
        p = strchr(p, ':');
        if (p) {
            out_info->pid = atoi(p + 1);
        }
    }

    /* Search for Exception Type */
    p = strstr(ips_data, "\"type\":\"");
    if (!p) p = strstr(ips_data, "\"type\" : \"");
    if (p) {
        p = strchr(p, ':');
        if (p) {
            p = strchr(p, '"');
            if (p) {
                p++;
                const char *end = strchr(p, '"');
                if (end) {
                    size_t n = end - p;
                    if (n >= sizeof(out_info->exception_type)) n = sizeof(out_info->exception_type) - 1;
                    strncpy(out_info->exception_type, p, n);
                }
            }
        }
    }

    /* Search for Signal / Termination */
    p = strstr(ips_data, "\"signal\":\"");
    if (!p) p = strstr(ips_data, "\"signal\" : \"");
    if (!p) p = strstr(ips_data, "\"indicator\":\"");
    if (p) {
        p = strchr(p, ':');
        if (p) {
            p = strchr(p, '"');
            if (p) {
                p++;
                const char *end = strchr(p, '"');
                if (end) {
                    size_t n = end - p;
                    if (n >= sizeof(out_info->termination_signal)) n = sizeof(out_info->termination_signal) - 1;
                    strncpy(out_info->termination_signal, p, n);
                }
            }
        }
    }

    /* Check for ObjC Exception vs Memory Corruption */
    if (strstr(ips_data, "objc_exception_throw") || strstr(ips_data, "__exceptionPreprocess") ||
        strstr(ips_data, "NSInvalidArgumentException") || strstr(ips_data, "unrecognized selector")) {
        out_info->is_objc_exception = true;
    }

    if (strstr(ips_data, "EXC_BAD_ACCESS") || strstr(ips_data, "KERN_INVALID_ADDRESS") ||
        strstr(ips_data, "SIGSEGV") || strstr(ips_data, "SIGBUS")) {
        out_info->is_memory_corruption = true;
    }

    /* Extract Backtrace snippet */
    p = strstr(ips_data, "\"asiBacktraces\"");
    if (!p) p = strstr(ips_data, "\"lastExceptionBacktrace\"");
    if (!p) p = strstr(ips_data, "\"frames\"");
    if (p) {
        const char *end = strstr(p, "]}");
        if (!end) end = p + 512;
        size_t n = end - p;
        if (n >= sizeof(out_info->backtrace)) n = sizeof(out_info->backtrace) - 1;
        strncpy(out_info->backtrace, p, n);
    }

    out_info->parsed_successfully = (strlen(out_info->process_name) > 0 || strlen(out_info->exception_type) > 0);
    return out_info->parsed_successfully ? 0 : -1;
}

void crash_reporter_print_triage(const crash_triage_info_t *info)
{
    if (!info) return;

    printf("\n" ANSI_COLOR_BOLD ANSI_COLOR_MAGENTA "==================== AUTOMATED CRASH TRIAGE REPORT ====================" ANSI_COLOR_RESET "\n");
    printf("Incident ID:        %s\n", info->incident_id[0] ? info->incident_id : "N/A");
    printf("Faulting Process:   " ANSI_COLOR_BOLD ANSI_COLOR_CYAN "%s" ANSI_COLOR_RESET " (PID: %d)\n",
           info->process_name[0] ? info->process_name : "unknown", info->pid);
    printf("Exception Type:     " ANSI_COLOR_RED "%s" ANSI_COLOR_RESET "\n",
           info->exception_type[0] ? info->exception_type : "EXC_CRASH / UNKNOWN");
    printf("Termination Signal: %s\n", info->termination_signal[0] ? info->termination_signal : "SIGABRT");
    
    printf("Vulnerability Type: ");
    if (info->is_objc_exception) {
        printf(ANSI_COLOR_YELLOW ANSI_COLOR_BOLD "Type Confusion / Uncaught ObjC Exception" ANSI_COLOR_RESET "\n");
        printf("Analysis:           Missing manifest presence/type validation before selector invocation.\n");
    } else if (info->is_memory_corruption) {
        printf(ANSI_COLOR_RED ANSI_COLOR_BOLD "Memory Corruption / Memory Access Violation" ANSI_COLOR_RESET "\n");
        printf("Analysis:           Out-of-bounds dereference or invalid pointer access during manifest unpack.\n");
    } else {
        printf(ANSI_COLOR_CYAN "Privileged Daemon Crash / DoS" ANSI_COLOR_RESET "\n");
        printf("Analysis:           Unexpected termination in pre-boot cryptographic stashbag daemon.\n");
    }

    if (info->backtrace[0]) {
        printf("\n" ANSI_COLOR_BOLD "Backtrace Telemetry:" ANSI_COLOR_RESET "\n");
        printf("%s\n", info->backtrace);
    }
    printf(ANSI_COLOR_MAGENTA "========================================================================" ANSI_COLOR_RESET "\n\n");
}

int crash_reporter_fetch_latest(idevice_t dev, lockdownd_client_t ld, const char *process_filter, char **out_ips, size_t *out_len)
{
    if (!dev || !ld || !out_ips || !out_len) return -1;
    *out_ips = NULL;
    *out_len = 0;

    LOG_INFO("Connecting to com.apple.crashreportcopymobile service...");

    lockdownd_service_descriptor_t desc = NULL;
    lockdownd_error_t lerr = lockdownd_start_service(ld, "com.apple.crashreportcopymobile", &desc);
    if (lerr == LOCKDOWN_E_SESSION_INACTIVE) {
        lerr = lockdownd_start_service_with_escrow_bag(ld, "com.apple.crashreportcopymobile", &desc);
    }
    
    afc_client_t crash_afc = NULL;
    if (lerr == LOCKDOWN_E_SUCCESS && desc) {
        afc_client_new(dev, desc, &crash_afc);
        lockdownd_service_descriptor_free(desc);
        desc = NULL;
    }

    /* If crashreportcopymobile is blocked, fallback to standard AFC */
    if (!crash_afc) {
        LOG_INFO("Falling back to standard com.apple.afc for crash log discovery...");
        lerr = lockdownd_start_service(ld, "com.apple.afc", &desc);
        if (lerr == LOCKDOWN_E_SESSION_INACTIVE) {
            lerr = lockdownd_start_service_with_escrow_bag(ld, "com.apple.afc", &desc);
        }
        if (lerr == LOCKDOWN_E_SUCCESS && desc) {
            afc_client_new(dev, desc, &crash_afc);
            lockdownd_service_descriptor_free(desc);
            desc = NULL;
        }
    }

    if (!crash_afc) {
        LOG_WARN("Could not connect to CrashReporter or AFC service.");
        return -1;
    }

    /* Probe directories */
    const char *probe_paths[] = {
        "/CrashReporter",
        "/CrashReporter/DiagnosticReports",
        "/DiagnosticReports",
        "/Logs/CrashReporter",
        "/var/mobile/Library/Logs/CrashReporter",
        "/"
    };

    char target_file[1024] = {0};
    const char *filter = process_filter ? process_filter : "preboard";

    for (size_t p = 0; p < sizeof(probe_paths)/sizeof(probe_paths[0]); p++) {
        char **list = NULL;
        if (afc_read_directory(crash_afc, probe_paths[p], &list) == AFC_E_SUCCESS && list) {
            for (int i = 0; list[i] != NULL; i++) {
                if (strstr(list[i], filter) && (strstr(list[i], ".ips") || strstr(list[i], ".crash") || strstr(list[i], ".synced"))) {
                    if (strcmp(probe_paths[p], "/") == 0) {
                        snprintf(target_file, sizeof(target_file), "/%s", list[i]);
                    } else {
                        snprintf(target_file, sizeof(target_file), "%s/%s", probe_paths[p], list[i]);
                    }
                    break;
                }
            }
            afc_dictionary_free(list);
            if (target_file[0]) break;
        }
    }

    if (!target_file[0]) {
        LOG_INFO("No new matching crash log found in standard directories for '%s'.", filter);
        afc_client_free(crash_afc);
        return 1; /* Not a fatal error, just no log available */
    }

    LOG_SUCCESS("Located crash dump: %s", target_file);

    uint64_t handle = 0;
    if (afc_file_open(crash_afc, target_file, AFC_FOPEN_RDONLY, &handle) != AFC_E_SUCCESS) {
        afc_client_free(crash_afc);
        return -1;
    }

    size_t cap = 65536;
    char *buf = malloc(cap);
    if (!buf) {
        afc_file_close(crash_afc, handle);
        afc_client_free(crash_afc);
        return -1;
    }

    size_t total = 0;
    uint32_t bytes_read = 0;
    while (afc_file_read(crash_afc, handle, buf + total, 4096, &bytes_read) == AFC_E_SUCCESS && bytes_read > 0) {
        total += bytes_read;
        if (total + 4096 >= cap) {
            cap *= 2;
            char *nb = realloc(buf, cap);
            if (!nb) break;
            buf = nb;
        }
    }

    afc_file_close(crash_afc, handle);
    afc_client_free(crash_afc);

    buf[total] = '\0';
    *out_ips = buf;
    *out_len = total;

    return 0;
}

int crash_reporter_fetch_latest_session(l0fck_session_t *sess, const char *process_filter, char **out_ips, size_t *out_len)
{
    if (!sess || !out_ips || !out_len) return -1;
    *out_ips = NULL;
    *out_len = 0;

    if (!sess->is_connected || !sess->ld) {
        if (session_connect(sess) != 0 || !sess->ld) return -1;
    }

    LOG_INFO("Connecting to crash reporter via session manager...");

    afc_client_t crash_afc = NULL;
    if (session_get_afc_client(sess, &crash_afc) != 0 || !crash_afc) {
        LOG_WARN("Could not connect to any AFC service for crash logs.");
        return -1;
    }

    /* Probe directories */
    const char *probe_paths[] = {
        "/CrashReporter",
        "/CrashReporter/DiagnosticReports",
        "/DiagnosticReports",
        "/Logs/CrashReporter",
        "/var/mobile/Library/Logs/CrashReporter",
        "/"
    };

    char target_file[1024] = {0};
    const char *filter = process_filter ? process_filter : "preboard";

    for (size_t p = 0; p < sizeof(probe_paths)/sizeof(probe_paths[0]); p++) {
        char **list = NULL;
        if (afc_read_directory(crash_afc, probe_paths[p], &list) == AFC_E_SUCCESS && list) {
            for (int i = 0; list[i] != NULL; i++) {
                if (strstr(list[i], filter) && (strstr(list[i], ".ips") || strstr(list[i], ".crash") || strstr(list[i], ".synced"))) {
                    if (strcmp(probe_paths[p], "/") == 0) {
                        snprintf(target_file, sizeof(target_file), "/%s", list[i]);
                    } else {
                        snprintf(target_file, sizeof(target_file), "%s/%s", probe_paths[p], list[i]);
                    }
                    break;
                }
            }
            afc_dictionary_free(list);
            if (target_file[0]) break;
        }
    }

    if (!target_file[0]) {
        LOG_INFO("No new matching crash log found in standard directories for '%s'.", filter);
        afc_client_free(crash_afc);
        return 1; /* Not a fatal error, just no log available */
    }

    LOG_SUCCESS("Located crash dump: %s", target_file);

    uint64_t handle = 0;
    if (afc_file_open(crash_afc, target_file, AFC_FOPEN_RDONLY, &handle) != AFC_E_SUCCESS) {
        afc_client_free(crash_afc);
        return -1;
    }

    size_t cap = 65536;
    char *buf = malloc(cap);
    if (!buf) {
        afc_file_close(crash_afc, handle);
        afc_client_free(crash_afc);
        return -1;
    }

    size_t total = 0;
    uint32_t bytes_read = 0;
    while (afc_file_read(crash_afc, handle, buf + total, 4096, &bytes_read) == AFC_E_SUCCESS && bytes_read > 0) {
        total += bytes_read;
        if (total + 4096 >= cap) {
            cap *= 2;
            char *nb = realloc(buf, cap);
            if (!nb) break;
            buf = nb;
        }
    }

    afc_file_close(crash_afc, handle);
    afc_client_free(crash_afc);

    buf[total] = '\0';
    *out_ips = buf;
    *out_len = total;

    return 0;
}
