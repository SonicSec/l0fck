#include "l0fck.h"
#include "lockdown/flag_injector.h"
#include "lockdown/session_manager.h"
#include "core/log.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct {
    const char *domain;
    const char *key;
    enum { FLAG_TYPE_BOOL, FLAG_TYPE_STRING, FLAG_TYPE_INT } type;
    union {
        bool b_val;
        const char *s_val;
        uint64_t u_val;
    } value;
    bool is_critical_lockdown;
} flag_entry_t;

static const flag_entry_t INJECTION_TARGETS[] = {
    /* com.apple.purplebuddy keys directly accepted by modern lockdownd */
    { "com.apple.purplebuddy",    "SkipSetup",                    FLAG_TYPE_BOOL,   { .b_val = true }, true },
    { "com.apple.purplebuddy",    "SetupState",                   FLAG_TYPE_STRING, { .s_val = "Done" }, true },
    { "com.apple.purplebuddy",    "kSetupState",                  FLAG_TYPE_STRING, { .s_val = "SetupFinishedAllSteps" }, false },
    /* SetupDone & SetupFinishedAllSteps: attempt lockdownd write, cascade on -14 */
    { "com.apple.purplebuddy",    "SetupDone",                    FLAG_TYPE_BOOL,   { .b_val = true }, false },
    { "com.apple.purplebuddy",    "SetupFinishedAllSteps",        FLAG_TYPE_BOOL,   { .b_val = true }, false },
    /* com.apple.mobile.iTunes setup completion flags */
    { "com.apple.mobile.iTunes",  "BuddySetupComplete",           FLAG_TYPE_BOOL,   { .b_val = true }, true },
    { "com.apple.mobile.iTunes",  "SetupComplete",                FLAG_TYPE_BOOL,   { .b_val = true }, true },
    { "com.apple.mobile.iTunes",  "kSetupState",                  FLAG_TYPE_STRING, { .s_val = "SetupFinishedAllSteps" }, false },
    /* MobileActivation hactivation & signing bypass flags */
    { "com.apple.MobileActivation", "allow-hactivation",          FLAG_TYPE_BOOL,   { .b_val = true }, true },
    { "com.apple.MobileActivation", "DisableHactivation",         FLAG_TYPE_BOOL,   { .b_val = false }, true },
    { "com.apple.MobileActivation", "FDRForceLegacySigning",      FLAG_TYPE_BOOL,   { .b_val = true }, true },
    { "com.apple.MobileActivation", "FillmoreBypassOTDataPersist",FLAG_TYPE_BOOL,   { .b_val = true }, true },
    /* SetupAssistant dismissal hints */
    { "com.apple.SetupAssistant", "DidSeeExpress",                FLAG_TYPE_BOOL,   { .b_val = true }, false },
    { "com.apple.SetupAssistant", "LastSeenBuddyVersion",         FLAG_TYPE_INT,    { .u_val = 2 }, false }
};
#define N_FLAGS (sizeof(INJECTION_TARGETS) / sizeof(INJECTION_TARGETS[0]))

static plist_t create_value_node(const flag_entry_t *entry)
{
    if (entry->type == FLAG_TYPE_BOOL) {
        return plist_new_bool((uint8_t)entry->value.b_val);
    } else if (entry->type == FLAG_TYPE_STRING) {
        return plist_new_string(entry->value.s_val);
    } else if (entry->type == FLAG_TYPE_INT) {
        return plist_new_uint(entry->value.u_val);
    }
    return NULL;
}

int flag_injector_inject_all(lockdownd_client_t ld)
{
    if (!ld) return -1;

    printf("\n" ANSI_COLOR_BOLD ANSI_COLOR_CYAN "================ LOCKDOWND CONFIG & FLAG INJECTION ================" ANSI_COLOR_RESET "\n");
    printf("Injecting persistent PurpleBuddy & MobileActivation flags...\n\n");

    int success_count = 0;
    int disk_staged_count = 0;

    for (size_t i = 0; i < N_FLAGS; i++) {
        const flag_entry_t *entry = &INJECTION_TARGETS[i];
        plist_t val_node = create_value_node(entry);
        if (!val_node) continue;

        lockdownd_error_t err = lockdownd_set_value(ld, entry->domain, entry->key, val_node);

        /* If rejected with -14 (SET_PROHIBITED), attempt fallback domains */
        if (err == LOCKDOWN_E_SET_PROHIBITED) {
            const char *fallbacks[] = { "com.apple.mobile.iTunes", "com.apple.SetupAssistant", NULL };
            for (size_t f = 0; f < sizeof(fallbacks)/sizeof(fallbacks[0]); f++) {
                if (fallbacks[f] && entry->domain && strcmp(fallbacks[f], entry->domain) == 0) continue;
                plist_t fb_node = create_value_node(entry);
                if (!fb_node) continue;
                err = lockdownd_set_value(ld, fallbacks[f], entry->key, fb_node);
                if (err == LOCKDOWN_E_SUCCESS) {
                    printf("  " ANSI_COLOR_GREEN "[INJECTED (FALLBACK)]" ANSI_COLOR_RESET " %-20s -> %-24s\n",
                           fallbacks[f] ? fallbacks[f] : "(default)", entry->key);
                    success_count++;
                    break;
                }
            }
        }

        if (err == LOCKDOWN_E_SUCCESS) {
            success_count++;
            printf("  " ANSI_COLOR_GREEN "[INJECTED]" ANSI_COLOR_RESET " %-30s -> %-28s = ", entry->domain, entry->key);
            if (entry->type == FLAG_TYPE_BOOL) {
                printf("%s\n", entry->value.b_val ? "true" : "false");
            } else if (entry->type == FLAG_TYPE_STRING) {
                printf("\"%s\"\n", entry->value.s_val);
            } else if (entry->type == FLAG_TYPE_INT) {
                printf("%llu\n", (unsigned long long)entry->value.u_val);
            }
        } else if (err == LOCKDOWN_E_SET_PROHIBITED) {
            /* Handled via Stage 1 AFC disk-level staging into /var/mobile/Media/com.apple.purplebuddy.plist */
            disk_staged_count++;
            printf("  " ANSI_COLOR_YELLOW "[DISK-STAGED]" ANSI_COLOR_RESET " %-27s -> %-28s (managed via AFC plist)\n",
                   entry->domain, entry->key);
        } else {
            printf("  " ANSI_COLOR_YELLOW "[REJECTED]" ANSI_COLOR_RESET " %-30s -> %-28s (err %d)\n",
                   entry->domain, entry->key, err);
        }
    }

    printf("\nResult: %d flags directly injected into lockdown (%d disk-staged via AFC).\n",
           success_count, disk_staged_count);
    printf(ANSI_COLOR_CYAN "====================================================================" ANSI_COLOR_RESET "\n\n");

    return (success_count > 0 || disk_staged_count > 0) ? 0 : -1;
}

int flag_injector_inject_all_session(l0fck_session_t *sess)
{
    if (!sess) return -1;

    /* Ensure fresh connection before starting */
    if (!sess->is_connected || !sess->ld) {
        if (session_connect(sess) != 0 || !sess->ld) return -1;
    }

    printf("\n" ANSI_COLOR_BOLD ANSI_COLOR_CYAN "================ LOCKDOWND CONFIG & FLAG INJECTION ================" ANSI_COLOR_RESET "\n");
    printf("Injecting persistent PurpleBuddy & MobileActivation flags (session-aware)...\n\n");

    int success_count = 0;
    int disk_staged_count = 0;
    int consecutive_mux_errors = 0;

    for (size_t i = 0; i < N_FLAGS; i++) {
        const flag_entry_t *entry = &INJECTION_TARGETS[i];
        plist_t val_node = create_value_node(entry);
        if (!val_node) continue;

        lockdownd_error_t err = lockdownd_set_value(sess->ld, entry->domain, entry->key, val_node);

        /* On MUX error (-8), reconnect session and retry */
        if (err == LOCKDOWN_E_MUX_ERROR) {
            consecutive_mux_errors++;
            if (consecutive_mux_errors <= 2) {
                LOG_INFO("MUX error on flag '%s', reconnecting session...", entry->key);
                session_reconnect(sess);
                if (sess->ld) {
                    val_node = create_value_node(entry);
                    if (val_node) {
                        err = lockdownd_set_value(sess->ld, entry->domain, entry->key, val_node);
                    }
                }
            }
        } else {
            consecutive_mux_errors = 0;
        }

        /* If rejected with -14 (SET_PROHIBITED), attempt fallback domains */
        if (err == LOCKDOWN_E_SET_PROHIBITED) {
            const char *fallbacks[] = { "com.apple.mobile.iTunes", "com.apple.SetupAssistant", NULL };
            for (size_t f = 0; f < sizeof(fallbacks)/sizeof(fallbacks[0]); f++) {
                if (fallbacks[f] && entry->domain && strcmp(fallbacks[f], entry->domain) == 0) continue;
                plist_t fb_node = create_value_node(entry);
                if (!fb_node) continue;
                err = lockdownd_set_value(sess->ld, fallbacks[f], entry->key, fb_node);
                if (err == LOCKDOWN_E_SUCCESS) {
                    printf("  " ANSI_COLOR_GREEN "[INJECTED (FALLBACK)]" ANSI_COLOR_RESET " %-20s -> %-24s\n",
                           fallbacks[f] ? fallbacks[f] : "(default)", entry->key);
                    success_count++;
                    break;
                }
            }
        }

        if (err == LOCKDOWN_E_SUCCESS) {
            success_count++;
            printf("  " ANSI_COLOR_GREEN "[INJECTED]" ANSI_COLOR_RESET " %-30s -> %-28s = ", entry->domain, entry->key);
            if (entry->type == FLAG_TYPE_BOOL) {
                printf("%s\n", entry->value.b_val ? "true" : "false");
            } else if (entry->type == FLAG_TYPE_STRING) {
                printf("\"%s\"\n", entry->value.s_val);
            } else if (entry->type == FLAG_TYPE_INT) {
                printf("%llu\n", (unsigned long long)entry->value.u_val);
            }
        } else if (err == LOCKDOWN_E_SET_PROHIBITED) {
            disk_staged_count++;
            printf("  " ANSI_COLOR_YELLOW "[DISK-STAGED]" ANSI_COLOR_RESET " %-27s -> %-28s (managed via AFC plist)\n",
                   entry->domain, entry->key);
        } else {
            printf("  " ANSI_COLOR_YELLOW "[REJECTED]" ANSI_COLOR_RESET " %-30s -> %-28s (err %d)\n",
                   entry->domain, entry->key, err);
        }
    }

    printf("\nResult: %d flags directly injected into lockdown (%d disk-staged via AFC).\n",
           success_count, disk_staged_count);
    printf(ANSI_COLOR_CYAN "====================================================================" ANSI_COLOR_RESET "\n\n");

    return (success_count > 0 || disk_staged_count > 0) ? 0 : -1;
}

int flag_injector_verify(lockdownd_client_t ld)
{
    if (!ld) return -1;
    printf("\n" ANSI_COLOR_BOLD "Verifying PurpleBuddy flag status in lockdown:\n" ANSI_COLOR_RESET);

    for (size_t i = 0; i < N_FLAGS; i++) {
        const flag_entry_t *entry = &INJECTION_TARGETS[i];
        plist_t node = NULL;
        lockdownd_error_t err = lockdownd_get_value(ld, entry->domain, entry->key, &node);
        if (err == LOCKDOWN_E_SUCCESS && node) {
            printf("  %-30s -> %-28s: " ANSI_COLOR_GREEN "PRESENT" ANSI_COLOR_RESET "\n", entry->domain, entry->key);
            plist_free(node);
        } else {
            printf("  %-30s -> %-28s: " ANSI_COLOR_YELLOW "UNSET / DEFAULT" ANSI_COLOR_RESET "\n", entry->domain, entry->key);
        }
    }
    return 0;
}
