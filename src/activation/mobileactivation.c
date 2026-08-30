#include "l0fck.h"
#include "activation/mobileactivation.h"
#include "core/log.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static int get_ma_client(idevice_t dev, lockdownd_client_t ld, mobileactivation_client_t *out_ma)
{
    if (!dev || !ld || !out_ma) return -1;
    *out_ma = NULL;

    lockdownd_client_t temp_ld = NULL;
    
    lockdownd_service_descriptor_t desc = NULL;
    lockdownd_error_t lerr = lockdownd_start_service(ld, "com.apple.mobileactivationd", &desc);
    
    if (lerr == LOCKDOWN_E_SESSION_INACTIVE) {
        LOG_INFO("get_ma_client: Service requires session negotiation (Error -23). Attempting escrow bag...");
        lerr = lockdownd_start_service_with_escrow_bag(ld, "com.apple.mobileactivationd", &desc);
        if (lerr == LOCKDOWN_E_SESSION_INACTIVE) {
            LOG_INFO("get_ma_client: Escrow bag inactive. Attempting handshake negotiation...");
            // Unauthenticated session requires a handshake
            lockdownd_error_t herr = lockdownd_client_new_with_handshake(dev, &temp_ld, "l0fck");
            if (herr == LOCKDOWN_E_SUCCESS && temp_ld) {
                lerr = lockdownd_start_service(temp_ld, "com.apple.mobileactivationd", &desc);
                if (lerr == LOCKDOWN_E_SESSION_INACTIVE) {
                    lerr = lockdownd_start_service_with_escrow_bag(temp_ld, "com.apple.mobileactivationd", &desc);
                }
            } else {
                LOG_INFO("get_ma_client: Handshake returned %d, attempting legacy pairing...", herr);
                // Fallback to legacy pairing if handshake fails
                lockdownd_pair(ld, NULL);
                lerr = lockdownd_start_service(ld, "com.apple.mobileactivationd", &desc);
                if (lerr == LOCKDOWN_E_SESSION_INACTIVE) {
                    lerr = lockdownd_start_service_with_escrow_bag(ld, "com.apple.mobileactivationd", &desc);
                }
            }
        }
    }

    if (lerr != LOCKDOWN_E_SUCCESS || !desc) {
        LOG_ERROR("Failed to start com.apple.mobileactivationd service (error %d)", lerr);
        if (temp_ld) lockdownd_client_free(temp_ld);
        return -1;
    }

    mobileactivation_client_t ma = NULL;
    mobileactivation_error_t merr = mobileactivation_client_new(dev, desc, &ma);
    lockdownd_service_descriptor_free(desc);
    if (temp_ld) lockdownd_client_free(temp_ld);

    if (merr != MOBILEACTIVATION_E_SUCCESS || !ma) {
        LOG_ERROR("Failed to initialize mobileactivation client (error %d)", merr);
        return -1;
    }

    *out_ma = ma;
    return 0;
}

int mobileact_get_state(idevice_t dev, lockdownd_client_t ld, char *out_state, size_t max_len)
{
    if (!out_state || max_len == 0) return -1;
    out_state[0] = '\0';

    mobileactivation_client_t ma = NULL;
    if (get_ma_client(dev, ld, &ma) != 0 || !ma) return -1;

    plist_t state_node = NULL;
    mobileactivation_error_t merr = mobileactivation_get_activation_state(ma, &state_node);
    mobileactivation_client_free(ma);

    if (merr != MOBILEACTIVATION_E_SUCCESS || !state_node) {
        LOG_ERROR("mobileactivation_get_activation_state returned %d", merr);
        return -1;
    }

    if (plist_get_node_type(state_node) == PLIST_STRING) {
        char *str = NULL;
        plist_get_string_val(state_node, &str);
        if (str) {
            snprintf(out_state, max_len, "%s", str);
            free(str);
        }
    } else {
        snprintf(out_state, max_len, "UnknownState");
    }

    plist_free(state_node);
    return 0;
}

int mobileact_get_session_info(idevice_t dev, lockdownd_client_t ld, plist_t *out_session_info)
{
    if (!out_session_info) return -1;
    *out_session_info = NULL;

    mobileactivation_client_t ma = NULL;
    if (get_ma_client(dev, ld, &ma) != 0 || !ma) return -1;

    LOG_INFO("Requesting activation session info (CreateTunnel1SessionInfoRequest)...");
    mobileactivation_error_t merr = mobileactivation_create_activation_session_info(ma, out_session_info);
    mobileactivation_client_free(ma);

    if (merr != MOBILEACTIVATION_E_SUCCESS || !*out_session_info) {
        LOG_ERROR("mobileactivation_create_activation_session_info failed (error %d)", merr);
        return -1;
    }

    LOG_SUCCESS("Received activation session info from device.");
    return 0;
}

int mobileact_create_activation_info(idevice_t dev, lockdownd_client_t ld, plist_t *out_act_info)
{
    if (!out_act_info) return -1;
    *out_act_info = NULL;

    mobileactivation_client_t ma = NULL;
    if (get_ma_client(dev, ld, &ma) != 0 || !ma) return -1;

    LOG_INFO("Requesting activation info (CreateActivationInfoRequest)...");
    mobileactivation_error_t merr = mobileactivation_create_activation_info(ma, out_act_info);
    mobileactivation_client_free(ma);

    if (merr != MOBILEACTIVATION_E_SUCCESS || !*out_act_info) {
        LOG_ERROR("mobileactivation_create_activation_info failed (error %d)", merr);
        return -1;
    }

    LOG_SUCCESS("Received activation info payload from device.");
    return 0;
}

int mobileact_create_with_session(idevice_t dev, lockdownd_client_t ld, plist_t handshake_resp, plist_t *out_act_info)
{
    if (!handshake_resp || !out_act_info) return -1;
    *out_act_info = NULL;

    mobileactivation_client_t ma = NULL;
    if (get_ma_client(dev, ld, &ma) != 0 || !ma) return -1;

    LOG_INFO("Creating activation info with session handshake response...");
    mobileactivation_error_t merr = mobileactivation_create_activation_info_with_session(ma, handshake_resp, out_act_info);
    mobileactivation_client_free(ma);

    if (merr != MOBILEACTIVATION_E_SUCCESS || !*out_act_info) {
        LOG_ERROR("mobileactivation_create_activation_info_with_session failed (error %d)", merr);
        return -1;
    }

    LOG_SUCCESS("Created session-bound activation info payload.");
    return 0;
}

int mobileact_handle_activation_info(idevice_t dev, lockdownd_client_t ld, plist_t act_record)
{
    if (!act_record) return -1;

    mobileactivation_client_t ma = NULL;
    if (get_ma_client(dev, ld, &ma) != 0 || !ma) return -1;

    LOG_INFO("Submitting activation record (HandleActivationInfoRequest)...");
    mobileactivation_error_t merr = mobileactivation_activate(ma, act_record);
    mobileactivation_client_free(ma);

    if (merr != MOBILEACTIVATION_E_SUCCESS) {
        LOG_ERROR("mobileactivation_activate failed (error %d)", merr);
        return -1;
    }

    LOG_SUCCESS("Activation record processed and accepted by device!");
    return 0;
}

int mobileact_handle_with_session(idevice_t dev, lockdownd_client_t ld, plist_t act_record, plist_t session_headers)
{
    if (!act_record || !session_headers) return -1;

    mobileactivation_client_t ma = NULL;
    if (get_ma_client(dev, ld, &ma) != 0 || !ma) return -1;

    LOG_INFO("Submitting session activation record (HandleActivationInfoWithSessionRequest)...");
    mobileactivation_error_t merr = mobileactivation_activate_with_session(ma, act_record, session_headers);
    mobileactivation_client_free(ma);

    if (merr != MOBILEACTIVATION_E_SUCCESS) {
        if (merr == MOBILEACTIVATION_E_REQUEST_FAILED) {
            LOG_INFO("mobileactivation_activate_with_session returned code %d (device SEP local nonce validation active)", merr);
        } else {
            LOG_ERROR("mobileactivation_activate_with_session failed (error %d)", merr);
        }
        return (int)merr;
    }

    LOG_SUCCESS("Session activation record accepted by device!");
    return 0;
}

int mobileact_deactivate(idevice_t dev, lockdownd_client_t ld)
{
    mobileactivation_client_t ma = NULL;
    if (get_ma_client(dev, ld, &ma) != 0 || !ma) return -1;

    LOG_INFO("Sending deactivation request to device...");
    mobileactivation_error_t merr = mobileactivation_deactivate(ma);
    mobileactivation_client_free(ma);

    if (merr != MOBILEACTIVATION_E_SUCCESS) {
        LOG_ERROR("mobileactivation_deactivate failed (error %d)", merr);
        return -1;
    }

    LOG_SUCCESS("Device successfully deactivated.");
    return 0;
}

int mobileact_handle_with_session_prewarmed(idevice_t dev, lockdownd_client_t ld, plist_t act_record, plist_t session_headers, int delay_ms, void (*ready_cb)(void*, int), void* cb_arg)
{
    if (!act_record || !session_headers) {
        if (ready_cb) ready_cb(cb_arg, 1);
        return -1;
    }

    mobileactivation_client_t ma = NULL;
    // Pre-warm the socket BEFORE the race delay
    if (get_ma_client(dev, ld, &ma) != 0 || !ma) {
        if (ready_cb) ready_cb(cb_arg, 1);
        return -1;
    }

    LOG_INFO("Pre-warmed mobileactivationd connection. Waiting %dms before transmission...", delay_ms);
    // Signal the main thread to start the crash NOW
    if (ready_cb) ready_cb(cb_arg, 0);

    usleep(delay_ms * 1000);

    LOG_INFO("Submitting session activation record (HandleActivationInfoWithSessionRequest)...");
    mobileactivation_error_t merr = mobileactivation_activate_with_session(ma, act_record, session_headers);
    mobileactivation_client_free(ma);

    if (merr != MOBILEACTIVATION_E_SUCCESS) {
        if (merr == MOBILEACTIVATION_E_REQUEST_FAILED) {
            LOG_INFO("mobileactivation_activate_with_session returned code %d", merr);
        } else {
            LOG_ERROR("mobileactivation_activate_with_session failed (error %d)", merr);
        }
        return (int)merr;
    }

    LOG_SUCCESS("Session activation record accepted by device!");
    return 0;
}

int mobileact_prewarm_client(idevice_t dev, lockdownd_client_t ld, mobileactivation_client_t *out_ma)
{
    return get_ma_client(dev, ld, out_ma);
}
