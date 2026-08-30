#include "l0fck.h"
#include "lockdown/session_manager.h"
#include "lockdown/lockdown_unauth.h"
#include "core/log.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

int session_init(l0fck_session_t *sess)
{
    if (!sess) return -1;
    memset(sess, 0, sizeof(l0fck_session_t));
    return 0;
}

int session_connect(l0fck_session_t *sess)
{
    if (!sess) return -1;
    if (sess->is_connected && sess->dev && sess->ld) {
        return 0;
    }

    int res = lockdown_unauth_connect(&sess->dev, &sess->ld, &sess->info);
    sess->is_connected = (res == 0 && sess->dev && sess->ld);
    return res;
}

int session_reconnect(l0fck_session_t *sess)
{
    if (!sess) return -1;
    LOG_DEBUG("session_reconnect: Reconnecting lockdown session...");

    if (sess->ld) {
        lockdownd_client_free(sess->ld);
        sess->ld = NULL;
    }
    if (sess->dev) {
        idevice_free(sess->dev);
        sess->dev = NULL;
    }
    sess->is_connected = false;

    usleep(500000); /* Settle for 500ms */

    int res = lockdown_unauth_connect(&sess->dev, &sess->ld, &sess->info);
    sess->is_connected = (res == 0 && sess->dev && sess->ld);
    if (sess->is_connected) {
        LOG_DEBUG("session_reconnect: Successfully reconnected.");
    } else {
        LOG_WARN("session_reconnect: Reconnection attempt returned %d", res);
    }
    return res;
}

void session_disconnect(l0fck_session_t *sess)
{
    if (!sess) return;
    if (sess->ld) {
        lockdownd_client_free(sess->ld);
        sess->ld = NULL;
    }
    if (sess->dev) {
        idevice_free(sess->dev);
        sess->dev = NULL;
    }
    sess->is_connected = false;
}

static const char *get_fallback_service_name(const char *service_name)
{
    if (!service_name) return NULL;
    if (strcmp(service_name, "com.apple.mobile.notification_proxy") == 0) {
        return "com.apple.mobile.insecure_notification_proxy";
    }
    if (strcmp(service_name, "com.apple.mobile.diagnostics_relay") == 0) {
        return "com.apple.mobile.insecure_diagnostics_relay";
    }
    if (strcmp(service_name, "com.apple.afc") == 0) {
        return "com.apple.crashreportcopymobile";
    }
    if (strcmp(service_name, "com.apple.crashreportcopymobile") == 0) {
        return "com.apple.afc";
    }
    return NULL;
}

lockdownd_error_t session_start_service(
    l0fck_session_t *sess,
    const char *service_name,
    lockdownd_service_descriptor_t *out_desc
)
{
    if (!sess || !service_name || !out_desc) return LOCKDOWN_E_INVALID_ARG;
    *out_desc = NULL;

    if (!sess->is_connected || !sess->ld) {
        if (session_connect(sess) != 0 || !sess->ld) {
            LOG_ERROR("session_start_service: Device session unavailable");
            return LOCKDOWN_E_MUX_ERROR;
        }
    }

    /* Try 1: Standard lockdownd_start_service */
    lockdownd_error_t lerr = lockdownd_start_service(sess->ld, service_name, out_desc);

    /* If socket broke or mux error, reconnect and retry */
    if (lerr == LOCKDOWN_E_MUX_ERROR || lerr == LOCKDOWN_E_UNKNOWN_ERROR) {
        LOG_INFO("session_start_service: Connection issue (%d), performing atomic reconnect...", lerr);
        if (session_reconnect(sess) == 0 && sess->ld) {
            lerr = lockdownd_start_service(sess->ld, service_name, out_desc);
        }
    }

    /* Try 2: Error -23 (LOCKDOWN_E_SESSION_INACTIVE) handling */
    if (lerr == LOCKDOWN_E_SESSION_INACTIVE) {
        LOG_INFO("session_start_service: Service '%s' requires session negotiation (Error -23). Attempting escrow bag...", service_name);
        lerr = lockdownd_start_service_with_escrow_bag(sess->ld, service_name, out_desc);

        if (lerr == LOCKDOWN_E_SESSION_INACTIVE) {
            LOG_INFO("session_start_service: Escrow bag inactive. Attempting handshake negotiation...");
            lockdownd_client_t new_ld = NULL;
            lockdownd_error_t herr = lockdownd_client_new_with_handshake(sess->dev, &new_ld, "l0fck");
            if (herr == LOCKDOWN_E_SUCCESS && new_ld) {
                lockdownd_client_free(sess->ld);
                sess->ld = new_ld;
                lerr = lockdownd_start_service(sess->ld, service_name, out_desc);
                if (lerr == LOCKDOWN_E_SESSION_INACTIVE) {
                    lerr = lockdownd_start_service_with_escrow_bag(sess->ld, service_name, out_desc);
                }
            } else {
                LOG_DEBUG("session_start_service: Handshake returned %d, attempting pair record validation...", herr);
                lockdownd_pair(sess->ld, NULL);
                lerr = lockdownd_start_service(sess->ld, service_name, out_desc);
                if (lerr == LOCKDOWN_E_SESSION_INACTIVE) {
                    lerr = lockdownd_start_service_with_escrow_bag(sess->ld, service_name, out_desc);
                }
            }
        }
    }

    /* Try 3: Check unauthenticated fallback service alias */
    if (lerr != LOCKDOWN_E_SUCCESS) {
        const char *fallback_name = get_fallback_service_name(service_name);
        if (fallback_name) {
            LOG_INFO("session_start_service: Probing insecure service fallback '%s'...", fallback_name);
            lerr = lockdownd_start_service(sess->ld, fallback_name, out_desc);
            if (lerr == LOCKDOWN_E_SESSION_INACTIVE) {
                lerr = lockdownd_start_service_with_escrow_bag(sess->ld, fallback_name, out_desc);
            }
        }
    }

    if (lerr == LOCKDOWN_E_SUCCESS && *out_desc) {
        LOG_DEBUG("session_start_service: Service '%s' started successfully (port %d)", service_name, (*out_desc)->port);
    } else {
        LOG_WARN("session_start_service: Failed to start '%s' (lockdown error %d)", service_name, lerr);
    }

    return lerr;
}

int session_get_afc_client(l0fck_session_t *sess, afc_client_t *out_afc)
{
    if (!sess || !out_afc) return -1;
    *out_afc = NULL;

    if (!sess->is_connected || !sess->ld) {
        if (session_connect(sess) != 0 || !sess->ld) {
            LOG_ERROR("session_get_afc_client: Device session unavailable");
            return -1;
        }
    }

    /* Tier 1: Attempt standard session_start_service with com.apple.afc */
    lockdownd_service_descriptor_t desc = NULL;
    lockdownd_error_t lerr = session_start_service(sess, "com.apple.afc", &desc);
    if (lerr == LOCKDOWN_E_SUCCESS && desc) {
        afc_client_t afc = NULL;
        afc_error_t aerr = afc_client_new(sess->dev, desc, &afc);
        lockdownd_service_descriptor_free(desc);
        if (aerr == AFC_E_SUCCESS && afc) {
            *out_afc = afc;
            LOG_DEBUG("session_get_afc_client: Connected via com.apple.afc");
            return 0;
        }
    }

    /* Tier 2: Attempt libimobiledevice direct afc_client_start_service */
    LOG_INFO("session_get_afc_client: Standard AFC start returned %d. Trying direct afc_client_start_service...", lerr);
    afc_client_t direct_afc = NULL;
    afc_error_t daerr = afc_client_start_service(sess->dev, &direct_afc, "l0fck");
    if (daerr == AFC_E_SUCCESS && direct_afc) {
        *out_afc = direct_afc;
        LOG_SUCCESS("session_get_afc_client: Connected via direct afc_client_start_service");
        return 0;
    }

    /* Tier 3: Attempt unauthenticated AFC fallback alias (com.apple.crashreportcopymobile) */
    LOG_INFO("session_get_afc_client: Probing unauthenticated AFC alias (com.apple.crashreportcopymobile)...");
    desc = NULL;
    lerr = lockdownd_start_service(sess->ld, "com.apple.crashreportcopymobile", &desc);
    if (lerr == LOCKDOWN_E_SUCCESS && desc) {
        afc_client_t alias_afc = NULL;
        afc_error_t aaerr = afc_client_new(sess->dev, desc, &alias_afc);
        lockdownd_service_descriptor_free(desc);
        if (aaerr == AFC_E_SUCCESS && alias_afc) {
            *out_afc = alias_afc;
            LOG_SUCCESS("session_get_afc_client: Connected via com.apple.crashreportcopymobile");
            return 0;
        }
    }

    LOG_WARN("session_get_afc_client: All AFC connection tiers exhausted");
    return -1;
}

int session_get_afc2_client(l0fck_session_t *sess, afc_client_t *out_afc)
{
    if (!sess || !out_afc) return -1;
    *out_afc = NULL;

    if (!sess->is_connected || !sess->ld) {
        if (session_connect(sess) != 0 || !sess->ld) return -1;
    }

    lockdownd_service_descriptor_t desc = NULL;
    lockdownd_error_t lerr = session_start_service(sess, "com.apple.afc2", &desc);
    if (lerr == LOCKDOWN_E_SUCCESS && desc) {
        afc_client_t afc = NULL;
        afc_error_t aerr = afc_client_new(sess->dev, desc, &afc);
        lockdownd_service_descriptor_free(desc);
        if (aerr == AFC_E_SUCCESS && afc) {
            *out_afc = afc;
            LOG_SUCCESS("session_get_afc2_client: Connected via com.apple.afc2");
            return 0;
        }
    }

    return -1;
}
