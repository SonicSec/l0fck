#include "l0fck.h"
#include "activation/ingest_parser.h"
#include "core/log.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void ingest_parser_print_json_fields(const char *json, size_t len)
{
    const char *p = json;
    const char *end = json + len;

    printf("\n" ANSI_COLOR_BOLD ANSI_COLOR_CYAN "--- IngestBody Parsed Fields (Device DRM Identity) ---" ANSI_COLOR_RESET "\n");

    while (p < end) {
        const char *ks = memchr(p, '"', (size_t)(end - p));
        if (!ks) break;
        ks++;
        const char *ke = memchr(ks, '"', (size_t)(end - ks));
        if (!ke) break;

        size_t klen = (size_t)(ke - ks);
        char key[128] = {0};
        if (klen < sizeof(key))
            memcpy(key, ks, klen);
        else
            memcpy(key, ks, sizeof(key) - 1);

        p = ke + 1;
        while (p < end && (*p == ' ' || *p == '\t' || *p == ':')) p++;
        if (p >= end) break;

        char val[256] = {0};
        if (*p == '"') {
            const char *vs = p + 1;
            const char *ve = memchr(vs, '"', (size_t)(end - vs));
            if (!ve) break;
            size_t vlen = (size_t)(ve - vs);
            if (vlen > 80) {
                snprintf(val, sizeof(val), "[%zu bytes blob: %.16s...]", vlen, vs);
            } else {
                if (vlen < sizeof(val))
                    memcpy(val, vs, vlen);
            }
            p = ve + 1;
        } else {
            const char *vs = p;
            while (p < end && *p != ',' && *p != '}' && *p != '\n') p++;
            size_t vlen = (size_t)(p - vs);
            if (vlen < sizeof(val))
                memcpy(val, vs, vlen);
        }

        printf("  %-32s : %s\n", key, val);
    }
    printf(ANSI_COLOR_CYAN "------------------------------------------------------" ANSI_COLOR_RESET "\n\n");
}

int ingest_parser_dump_session_info(plist_t session_info, ingest_summary_t *out_summary)
{
    if (!session_info) return -1;
    if (out_summary) memset(out_summary, 0, sizeof(ingest_summary_t));

    plist_t cb = plist_dict_get_item(session_info, "CollectionBlob");
    if (!cb) {
        LOG_WARN("No CollectionBlob node found in session_info plist");
        return -1;
    }

    char *cb_data = NULL;
    uint64_t cb_len = 0;
    plist_get_data_val(cb, &cb_data, &cb_len);

    if (!cb_data || cb_len == 0) {
        LOG_WARN("CollectionBlob data is empty");
        return -1;
    }

    LOG_INFO("CollectionBlob size: %llu bytes", (unsigned long long)cb_len);

    plist_t cb_plist = NULL;
    plist_from_memory(cb_data, (uint32_t)cb_len, &cb_plist, NULL);

    if (cb_plist) {
        plist_t ib = plist_dict_get_item(cb_plist, "IngestBody");
        if (ib) {
            plist_type t = plist_get_node_type(ib);
            char *ib_str = NULL;

            if (t == PLIST_STRING) {
                plist_get_string_val(ib, &ib_str);
            } else if (t == PLIST_DATA) {
                uint64_t ib_len = 0;
                plist_get_data_val(ib, &ib_str, &ib_len);
            }

            if (ib_str) {
                ingest_parser_print_json_fields(ib_str, strlen(ib_str));
                free(ib_str);
            }
        }

        if (plist_dict_get_item(cb_plist, "scrt-part2")) {
            LOG_INFO("scrt-part2 blob present in CollectionBlob");
            if (out_summary) out_summary->has_scrt_part2 = true;
        }
        if (plist_dict_get_item(cb_plist, "pcrt")) {
            LOG_INFO("pcrt certificate blob present in CollectionBlob");
            if (out_summary) out_summary->has_pcrt = true;
        }

        plist_free(cb_plist);
    } else {
        LOG_DEBUG("CollectionBlob is opaque binary format");
    }

    free(cb_data);

    plist_t hrm = plist_dict_get_item(session_info, "HandshakeRequestMessage");
    if (hrm) {
        char *hbuf = NULL;
        uint64_t hlen = 0;
        plist_get_data_val(hrm, &hbuf, &hlen);
        LOG_INFO("HandshakeRequestMessage size: %llu bytes", (unsigned long long)hlen);
        free(hbuf);
    }

    return 0;
}
