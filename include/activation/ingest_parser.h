#ifndef ACTIVATION_INGEST_PARSER_H
#define ACTIVATION_INGEST_PARSER_H

#include <plist/plist.h>
#include <stdbool.h>

typedef struct {
    char udid[64];
    char serial_number[64];
    char imei[32];
    char meid[32];
    char chip_id[32];
    char ecid[32];
    char baseband_serial[64];
    bool has_scrt_part2;
    bool has_pcrt;
    bool has_fdr_blobs;
} ingest_summary_t;

int ingest_parser_dump_session_info(plist_t session_info, ingest_summary_t *out_summary);
void ingest_parser_print_json_fields(const char *json, size_t len);

#endif /* ACTIVATION_INGEST_PARSER_H */
