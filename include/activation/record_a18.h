#ifndef ACTIVATION_RECORD_A18_H
#define ACTIVATION_RECORD_A18_H

#include <plist/plist.h>
#include <libimobiledevice/lockdown.h>
#include <stdbool.h>

typedef struct l0fck_device_s l0fck_device_t;

int record_a18_generate(const void *dev_ptr, plist_t handshake_resp, plist_t *out_record, plist_t *out_session_headers);
int record_a18_generate_offline(const void *dev_ptr, plist_t *out_record, plist_t *out_session_headers);
int record_a18_enrich_with_device_certs(lockdownd_client_t ld, plist_t record);
void record_a18_print_summary(plist_t record);

#endif /* ACTIVATION_RECORD_A18_H */
