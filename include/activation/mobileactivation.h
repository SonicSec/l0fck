#ifndef ACTIVATION_MOBILEACTIVATION_H
#define ACTIVATION_MOBILEACTIVATION_H

#include <libimobiledevice/libimobiledevice.h>
#include <libimobiledevice/lockdown.h>
#include <libimobiledevice/mobileactivation.h>
#include <plist/plist.h>
#include <stdbool.h>

int mobileact_get_state(idevice_t dev, lockdownd_client_t ld, char *out_state, size_t max_len);
int mobileact_get_session_info(idevice_t dev, lockdownd_client_t ld, plist_t *out_session_info);
int mobileact_create_activation_info(idevice_t dev, lockdownd_client_t ld, plist_t *out_act_info);
int mobileact_create_with_session(idevice_t dev, lockdownd_client_t ld, plist_t handshake_resp, plist_t *out_act_info);
int mobileact_handle_activation_info(idevice_t dev, lockdownd_client_t ld, plist_t act_record);
int mobileact_handle_with_session(idevice_t dev, lockdownd_client_t ld, plist_t act_record, plist_t session_headers);
int mobileact_deactivate(idevice_t dev, lockdownd_client_t ld);

#endif /* ACTIVATION_MOBILEACTIVATION_H */
