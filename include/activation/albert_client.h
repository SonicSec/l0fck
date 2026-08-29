#ifndef ACTIVATION_ALBERT_CLIENT_H
#define ACTIVATION_ALBERT_CLIENT_H

#include <libimobiledevice/libimobiledevice.h>
#include <libimobiledevice/lockdown.h>
#include <plist/plist.h>
#include <stdbool.h>

typedef struct l0fck_session_s l0fck_session_t;

#define ALBERT_DRM_HANDSHAKE_URL    "https://albert.apple.com/deviceservices/drmHandshake"
#define ALBERT_DEVICE_ACTIV_URL     "https://albert.apple.com/deviceservices/deviceActivation"
#define ALBERT_USER_AGENT           "iOS Device Activator (MobileActivation-592.103.2)"

int albert_drm_handshake(plist_t session_info, plist_t *out_handshake_response);
int albert_device_activation(plist_t activation_info, plist_t *out_activation_record);
int albert_probe_full(idevice_t dev, lockdownd_client_t ld);
int albert_perform_online_activation(idevice_t dev, lockdownd_client_t ld);
int albert_perform_offline_activation(idevice_t dev, lockdownd_client_t ld);
int albert_perform_hybrid_activation(idevice_t dev, lockdownd_client_t ld, plist_t handshake_resp);
int albert_perform_race_activation(l0fck_session_t *sess, plist_t handshake_resp);

#endif /* ACTIVATION_ALBERT_CLIENT_H */
