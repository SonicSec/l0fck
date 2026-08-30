#ifndef SESSION_MANAGER_H
#define SESSION_MANAGER_H

#include <libimobiledevice/libimobiledevice.h>
#include <libimobiledevice/lockdown.h>
#include <libimobiledevice/afc.h>
#include <stdbool.h>

typedef struct l0fck_device_s l0fck_device_t;
typedef struct l0fck_session_s l0fck_session_t;

struct l0fck_session_s {
    idevice_t dev;
    lockdownd_client_t ld;
    l0fck_device_t info;
    bool is_connected;
    bool is_paired;
};

int session_init(l0fck_session_t *sess);
int session_connect(l0fck_session_t *sess);
int session_reconnect(l0fck_session_t *sess);
void session_disconnect(l0fck_session_t *sess);

/* Safe service starter with Error -23 resolution & unauthenticated fallbacks */
lockdownd_error_t session_start_service(
    l0fck_session_t *sess,
    const char *service_name,
    lockdownd_service_descriptor_t *out_desc
);

/* Multi-tier resilient AFC client acquisition */
int session_get_afc_client(l0fck_session_t *sess, afc_client_t *out_afc);
int session_get_afc2_client(l0fck_session_t *sess, afc_client_t *out_afc);

#endif /* SESSION_MANAGER_H */
