#ifndef LOCKDOWN_UNAUTH_H
#define LOCKDOWN_UNAUTH_H

#include <libimobiledevice/libimobiledevice.h>
#include <libimobiledevice/lockdown.h>
#include <stdbool.h>

typedef struct l0fck_device_s l0fck_device_t;

int lockdown_unauth_connect(idevice_t *out_dev, lockdownd_client_t *out_ld, void *out_info);
int lockdown_unauth_reconnect(idevice_t *dev, lockdownd_client_t *ld);
void lockdown_unauth_disconnect(idevice_t dev, lockdownd_client_t ld);
int lockdown_unauth_query_string(lockdownd_client_t ld, const char *domain, const char *key, char *buf, size_t buf_len);
int lockdown_unauth_query_plist(lockdownd_client_t ld, const char *domain, const char *key, plist_t *out_plist);

#endif /* LOCKDOWN_UNAUTH_H */
