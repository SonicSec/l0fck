#ifndef LOCKDOWN_FLAG_INJECTOR_H
#define LOCKDOWN_FLAG_INJECTOR_H

#include <libimobiledevice/libimobiledevice.h>
#include <libimobiledevice/lockdown.h>
#include <stdbool.h>

typedef struct l0fck_session_s l0fck_session_t;

int flag_injector_inject_all(lockdownd_client_t ld);
int flag_injector_inject_all_session(l0fck_session_t *sess);
int flag_injector_verify(lockdownd_client_t ld);

#endif /* LOCKDOWN_FLAG_INJECTOR_H */
