#ifndef LOCKDOWN_SERVICES_H
#define LOCKDOWN_SERVICES_H

#include <libimobiledevice/libimobiledevice.h>
#include <libimobiledevice/lockdown.h>
#include <stdbool.h>

typedef struct {
    const char *service_name;
    const char *description;
    bool is_vulnerable_target; /* Expected accessible on vulnerable iOS 26.6.1 */
} lockdown_service_entry_t;

int services_audit_unauthenticated(idevice_t dev, lockdownd_client_t ld, bool verbose);
int services_reboot_device(idevice_t dev, lockdownd_client_t ld);
int services_stream_syslog(idevice_t dev, lockdownd_client_t ld, int duration_sec);
int services_probe_service(lockdownd_client_t ld, const char *service_name);

#endif /* LOCKDOWN_SERVICES_H */
