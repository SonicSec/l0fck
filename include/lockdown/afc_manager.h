#ifndef LOCKDOWN_AFC_MANAGER_H
#define LOCKDOWN_AFC_MANAGER_H

#include <libimobiledevice/libimobiledevice.h>
#include <libimobiledevice/lockdown.h>
#include <libimobiledevice/afc.h>
#include <stdbool.h>

int afc_mkdir_p(afc_client_t afc, const char *path);
int afc_write_file_data(afc_client_t afc, const char *path, const char *buf, uint32_t len);
int afc_manager_list_dir(idevice_t dev, lockdownd_client_t ld, const char *path);
int afc_manager_pull_file(idevice_t dev, lockdownd_client_t ld, const char *remote_path, const char *local_path);
int afc_manager_push_file(idevice_t dev, lockdownd_client_t ld, const char *local_path, const char *remote_path);
int afc_manager_write_test(idevice_t dev, lockdownd_client_t ld);

#endif /* LOCKDOWN_AFC_MANAGER_H */
