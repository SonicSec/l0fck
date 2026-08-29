#include "l0fck.h"
#include "lockdown/lockdown_unauth.h"
#include "core/log.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

int lockdown_unauth_query_plist(lockdownd_client_t ld, const char *domain, const char *key, plist_t *out_plist)
{
    if (!ld || !out_plist) return -1;
    *out_plist = NULL;
    lockdownd_error_t err = lockdownd_get_value(ld, domain, key, out_plist);
    return (err == LOCKDOWN_E_SUCCESS && *out_plist != NULL) ? 0 : -1;
}

int lockdown_unauth_query_string(lockdownd_client_t ld, const char *domain, const char *key, char *buf, size_t buf_len)
{
    if (!ld || !buf || buf_len == 0) return -1;
    buf[0] = '\0';

    plist_t node = NULL;
    if (lockdown_unauth_query_plist(ld, domain, key, &node) != 0 || !node) {
        return -1;
    }

    if (plist_get_node_type(node) == PLIST_STRING) {
        char *val = NULL;
        plist_get_string_val(node, &val);
        if (val) {
            snprintf(buf, buf_len, "%s", val);
            free(val);
        }
    } else if (plist_get_node_type(node) == PLIST_UINT) {
        uint64_t v = 0;
        plist_get_uint_val(node, &v);
        snprintf(buf, buf_len, "%llu", (unsigned long long)v);
    }

    plist_free(node);
    return (buf[0] != '\0') ? 0 : -1;
}

static uint64_t query_uint(lockdownd_client_t ld, const char *domain, const char *key)
{
    plist_t node = NULL;
    uint64_t val = 0;
    if (lockdown_unauth_query_plist(ld, domain, key, &node) == 0 && node) {
        if (plist_get_node_type(node) == PLIST_UINT) {
            plist_get_uint_val(node, &val);
        }
        plist_free(node);
    }
    return val;
}

int lockdown_unauth_connect(idevice_t *out_dev, lockdownd_client_t *out_ld, void *out_info)
{
    if (!out_dev || !out_ld) return -1;
    *out_dev = NULL;
    *out_ld = NULL;

    idevice_t dev = NULL;
    idevice_error_t ierr = idevice_new_with_options(&dev, NULL, IDEVICE_LOOKUP_USBMUX);
    if (ierr != IDEVICE_E_SUCCESS || !dev) {
        LOG_DEBUG("No USB device discovered via usbmux");
        return -1;
    }

    lockdownd_client_t ld = NULL;
    lockdownd_error_t lerr = lockdownd_client_new(dev, &ld, "l0fck");
    if (lerr != LOCKDOWN_E_SUCCESS || !ld) {
        LOG_ERROR("lockdownd_client_new failed (error %d)", lerr);
        idevice_free(dev);
        return -1;
    }

    if (out_info) {
        l0fck_device_t *d = (l0fck_device_t *)out_info;
        memset(d, 0, sizeof(l0fck_device_t));

        char *udid = NULL;
        idevice_get_udid(dev, &udid);
        if (udid) {
            snprintf(d->udid, sizeof(d->udid), "%s", udid);
            free(udid);
        }

        lockdown_unauth_query_string(ld, NULL, "DeviceName", d->device_name, sizeof(d->device_name));
        lockdown_unauth_query_string(ld, NULL, "ProductType", d->product_type, sizeof(d->product_type));
        lockdown_unauth_query_string(ld, NULL, "ProductVersion", d->product_version, sizeof(d->product_version));
        lockdown_unauth_query_string(ld, NULL, "BuildVersion", d->build_version, sizeof(d->build_version));
        lockdown_unauth_query_string(ld, NULL, "HardwareModel", d->hardware_model, sizeof(d->hardware_model));
        lockdown_unauth_query_string(ld, NULL, "SerialNumber", d->serial_number, sizeof(d->serial_number));
        lockdown_unauth_query_string(ld, NULL, "CPUArchitecture", d->cpu_architecture, sizeof(d->cpu_architecture));
        lockdown_unauth_query_string(ld, NULL, "ActivationState", d->activation_state, sizeof(d->activation_state));
        lockdown_unauth_query_string(ld, NULL, "WiFiAddress", d->wifi_address, sizeof(d->wifi_address));
        lockdown_unauth_query_string(ld, NULL, "BluetoothAddress", d->bluetooth_address, sizeof(d->bluetooth_address));

        d->cpid = (uint32_t)query_uint(ld, NULL, "ChipID");
        if (d->cpid == 0) {
            d->cpid = (uint32_t)query_uint(ld, NULL, "EffectiveProductionStatusAp");
        }
        if (d->cpid == 0 && (strcmp(d->product_type, TARGET_MODEL_1) == 0 || strcmp(d->product_type, TARGET_MODEL_2) == 0)) {
            d->cpid = TARGET_CPID;
        }

        d->bdid = (uint32_t)query_uint(ld, NULL, "BoardId");
        d->ecid = query_uint(ld, NULL, "UniqueChipID");
        d->mode = MODE_NORMAL;
        d->is_target_soc = target_is_a18_pro(d->cpid, d->product_type);
        d->is_target_os = target_is_ios_26_6_1(d->product_version, d->build_version);
        d->is_validated = (target_validate_device(d) == TARGET_VALID);
    }

    *out_dev = dev;
    *out_ld = ld;
    return 0;
}

void lockdown_unauth_disconnect(idevice_t dev, lockdownd_client_t ld)
{
    if (ld) lockdownd_client_free(ld);
    if (dev) idevice_free(dev);
}

int lockdown_unauth_reconnect(idevice_t *dev, lockdownd_client_t *ld)
{
    if (!dev || !ld) return -1;
    if (*ld) {
        lockdownd_client_free(*ld);
        *ld = NULL;
    }
    if (*dev) {
        idevice_free(*dev);
        *dev = NULL;
    }
    usleep(500000); /* Settle for 500ms */
    return lockdown_unauth_connect(dev, ld, NULL);
}
