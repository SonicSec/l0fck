#ifndef L0FCK_H
#define L0FCK_H

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>

#include <libimobiledevice/libimobiledevice.h>
#include <libimobiledevice/lockdown.h>
#include <libimobiledevice/afc.h>
#include <libimobiledevice/diagnostics_relay.h>
#include <libimobiledevice/syslog_relay.h>
#include <libimobiledevice/mobileactivation.h>
#include <plist/plist.h>
#include <libusb.h>

#define L0FCK_VERSION "1.0.0"
#define L0FCK_CODENAME "A18Pro-Titan"

/* Target Hardware Specifications */
#define TARGET_CHIP_NAME        "Apple A18 Pro (T8140)"
#define TARGET_CPID             0x8140
#define TARGET_MODEL_1          "iPhone17,1" /* iPhone 16 Pro */
#define TARGET_MODEL_2          "iPhone17,2" /* iPhone 16 Pro Max */
#define TARGET_OS_VERSION       "26.6.1"
#define TARGET_BUILD_VERSION    "23G83"

/* USB Vendor & Product IDs */
#define APPLE_VID               0x05AC
#define APPLE_PID_PORT_DFU      0xF014 /* iPhone 15/16 Pro USB-C Port DFU */
#define APPLE_PID_DFU_LEGACY    0x1227 /* Legacy SecureROM DFU */
#define APPLE_PID_RECOVERY_MIN  0x1280
#define APPLE_PID_RECOVERY_MAX  0x1283
#define APPLE_PID_NORMAL        0x12A8

/* Device Mode */
typedef enum {
    MODE_UNKNOWN = 0,
    MODE_NORMAL,
    MODE_RECOVERY,
    MODE_PORT_DFU,
    MODE_LEGACY_DFU
} device_mode_t;

/* Device Information Structure */
typedef struct l0fck_device_s l0fck_device_t;

struct l0fck_device_s {
    char udid[64];
    char device_name[128];
    char product_type[32];
    char product_version[32];
    char build_version[32];
    char hardware_model[32];
    char serial_number[64];
    char cpu_architecture[32];
    char activation_state[32];
    char wifi_address[32];
    char bluetooth_address[32];
    uint32_t cpid;
    uint32_t bdid;
    uint64_t ecid;
    uint32_t sdom;
    uint32_t sysi;
    device_mode_t mode;
    bool is_target_soc;
    bool is_target_os;
    bool is_validated;
};

#include "core/log.h"
#include "core/target.h"
#include "core/util.h"
#include "usb/port_dfu.h"
#include "usb/usb_ctrl.h"
#include "lockdown/lockdown_unauth.h"
#include "lockdown/session_manager.h"
#include "lockdown/services.h"
#include "lockdown/afc_manager.h"
#include "lockdown/flag_injector.h"
#include "lockdown/crash_reporter.h"
#include "activation/mobileactivation.h"
#include "activation/albert_client.h"
#include "activation/record_a18.h"
#include "activation/ingest_parser.h"
#include "exploits/preboard_poc.h"
#include "exploits/preboard_triage.h"
#include "exploits/preboard_exploit.h"
#include "exploits/springboard_injector.h"
#include "exploits/bypass_chain.h"
#include "exploits/captive_server.h"

#endif /* L0FCK_H */
