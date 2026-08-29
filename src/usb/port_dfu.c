#include "l0fck.h"
#include "usb/port_dfu.h"
#include "usb/usb_ctrl.h"
#include "core/log.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

static int parse_hex_u32(const char *str, const char *key, uint32_t *val)
{
    const char *pos = strstr(str, key);
    if (!pos) return -1;
    pos += strlen(key);
    while (*pos == ' ' || *pos == ':') pos++;
    char *end = NULL;
    unsigned long v = strtoul(pos, &end, 16);
    if (end == pos) return -1;
    *val = (uint32_t)v;
    return 0;
}

static int parse_hex_u64(const char *str, const char *key, uint64_t *val)
{
    const char *pos = strstr(str, key);
    if (!pos) return -1;
    pos += strlen(key);
    while (*pos == ' ' || *pos == ':') pos++;
    char *end = NULL;
    unsigned long long v = strtoull(pos, &end, 16);
    if (end == pos) return -1;
    *val = (uint64_t)v;
    return 0;
}

static int parse_str_field(const char *str, const char *key, char *out, size_t out_len)
{
    const char *pos = strstr(str, key);
    if (!pos) return -1;
    pos += strlen(key);
    while (*pos == ' ' || *pos == ':') pos++;
    size_t i = 0;
    if (*pos == '[') {
        while (*pos && i < out_len - 1) {
            out[i++] = *pos;
            if (*pos == ']') break;
            pos++;
        }
    } else {
        while (*pos && *pos != ' ' && *pos != '\r' && *pos != '\n' && i < out_len - 1) {
            out[i++] = *pos++;
        }
    }
    out[i] = '\0';
    return (i > 0) ? 0 : -1;
}

int port_dfu_parse_serial(const char *serial_str, port_dfu_info_t *out_info)
{
    if (!serial_str || !out_info) return -1;

    snprintf(out_info->serial_str, sizeof(out_info->serial_str), "%s", serial_str);

    parse_hex_u32(serial_str, "CPID", &out_info->cpid);
    parse_hex_u32(serial_str, "BDID", &out_info->bdid);
    parse_hex_u32(serial_str, "SDOM", &out_info->sdom);
    parse_hex_u32(serial_str, "SYSI", &out_info->sysi);
    parse_hex_u64(serial_str, "ECID", &out_info->ecid);
    parse_str_field(serial_str, "SRTG", out_info->srtg, sizeof(out_info->srtg));
    parse_str_field(serial_str, "CHIP", out_info->chip, sizeof(out_info->chip));

    if (out_info->cpid == TARGET_CPID || out_info->cpid == 0x0022) {
        out_info->is_a18_pro = true;
    }

    return 0;
}

int port_dfu_detect(libusb_context *ctx, port_dfu_info_t *out_info)
{
    if (!out_info) return -1;
    memset(out_info, 0, sizeof(port_dfu_info_t));

    libusb_device **dev_list = NULL;
    ssize_t count = libusb_get_device_list(ctx, &dev_list);
    if (count < 0) {
        LOG_ERROR("Failed to get USB device list: %s", libusb_error_name(count));
        return -1;
    }

    int found = 0;

    for (ssize_t i = 0; i < count; i++) {
        struct libusb_device_descriptor desc;
        int r = libusb_get_device_descriptor(dev_list[i], &desc);
        if (r < 0) continue;

        if (desc.idVendor != APPLE_VID) continue;

        bool is_port_dfu = (desc.idProduct == APPLE_PID_PORT_DFU);
        bool is_legacy_dfu = (desc.idProduct == APPLE_PID_DFU_LEGACY);
        bool is_recovery = (desc.idProduct >= APPLE_PID_RECOVERY_MIN && desc.idProduct <= APPLE_PID_RECOVERY_MAX);

        if (!is_port_dfu && !is_legacy_dfu && !is_recovery) continue;

        out_info->vid = desc.idVendor;
        out_info->pid = desc.idProduct;
        out_info->bus = libusb_get_bus_number(dev_list[i]);
        out_info->address = libusb_get_device_address(dev_list[i]);
        out_info->is_port_dfu = is_port_dfu;
        out_info->is_legacy_dfu = is_legacy_dfu;
        out_info->is_recovery = is_recovery;

        libusb_device_handle *handle = NULL;
        r = libusb_open(dev_list[i], &handle);
        if (r == 0 && handle) {
            unsigned char serial_buf[512] = {0};
            int s_len = 0;

            /* Try iSerialNumber descriptor index first */
            if (desc.iSerialNumber > 0) {
                s_len = libusb_get_string_descriptor_ascii(handle, desc.iSerialNumber, serial_buf, sizeof(serial_buf) - 1);
            }

            /* Probing fallback: indices 1 to 6 if initial read failed */
            if (s_len <= 0) {
                for (uint8_t idx = 1; idx <= 6; idx++) {
                    s_len = libusb_get_string_descriptor_ascii(handle, idx, serial_buf, sizeof(serial_buf) - 1);
                    if (s_len > 0 && strstr((char *)serial_buf, "CPID") != NULL) {
                        break;
                    }
                }
            }

            if (s_len > 0) {
                serial_buf[s_len] = '\0';
                port_dfu_parse_serial((char *)serial_buf, out_info);
            }

            libusb_close(handle);
        }

        found = 1;
        break;
    }

    libusb_free_device_list(dev_list, 1);
    return found ? 0 : -1;
}

void port_dfu_print_info(const port_dfu_info_t *info)
{
    if (!info) return;

    printf("\n" ANSI_COLOR_BOLD ANSI_COLOR_MAGENTA "======================= PORT DFU DIAGNOSTICS =======================" ANSI_COLOR_RESET "\n");
    printf("  " ANSI_COLOR_BOLD "USB Identifier:      " ANSI_COLOR_RESET "%04x:%04x (Bus %03d, Addr %03d)\n",
           info->vid, info->pid, info->bus, info->address);
    printf("  " ANSI_COLOR_BOLD "DFU Subsystem:       " ANSI_COLOR_RESET "%s\n",
           info->is_port_dfu ? ANSI_COLOR_GREEN "Apple USB-C Port DFU (0x05AC:0xF014)" ANSI_COLOR_RESET :
           info->is_legacy_dfu ? "Legacy SecureROM DFU (0x05AC:0x1227)" : "Recovery Mode");
    if (info->serial_str[0]) {
        printf("  " ANSI_COLOR_BOLD "Raw Descriptor:      " ANSI_COLOR_RESET "%s\n", info->serial_str);
    }
    printf("  " ANSI_COLOR_BOLD "CPID (Chip ID):      " ANSI_COLOR_RESET "0x%04X [%s]\n",
           info->cpid, target_cpid_to_name(info->cpid));
    printf("  " ANSI_COLOR_BOLD "BDID (Board ID):     " ANSI_COLOR_RESET "0x%02X\n", info->bdid);
    if (info->sdom) {
        printf("  " ANSI_COLOR_BOLD "SDOM (Sec Domain):   " ANSI_COLOR_RESET "0x%02X\n", info->sdom);
    }
    if (info->sysi) {
        printf("  " ANSI_COLOR_BOLD "SYSI (System Info):  " ANSI_COLOR_RESET "0x%02X\n", info->sysi);
    }
    if (info->ecid) {
        printf("  " ANSI_COLOR_BOLD "ECID:                " ANSI_COLOR_RESET "0x%016llX\n", (unsigned long long)info->ecid);
    }
    if (info->srtg[0]) {
        printf("  " ANSI_COLOR_BOLD "SRTG (Software):     " ANSI_COLOR_RESET "%s\n", info->srtg);
    }
    if (info->chip[0]) {
        printf("  " ANSI_COLOR_BOLD "CHIP Type:           " ANSI_COLOR_RESET "%s\n", info->chip);
    }

    printf("  " ANSI_COLOR_BOLD "Status:              " ANSI_COLOR_RESET);
    if (info->is_port_dfu && (info->cpid == TARGET_CPID || info->cpid == 0x0022)) {
        printf(ANSI_COLOR_GREEN ANSI_COLOR_BOLD "NATIVE A18 PRO PORT DFU DETECTED" ANSI_COLOR_RESET "\n");
    } else if (info->is_port_dfu) {
        printf(ANSI_COLOR_YELLOW ANSI_COLOR_BOLD "PORT DFU DETECTED (SoC 0x%04X)" ANSI_COLOR_RESET "\n", info->cpid);
    } else {
        printf(ANSI_COLOR_CYAN "LEGACY OR RECOVERY MODE" ANSI_COLOR_RESET "\n");
    }
    printf(ANSI_COLOR_MAGENTA "====================================================================" ANSI_COLOR_RESET "\n\n");
}

int port_dfu_reset(libusb_device_handle *handle)
{
    if (!handle) return -1;
    LOG_INFO("Issuing safe Port DFU port reset...");
    return usb_ctrl_safe_reset(handle);
}
