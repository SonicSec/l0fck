#include "usb/usb_ctrl.h"
#include "l0fck.h"
#include "core/log.h"
#include <stdio.h>
#include <string.h>

int usb_ctrl_init(libusb_context **ctx)
{
    if (!ctx) return -1;
    int r = libusb_init(ctx);
    if (r < 0) {
        LOG_ERROR("libusb_init failed: %s", libusb_error_name(r));
        return -1;
    }
    return 0;
}

void usb_ctrl_exit(libusb_context *ctx)
{
    if (ctx) {
        libusb_exit(ctx);
    }
}

int usb_ctrl_safe_reset(libusb_device_handle *handle)
{
    if (!handle) return -1;
    int r = libusb_reset_device(handle);
    if (r < 0) {
        LOG_WARN("libusb_reset_device returned %s", libusb_error_name(r));
        return r;
    }
    return 0;
}

int usb_ctrl_read_descriptor(libusb_device_handle *handle, uint8_t desc_index, unsigned char *buf, int max_len)
{
    if (!handle || !buf || max_len <= 0) return -1;
    return libusb_get_string_descriptor_ascii(handle, desc_index, buf, max_len);
}

int usb_ctrl_probe_apple_devices(libusb_context *ctx)
{
    libusb_device **dev_list = NULL;
    ssize_t count = libusb_get_device_list(ctx, &dev_list);
    if (count < 0) {
        LOG_ERROR("Unable to scan USB bus: %s", libusb_error_name(count));
        return -1;
    }

    int apple_count = 0;
    for (ssize_t i = 0; i < count; i++) {
        struct libusb_device_descriptor desc;
        if (libusb_get_device_descriptor(dev_list[i], &desc) == 0) {
            if (desc.idVendor == APPLE_VID) {
                apple_count++;
                const char *mode_str = "Unknown Apple Mode";
                if (desc.idProduct == APPLE_PID_PORT_DFU) {
                    mode_str = "Port DFU Mode (0x05AC:0xF014)";
                } else if (desc.idProduct == APPLE_PID_DFU_LEGACY) {
                    mode_str = "Legacy SecureROM DFU Mode (0x05AC:0x1227)";
                } else if (desc.idProduct >= APPLE_PID_RECOVERY_MIN && desc.idProduct <= APPLE_PID_RECOVERY_MAX) {
                    mode_str = "Recovery Mode (0x05AC:0x128x)";
                } else if (desc.idProduct == APPLE_PID_NORMAL) {
                    mode_str = "Normal / Lockdown Mode (0x05AC:0x12A8)";
                }
                LOG_INFO("USB Device [%04x:%04x] on Bus %03d Addr %03d: %s",
                         desc.idVendor, desc.idProduct,
                         libusb_get_bus_number(dev_list[i]),
                         libusb_get_device_address(dev_list[i]),
                         mode_str);
            }
        }
    }

    libusb_free_device_list(dev_list, 1);
    return apple_count;
}
