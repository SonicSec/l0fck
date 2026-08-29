#ifndef USB_USB_CTRL_H
#define USB_USB_CTRL_H

#include <libusb.h>
#include <stdint.h>
#include <stdbool.h>

int usb_ctrl_init(libusb_context **ctx);
void usb_ctrl_exit(libusb_context *ctx);
int usb_ctrl_safe_reset(libusb_device_handle *handle);
int usb_ctrl_read_descriptor(libusb_device_handle *handle, uint8_t desc_index, unsigned char *buf, int max_len);
int usb_ctrl_probe_apple_devices(libusb_context *ctx);

#endif /* USB_USB_CTRL_H */
