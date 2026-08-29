#ifndef USB_PORT_DFU_H
#define USB_PORT_DFU_H

#include <stdint.h>
#include <stdbool.h>
#include <libusb.h>

typedef struct {
    uint32_t cpid;
    uint32_t bdid;
    uint32_t sdom;
    uint32_t sysi;
    uint64_t ecid;
    char srtg[64];
    char chip[64];
    char serial_str[512];
    uint16_t vid;
    uint16_t pid;
    uint8_t bus;
    uint8_t address;
    bool is_port_dfu;
    bool is_legacy_dfu;
    bool is_recovery;
    bool is_a18_pro;
} port_dfu_info_t;

int port_dfu_detect(libusb_context *ctx, port_dfu_info_t *out_info);
int port_dfu_parse_serial(const char *serial_str, port_dfu_info_t *out_info);
void port_dfu_print_info(const port_dfu_info_t *info);
int port_dfu_reset(libusb_device_handle *handle);

#endif /* USB_PORT_DFU_H */
