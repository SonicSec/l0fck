#ifndef CORE_UTIL_H
#define CORE_UTIL_H

#include <stdint.h>
#include <stddef.h>
#include <plist/plist.h>

char *util_plist_to_xml(plist_t node, uint32_t *length);
plist_t util_xml_to_plist(const char *xml, uint32_t length);
void util_plist_mem_free(char *ptr);

char *util_base64_encode(const unsigned char *data, size_t input_length, size_t *output_length);
unsigned char *util_base64_decode(const char *data, size_t input_length, size_t *output_length);

char *util_bytes_to_hex(const uint8_t *bytes, size_t len);
int util_hex_to_bytes(const char *hex, uint8_t **bytes, size_t *out_len);
void util_print_hex_dump(const char *label, const uint8_t *data, size_t len);

int util_save_file(const char *path, const void *data, size_t len);
int util_read_file(const char *path, void **data, size_t *len);
void util_sleep_ms(unsigned int ms);

#endif /* CORE_UTIL_H */
