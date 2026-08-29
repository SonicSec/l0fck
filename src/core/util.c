#include "core/util.h"
#include "core/log.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <ctype.h>

char *util_plist_to_xml(plist_t node, uint32_t *length)
{
    if (!node) return NULL;
    char *xml = NULL;
    uint32_t len = 0;
    plist_to_xml(node, &xml, &len);
    if (length) *length = len;
    return xml;
}

plist_t util_xml_to_plist(const char *xml, uint32_t length)
{
    if (!xml || length == 0) return NULL;
    plist_t node = NULL;
    plist_from_xml(xml, length, &node);
    return node;
}

void util_plist_mem_free(char *ptr)
{
    if (!ptr) return;
    free(ptr);
}

static const char base64_table[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

char *util_base64_encode(const unsigned char *data, size_t input_length, size_t *output_length)
{
    if (!data) return NULL;
    size_t out_len = 4 * ((input_length + 2) / 3);
    char *out = malloc(out_len + 1);
    if (!out) return NULL;

    size_t i = 0, j = 0;
    while (i < input_length) {
        size_t rem = input_length - i;
        uint32_t a = data[i++];
        uint32_t b = (rem > 1) ? data[i++] : 0;
        uint32_t c = (rem > 2) ? data[i++] : 0;
        uint32_t triple = (a << 16) | (b << 8) | c;

        out[j++] = base64_table[(triple >> 18) & 0x3F];
        out[j++] = base64_table[(triple >> 12) & 0x3F];
        out[j++] = (rem > 1) ? base64_table[(triple >> 6) & 0x3F] : '=';
        out[j++] = (rem > 2) ? base64_table[triple & 0x3F] : '=';
    }
    out[out_len] = '\0';
    if (output_length) *output_length = out_len;
    return out;
}

static inline int b64_char_value(char c) {
    if (c >= 'A' && c <= 'Z') return c - 'A';
    if (c >= 'a' && c <= 'z') return c - 'a' + 26;
    if (c >= '0' && c <= '9') return c - '0' + 52;
    if (c == '+') return 62;
    if (c == '/') return 63;
    return -1;
}

unsigned char *util_base64_decode(const char *data, size_t input_length, size_t *output_length)
{
    if (!data) return NULL;
    if (input_length % 4 != 0) return NULL;

    size_t out_len = (input_length / 4) * 3;
    if (input_length > 0 && data[input_length - 1] == '=') out_len--;
    if (input_length > 1 && data[input_length - 2] == '=') out_len--;

    unsigned char *out = malloc(out_len + 1);
    if (!out) return NULL;

    size_t j = 0;
    for (size_t i = 0; i < input_length; i += 4) {
        int v0 = b64_char_value(data[i]);
        int v1 = b64_char_value(data[i+1]);
        int v2 = (data[i+2] == '=') ? 0 : b64_char_value(data[i+2]);
        int v3 = (data[i+3] == '=') ? 0 : b64_char_value(data[i+3]);

        if (v0 < 0 || v1 < 0 || v2 < 0 || v3 < 0) {
            free(out);
            return NULL;
        }

        uint32_t triple = ((uint32_t)v0 << 18) | ((uint32_t)v1 << 12) | ((uint32_t)v2 << 6) | (uint32_t)v3;

        if (j < out_len) out[j++] = (triple >> 16) & 0xFF;
        if (j < out_len) out[j++] = (triple >> 8) & 0xFF;
        if (j < out_len) out[j++] = triple & 0xFF;
    }
    out[out_len] = '\0';
    if (output_length) *output_length = out_len;
    return out;
}

char *util_bytes_to_hex(const uint8_t *bytes, size_t len)
{
    if (!bytes) return NULL;
    char *hex = malloc(len * 2 + 1);
    if (!hex) return NULL;
    for (size_t i = 0; i < len; i++) {
        sprintf(hex + (i * 2), "%02X", bytes[i]);
    }
    hex[len * 2] = '\0';
    return hex;
}

int util_hex_to_bytes(const char *hex, uint8_t **bytes, size_t *out_len)
{
    if (!hex || !bytes) return -1;
    size_t len = strlen(hex);
    if (len % 2 != 0) return -1;
    size_t count = len / 2;
    uint8_t *buf = malloc(count);
    if (!buf) return -1;

    for (size_t i = 0; i < count; i++) {
        unsigned int val = 0;
        if (sscanf(hex + (i * 2), "%02x", &val) != 1) {
            free(buf);
            return -1;
        }
        buf[i] = (uint8_t)val;
    }
    *bytes = buf;
    if (out_len) *out_len = count;
    return 0;
}

void util_print_hex_dump(const char *label, const uint8_t *data, size_t len)
{
    if (label) printf("%s (%zu bytes):\n", label, len);
    for (size_t i = 0; i < len; i += 16) {
        printf("  %04zx: ", i);
        for (size_t j = 0; j < 16; j++) {
            if (i + j < len)
                printf("%02X ", data[i + j]);
            else
                printf("   ");
        }
        printf(" |");
        for (size_t j = 0; j < 16; j++) {
            if (i + j < len) {
                unsigned char c = data[i + j];
                printf("%c", isprint(c) ? c : '.');
            } else {
                printf(" ");
            }
        }
        printf("|\n");
    }
}

int util_save_file(const char *path, const void *data, size_t len)
{
    if (!path || !data) return -1;
    FILE *f = fopen(path, "wb");
    if (!f) return -1;
    size_t written = fwrite(data, 1, len, f);
    fclose(f);
    return written == len ? 0 : -1;
}

int util_read_file(const char *path, void **data, size_t *len)
{
    if (!path || !data || !len) return -1;
    FILE *f = fopen(path, "rb");
    if (!f) return -1;
    fseek(f, 0, SEEK_END);
    long size = ftell(f);
    fseek(f, 0, SEEK_SET);
    if (size < 0) { fclose(f); return -1; }

    void *buf = malloc(size + 1);
    if (!buf) { fclose(f); return -1; }
    size_t read_bytes = fread(buf, 1, size, f);
    fclose(f);
    ((char *)buf)[read_bytes] = '\0';
    *data = buf;
    *len = read_bytes;
    return 0;
}

void util_sleep_ms(unsigned int ms)
{
    usleep(ms * 1000);
}
