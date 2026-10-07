#ifndef PMAP_CORE_H
#define PMAP_CORE_H

#include "pmap_reclaim.h"
#include <stdint.h>

typedef struct {
    int overflow_ok;
    int mappings_created;
    int dangling_ptes;
    int kernel_reads;
    int write_confirmed;
    int prove_attempts;
    int puaf_ready;
    int krw_ready;
    int reclaim_ready;
    int object_corrupt_ready;
    char reclaim_strategy[32];
    int l3_faults;
    int l3_changed;
    int iosurface_hits;
    int spray_count;
    int retry_attempts;
    uint64_t elapsed_ms;
    char verdict[256];
    char error[256];
} pmap_prove_result_t;

int pmap_run_prove(int nprove, pmap_prove_result_t *out);

/* pmap_run_reclaim: wrapper writing into pmap_prove_result_t for host plist */
int pmap_run_reclaim(const pmap_reclaim_config_t *cfg, pmap_prove_result_t *out);

#endif /* PMAP_CORE_H */
