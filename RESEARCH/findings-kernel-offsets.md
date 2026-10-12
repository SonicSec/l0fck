# Finding: Kernel Offsets (iOS 26.6.1 / T8140 / build 23G83)

The offset source of truth and the recovery/promotion rules for kernel R/W
chains. **Only non-zero values are valid.**

## Source of truth

`kernel-deltas/state/t8140/26.6.1-23G83.txt`. All Apple-Bug-Bounty-Skill
(iOS 26.0.x) offsets are **DEPRECATED** and must not be used. Kernel base
slide hint: `KOFF_KERNEL_BASE_SLIDE_HINT = 0xfffffff007004000`.

## Verified in-tree symbols (per README / `include/exploits/kernel_offsets.h`)

| Symbol | Address |
|---|---|
| `kalloc_data_external` | `0xfffffff00a6cc6f8` |
| `kfree_data_external` | `0xfffffff00a6cce30` |
| `allproc` | `0xfffffff00b23a880` |
| `trust_cache_rt` | `0xfffffff007cdab20` |
| `load_static_trust_cache` | `0xfffffff00abe4888` |
| `pmap_enter_options_addr` | `0xfffffff00a80f198` |
| `pmap_remove_options` | `0xfffffff00a816edc` |
| `str_x8_x0` (gadget) | `0xfffffff00a68c33c` |
| `gVirtBase` | `0xfffffff007cb8c78` (lives in freed `__INIT`) |
| `gPhysBase` | `0xfffffff007ced2e0` |
| `ptov_table` | `0xfffffff007d30900` |
| `cpu_ttep` | `0xfffffff00b1dbcd8` |
| `developer_mode_enabled` | `0xfffffff007cdb118` |
| `exception_return` | `0xfffffff00a65147c` |
| `phystokv` | `0xfffffff00aebc504` |
| `proc.p_name` | `0x4d8` |
| `proc.p_flag` | `0x454` (pattern RE, high) |
| `proc.p_pid` | `0x60` (kdk-stable, medium) |
| `task.itk_space` | `0x310` |
| `thread.t_tro` | `0x408` |
| PAC pointer mask | `0xFF00000000000000` |
| T1SZ_BOOT | `0x11` |

## Recovered 2026-09-02 RE (medium/high confidence, per `PLAN/awaiting_offsets.txt`)

`proc.p_fd 0xd0`, `proc.p_ucred/ucred 0x28`, `proc.p_proc_ro 0x18`,
`task.map 0x28`, `task.threads_next 0x50`, `task.bsd_info 0x30`,
`thread.ctid 0x4c8`, `thread.ast 0x42c`, `thread.threads_next 0x3f8`,
`thread.machine_kstackptr 0x148`, `machine_upcb 0x108`,
`machine_contextData 0x100`, `machine_rop_pid 0x1b8`, `jop_pid 0x1c0`,
`thread.mutex 0x420`, `options 0xc0`, `smr_base 0x2`,
`vnode.v_data 0xe0` / `vnode.v_mount 0xd8` (low — validate on device).

## Still blocked (0x0 / unresolved)

- All **PPL** symbols: `ppl_enter`, `ppl_bootstrap_dispatch`,
  `ppl_dispatch_section`, `ppl_handler_table`.
- **PMAP-PPL**: `pmap_enter_options_ppl`, `pmap_remove_options_ppl`,
  `pmap_pin_kernel_pages`, `pmap_lookup_in_loaded_trust_caches_internal`,
  `pmap_enter_pv` (unresolved/crash), `pmap_query_trust_cache_safe`,
  `pmap_bootstrap`.
- Constants: `ARM_TT_L1_INDEX_MASK`, `PT_INDEX_MAX`, `kernel_el`.
- `proc_apply_sandbox` / `mac_label_set`, `kcall_return` gadget,
  `thread.machine_CpuDatap`, `proc.p_limit/p_stats/p_sigacts/task`,
  `task.itk_registered`, `vm_map.max/min_offset/hdr`, `pmap.pm_stats`.
- **Userspace**: `mobileactivationd_should_hactivate`, WebKit GPU IPC
  (iOS 18.4 offsets deprecated).
- **Hardware**: SEP mailbox registers.
- **Others**: `kalloc_type_view` (KASLR-defeat symbol), IOMFB_bics,
  PUAF-specific (likely patched), checkm8 (A18 not compatible — reference
  only).

## Priority (per `PLAN/plan_to_get_offsets.txt`)

1. `task.map`/`bsd_info`, `proc.task`/`ucred`/`p_flag`
2. `thread.*` / `machine_*`
3. `pmap_*_ppl` / `bootstrap` / `enter_pv`
4. `pointer_mask` / `T1SZ` / `ARM_TT_L1_INDEX_MASK` / `smr_base`
5. `vnode` / `vm_map` / `pmap.pm_stats`
6. sandbox / MAC
7. `kcall_return`
8. userspace (mobileactivationd / WebKit / IOMFB)
9. SEP mailbox + PUAF

**Method**: static RE (base-register proof + ≥2 code paths, or 1 path +
read-only runtime), then **promotion with evidence**; **read-first**
validation, no write until identity proven.

## 2-anchor cross-check rule

A leaked kbase is trusted **only if ≥2 independent anchors yield the same
kbase**. The JS `glyphgrift_krw.js` anchor table was wrong (defect D2 —
`allproc` was `0x00c4d000` instead of `0xb23a880`), producing a
plausible-but-wrong kbase and ~80% kwrite failures. Regenerate anchor
tables from `OFFSETS/t8140-26.6.1-23G83/` and cross-check before trusting
any single leaked pointer.
