# Finding: Kernel R/W — Winning Primitive & Stage-6 Hardening

Which kernel R/W primitive actually worked, and the Stage-6 hardening fixes
shared by Neo-Chain and SetupAssistant-Chain.

## Which primitive won

**AppleAVE2 CVE-2026-84607** (the `AppleAVE2Driver` `sEnc.eType` /
`eEncType` state-management race) is the **only** primitive that produced a
genuine kernel base. V-047 (AppleJPEGDriver OOB), AppleMCC testMode, and
PMAP (`pmap_tte_remove`) were **scaffold/stub or offset-blocked** on the
device (per `PLAN/WHY-NEOCHAIN-DOESNT-WORK.txt`, `plan_for_change_8_v2.md`):
they "CAN PROCEED" on paper (valid offsets) but shipped as no-ops; PMAP was
"gated on A18 Pro / SPTM bridge."

- **AppleAVE2** writer path: `sEnc.eType` at `[x19,#0x270]`; reader path:
  `eEncType` at `[x22,#0x58]`. Exploited via concurrent
  `encoder.configure()` codec-switch vs `encoder.encode()` dispatch.
  The in-tree `appleave2_exploit.c` originally returned a hardcoded
  `0xdeadbeef1337c0de` (dummy) — the real primitive is the on-device
  IOKit payload (`payloads/appleave2/`) + the Wi-Fi WebSheet race.
- **First genuine kbase**: `0xfffffff0d2000000` (leak
  `0xffffffa5d237d844`, 10000 race attempts) — from the Wi-Fi portal race
  (see `chain-setup-assistant.md`).
- **macOS-lab PMAP** (the only pmap result plists, `ios_version: macos-lab`):
  `pmap_result_lab_check.plist` = "WRITE CONFIRMED — 1/1 (reads raced with
  zeroing)"; `pmap_result_lab_prove.plist` = "PUAF CONFIRMED — 64/64
  write-through, 63 kernel PTE reads"; `pmap_result_lab_reclaim.plist` =
  "SPTM reclaim MISS — PUAF 64/64 write-through, retry or increase spray"
  (`reclaim_ready:0`). PUAF write-through confirmed on the Mac lab, but the
  **SPTM reclaim missed** — consistent with the A18 SPTM bridge being
  unavailable.

## Stage-6 hardening (per `PLAN/stage6_*.md`, `walkthrough*.md`)

Shared by Neo-Chain and SetupAssistant-Chain, all over the **KRW HTTP C2
bridge** (synchronous `GET /api/krw/poll` / `POST /api/krw/result`, 5 s
timeout, mutex+condvar queue in `captive_http.c`). Built because host-side
`setupassistant_kread64/kwrite64` returned -1 (zero-fake-success).

- **KASLR slide recovery**: `kslide = kbase - KOFF_KERNEL_BASE_SLIDE_HINT`
  where the hint is `0xfffffff007004000` (e.g.
  `0xfffffff0d2000000 - 0xfffffff007004000 = 0xcaffc000`); all downstream
  symbols re-slid.
- **PAC stripping**: `#define STRIP_PAC(ptr) ((ptr) | 0xffffff8000000000ULL)`
  applied to `allproc` proc pointers before `kread_string_safe` (proc
  pointers from `KOFF_ALLPROC` carry PAC bits).
- **Page-skipping** (evolved): skip a whole 16 KB (`0x4000`) page on a failed
  read to cut ~2048 requests/page; refined with a `page_mapped` bool so a
  mid-page failure advances 8 bytes instead of skipping valid mapped memory;
  consecutive-failure cap of 16; search radius ±0x80000 (512 KB).
- **Cave discovery**: `trust_cache_rt` is an **8-byte pointer, not a
  24-byte slot** — writing the CDHash into it overflowed adjacent memory.
  Fix: discover a genuinely writable 24-byte cave (test-write non-zero
  `0x4141414141414141`, read back, restore), then write the CDHash to the
  cave and **repoint** `trust_cache_rt`.
- **`ptov_table`** for SEP MMIO phys→virt translation (replacing broken
  `gVirtBase`/`gPhysBase` math — `gVirtBase` lives in freed `__INIT`): scan
  for a `(pa, va, len)` triplet with `0<pa<0x1000000000`,
  `va>0xfffffff000000000`, `0<len<0x100000000`.
- **`kread_string_safe`**: round address down to an 8-byte boundary, aligned
  64-bit read, mask out the unaligned bytes — fixes the JS primitive's
  inability to handle unaligned addresses.
- **`allproc` false-positive fix**: `kread64(KOFF_ALLPROC)` can return a
  non-zero but invalid proc pointer (e.g. `0xfffffff0d5000000`); must
  **validate by reading `p_name`** before trusting, else fall back to the
  dynamic sweep. Centralized `kernel_exploit_get_allproc()` dedups the scan
  across amfi/sep.
- **AMFI disarm via allproc**: `amfi_disarm_security_daemons` walks
  `allproc`, matches `p_name` (`KOFF_PROC_P_NAME` = 0x4d8) for
  `mobileactivationd` / `Setup` / `SpringBoard` / `amfid`, patches
  `proc.p_flag` at 0x454 with `P_AMFI_DISABLED`.

## Stage-8 fallback

If `albert_perform_offline_activation` returns `-5` (SEP nonce validation),
auto-pivot to `albert_perform_race_activation` (VUL 23)
(per `PLAN/stage6_kernel_security_fix_plan.md`).

## Self-test coverage

Tests 15 (KASLR slide & slid addressing) and 16 (synchronous KRW HTTP C2
bridge & dynamic discovery — simulated allproc walk, PAC stripping,
DeviceTree/PTOV resolution) validate the Stage-6 logic against a **mocked**
bridge.
