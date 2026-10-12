# Finding: Activation Ambit — SEP Nonce Wall, AFC Limits, mb2 Gates

The three device-side gates that bound every activation path, plus the
AFC write limits. These explain why the chains stop where they stop.

## 1. SEP local-nonce crypto wall (`Error -5`)

- The synthesized offline A18 activation record
  (`record_a18_generate`) fails **SEP local-nonce cryptographic validation**
  (`Error -5`) on **100% of attempts** (per `PLAN/plan_for_change_5.md`):
  "No amount of timing precision will fix this — the race infrastructure is
  now perfect, but the payload it delivers is fundamentally invalid."
- This is the **fundamental wall for every record-based activation**
  (bypass-full, offline Albert, restore-chain Stage 6b).
- The only discussed escapes: real kernel writes to SEP/NVRAM (offsets
  unresolved — see `findings-kernel-offsets.md`), or the (invented,
  unproven) preboard race (see `findings-preboard-vul23.md`).
- Stage-8 fallback: if `albert_perform_offline_activation` returns `-5`,
  auto-pivot to `albert_perform_race_activation` (VUL 23).

## 2. AFC Media-partition write limits

- Unauthenticated Media-partition AFC **rejects `.plist` writes** (0/4
  deployed). Attempts that failed: afc2, write-as-`.data`-then-rename,
  priority dirs (`iTunes_Control/iTunes`), multi-vector salvo inside the
  crash window.
- Consequence: lockdown **flag injection alone is ignored by Setup
  Assistant** (per `PLAN/WHY-NEOCHAIN-DOESNT-WORK.txt`); persistence needs
  privileged AFC / sandbox escape / kernel writes.
- **AFC itself stays live on the A18 Pro** — the restore-chain Stage-4 hard
  gate (AFC canary read-back) and stages 5–6 are unaffected by the mb2
  `ServiceProhibited` block.

## 3. mobilebackup2 registration / StartService gates (A18 Pro close-out)

The mb2 (Restore-Chain) path hit two distinct device-side gates on the A18
Pro (full close-out in `chain-restore-chain.md`):

- **Legacy lockdown surface**: `com.apple.mobilebackup2` **not
  registered** → `StartService` fails `InvalidService`
  (`LOCKDOWN_E_INVALID_SERVICE`, -27; -256 at the mb2 layer). A
  device-side **registration gate**, not pairing/SSL. **Red-herring
  correction**: the earlier `[lockdown=-23]` came from a session-less
  `lockdownd_client_new` probe (returns -23 by construction), not a real
  failure.
- **CoreDevice RSD surface**: `com.apple.mobilebackup2.shim.remote` **is
  registered** (RSD tunnel up, trusted session) but `StartService` returns
  **`ServiceProhibited`**.
- **A/B control** (`l0fck/tools/mb2_control_diag.py`): `afc`,
  `lockdown.trusted`, `notification_proxy` all start; **only** user-session
  anti-theft services (`mobilebackup2`, `springboardservices`,
  `installation_proxy`) are `ServiceProhibited`. Gate = device's own
  anti-theft / user-service gate on a **locked + Find My ON** device,
  enforced at StartService (earlier than `MBErrorDomain/211`).
- **Root cause**: device locked + Find My ON (user-confirmed). Find My
  cannot be turned off from the host → **host-unclearable**. Chain is
  **A13-class only** on this host; Phase 1 (CoreDevice sidecar) not built.
- **Find My prerequisite** for any mb2 restore: disable Find My on the
  device (Vol Down + Power → "Turn off" → Find My off). The chain retries
  on `MBErrorDomain/211` up to 3 rounds, with a manual TTY pre-gate.

## 4. Why DFU is not a substitute (close-out, user-confirmed)

DFU/Recovery exposes only the SecureROM/bootrom firmware blob writer
(irecv/ftab) — **no** lockdownd user services, no `mobilebackup2`, no
`springboardservices`, no AFC user-FS, no Darwin, no respring. The chain
requires a **booted OS at every stage** (live mb2 daemon, AFC read-back,
live-kernel flag injection, respring). A18 Pro (T8140) is post-checkm8 →
DFU is signed-firmware-only. A signed IPSW restore does **not** clear Find
My / activation lock. `src/usb/port_dfu.c` only detects/parses Port DFU /
Recovery PIDs (0xf014 / 0x1227 / 0x1281) — l0fck has no firmware-restore
engine today. **Decision: no DFU implementation of the chain** (plan
`1791770730089-dfu-device-state-evaluation.md`, CLOSED).
