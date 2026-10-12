# Chain: Restore-Chain (MobileBackup2 Restore-Staging Traversal)

- **CLI**: `--restore-chain` (menu 6.8, full stages 0–6) · `--restore-probe`
  (stages 0–3 only, protocol validation, no unlock).
- **Transport**: USB only — no Wi-Fi, **no kernel exploit**. Drives a full
  `com.apple.mobilebackup2` (mb2) restore session. Transport is selected by
  target: A13-class → legacy lockdown; A18 Pro → CoreDevice RSD
  (`com.apple.mobilebackup2.shim.remote`) via a `pymobiledevice3` sidecar
  (Phase 1, **not built** — see close-out below).
- **Goal**: exploit CVE-2026-84598-class domain-escape in the mb2 restore
  path to stage canary / unlock files, hard-gate on a confirmed write, then
  reuse the proven post-exploit stack to reach the unlocked Home Screen.
- **Key files**: `src/backup/mb2_restore.c` (45.7K — full chain) +
  `include/backup/mb2_restore.h`; diagnostics `l0fck/tools/mb2_reachability.py`,
  `mb2_checkin_diag.py` (raw RSD bytes), `mb2_fmip_diag.py` (lockdown
  state), `mb2_control_diag.py` (A/B service control).

## Stages (per `src/backup/mb2_restore.c`, README)

```
Stage 0: Preflight — A18 Pro / iOS 26.6.1 gate; Find My manual OFF step
         (Vol Down + Power → "Turn off" screen → Find My off). TTY pre-gate
         prompt.
Stage 1: MB2 Session — com.apple.mobilebackup2, DL version exchange
         (v400/0), "Hello" with SupportedProtocolVersions [2.0, 2.1]
Stage 2: Manifest + .MBDB Stream — synthesized Manifest.plist (Version 8.0,
         SystemDomainsVersion 19.0); phase-1 domain-escape entries
         (SysContainerDomain-../..) stage canaries at /var/mobile/Media
         in-jail root and /var/tmp
Stage 3: 211 Find My Gate — MBErrorDomain/211 retry, max 3 rounds; daemon
         wedge → reboot recovery
Stage 4: HARD GATE — re-read phase-1 canary over plain AFC = confirmed
         arbitrary write (parse-accept alone is NOT a write primitive);
         stops honestly if only parse-accept
Stage 5: Unlock Artifacts — purplebuddy / SetupAssistant plists planted in
         the same restore pass
Stage 6: Finalize — lockdown flag injection + offline A18 Pro activation +
         SpringBoard/Setup preferences + 14 Darwin dismissal bursts +
         respring → unlocked Home Screen
```

Message dumps land in `/tmp/l0fck-restore/`.

## Close-out — A18 Pro NOT REACHABLE (2026-10-12, user-confirmed)

Live A18 Pro (UDID `00008140-0011285A20E3C01C`, iOS 26.6.1, paired host):

1. **Legacy lockdown surface**: `com.apple.mobilebackup2` is **not
   registered** — `StartService` fails `InvalidService`
   (`LOCKDOWN_E_INVALID_SERVICE`, -27; surfaced as -256 at the mb2 layer).
   This is a device-side **registration gate**, not a pairing/SSL bug.
   **Red-herring correction**: l0fck's earlier `[lockdown=-23]` came from a
   session-less `lockdownd_client_new` probe (returns -23 by construction).
2. **CoreDevice RSD surface**: `mb2_reachability.py` (venv
   `l0fck/tools/.venv`, pymobiledevice3 11.27.2) confirms
   `com.apple.mobilebackup2.shim.remote` **is registered** on the RSD, RSD
   tunnel up, trusted session — but `StartService` returns
   **`ServiceProhibited`**.
3. **A/B control** (`mb2_control_diag.py`, identical path): `afc`,
   `lockdown.trusted`, `notification_proxy` all start; **only** the
   user-session anti-theft services (`mobilebackup2`,
   `springboardservices`, `installation_proxy`) are `ServiceProhibited`.
   The gate is the device's own anti-theft / user-service gate on a
   **passcode-locked + Find My ON** device, enforced at StartService —
   earlier than the `MBErrorDomain/211` restore-time gate.
4. **Root cause**: device locked + Find My ON (user-confirmed). Find My
   cannot be turned off from the host (the only Find My off path only
   deactivates localization at shutdown and powers off). **Host-unclearable.**

**Outcome**: chain is **A13-class only** on this host (legacy path validated
on A13, 2026-09-16). Phase 1 (CoreDevice mb2 sidecar `mb2_coredevice.py` +
l0fck C rewiring) is **not built** — it would hit `ServiceProhibited` at
service start. Transport is proven working (RSD up, trusted, AFC live); the
block is the device's own anti-theft gate. Full detail:
`../../RESEARCH/IMPORTANT TO CHECK/research-2026-09-16-afc-26.6.1.md`
(Session 4 addendum) + `l0fck/tools/mb2_reachability_2026-10-12_*.txt`.

## Re-open path

If the A18 Pro is ever **unlocked + Find My OFF**, re-run:

```
l0fck/tools/.venv/bin/python l0fck/tools/mb2_reachability.py \
    --udid 00008140-0011285A20E3C01C
```

`REACHABLE` → proceed to the CoreDevice mb2 sidecar + l0fck rewiring
(Phase 1). Still `ServiceProhibited` → true negative; document, no Phase 1.
