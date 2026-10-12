# Chain: Neo-Chain (Kernel Exploitation Framework)

- **CLI**: `--neo-chain` (menu 6.5) · isolated tests:
  `--test-kernel-exploit`, `--test-amfi-bypass` (menu 7.2 / 7.3)
- **Transport**: USB
- **Kernel R/W**: **yes** — the strategic pivot away from the TOCTOU race
  (blocked by SEP crypto) to kernel R/W → AMFI/CoreTrust → SEP/NVRAM →
  activation → persistence, enabled by the finding that **A18 Pro has zero
  MTE** (vs M5 full MTE4) so kernel-heap exploits work unmitigated
  (per `PLAN/plan_for_change_8_v2.md`, `docs_for_plan_8_v2.md`).
- **Key files**:
  - `src/exploits/bypass_chain.c` — `neo_chain_run`
  - `src/exploits/kernel_exploit.c` — unified `kernel_exploit_ops_t`,
    `g_exploit_ops`, `kernel_exploit_get_allproc()`, `kread_string_safe`
  - `src/exploits/applejpegdriver_exploit.c` — V-047 (primary fallback)
  - `src/exploits/applemcc_exploit.c` — AppleMCCUserClientV2 testMode
  - `src/exploits/pmap_exploit.c` — PMAP TTE-remove PUAF + reclaim
  - `src/exploits/amfi_bypass.c`, `coretrust_bypass.c`, `cvmserver_exploit.c`,
    `sep_bypass.c` — stages 2/3
  - `src/exploits/appleave2_exploit.c` + `payloads/appleave2/` — primary
    primitive (AppleAVE2 CVE-2026-84607)

## Stages (per `PLAN/plan_for_change_8_v2.md`)

```
Stage 0: Recon — A18 Pro detection, MTE absence confirmation (ID_AA64PFR0_EL1),
          open IOKit userclient audit, primitive selection
Stage 1: Kernel R/W — AppleAVE2 CVE-2026-84607 eEncType race (primary);
          fallback V-047 AppleJPEGDriver OOB / AppleMCC testMode / PMAP
Stage 2: AMFI / CoreTrust — CVMServer cdhash registration + trust_cache_rt
          cave injection + AMFI HSP disable (P_AMFI_DISABLED via allproc walk)
Stage 3: SEP / MobileActivation — NVRAM activated-state write via PMAP;
          SEP mailbox currently blocked (offsets unresolved)
Stage 4: Persistence — AFC staging (IOMFB NVMe-EAN blocked)
Stage 5: Cleanup — Darwin notifications, respring, verification
```

The **Stage 6 fix saga** (kernel R/W + dynamic discovery over the KRW HTTP C2
bridge) is documented in `findings-kernel-rw-hardening.md` — KASLR slide
recovery, PAC stripping, page-skip refinement, writable-cave discovery,
`allproc` false-positive validation, `ptov_table` translation.

## On-device primitive requirement

Host-side orchestration cannot invoke IOKit/Mach VM across USB. Stage 1 needs
a delivered on-device payload (V-047 / PMAP / AppleAVE2 `.app` bundles under
`payloads/` — built via `make payload-v047|pmap|appleave2`). A18 Pro is not
checkm8-compatible, so the payload must reach the device by other means
(AFC staging works for the Media partition). The original in-tree
`appleave2_exploit.c` kread returned a hardcoded `0xdeadbeef1337c0de`
(dummy); see `findings-zero-fake-success.md` for the honest-stub policy and
`WHY-NEOCHAIN-DOESNT-WORK.txt` for the full refutation of the early
"won R/W" claims.

## Success telemetry

- Result plists: `/tmp/l0fck_appleave2_result.json` (first genuine kbase
  `0xfffffff0d2000000` came from the Wi-Fi AppleAVE2 portal race — see
  `chain-setup-assistant.md`), PMAP plists (lab: `pmap_result_lab_*.plist`).
- Self-tests 15–16 (KASLR slide, C2 bridge + dynamic discovery) validate the
  stage-6 logic against a mocked bridge.
