# l0fck RESEARCH — Chain & Findings Reference

Canonical reference for every chain implemented in `l0fck` and the important
cross-cutting findings behind them. **Read the relevant doc here before
implementing changes to an existing chain or a new custom chain** (see the
`l0fck-research` skill at `../../.agents/skills/l0fck-research/SKILL.md`).

Target across all chains: **iPhone 16 Pro / iPhone 16 Pro Max
(`iPhone17,1` / `iPhone17,2`, A18 Pro, T8140, CPID `0x8140`), iOS 26.6.1
(build `23G83`)** in Setup Assistant.

## Chains

| Doc | Chain | CLI | Transport | Kernel R/W | Status |
|---|---|---|---|---|---|
| `chain-bypass-full.md` | Bypass-Full (5-stage TOCTOU) | `--bypass-full` / `--bypass-watch` | USB | No (race vs `mobileactivationd`) | Blocked on SEP nonce crypto (`Error -5`) |
| `chain-sovereign.md` | Sovereign-Chain / Sovereign-Lite | `--sovereign` / `--sovereign-lite` | USB | No | No race stage; injection + notification + respring |
| `chain-neo-chain.md` | Neo-Chain (kernel R/W framework) | `--neo-chain` (+ Stage 6 fixes) | USB | Yes (AppleAVE2 primary) | Stages 0–6 implemented; on-device primitive mandatory |
| `chain-setup-assistant.md` | SetupAssistant-Chain (Wi-Fi only) | `--setup-assistant-chain` | **Wi-Fi (no USB)** | Yes (AppleAVE2 over WebSheet) | First genuine kbase leak (`0xfffffff0d2000000`) |
| `chain-glyphgrift.md` | GlyphGrift-Chain (CVE-2026-86950) | `--glyphgrift-chain` | **Wi-Fi (no USB)** | Userspace OOB (not kernel R/W yet) | Trigger fires; corruption not yet observed |
| `chain-restore-chain.md` | Restore-Chain (MB2 restore-staging) | `--restore-chain` / `--restore-probe` | USB (lockdown / CoreDevice RSD) | No | A13-class only on this host; A18 Pro close-out (`ServiceProhibited`) |

Supporting subsystems (not standalone chains): **Preboard / VUL 23**
(`--crash-preboard`, `--triage-crash`, `--exploit-preboard`) and the
**captive portal / WebSheet suite** (`--captive-server`) — see the
corresponding findings docs.

## Findings

| Doc | Topic |
|---|---|
| `findings-kernel-rw-hardening.md` | Which primitive won, Stage 6 fixes (KASLR slide, PAC strip, page-skip, cave discovery, allproc validation), C2 bridge, PMAP lab results |
| `findings-kernel-offsets.md` | 26.6.1-23G83 T8140 offset source of truth, recovered 2026-09-02 values, blocked list, promotion rules |
| `findings-preboard-vul23.md` | Preboard PoC/weaponization + the D1 finding that the "USB-first 60%" race keys are invented (dead end) |
| `findings-lockdown-ssl-bypass.md` | Unauthenticated lockdownd SSL bypass & host-trust path traversal (pairing-record load, expiry skip, cert-verify disable) |
| `findings-activation-ambit.md` | SEP local-nonce `Error -5` wall, AFC Media write limits, mobilebackup2 `InvalidService` / `ServiceProhibited` gates, A18 Pro close-out |
| `findings-zero-fake-success.md` | The governing project policy: no fake success, crash ≠ RCE, read-back proof; refuted "final reports" |

## Conventions (read before implementing)

1. **Zero-fake-success** — every stage must return honest failure
   (`-1` / `STAGED / PENDING ON-DEVICE BRIDGE`) when its primitive is a stub.
   See `findings-zero-fake-success.md`.
2. **Offsets** — only non-zero values from
   `kernel-deltas/state/t8140/26.6.1-23G83.txt` are valid. Apple-Bug-Bounty-Skill
   (iOS 26.0.x) offsets are deprecated. A leaked kbase is trusted only with a
   **2-anchor cross-check**. See `findings-kernel-offsets.md`.
3. **On-device execution is mandatory** for kernel exploits — the host cannot
   invoke IOKit/Mach VM across USB. A18 Pro is not checkm8-compatible.
4. **A18 Pro has zero MTE** (vs M5 full MTE4) — kernel-heap exploits are
   unmitigated; this is the strategic enabler for Neo/SetupAssistant/GlyphGrift.
5. **Success claims need a read-back** (canary, telemetry, plist) — a crash or
   a "stage completed" log is not success.

## Provenance

Chain docs synthesize `PLAN/*.md` (per plan cited inline), `l0fck/src/**`,
and live A18 Pro results (2026-10-12 close-out in
`../../RESEARCH/IMPORTANT TO CHECK/research-2026-09-16-afc-26.6.1.md`,
Session 4 addendum, and `l0fck/tools/mb2_reachability_*.txt`). Where a
"final report" in `PLAN/` was later refuted by logs, the corrective plan
(cited) wins and the refuted claim is marked **superseded**.
