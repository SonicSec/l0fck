# Chain: SetupAssistant-Chain (Wi-Fi Only — No USB)

- **CLI**: `--setup-assistant-chain` (menu 6.6), with
  `--captive-server <port> --captive-dns-port <port> --captive-tls-port <port>`
  for user ports; `sudo` required for privileged CNA ports 53/80/443.
- **Transport**: **Wi-Fi Soft AP only — no USB cable required** for exploit
  delivery.
- **Kernel R/W**: yes — AppleAVE2 CVE-2026-84607 driven from the captive
  browser (WebSheet) via WebCodecs `VideoEncoder`, not an on-device `.app`.
- **Goal**: pure over-the-air exploit for unactivated devices stuck in Setup
  Assistant (where app install / Developer Mode are blocked): intercept the
  Apple CNA probe, pop WebSheet, win kernel R/W, then (optionally on USB
  attach) complete activation to the unlocked Home Screen.
- **Key files**:
  - `src/exploits/bypass_chain.c` — `setup_assistant_chain_run`
  - `src/exploits/captive_server.c` / `captive_dns.c` / `captive_http.c` /
    `captive_tls.c` / `captive_payloads.c` — DNS spoofer
    (`captive.apple.com`), CNA probe handler (`/hotspot-detect.html`),
    WebSheet, TLS pinning inspector, `/api/appleave2-result` telemetry,
    `/api/krw/*` C2 bridge
  - `payloads/websheet/` — `loader.js`, `manifest.json`, probes:
    `appleave2_portal_race.js` (WebCodecs race), `video_encoder_probe.js`,
    `capability_probe.js`, `jsc_watchpoint_oom.js`, `captive_krw_client.js`

## Stages (per `PLAN/plan_for_change_9.md`,
`setupassistant_appleave2_integration_plan.md`,
`setupassistant_device_activation_plan.md`)

```
Stage 0: Network Prep — Soft AP, DNS/HTTP/TLS servers (privileged 53/80/443
          or user ports 5353/8080/8443)
Stage 1: Force WebSheet — non-"Success" on /hotspot-detect.html pops the
          CNA/WebSheet modal
Stage 2: JS Foothold Confirmed — telemetry POST from WebSheet UA
          (stage2_js_confirmed=true, /tmp/l0fck_websheet_result.json)
Stage 3: Recon & Capability Audit — SAB/WASM/timer/scheme probes (research
          harness only; stage4_native_rce stays false — no live 23G83 WebKit
          RCE in tree, see PLAN/webkit_23G83_triage.md)
Stage 4: Probes Complete — video_encoder_probe confirmed WebCodecs hardware
          acceleration (H.264/HEVC prefer-hardware) → OTA AppleAVE2 viable
Stage 5: AppleAVE2 Portal Race — WebCodecs VideoEncoder eEncType desync
          (CVE-2026-84607) via concurrent encoder.configure() codec switch vs
          encoder.encode() dispatch; telemetry POST /api/appleave2-result
Stage 6: Kernel R/W Won → AMFI/CoreTrust/SEP (same Stage-6 stack as Neo-Chain,
          over the KRW HTTP C2 bridge)
Stage 7: Captive Success Release — force "Success" on CNA + serve synthesized
          A18 activation record on /deviceservices/deviceActivation
Stage 8: Optional USB Attachment — flag injection + offline activation +
          14 Darwin dismissal broadcasts → Home Screen
```

## AppleAVE2 race fix specifics (per `PLAN/setupassistant_appleave2_fix_plan.md`)

The original scanner only read the first 64 bytes at an 8-byte stride with a
`high===0xfffffff0` mask and missed the leaked slice buffer. Fixes: **inline
Web Worker** (concurrent `configure` mutator vs `encode` dispatcher for a
true driver race), **full-payload sliding-window scan** (`o++`), **ARM64e
pointer mask `0xfffffe00..0xffffffff`**, progressive telemetry every 250
attempts (batches of 2500 up to 10000).

## Real win telemetry (first genuine kbase)

`/tmp/l0fck_appleave2_result.json` (per
`PLAN/setupassistant_device_activation_plan.md`):
`driver_open:true, race_attempts:10000, desync_detected:true,
corrupted_ptr:0xffffffa5d237d844, kbase:0xfffffff0d2000000, krw_ready:true,
diagnostic:"Kernel pointer leak confirmed via slice desync at offset 1378
(BE)"`. AppleAVE2 was the only primitive that produced a genuine kbase —
V-047/MCC/PMAP were stub or offset-blocked (see
`findings-kernel-rw-hardening.md`).

## Known limits

- Stage 6 kernel writes were simulated until the C2 bridge + Stage-6 fixes
  landed; full activation still requires the SEP/NVRAM offset work (see
  `findings-kernel-offsets.md`).
- Stage 8 needs USB at the end; pure-OTA activation is not yet achievable.
