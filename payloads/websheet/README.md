# WebSheet Stage-4 research harness

**Ceiling:** probe + triage only. There is **no** live WebKit/JSC RCE for iOS 26.6.1 (23G83) in this tree.

## Layout

| Path | Role |
|------|------|
| `manifest.json` | Probe catalog (`live` must stay `0` until a real 23G83 RCE exists) |
| `loader.js` | Loads auto probes; posts to `/api/stage4-probe` |
| `probes/capability_probe.js` | SAB / Atomics / WASM / timer recon |
| `probes/jsc_watchpoint_oom.js` | Opt-in OOM stress (DoS research), capped |

## Serving

Captive HTTP serves these files under `/websheet/*` when `l0fck` runs.

Override root with:

```bash
export L0FCK_WEBSHEET_PAYLOAD_DIR=/absolute/path/to/l0fck/payloads/websheet
```

Stage-4 probe results:

```bash
export L0FCK_STAGE4_RESULT=/tmp/l0fck_stage4_probe.json
```

## Operator flow

1. `./l0fck --setup-assistant-chain` (sudo for ports 53/80/443).
2. Phone in Setup joins Soft AP → WebSheet opens → telemetry + capability probe auto-run.
3. Optional OOM stress: open WebSheet with `?stage4=oom`, or tap **Run OOM stress probe**, or call `window.__L0FCK_STAGE4_RUN_OOM()` from the console.
4. Host shows `stage4_probes_done` if any probe reported; **`stage4_native_rce` stays false**.

## Marking a future live payload

Only when a real 23G83 WebSheet native RCE exists:

1. Add `probes/<id>.js` that registers `__L0FCK_STAGE4_RUNNERS.<id>`.
2. Set `"live": 1` and `"status": "live"` in `manifest.json` for that build.
3. Host code may then flip `stage4_native_rce` — **do not** set `live: 1` for DoS/recon probes.

See `PLAN/webkit_23G83_triage.md` for candidate scoring.
