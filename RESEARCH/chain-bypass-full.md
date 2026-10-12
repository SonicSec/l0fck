# Chain: Bypass-Full (5-Stage Activation Bypass / VUL 23 TOCTOU)

- **CLI**: `--bypass-full` (menu 6.1) · watcher: `--bypass-watch` (menu 6.2)
- **Transport**: USB lockdown (A18 Pro / iOS 26.6.1, booted, unlocked not
  required — the chain targets the Setup Assistant state)
- **Kernel R/W**: none — it races `mobileactivationd` activation submission
  against a `preboardservice_v2` (VUL 23) crash window.
- **Goal**: dismiss Setup Assistant + activate the device to Home Screen
  without a real kernel exploit.
- **Key files**:
  - `src/activation/albert_client.c` — `albert_perform_race_activation`,
    `activation_race_thread`
  - `src/activation/mobileactivation.c` — `get_ma_client`
    (handshake fix), `mobileact_handle_with_session_prewarmed`
  - `src/activation/record_a18.c` — synthesized offline A18 activation record
  - `src/exploits/preboard_exploit.c` — VUL 23 crash trigger
  - `src/exploits/springboard_injector.c` — prefs staging, Darwin burst, respring
  - `src/lockdown/afc_manager.c` — Media-partition plist staging
  - `src/backup/../activation/*` + `src/exploits/bypass_chain.c` — orchestration

## Stage flow

1. **Pre-warm** the `mobileactivationd` lockdown connection on a background
   thread (pre-warmed socket + pthread cond barrier so the race `usleep`
   starts exactly at the crash instant — fixes `Error -23` /
   `LOCKDOWN_E_SESSION_INACTIVE`).
2. **Fire VUL 23 crash** (`CreateStashbag` → daemon hang; `CommitStashbag` →
   memory/state fault; two-way barrier + 10 ms `CreateStashbag` timeout, sync
   point just before `CommitStashbag` hits the wire to eliminate USB I/O
   jitter).
3. **Submit activation** inside the crash window — synthesized A18 offline
   activation record (`record_a18_generate`).
4. **Post-crash**: lockdownd flag injection + AFC plist staging.
5. **14 Darwin notifications + respring** to Home Screen.

Race window: **macro-sweep 3500–6000 ms** (preserved over micro-sweep because
logs showed the daemon crash already aligned with payload delivery), with a
**3 s cooldown** between sweeps to avoid launchd `ThrottleInterval` respawn
rate-limiting ("daemon stops crashing after 3 attempts").

## Key design decisions (per `PLAN/plan_for_refactor.md`,
`plan_for_change_1..5.md`)

- Handshake fix in `get_ma_client` (`lockdownd_client_new_with_handshake`)
  was the root-cause fix for persistent `-23` (per `plan_for_change_2.md`).
- Pre-warmed socket + cond barrier fixes timing jitter
  (`plan_for_change_1.md`).

## Known limits / red herrings (honest status)

- **Daemon crash was reliable (45/45) — the blocker is the payload**:
  the synthesized offline record fails **SEP local-nonce cryptographic
  validation** (`Error -5` on 100% of attempts). Per
  `PLAN/plan_for_change_5.md`: "No amount of timing precision will fix this —
  the race infrastructure is now perfect, but the payload it delivers is
  fundamentally invalid."
- **AFC 0/4 plists deployed**: unauthenticated Media-partition AFC rejects
  `.plist` writes. Tried: afc2, write-as-`.data`-then-rename, priority dirs
  (`iTunes_Control/iTunes`), multi-vector salvo fired inside the crash window
  (`lockdownd_activate`, `lockdownd_set_value`, session + non-session
  `HandleActivationInfoRequest`).
- **VUL 23 race mechanism is unproven** — see
  `findings-preboard-vul23.md` (defect D1): the RPC keys are invented.

## Success criteria

Any activation vector returns `LOCKDOWN_E_SUCCESS` /
`MOBILEACTIVATION_E_SUCCESS`; device reaches Home Screen. **Not met on A18
Pro** — the SEP nonce wall applies to every record-based activation (see
`findings-activation-ambit.md`).

`--bypass-watch`: persistent USB watcher that auto-triggers `--bypass-full`
on device connect (no dedicated plan file; same stages).
