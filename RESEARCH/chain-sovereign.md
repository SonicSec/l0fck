# Chain: Sovereign-Chain & Sovereign-Lite (Hybrid Security Degradation)

- **CLI**: `--sovereign` (menu 6.3) · `--sovereign-lite` (menu 6.4)
- **Transport**: USB
- **Kernel R/W**: none
- **Goal**: Setup Assistant bypass via dual-vector memory pressure + AI
  guardrail AFC overrides, then either the full 5-stage bypass (Sovereign)
  or a lighter injection + notification + respring path (Sovereign-Lite).
- **Key files**: `src/exploits/bypass_chain.c` — `sovereign_run` /
  `sovereign_lite_run`; `src/lockdown/flag_injector.c`;
  `src/exploits/springboard_injector.c`.

## Sovereign-Chain flow

1. `dual_vector_pressure_dos` — dual-vector memory pressure (NECP + IOSurface)
   DoS on security daemons.
2. `ai_guardrail_bypass` — AI guardrail AFC overrides.
3. Full 5-stage bypass (same as `--bypass-full`: VUL 23 race → activation
   record → flags → Darwin burst → respring).

## Sovereign-Lite flow (`sovereign_lite_run`)

1. `dual_vector_pressure_dos` (memory-pressure DoS on security daemons)
2. `ai_guardrail_bypass`
3. `flag_injector_inject_all_session` (deep lockdown flag injection,
   "Option 16")
4. `springboard_dispatch_notifications` — optimized burst: **5 cycles
   (was 2), 30 ms spacing (was 15 ms)**, each cycle ending with
   `com.apple.mobileactivationd.activation_state_changed` +
   `com.apple.springboard.attemptactivation`
5. `springboard_trigger_respring`

## Design rationale (per `PLAN/plan_for_change_7.md`)

The pivot away from the TOCTOU race: the user reported Option 16
(Lockdown Config & Flag Injection) "partially works on its own," so the
hypothesis was that the missing piece was the **state transition**, not the
flags — hence targeted notification burst + respring instead of the race.

Note (per `PLAN/WHY-NEOCHAIN-DOESNT-WORK.txt`): `sovereign_lite_run`
*actually calls* `springboard_trigger_respring(sess)` — unlike the early
neo-chain which only logged the message. That respring bug was a real
differentiator when comparing chains.

## Known limits

- Sovereign-Chain inherits the bypass-full SEP `Error -5` wall on its
  activation stage (record-based activation cannot pass SEP local-nonce
  crypto validation — see `findings-activation-ambit.md`).
- Sovereign-Lite has **no activation stage at all** — it degrades security
  posture and re-springs; it does not activate the device.
- Lockdown flag injection alone is ignored by Setup Assistant (per
  `WHY-NEOCHAIN-DOESNT-WORK.txt`); the notification burst is the transition
  attempt.
