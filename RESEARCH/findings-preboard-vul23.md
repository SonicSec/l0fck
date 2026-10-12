# Finding: Preboard / VUL 23 — PoC, Weaponization & the D1 Dead-End

`preboardservice_v2` (Vulnerability #23) is used for unauthenticated probing
and crash triage, and was claimed as a TOCTOU race primitive. The **race is
unproven** — this doc records both the working PoC/triage path and the D1
refutation.

## Working parts (PoC + triage, not the race)

- **CLI**: `--crash-preboard` (PoC crash), `--triage-crash` (auto-fetch +
  parse `.ips`), `--exploit-preboard` (weaponized attempt), `--stage-bypass`
  (AFC plist staging), `--dismiss-setup` (Darwin dismissal).
- **Files**: `src/exploits/preboard_poc.c` (unauthenticated probe with
  crafted stashbag manifest), `preboard_triage.c` (crash triage & register
  analyzer), `preboard_exploit.c` (weaponized RPC sequence),
  `preboard_race.c` (synchronized bg-thread race timer),
  `src/lockdown/crash_reporter.c` (unauthenticated `.ips` fetcher & parser).
- The **daemon crash itself was reliable** (45/45 in
  `PLAN/plan_for_change_5.md`) — the PoC and triage are real.

## The claimed race (how it was supposed to work)

`CreateStashbag` (crafted manifest) → daemon validates then hangs
(memory fault); send `CommitStashbag` inside a 20–50 ms TOCTOU window →
accepted without re-validation → stashbag commits with bypass payload →
inject `com.apple.purplebuddy` SetupFinished=true +
`com.apple.mobileactivationd` ActivationState=Activated → respring.
Race timing via `preboard_race.c` (synchronized bg thread, 30 ms delay,
auto-tune 20/30/40/50/10 ms).

## D1 — the race is a dead end (per `PLAN/GLYPHGRIFT_CHAIN_FIX_PLAN.md`)

- The RPC keys (`CreateStashbag` / `SprayTag` / `SprayBlob` /
  `CommitStashbag` / `Manifest{SkipAuthCheck=true}`) in
  `preboard_exploit.c:88-122` are **invented** — no protocol evidence, no
  RE/log shows `preboardservice_v2` implementing them.
- The "~60% success" was a **model, never measured**; there is no log of a
  committed stashbag or dismissed SetupAssistant via USB.
- **Resolution**: quarantine behind a `--research` flag labeled "UNPROVEN",
  remove the "GlyphGrift is DEAD / USB is the FUTURE" framing (both
  unproven). If pursued, it must start with **real RE of the
  `preboardservice_v2` protocol** (dtrace/lldb or Ghidra), not guessed
  plist keys.

## Consequence for chains

- `bypass-full` (its Stage 3 activation submission) and the sovereign
  chain's activation stage depend on this race for the activation vector —
  both are therefore blocked at the payload/validation layer, not the
  timing layer (see `findings-activation-ambit.md` for the SEP nonce wall
  that hits any record-based activation regardless).
