# Finding: Zero-Fake-Success Policy (Governing Rule)

The project's governing engineering rule, refined after several "mission
accomplished" reports were refuted by device logs. **Every implementer must
apply this before and after a change.**

## The rule

1. **No stage completes on a placeholder.** A stub primitive must return
   an honest `-1` / `STAGED / PENDING ON-DEVICE BRIDGE` — never a fake
   `return 0` and never a hardcoded value presented as a live read.
   (The original `appleave2_exploit.c` `kread64` returned
   `0xdeadbeef1337c0de`; V-047's `jpeg_kread64` was `addr ^ 0xDEADBEEF`;
   these were the "kernel R/W achieved" claims that logs refuted.)
2. **Crash ≠ RCE, crash ≠ write.** A daemon crash, a "stage completed"
   log line, or a parse-accept of a crafted blob is **not** success. The
   restore-chain hard gate exists precisely because "parse-accept alone is
   not a write primitive" — a staged canary must be **read back over AFC**.
3. **Every success claim needs a read-back.** Canary read-back, telemetry
   JSON with `krw_ready:true`, a result plist, or a 2-anchor kbase
   cross-check. A leak is trusted only if ≥2 anchors agree
   (`findings-kernel-offsets.md`).
4. **Honest status labels.** Stages that are scaffold must be labeled
   STAGED/BLOCKED, not "achieved."

## Refuted "final reports" (superseded)

| Report | Claim | Refutation |
|---|---|---|
| `PLAN/GLYPHGRIFT_FINAL_REPORT.md`, `GLYPHGRIFT_IMPLEMENTATION_SUMMARY.md` | 0→60% corruption, production-ready | Vector 1/2 logs: `corruption:no` every round, 5 rounds exhausted, "honest stop"; the 5-round retry was a cache illusion (D3) |
| `PLAN/KERNEL_RW_FINAL_REPORT.md` | kernel R/W achieved | `WHY-NEOCHAIN-DOESNT-WORK.txt`: Stage 1 was a simulated stub, trust-cache/NVRAM writes no-ops, `sep_disable_enforcement` always `-1`, AFC 0/4, no respring call |
| `PLAN/USB_FIRST_IMPLEMENTATION.md` | "GlyphGrift is DEAD, USB is the FUTURE," VUL 23 USB 60% | D1: the 60% was a model, never measured; the RPC keys are invented |

The corrective baseline is `PLAN/GLYPHGRIFT_CHAIN_FIX_PLAN.md` +
`PLAN/WHY-NEOCHAIN-DOESNT-WORK.txt`: re-baseline on "crash ≠ RCE, no fake
success," label every stage honestly, and gate each stage on a named,
measured primitive.

## How to apply it in a change

- Before claiming a chain stage works: cite the **telemetry artifact**
  (JSON/plist/rtf log) that proves it, with the file path.
- When adding a new primitive: wire it to return honest failure until an
  on-device payload or read-back exists; add a self-test that exercises
  the **failure path**, not just the mocked success path.
- When a "final report" conflicts with a fix plan or logs, the **fix plan
  and logs win** — mark the report superseded in this folder rather than
  deleting it.
- Self-test suite (`./l0fck --test`, 22/22) must stay green; a new chain
  gets a new numbered test (see the Self-Test table in `../README.md`).
