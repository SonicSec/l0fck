# Finding: Lockdown SSL Bypass & Host-Trust Traversal (Vulnerability #03)

The unauthenticated lockdownd capability that lets `l0fck` establish
lockdown/AFC sessions **without pairing records or a device trust prompt**.
This is a documented, real userspace capability and a prerequisite for the
USB chains (bypass-full, sovereign, restore-chain A13 path, Neo-Chain
staging).

## Mechanism (per `PLAN/appleave2_definitive_implementation_plan.md`,
`lockdown_ssl_bypass.c/.h`)

Four lockdownd functions are abused to bypass the untrusted-host blocklist
and expiry enforcement:

| Function | Role |
|---|---|
| `sub_100019ca8` | `IgnoreUntrustedList=true` option-dictionary injection — bypasses the untrusted host blocklist |
| `sub_100016160` | **HostID path traversal** — load arbitrary pair records via `valid/../../../` without `..` restriction (bypasses 30-day expiry) |
| `sub_100003f0c` | Pair-record **expiry skip** |
| `sub_1000ac4f8` | **Certificate-verify disable** |

Combined effect: an unauthenticated host can load a pair record it does not
legitimately own, past its expiry, without passing certificate
validation — then establish an **unauthenticated SSL session** using a
custom SSL trust-anchor validation bypass.

## Implementation

- **Files**: `src/lockdown/lockdown_ssl_bypass.c` +
  `include/lockdown/lockdown_ssl_bypass.h`.
- **CLI**: `--test-lockdown-bypass` (test unauthenticated lockdown SSL
  bypass & host trust traversal).
- **Related**: `src/lockdown/lockdown_unauth.c`
  (`lockdownd_client_new()` — no pairing records required) and
  `session_manager.c` (memory-safe session & atomic reconnect). The
  `get_ma_client` handshake fix (`lockdownd_client_new_with_handshake`)
  was the root-cause fix for persistent `-23` /
  `LOCKDOWN_E_SESSION_INACTIVE` in the race chains (per
  `PLAN/plan_for_change_2.md`).

## Sensitive services reachable unauthenticated (Vulnerability #02)

`com.apple.afc` (media partition R/W), `com.apple.mobile.diagnostics_relay`
(reboot), `com.apple.syslog_relay`, `com.apple.os_trace_relay`,
`com.apple.mobile.notification_proxy` — all via `lockdownd_client_new()`
without pairing/trust. **AFC stays live on the A18 Pro** (relevant to the
restore-chain hard gate, see `chain-restore-chain.md`).

## Limits

- This establishes **lockdown + AFC**, not kernel access. It does **not**
  clear the anti-theft / Find-My gate (the `ServiceProhibited` block is at
  StartService for user-session services on a locked device — see
  `findings-activation-ambit.md`).
- AFC Media-partition writes are rejected for non-media file types
  unauthenticated (`.plist` writes fail 0/4) — persistence needs privileged
  AFC / sandbox escape / kernel writes.
