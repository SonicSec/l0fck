#!/usr/bin/env python3
"""Phase 0 read-only reachability probe for the CoreDevice/RSD MobileBackup2 service.

Context (2026-10-12, A18 Pro / iOS 26.6.1, UDID 00008140-0011285A20E3C01C):
  The legacy-lockdown service `com.apple.mobilebackup2` is NOT registered on this
  OS/hardware -- `idevicebackup2` reaches TLS + notification_proxy + AFC, then
  `StartService com.apple.mobilebackup2` fails with `InvalidService`. The device
  only offers the CoreDevice-gated transport, so this probe establishes a
  RemoteServiceDiscovery (RSD) tunnel (via pymobiledevice3) and checks whether the
  MobileBackup2 service is reachable there.

It is strictly read-only:
  * establishes an RSD tunnel (no restore, no writes, no state change),
  * enumerates the RSD service list,
  * looks for the MobileBackup2 service(s),
  * if present, opens the service socket and performs the minimal device-link
    version exchange to prove protocol liveness.

Final verdict (printed as the last line and written to the report file):
  REACHABLE              service present AND device-link version exchange OK
  NOT_IN_RSD_LIST        RSD established but no MobileBackup2 service advertised
  CONNECT_FAILED <reason>  RSD tunnel / service socket / version exchange failed

Usage:
  tools/.venv/bin/python l0fck/tools/mb2_reachability.py --udid <UDID> [--no-native]
"""

import argparse
import asyncio
import datetime
import sys
from pathlib import Path

# Candidate service names, most-likely first. pymobiledevice3 drives the RSD
# MobileBackup2 channel through the `.shim.remote` variant (see
# pymobiledevice3/services/mobilebackup2.py:RSD_SERVICE_NAME), so check that first.
MB2_SERVICE_CANDIDATES = [
    "com.apple.mobilebackup2.shim.remote",
    "com.apple.mobilebackup2",
    "com.apple.mobile.mobilebackup2",
]

RECEIVE_TIMEOUT = 30.0  # bounded receive for the version exchange (plan: report, don't hang)

ROOT = Path(__file__).resolve().parent


def emit(text: str) -> None:
    print(text, flush=True)


def report_path() -> Path:
    stamp = datetime.datetime.now().strftime("%Y-%m-%d_%H%M%S")
    return ROOT / f"mb2_reachability_{stamp}.txt"


async def establish_rsd(udid: str, native: bool):
    """Establish a connected RSD, preferring the no-root native path on macOS."""
    from pymobiledevice3.remote import native_tunnel, userspace_tunnel

    if native:
        try:
            emit("[*] RSD: establishing via macOS native tunnel (remotepairingd, no root)...")
            rsd = await native_tunnel.establish_native_rsd(serial=udid)
            emit(f"[*] RSD: native tunnel up; udid={rsd.udid} addr={rsd.service.address}")
            return rsd
        except Exception as e:
            emit(f"[*] RSD: native tunnel failed ({type(e).__name__}: {e}); falling back to userspace")

    emit("[*] RSD: establishing via in-process userspace tunnel (PyTCP, no root)...")
    rsd = await userspace_tunnel.establish_userspace_rsd(serial=udid)
    emit(f"[*] RSD: userspace tunnel up; udid={rsd.udid} addr={rsd.service.address}")
    return rsd


def enumerate_services(rsd):
    """Return {name: entry} from the RSD handshake peer_info."""
    peer = rsd.peer_info or {}
    services = peer.get("Services", {}) or {}
    props = peer.get("Properties", {}) or {}
    return services, props


async def device_link_probe(rsd, service_name: str) -> str:
    """Open the service and run the minimal device-link version exchange.

    Uses `rsd.start_lockdown_service(service_name)` with the DEFAULT
    include_escrow_bag=False: this performs the full RSD check-in handshake
    (RSDCheckin -> StartService) WITHOUT attaching an EscrowBag. The EscrowBag
    is only needed to UNLOCK a locked device; it requires a remote pairing
    record (~/.pymobiledevice3/remote_<udid>.plist) which a legacy-paired,
    unlocked A18 Pro does not have. For a liveness probe on a trusted,
    unlocked device (Find My off) the check-in must NOT request the escrow bag,
    otherwise pymobiledevice3 raises NotPairedError before any device-link
    traffic.

    This is distinct from start_lockdown_service_without_checkin (a raw socket
    that never does RSDCheckin -> StartService, so the device never emits its
    first device-link message and the probe hangs like a wedge).

    Returns a human-readable status string. Never raises.
    """
    from pymobiledevice3.exceptions import PyMobileDevice3Exception
    from pymobiledevice3.services.device_link import DeviceLink

    port = rsd.get_service_port(service_name)
    try:
        # RSDCheckin (no escrow bag) -> StartService. Canonical, check-in done,
        # pairing record NOT required.
        svc = await rsd.start_lockdown_service(service_name)
        emit(f"[*] service checked in (no escrow): {service_name} @ {rsd.service.address[0]}:{port}")
    except Exception as e:
        # pymobiledevice3's StartServiceError.__init__ calls super().__init__()
        # with no message, so str(e) is empty; the real value is in .message.
        detail = getattr(e, "message", "") or ""
        svc_name = getattr(e, "service_name", "") or ""
        note = ""
        if "ServiceProhibited" in detail:
            note = (" [device refuses to start; most often FIND MY IPHONE ON -- "
                    "the backup/restore service is hard-gated at StartService] "
                    "run tools/mb2_checkin_diag.py for the raw exchange")
        return (f"service_start_failed (RSD check-in / StartService): "
                f"{type(e).__name__}: service={svc_name} detail={detail!r}{note}")

    try:
        dl = DeviceLink(svc, ROOT)
        try:
            await asyncio.wait_for(dl.version_exchange(), timeout=RECEIVE_TIMEOUT)
            return "device_link_version_exchange_ok"
        except asyncio.TimeoutError:
            return f"version_exchange_timeout after {RECEIVE_TIMEOUT:.0f}s (device may be wedged)"
        except PyMobileDevice3Exception as e:
            return f"version_exchange_failed: {e}"
    finally:
        try:
            await svc.close()
        except Exception:
            pass


async def run(udid: str, native: bool):
    from pymobiledevice3.exceptions import NoDeviceConnectedError, PyMobileDevice3Exception

    lines = []

    def rec(s=""):
        lines.append(s)
        emit(s)

    rec("l0fck Restore-Chain MobileBackup2 reachability probe")
    rec(f"date: {datetime.datetime.now().isoformat()}")
    rec(f"target udid: {udid}")
    rec(f"pymobiledevice3: {pymd3_version()}")
    rec(f"candidates: {', '.join(MB2_SERVICE_CANDIDATES)}")
    rec("")

    # 1. RSD tunnel.
    try:
        rsd = await establish_rsd(udid, native)
    except NoDeviceConnectedError as e:
        return finalize(None, lines, f"CONNECT_FAILED no_device_connected: {e}")
    except Exception as e:
        return finalize(None, lines, f"CONNECT_FAILED rsd_tunnel: {type(e).__name__}: {e}")

    try:
        services, props = enumerate_services(rsd)
        rec(f"rsd udid: {rsd.udid}")
        rec(f"product_type: {props.get('ProductType')}")
        rec(f"os_version: {props.get('OSVersion')} build {props.get('BuildVersion')}")
        rec("")

        # 2. Service list.
        rec(f"rsd services ({len(services)}):")
        for name in sorted(services):
            entry = services[name] or {}
            port = entry.get("Port", "?")
            features = (entry.get("Properties", {}) or {}).get("Features") or ()
            rec(f"  - {name}  (port={port})" + (f"  features={list(features)}" if features else ""))
        rec("")

        found = [n for n in MB2_SERVICE_CANDIDATES if n in services]
        if not found:
            # Record any near-miss for diagnostics.
            near = [n for n in services if "backup" in n.lower()]
            if near:
                rec(f"note: non-MB2 candidates with 'backup' in name: {near}")
            rec("")
            return finalize(found, lines, "NOT_IN_RSD_LIST")

        rec(f"mobilebackup2 service(s) present: {found}")
        target = found[0]
        rec(f"probing: {target}")
        rec("")

        # 3. Device-link version exchange (protocol liveness, no restore).
        status = await device_link_probe(rsd, target)
        rec(f"device-link probe: {status}")
        rec("")

        if status == "device_link_version_exchange_ok":
            return finalize(found, lines, "REACHABLE")
        return finalize(found, lines, f"CONNECT_FAILED {status}")
    finally:
        try:
            await rsd.close()
        except Exception:
            pass


def pymd3_version() -> str:
    try:
        import pymobiledevice3
        from importlib.metadata import version
        return version("pymobiledevice3")
    except Exception:
        return "unknown"


def finalize(found, lines, verdict: str) -> int:
    lines.append("")
    lines.append(f"VERDICT: {verdict}")
    emit("")
    emit(f"VERDICT: {verdict}")
    try:
        report_path().write_text("\n".join(lines) + "\n")
        emit(f"[*] report written: {report_path()}")
    except OSError as e:
        emit(f"[*] could not write report: {e}")
    # Exit 0 = a clean, documented result (REACHABLE or a valid negative).
    # Exit 1 = could not even establish a transport (true connectivity failure).
    return 1 if verdict.startswith("CONNECT_FAILED") else 0


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--udid", required=True, help="device UDID (00008140-0011285A20E3C01C)")
    ap.add_argument("--no-native", action="store_true",
                    help="skip the macOS native (remotepairingd) tunnel; go straight to the userspace tunnel")
    args = ap.parse_args()
    try:
        return asyncio.run(run(args.udid, native=not args.no_native))
    except KeyboardInterrupt:
        emit("interrupted")
        return 130


if __name__ == "__main__":
    sys.exit(main())
