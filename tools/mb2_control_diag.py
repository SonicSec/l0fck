#!/usr/bin/env python3
"""Diagnostic (read-only): A/B control for the ServiceProhibited finding.

Starts a few services via the RSD check-in path and prints each StartService
response. If benign services start OK but com.apple.mobilebackup2 alone is
ServiceProhibited, the gate is mobilebackup2-specific (anti-theft / Find My),
not a general device-state refusal to start services.

Read-only: no restore, no writes; each service is closed after the response.
"""
import asyncio
import plistlib
import struct
import sys

from pymobiledevice3.remote import native_tunnel, userspace_tunnel

UDID = "00008140-0011285A20E3C01C"

# (label, service name). Tests the RSD trust model: untrusted-ok services
# (notification_proxy, lockdown.untrusted) should start; trusted-required
# services (mobilebackup2, AFC, springboardservices, installation_proxy,
# lockdown.trusted) should be ServiceProhibited on an untrusted session.
TESTS = [
    ("mb2 (anti-theft)", "com.apple.mobilebackup2.shim.remote"),
    ("AFC (stage-4 linchpin)", "com.apple.afc.shim.remote"),
    ("springboardservices", "com.apple.springboardservices.shim.remote"),
    ("installation_proxy", "com.apple.mobile.installation_proxy.shim.remote"),
    ("notification_proxy (untrusted-ok)", "com.apple.mobile.notification_proxy.shim.remote"),
    ("lockdown.untrusted", "com.apple.mobile.lockdown.remote.untrusted"),
    ("lockdown.trusted", "com.apple.mobile.lockdown.remote.trusted"),
]


def emit(s=""):
    print(s, flush=True)


async def start_service_probe(rsd, name: str) -> str:
    """Do RSDCheckin -> StartService on one service; return the StartService
    response dict as a compact string. Never raises."""
    try:
        port = rsd.get_service_port(name)
    except Exception as e:
        return f"<not in RSD list: {type(e).__name__}>"
    try:
        svc = await rsd.start_lockdown_service_without_checkin(name)
        await svc.start()
    except Exception as e:
        return f"<socket open failed: {type(e).__name__}: {e}>"
    try:
        checkin = {"Label": "l0fck-probe", "ProtocolVersion": "2", "Request": "RSDCheckin"}
        payload = plistlib.dumps(checkin, fmt=plistlib.FMT_XML)
        await svc.sendall(struct.pack(">L", len(payload)) + payload)

        async def recv_block():
            return await svc.recv_prefixed(">")

        # Step 0: RSDCheckin ack. Step 1: StartService response.
        for _ in range(2):
            try:
                raw = await asyncio.wait_for(recv_block(), timeout=8)
                pl = plistlib.loads(raw)
                if isinstance(pl, dict) and pl.get("Request") == "StartService":
                    err = pl.get("Error", "<none>")
                    return f"StartService OK" if err in (None, "") else f"Error={err!r}"
            except asyncio.TimeoutError:
                return "<timeout>"
            except Exception as e:
                return f"<recv err {type(e).__name__}: {e}>"
        return "<no StartService response>"
    finally:
        try:
            await svc.close()
        except Exception:
            pass


async def main() -> int:
    try:
        rsd = await native_tunnel.establish_native_rsd(serial=UDID)
        emit(f"[*] native RSD up: {rsd.service.address}")
    except Exception as e:
        emit(f"[*] native failed ({type(e).__name__}); userspace")
        rsd = await userspace_tunnel.establish_userspace_rsd(serial=UDID)
    try:
        emit(f"udid={rsd.udid}")
        for label, name in TESTS:
            result = await start_service_probe(rsd, name)
            emit(f"  {label:22s} {name:45s} -> {result}")
    finally:
        try:
            await rsd.close()
        except Exception:
            pass
    return 0


if __name__ == "__main__":
    try:
        sys.exit(asyncio.run(main()))
    except KeyboardInterrupt:
        print("interrupted")
        sys.exit(130)
