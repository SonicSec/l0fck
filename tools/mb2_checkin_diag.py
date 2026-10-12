#!/usr/bin/env python3
"""Diagnostic: dump the raw RSD check-in -> StartService exchange for the mb2
service so we can see exactly what the device returns (pmd3's StartServiceError
swallows the detail). Read-only: no restore, no writes.
"""
import asyncio
import plistlib
import struct
import sys

from pymobiledevice3.remote import native_tunnel, userspace_tunnel
from pymobiledevice3.service_connection import ServiceConnection

UDID = "00008140-0011285A20E3C01C"
TARGET = "com.apple.mobilebackup2.shim.remote"


def hx(b: bytes, n: int = 256) -> str:
    return b[:n].hex(" ")


async def main() -> int:
    try:
        rsd = await native_tunnel.establish_native_rsd(serial=UDID)
        emit(f"[*] native RSD up: {rsd.service.address}")
    except Exception as e:
        emit(f"[*] native failed ({type(e).__name__}: {e}); trying userspace")
        rsd = await userspace_tunnel.establish_userspace_rsd(serial=UDID)
        emit(f"[*] userspace RSD up: {rsd.service.address}")

    try:
        port = rsd.get_service_port(TARGET)
        emit(f"[*] target {TARGET} @ {rsd.service.address[0]}:{port}")

        # Raw socket (no check-in) so we can see every byte.
        svc = await rsd.start_lockdown_service_without_checkin(TARGET)
        await svc.start()

        async def recv_block():
            return await svc.recv_prefixed(">")

        # 1. RSDCheckin request (NO escrow bag).
        checkin = {"Label": "l0fck-probe", "ProtocolVersion": "2", "Request": "RSDCheckin"}
        payload = plistlib.dumps(checkin, fmt=plistlib.FMT_XML)
        wire = struct.pack(">L", len(payload)) + payload
        emit(f"[>] RSDCheckin ({len(wire)}B): {hx(wire, 120)}")
        await svc.sendall(wire)

        for step in range(4):
            pl = None
            try:
                raw = await asyncio.wait_for(recv_block(), timeout=10)
            except asyncio.TimeoutError:
                emit(f"[{step}] < TIMEOUT after 10s")
                break
            except Exception as e:
                emit(f"[{step}] < recv error: {type(e).__name__}: {e}")
                break
            emit(f"[{step}] < raw ({len(raw)}B): {hx(raw, 400)}")
            try:
                pl = plistlib.loads(raw)
                if isinstance(pl, dict):
                    kv = {k: (v if not isinstance(v, bytes) else f"<bytes {len(v)}>") for k, v in pl.items()}
                    emit(f"[{step}]   plist: {kv}")
                else:
                    emit(f"[{step}]   plist: {pl!r}")
            except Exception as e:
                emit(f"[{step}]   (non-plist payload: {e})")
            if isinstance(pl, dict) and pl.get("Request") == "StartService":
                emit("[*] StartService response received; stopping probe")
                break

        await svc.close()
    finally:
        try:
            await rsd.close()
        except Exception:
            pass
    return 0


def emit(s: str) -> None:
    print(s, flush=True)


if __name__ == "__main__":
    try:
        sys.exit(asyncio.run(main()))
    except KeyboardInterrupt:
        print("interrupted")
        sys.exit(130)
