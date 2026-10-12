#!/usr/bin/env python3
"""Diagnostic (read-only): read the device Find My / activation-lock state so we
can explain the `ServiceProhibited` refusal to start com.apple.mobilebackup2.
The most likely cause of a `ServiceProhibited` on the backup2 service is Find My
being ON. This reads FMIP + activation values via the RSD lockdown and prints
them. No writes.
"""
import asyncio
import sys

from pymobiledevice3.remote import native_tunnel, userspace_tunnel

UDID = "00008140-0011285A20E3C01C"


def emit(s=""):
    print(s, flush=True)


async def main() -> int:
    try:
        rsd = await native_tunnel.establish_native_rsd(serial=UDID)
        emit(f"[*] native RSD up: {rsd.service.address}")
    except Exception as e:
        emit(f"[*] native failed ({type(e).__name__}); userspace")
        rsd = await userspace_tunnel.establish_userspace_rsd(serial=UDID)

    try:
        emit(f"rsd.udid={rsd.udid}")
        emit(f"rsd.lockdown set: {rsd.lockdown is not None}")
        lock = rsd.lockdown
        if lock is None:
            emit("[!] no RSD lockdown; cannot read FMIP values")
            return 2

        probes = {
            "com.apple.FMIPFolder": ["FindMy", "Enabled", "LockOutTime", "EraseDevice"],
            "com.apple.mobile.lockdown": ["FindMyMode", "ActivationState", "ActivationLockState",
                                          "ActivationLockBypassCode", "ProductVersion", "BuildVersion",
                                          "ModelNumber", "DeviceName"],
            "com.apple.MobileActivation": ["ActivationState"],
        }
        for domain, keys in probes.items():
            emit(f"\n== domain {domain} ==")
            for k in keys:
                try:
                    v = await lock.get_value(domain=domain, key=k)
                    emit(f"  {k} = {v!r}")
                except Exception as e:
                    emit(f"  {k} = <err {type(e).__name__}: {e}>")
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
