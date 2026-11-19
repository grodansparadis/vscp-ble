#!/usr/bin/env python3
"""Broadcast VSCP events as E1 or A2 Bluetooth 5 extended advertising.

Examples
  # Cleartext E1 temperature (CLASS1.MEASUREMENT type 6), new event every 10 s
  ./vscp-ble-advertise.py --guid 00:01:02:03:04:05:06:07:08:09:0A:0B:0C:0D:0E:0F \\
      --class 10 --type 6 --data 0x89,0x02,0x1A --period 10

  # Authenticated/encrypted A2 with a provisioned key (see key.example.json)
  ./vscp-ble-advertise.py --a2 key.json --class 10 --type 6 --data 0x89,0x02,0x1A

The sequence counter (E1) or epoch/sequence (A2) is persisted in the state
file in blocks before use, so values are never reused after a restart.
Company Identifier 0xFFFF is for tests only: use your assigned identifier.

Needs BlueZ 5.56 or later and a controller with LE extended advertising
(bluetoothctl show: SupportedSecondaryChannels).

The MIT License (MIT)
Copyright (c) 2000-2026 Ake Hedman, the VSCP Project <info@grodansparadis.com>
"""

import argparse
import json
import os
import pathlib
import signal
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))

import dbus  # noqa: E402
from gi.repository import GLib  # noqa: E402

from vscp_ble import Event, SequenceCounter, a2_encode, e1_encode  # noqa: E402
from vscp_ble.bluez import (ADV_MANAGER_IFACE, BLUEZ, Advertisement, adapter_supports_extended,  # noqa: E402
                            find_adapter, manufacturer_data, system_bus)


def parse_guid(text):
    guid = bytes.fromhex(text.replace(":", "").replace("-", ""))
    if len(guid) != 16 or not any(guid):
        raise argparse.ArgumentTypeError("GUID must be 16 octets and not all zero")
    return guid


def parse_data(text):
    return bytes(int(x, 0) for x in text.split(",")) if text else b""


class StateFile:
    """Counter persistence: written to a temporary file, fsync'ed and
    renamed, so a power loss leaves the old or the new state."""

    def __init__(self, path):
        self.path = pathlib.Path(path)

    def load(self):
        try:
            d = json.loads(self.path.read_text())
            return int(d["epoch"]), int(d["reserved_until"])
        except FileNotFoundError:
            return 0, 0

    def save(self, epoch, reserved_until):
        tmp = self.path.with_suffix(".tmp")
        with open(tmp, "w") as f:
            json.dump({"epoch": epoch, "reserved_until": reserved_until}, f)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, self.path)
        dirfd = os.open(self.path.parent, os.O_RDONLY)
        try:
            os.fsync(dirfd)
        finally:
            os.close(dirfd)


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--adapter", help="hci0, hci1 ... (default: first)")
    ap.add_argument("--company", type=lambda x: int(x, 0), default=0xFFFF, help="Company Identifier")
    ap.add_argument("--guid", type=parse_guid, help="sender GUID (A2: from the key file)")
    ap.add_argument("--class", dest="vscp_class", type=lambda x: int(x, 0), required=True)
    ap.add_argument("--type", dest="vscp_type", type=lambda x: int(x, 0), required=True)
    ap.add_argument("--head", type=lambda x: int(x, 0), default=0)
    ap.add_argument("--data", type=parse_data, default=b"", help="comma separated octets, e.g. 0x89,0x02,0x1A")
    ap.add_argument("--a2", metavar="KEYFILE", help="send A2 with this key file (JSON)")
    ap.add_argument("--state", default="vscp-ble-advertise.state", help="counter state file")
    ap.add_argument("--period", type=float, default=0, help="seconds between new events (0 = one event)")
    ap.add_argument("--count", type=int, default=0, help="stop after this many events (0 = run until ^C)")
    args = ap.parse_args()

    key = None
    if args.a2:
        k = json.loads(pathlib.Path(args.a2).read_text())
        key = dict(key_id=int(k["key_id"]), key=bytes.fromhex(k["key"]), prefix=bytes.fromhex(k["nonce_prefix"]),
                   guid=parse_guid(k["guid"]))
        if len(key["key"]) != 16 or len(key["prefix"]) != 5 or not 1 <= key["key_id"] <= 0xFFFF:
            raise SystemExit("bad key file")
        guid = key["guid"]
    elif args.guid is None:
        raise SystemExit("--guid is needed for E1")
    else:
        guid = args.guid

    state = StateFile(args.state)
    counter = SequenceCounter(state.load, state.save, block=64, use_epoch=key is not None)

    bus = system_bus()
    adapter = find_adapter(bus, args.adapter)
    if not adapter_supports_extended(bus, adapter):
        raise SystemExit("The controller has no LE extended advertising (needed for E1/A2 frames)")
    manager = dbus.Interface(bus.get_object(BLUEZ, adapter), ADV_MANAGER_IFACE)
    loop = GLib.MainLoop()
    current = {"adv": None, "sent": 0, "n": 0}

    def frame():
        ev = Event(guid, args.vscp_class, args.vscp_type, args.data, args.head)
        epoch, seq = counter.take()
        if key:
            return a2_encode(ev, key["key_id"], epoch, seq, key["key"], key["prefix"], args.company), epoch, seq
        return e1_encode(ev, seq, args.company), epoch, seq

    def publish():
        if current["adv"] is not None:
            try:
                manager.UnregisterAdvertisement(current["adv"].path)
            except dbus.exceptions.DBusException:
                pass
            current["adv"].remove_from_connection()
        ad, epoch, seq = frame()
        current["n"] += 1
        props = {
            "Type": "broadcast",  # Non-connectable, non-scannable (EA-B)
            "ManufacturerData": manufacturer_data(ad),
            "SecondaryChannel": "1M",  # LE 1M primary and secondary PHY
        }
        current["adv"] = Advertisement(bus, "/org/vscp/advertisement%d" % current["n"], props)
        manager.RegisterAdvertisement(current["adv"].path, {},
                                      reply_handler=lambda: print("advertising %s epoch %d seq %d: %s"
                                                                  % ("A2" if key else "E1", epoch, seq, ad.hex()),
                                                                  flush=True),
                                      error_handler=lambda e: (print("RegisterAdvertisement failed:", e), loop.quit()))
        current["sent"] += 1
        if args.count and current["sent"] >= args.count:
            GLib.timeout_add(max(1000, int(args.period * 1000)), loop.quit)
            return False
        return True

    publish()
    if args.period > 0:
        GLib.timeout_add(int(args.period * 1000), publish)
    signal.signal(signal.SIGINT, lambda *a: loop.quit())
    signal.signal(signal.SIGTERM, lambda *a: loop.quit())
    try:
        loop.run()
    finally:
        if current["adv"] is not None:
            try:
                manager.UnregisterAdvertisement(current["adv"].path)
            except dbus.exceptions.DBusException:
                pass


if __name__ == "__main__":
    main()
