#!/usr/bin/env python3
"""Receive VSCP events from BLE advertising (E1, A2, F1 and L0).

Prints one JSON object per event. A2 frames are only delivered when a key
file (--a2 key.json, may be given several times) authenticates them; the
replay state is kept in --replay-state (fail closed if it cannot be saved).

  ./vscp-ble-observe.py
  ./vscp-ble-observe.py --a2 key.json --company 0xFFFF

Limitation: BlueZ reports Manufacturer Specific Data per Company Identifier
(one value per company), not the raw advertising data set, so the checks
for several candidate frames and truncated reports cannot be done here.
Use a raw HCI/mgmt socket (btmon-style) observer where that matters.

The MIT License (MIT)
Copyright (c) 2000-2026 Ake Hedman, the VSCP Project <info@grodansparadis.com>
"""

import argparse
import json
import os
import pathlib
import signal
import sys
import time

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))

import dbus  # noqa: E402
from gi.repository import GLib  # noqa: E402

from vscp_ble import A2Key, A2Receiver, F1Reassembler, VscpBleError, e1_decode, l0_decode, l0_guid  # noqa: E402
from vscp_ble.bluez import (ADAPTER_IFACE, BLUEZ, DEVICE_IFACE, OM_IFACE, PROP_IFACE, ad_structure,  # noqa: E402
                            device_address, find_adapter, system_bus)


def emit(kind, address, ev, **extra):
    out = dict(kind=kind, address=address, guid=":".join("%02X" % b for b in ev.guid), head=ev.head,
               vscp_class=ev.vscp_class, vscp_type=ev.vscp_type, data=ev.data.hex())
    out.update(extra)
    print(json.dumps(out), flush=True)


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--adapter")
    ap.add_argument("--company", type=lambda x: int(x, 0), default=0xFFFF)
    ap.add_argument("--a2", action="append", default=[], metavar="KEYFILE")
    ap.add_argument("--replay-state", default="vscp-ble-observe.replay")
    ap.add_argument("--legacy", action="store_true", help="also decode L0 (version 0) frames")
    args = ap.parse_args()

    # A2 key store and its persisted replay state
    replay_path = pathlib.Path(args.replay_state)
    saved = json.loads(replay_path.read_text()) if replay_path.exists() else {}
    keys = {}
    for kf in args.a2:
        k = json.loads(pathlib.Path(kf).read_text())
        rec = A2Key(args.company, int(k["key_id"]), bytes.fromhex(k["guid"].replace(":", "")),
                    bytes.fromhex(k["key"]), bytes.fromhex(k["nonce_prefix"]))
        last = saved.get("%d" % rec.key_id)
        rec.last = tuple(last) if last else None
        keys[(args.company, rec.key_id)] = rec

    def persist(rec):
        saved["%d" % rec.key_id] = list(rec.last)
        tmp = replay_path.with_suffix(".tmp")
        with open(tmp, "w") as f:
            json.dump(saved, f)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, replay_path)

    a2 = A2Receiver(keys, args.company, persist)
    f1 = F1Reassembler(args.company)
    last_seen = {}

    def handle(path, mdata):
        address = device_address(path)
        for company, value in mdata.items():
            if int(company) != args.company:
                continue
            ad = ad_structure(int(company), bytes(value))
            if last_seen.get((path, ad)) is not None:
                continue  # BlueZ repeats unchanged data
            last_seen[(path, ad)] = time.monotonic()
            version = ad[4] if len(ad) > 4 else None
            try:
                if version == 1:
                    ev, seq = e1_decode(ad, args.company)
                    emit("E1", address, ev, sequence=seq, trust="public")
                elif version == 2:
                    if not keys:
                        continue
                    ev, rec = a2.receive(ad)
                    emit("A2", address, ev, key_id=rec.key_id, epoch=rec.last[0], sequence=rec.last[1],
                         trust="authenticated")
                elif version == 3:
                    ev = f1.feed(ad, time.monotonic())
                    if ev is not None:
                        emit("F1", address, ev, trust="public")
                elif version is not None and version & 0x0F == 0 and args.legacy:
                    d = l0_decode(ad, args.company)
                    mac = bytes.fromhex(address.replace(":", ""))
                    print(json.dumps(dict(kind="L0", address=address, guid=l0_guid(mac, d["node_id"]).hex(),
                                          head=d["head"], vscp_class=d["vscp_class"], vscp_type=d["vscp_type"],
                                          data=d["data"].hex(), trust="public")), flush=True)
            except VscpBleError as e:
                print(json.dumps(dict(kind="rejected", address=address, version=version, reason=e.code)),
                      file=sys.stderr, flush=True)
        if len(last_seen) > 4096:
            last_seen.clear()

    bus = system_bus()
    adapter_path = find_adapter(bus, args.adapter)
    adapter = dbus.Interface(bus.get_object(BLUEZ, adapter_path), ADAPTER_IFACE)

    def interfaces_added(path, ifaces):
        dev = ifaces.get(DEVICE_IFACE)
        if dev and "ManufacturerData" in dev:
            handle(path, dev["ManufacturerData"])

    def properties_changed(iface, changed, invalidated, path=None):
        if iface == DEVICE_IFACE and "ManufacturerData" in changed:
            handle(path, changed["ManufacturerData"])

    bus.add_signal_receiver(interfaces_added, dbus_interface=OM_IFACE, signal_name="InterfacesAdded")
    bus.add_signal_receiver(properties_changed, dbus_interface=PROP_IFACE, signal_name="PropertiesChanged",
                            arg0=DEVICE_IFACE, path_keyword="path")
    adapter.SetDiscoveryFilter({"Transport": "le", "DuplicateData": dbus.Boolean(True)})
    adapter.StartDiscovery()
    print("scanning (company 0x%04X) ... ^C to stop" % args.company, file=sys.stderr, flush=True)

    loop = GLib.MainLoop()
    signal.signal(signal.SIGINT, lambda *a: loop.quit())
    signal.signal(signal.SIGTERM, lambda *a: loop.quit())
    try:
        loop.run()
    finally:
        try:
            adapter.StopDiscovery()
        except dbus.exceptions.DBusException:
            pass


if __name__ == "__main__":
    main()
