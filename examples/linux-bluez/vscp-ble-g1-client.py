#!/usr/bin/env python3
"""A VSCP G1 GATT client (BLE central) on BlueZ.

Connects to a G1 server, negotiates with HELLO, sends one event and prints
the events the server notifies.

  ./vscp-ble-g1-client.py AA:BB:CC:DD:EE:FF --class 30 --type 5 --data 0,1,2

Pair the devices first with authenticated pairing (bluetoothctl with a
KeyboardDisplay agent); the protected characteristics refuse other links.

The MIT License (MIT)
Copyright (c) 2000-2026 Ake Hedman, the VSCP Project <info@grodansparadis.com>
"""

import argparse
import pathlib
import signal
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))

import dbus  # noqa: E402
from gi.repository import GLib  # noqa: E402

from vscp_ble import G1_UUID, Event, G1Op, VscpBleError  # noqa: E402
from vscp_ble.bluez import BLUEZ, CHRC_IFACE, DEVICE_IFACE, OM_IFACE, PROP_IFACE, find_adapter, system_bus  # noqa: E402
from vscp_ble.g1session import G1Client  # noqa: E402

STATUS = {0: "OK", 1: "UNSUPPORTED_VERSION", 2: "BAD_LENGTH", 3: "BAD_FLAGS", 4: "BAD_SEQUENCE", 5: "BUSY",
          6: "NOT_AUTHORIZED", 7: "TOO_LARGE", 8: "TIMEOUT", 9: "INVALID_EVENT", 10: "NOT_READY",
          11: "INTERNAL_ERROR"}


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("address")
    ap.add_argument("--adapter")
    ap.add_argument("--guid", default="FF:FF:FF:FF:FF:FF:FF:FE:00:00:00:00:00:00:00:01",
                    help="client GUID (default: a test GUID)")
    ap.add_argument("--class", dest="vscp_class", type=lambda x: int(x, 0), default=20)
    ap.add_argument("--type", dest="vscp_type", type=lambda x: int(x, 0), default=9)
    ap.add_argument("--data", default="0,0,0")
    args = ap.parse_args()
    guid = bytes.fromhex(args.guid.replace(":", ""))
    data = bytes(int(x, 0) for x in args.data.split(",")) if args.data else b""

    bus = system_bus()
    adapter = find_adapter(bus, args.adapter)
    dev_path = "%s/dev_%s" % (adapter, args.address.upper().replace(":", "_"))
    try:
        device = bus.get_object(BLUEZ, dev_path)
    except dbus.exceptions.DBusException:
        raise SystemExit("Unknown device: scan for it first (bluetoothctl scan le)")
    props = dbus.Interface(device, PROP_IFACE)
    if not props.Get(DEVICE_IFACE, "Paired"):
        print("warning: not paired; protected characteristics will refuse access", file=sys.stderr)
    loop = GLib.MainLoop()
    chars = {}

    def find_chars():
        objs = bus.get_object(BLUEZ, "/").GetManagedObjects(dbus_interface=OM_IFACE)
        for path, ifaces in objs.items():
            c = ifaces.get(CHRC_IFACE)
            if c and path.startswith(dev_path):
                chars[str(c["UUID"]).lower()] = bus.get_object(BLUEZ, path)
        return all(G1_UUID(n) in chars for n in (1, 2, 3, 4, 5))

    def write(uuid):
        return lambda value: chars[uuid].WriteValue(dbus.Array(value, signature="y"), {"type": "request"},
                                                    dbus_interface=CHRC_IFACE)

    client = G1Client(write(G1_UUID(5)), write(G1_UUID(4)))

    def value_changed(uuid, handler):
        def cb(iface, changed, invalidated):
            if iface == CHRC_IFACE and "Value" in changed:
                handler(bytes(changed["Value"]))
        chars[uuid].connect_to_signal("PropertiesChanged", cb, dbus_interface=PROP_IFACE)

    def on_control(value):
        op, tid, status = client.on_control(value)
        print("control 0x%02X tid %d %s" % (op, tid, STATUS.get(status, status)), flush=True)
        if op == G1Op.HELLO_RESULT and status == 0:
            print("negotiated max data %d, max record %d" % client.negotiated, flush=True)
            chars[G1_UUID(3)].StartNotify(dbus_interface=CHRC_IFACE)
            tid = client.send_event(Event(guid, args.vscp_class, args.vscp_type, data))
            print("sent event tid %d" % tid, flush=True)

    def on_event(value):
        try:
            ev = client.on_event_tx(value)
        except VscpBleError as e:
            print("bad notification:", e.code, file=sys.stderr)
            return
        if ev is not None:
            print("event: class %d type %d data %s" % (ev.vscp_class, ev.vscp_type, ev.data.hex()), flush=True)

    def start():
        if not find_chars():
            print("G1 service not found on the device", file=sys.stderr)
            loop.quit()
            return False
        caps = bytes(chars[G1_UUID(1)].ReadValue({}, dbus_interface=CHRC_IFACE))
        print("capabilities", caps.hex(), "GUID",
              bytes(chars[G1_UUID(2)].ReadValue({}, dbus_interface=CHRC_IFACE)).hex(":"), flush=True)
        try:
            client.mtu = int(dbus.Interface(chars[G1_UUID(4)], PROP_IFACE).Get(CHRC_IFACE, "MTU"))
        except dbus.exceptions.DBusException:
            client.mtu = 23
        value_changed(G1_UUID(5), on_control)
        value_changed(G1_UUID(3), on_event)
        chars[G1_UUID(5)].StartNotify(dbus_interface=CHRC_IFACE)
        client.hello()
        return False

    def resolved(iface, changed, invalidated):
        if iface == DEVICE_IFACE and changed.get("ServicesResolved"):
            GLib.idle_add(start)

    props.connect_to_signal("PropertiesChanged", resolved)
    if props.Get(DEVICE_IFACE, "Connected") and props.Get(DEVICE_IFACE, "ServicesResolved"):
        GLib.idle_add(start)
    else:
        device.Connect(dbus_interface=DEVICE_IFACE, timeout=30)

    signal.signal(signal.SIGINT, lambda *a: loop.quit())
    try:
        loop.run()
    finally:
        try:
            device.Disconnect(dbus_interface=DEVICE_IFACE)
        except dbus.exceptions.DBusException:
            pass


if __name__ == "__main__":
    main()
