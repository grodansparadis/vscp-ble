#!/usr/bin/env python3
"""A VSCP G1 GATT server (BLE peripheral) on BlueZ.

Exposes the G1 service, advertises it (connectable), prints events written
by an authorized client and sends a heartbeat (CLASS1.INFORMATION type 9)
to it every --heartbeat seconds.

  ./vscp-ble-g1-server.py --guid 00:01:...:0F --authorize AA:BB:CC:DD:EE:FF

Security
  * Event RX, Control and Configuration require an encrypted link with
    authenticated (MITM) pairing: BlueZ flags encrypt-authenticated-*.
    Pair first, e.g. with bluetoothctl and an agent with a display or
    keyboard (KeyboardDisplay); Just Works pairing does not qualify.
  * Bonding is not authorization: only devices given with --authorize get
    event access, --admin devices also admin access.

One connected client at a time (BlueZ notifies all subscribers of a
characteristic; G1 state is per connection).

The MIT License (MIT)
Copyright (c) 2000-2026 Ake Hedman, the VSCP Project <info@grodansparadis.com>
"""

import argparse
import pathlib
import signal
import struct
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))

import dbus  # noqa: E402
import dbus.service  # noqa: E402
from gi.repository import GLib  # noqa: E402

from vscp_ble import G1_UUID, Event, G1Status  # noqa: E402
from vscp_ble.bluez import (ADV_MANAGER_IFACE, BLUEZ, CHRC_IFACE, DEVICE_IFACE, GATT_MANAGER_IFACE,  # noqa: E402
                            OM_IFACE, PROP_IFACE, SERVICE_IFACE, Advertisement, Failed, InvalidArgs, att_error,
                            device_address, find_adapter, system_bus)
from vscp_ble.g1session import AUTH_ADMIN, AUTH_EVENT, AUTH_NONE, AttError, G1Server  # noqa: E402

APP_PATH = "/org/vscp/g1"


class Characteristic(dbus.service.Object):
    def __init__(self, bus, service, index, uuid, flags, read=None, write=None):
        self.path = "%s/char%d" % (service.path, index)
        self.bus = bus
        self.uuid = uuid
        self.flags = flags
        self.service = service
        self.read = read
        self.write = write
        self.notifying = False
        self.value = b""
        super().__init__(bus, self.path)

    def properties(self):
        return {CHRC_IFACE: {"Service": dbus.ObjectPath(self.service.path), "UUID": self.uuid,
                             "Flags": dbus.Array(self.flags, signature="s")}}

    @dbus.service.method(PROP_IFACE, in_signature="s", out_signature="a{sv}")
    def GetAll(self, interface):
        if interface != CHRC_IFACE:
            raise InvalidArgs()
        return self.properties()[CHRC_IFACE]

    @dbus.service.method(CHRC_IFACE, in_signature="a{sv}", out_signature="ay")
    def ReadValue(self, options):
        if self.read is None:
            raise Failed("not readable")
        return dbus.Array(self.read(options), signature="y")

    @dbus.service.method(CHRC_IFACE, in_signature="aya{sv}")
    def WriteValue(self, value, options):
        if self.write is None:
            raise Failed("not writable")
        try:
            self.write(bytes(value), options)
        except AttError as e:
            raise att_error(e.code) from None

    @dbus.service.method(CHRC_IFACE)
    def StartNotify(self):
        self.notifying = True
        self.service.app.cccd(self, True)

    @dbus.service.method(CHRC_IFACE)
    def StopNotify(self):
        self.notifying = False
        self.service.app.cccd(self, False)

    @dbus.service.signal(PROP_IFACE, signature="sa{sv}as")
    def PropertiesChanged(self, interface, changed, invalidated):
        pass

    def send(self, value):
        """Notification or indication (per the characteristic's flags)."""
        if not self.notifying:
            raise RuntimeError("client not subscribed")
        self.PropertiesChanged(CHRC_IFACE, {"Value": dbus.Array(value, signature="y")}, [])


class Service(dbus.service.Object):
    def __init__(self, bus, app, uuid):
        self.path = APP_PATH + "/service0"
        self.app = app
        self.uuid = uuid
        self.chars = []
        super().__init__(bus, self.path)

    def properties(self):
        return {SERVICE_IFACE: {"UUID": self.uuid, "Primary": True,
                                "Characteristics": dbus.Array([dbus.ObjectPath(c.path) for c in self.chars],
                                                              signature="o")}}

    @dbus.service.method(PROP_IFACE, in_signature="s", out_signature="a{sv}")
    def GetAll(self, interface):
        return self.properties()[SERVICE_IFACE]


class App(dbus.service.Object):
    def __init__(self, bus, args):
        super().__init__(bus, APP_PATH)
        self.bus = bus
        self.args = args
        self.device = None
        self.session = G1Server(args.guid, self.indicate, self.notify, self.on_event, args.max_data)
        self.service = Service(bus, self, G1_UUID(0))
        protected_rw = ["encrypt-authenticated-read", "encrypt-authenticated-write"]
        add = self.service.chars.append
        add(Characteristic(bus, self.service, 1, G1_UUID(1), ["read"], read=self.read_capabilities))
        add(Characteristic(bus, self.service, 2, G1_UUID(2), ["read"], read=lambda o: args.guid))
        self.event_tx = Characteristic(bus, self.service, 3, G1_UUID(3), ["notify"])
        add(self.event_tx)
        add(Characteristic(bus, self.service, 4, G1_UUID(4), ["encrypt-authenticated-write"],
                           write=self.write_event_rx))
        self.control = Characteristic(bus, self.service, 5, G1_UUID(5), ["encrypt-authenticated-write", "indicate"],
                                      write=self.write_control)
        add(self.control)
        add(Characteristic(bus, self.service, 6, G1_UUID(6), protected_rw, read=lambda o: self.session.configuration(),
                           write=lambda v, o: self.begin(o) and self.session.write_configuration(v)))
        add(Characteristic(bus, self.service, 7, G1_UUID(7), ["encrypt-authenticated-read"],
                           read=self.read_security))

    @dbus.service.method(OM_IFACE, out_signature="a{oa{sa{sv}}}")
    def GetManagedObjects(self):
        objs = {self.service.path: self.service.properties()}
        for c in self.service.chars:
            objs[c.path] = c.properties()
        return objs

    # Connection tracking ---------------------------------------------------

    def begin(self, options):
        """Bind the session to the requesting device; refuse a second one."""
        dev = str(options.get("device", ""))
        if self.device is None or not self.device_connected(self.device):
            if self.device != dev:
                self.session.connected()
            self.device = dev
        if dev != self.device:
            raise AttError(0x08)
        mtu = int(options.get("mtu", 0))
        if mtu >= 23:
            self.session.mtu = mtu
        addr = device_address(dev)
        self.session.authorization = (AUTH_ADMIN if addr in self.args.admin else
                                      AUTH_EVENT if addr in self.args.authorize else AUTH_NONE)
        return True

    def device_connected(self, path):
        try:
            return bool(self.bus.get_object(BLUEZ, path).Get(DEVICE_IFACE, "Connected", dbus_interface=PROP_IFACE))
        except dbus.exceptions.DBusException:
            return False

    def device_changed(self, iface, changed, invalidated, path=None):
        if iface == DEVICE_IFACE and path == self.device and changed.get("Connected") is False:
            print("disconnected", device_address(path), flush=True)
            self.device = None
            self.session.disconnected()

    def cccd(self, chrc, enabled):
        if chrc is self.control:
            self.session.control_indicate = enabled
        elif chrc is self.event_tx:
            self.session.event_notify = enabled

    # Characteristic handlers ----------------------------------------------

    def read_capabilities(self, options):
        if self.device is not None and str(options.get("device", "")) == self.device:
            self.session.mtu = max(23, int(options.get("mtu", self.session.mtu)))
        return self.session.capabilities()

    def read_security(self, options):
        self.begin(options)
        return self.session.security_status(paired=True)  # BlueZ enforced encrypt-authenticated-read

    def write_control(self, value, options):
        self.begin(options)
        self.session.write_control(value)

    def write_event_rx(self, value, options):
        self.begin(options)
        self.session.write_event_rx(value)

    # Session callbacks ----------------------------------------------------

    def indicate(self, value):
        self.control.send(value)

    def notify(self, value):
        self.event_tx.send(value)

    def on_event(self, ev, tid):
        # Validate VSCP semantics and authorize per class/type here
        print("event from %s: class %d type %d data %s" % (device_address(self.device), ev.vscp_class,
                                                            ev.vscp_type, ev.data.hex()), flush=True)
        return G1Status.OK

    def heartbeat(self):
        ev = Event(self.args.guid, 20, 9, bytes([0, 0, 0]))  # CLASS1.INFORMATION, NODE_HEARTBEAT
        if self.session.send_event(ev):
            print("heartbeat sent", flush=True)
        return True


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--adapter")
    ap.add_argument("--guid", required=True, type=lambda t: bytes.fromhex(t.replace(":", "")))
    ap.add_argument("--authorize", default="", help="comma separated addresses with event access")
    ap.add_argument("--admin", default="", help="comma separated addresses with admin access")
    ap.add_argument("--max-data", type=int, default=487)
    ap.add_argument("--heartbeat", type=float, default=30)
    ap.add_argument("--name", default="VSCP G1")
    args = ap.parse_args()
    if len(args.guid) != 16 or not any(args.guid):
        raise SystemExit("bad GUID")
    args.admin = {a.strip().upper() for a in args.admin.split(",") if a.strip()}
    args.authorize = {a.strip().upper() for a in args.authorize.split(",") if a.strip()} | args.admin

    bus = system_bus()
    adapter = find_adapter(bus, args.adapter)
    app = App(bus, args)
    bus.add_signal_receiver(app.device_changed, dbus_interface=PROP_IFACE, signal_name="PropertiesChanged",
                            arg0=DEVICE_IFACE, path_keyword="path")
    loop = GLib.MainLoop()
    gatt = dbus.Interface(bus.get_object(BLUEZ, adapter), GATT_MANAGER_IFACE)
    gatt.RegisterApplication(APP_PATH, {}, reply_handler=lambda: print("G1 service registered", flush=True),
                             error_handler=lambda e: (print("RegisterApplication failed:", e), loop.quit()))
    # Connectable legacy advertising with the 128-bit service UUID
    adv = Advertisement(bus, "/org/vscp/g1adv", {"Type": "peripheral", "ServiceUUIDs": dbus.Array([G1_UUID(0)], "s"),
                                                 "LocalName": args.name})
    advm = dbus.Interface(bus.get_object(BLUEZ, adapter), ADV_MANAGER_IFACE)
    advm.RegisterAdvertisement(adv.path, {}, reply_handler=lambda: print("advertising", flush=True),
                               error_handler=lambda e: print("RegisterAdvertisement failed:", e))
    GLib.timeout_add(1000, lambda: (app.session.tick(), True)[1])
    if args.heartbeat > 0:
        GLib.timeout_add(int(args.heartbeat * 1000), app.heartbeat)
    signal.signal(signal.SIGINT, lambda *a: loop.quit())
    signal.signal(signal.SIGTERM, lambda *a: loop.quit())
    try:
        loop.run()
    finally:
        for call in (lambda: advm.UnregisterAdvertisement(adv.path), lambda: gatt.UnregisterApplication(APP_PATH)):
            try:
                call()
            except dbus.exceptions.DBusException:
                pass


if __name__ == "__main__":
    main()
