"""Small BlueZ D-Bus helpers (python3-dbus + GLib main loop).

The MIT License (MIT)
Copyright (c) 2000-2026 Ake Hedman, the VSCP Project <info@grodansparadis.com>
"""

import dbus
import dbus.exceptions
import dbus.mainloop.glib
import dbus.service

BLUEZ = "org.bluez"
OM_IFACE = "org.freedesktop.DBus.ObjectManager"
PROP_IFACE = "org.freedesktop.DBus.Properties"
ADAPTER_IFACE = "org.bluez.Adapter1"
DEVICE_IFACE = "org.bluez.Device1"
ADV_MANAGER_IFACE = "org.bluez.LEAdvertisingManager1"
ADV_IFACE = "org.bluez.LEAdvertisement1"
GATT_MANAGER_IFACE = "org.bluez.GattManager1"
SERVICE_IFACE = "org.bluez.GattService1"
CHRC_IFACE = "org.bluez.GattCharacteristic1"


def system_bus():
    dbus.mainloop.glib.DBusGMainLoop(set_as_default=True)
    return dbus.SystemBus()


def find_adapter(bus, name=None):
    """Object path of the adapter (hci0 ...) with LE advertising support."""
    objs = bus.get_object(BLUEZ, "/").GetManagedObjects(dbus_interface=OM_IFACE)
    for path, ifaces in objs.items():
        if ADAPTER_IFACE in ifaces and (name is None or path.endswith("/" + name)):
            return path
    raise SystemExit("No Bluetooth adapter found%s" % (" named " + name if name else ""))


def adapter_supports_extended(bus, adapter):
    props = bus.get_object(BLUEZ, adapter).GetAll(ADV_MANAGER_IFACE, dbus_interface=PROP_IFACE)
    return len(props.get("SupportedSecondaryChannels", [])) > 0


def device_address(path):
    """dev_AA_BB_CC_DD_EE_FF in an object path -> 'AA:BB:CC:DD:EE:FF'."""
    part = [p for p in str(path).split("/") if p.startswith("dev_")]
    return part[0][4:].replace("_", ":") if part else ""


class InvalidArgs(dbus.exceptions.DBusException):
    _dbus_error_name = "org.freedesktop.DBus.Error.InvalidArgs"


# BlueZ turns these D-Bus errors into ATT error responses
class NotAuthorized(dbus.exceptions.DBusException):
    _dbus_error_name = "org.bluez.Error.NotAuthorized"  # 0x08 Insufficient Authorization


class NotSupported(dbus.exceptions.DBusException):
    _dbus_error_name = "org.bluez.Error.NotSupported"  # 0x06 Request Not Supported


class ImproperlyConfigured(dbus.exceptions.DBusException):
    _dbus_error_name = "org.bluez.Error.ImproperlyConfigured"  # 0xFD CCCD Improperly Configured


class Failed(dbus.exceptions.DBusException):
    _dbus_error_name = "org.bluez.Error.Failed"  # 0x80 (value not allowed has no BlueZ mapping)


def att_error(code):
    return {0x08: NotAuthorized, 0x06: NotSupported, 0xFD: ImproperlyConfigured}.get(code, Failed)("ATT 0x%02x" % code)


class Advertisement(dbus.service.Object):
    """An LEAdvertisement1 object. props: dict of D-Bus properties."""

    def __init__(self, bus, path, props):
        self.path = path
        self.props = props
        super().__init__(bus, path)

    @dbus.service.method(PROP_IFACE, in_signature="s", out_signature="a{sv}")
    def GetAll(self, interface):
        if interface != ADV_IFACE:
            raise InvalidArgs()
        return self.props

    @dbus.service.method(ADV_IFACE, in_signature="", out_signature="")
    def Release(self):
        pass


def manufacturer_data(frame):
    """{company: value} for BlueZ from a complete VSCP AD structure: BlueZ
    adds the AD Length, AD Type and Company Identifier itself."""
    frame = bytes(frame)
    company = frame[2] | (frame[3] << 8)
    return dbus.Dictionary({dbus.UInt16(company): dbus.Array(frame[4:], signature="y")}, signature="qv")


def ad_structure(company, value):
    """Rebuild the AD structure from BlueZ's ManufacturerData entry."""
    value = bytes(value)
    return bytes([len(value) + 3, 0xFF, company & 0xFF, company >> 8]) + value
