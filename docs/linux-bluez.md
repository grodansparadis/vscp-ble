# Linux reference tools (BlueZ)

`examples/linux-bluez` holds Python 3 programs that use BlueZ over D-Bus,
and `vscp_ble`, a pure-Python codec for all profiles. The codec is written
independently of the C library; both are tested against the same vectors.

Needs BlueZ 5.56 or later, `python3-dbus`, `python3-gi` and
`python3-cryptography`, and for E1/A2 a controller with LE extended
advertising (`bluetoothctl show` lists `SupportedSecondaryChannels`).

```bash
sudo apt install bluez python3-dbus python3-gi python3-cryptography
```

## Programs

### vscp-ble-advertise.py — send E1 or A2

```bash
./vscp-ble-advertise.py --guid 00:01:02:03:04:05:06:07:08:09:0A:0B:0C:0D:0E:0F \
    --class 10 --type 6 --data 0x89,0x02,0x1A --period 10
./vscp-ble-advertise.py --a2 key.json --class 10 --type 6 --data 0x89,0x02,0x1A
```

A new event (new sequence number) every `--period` seconds; the same frame
is repeated by the controller in between. The counter is reserved in
blocks in `--state` (written to a temporary file, fsync'ed and renamed).
Advertising is non-connectable and non-scannable on LE 1M (profile EA-B).

### vscp-ble-observe.py — receive E1, A2, F1 (and L0)

```bash
./vscp-ble-observe.py                        # E1 and F1
./vscp-ble-observe.py --a2 key.json          # also A2 from this key
./vscp-ble-observe.py --legacy               # also L0
```

Prints one JSON object per event, with `trust` = `public` or
`authenticated`. A2 replay state is kept in `--replay-state`.

BlueZ hands applications Manufacturer Specific Data per Company
Identifier, not the raw advertising data set, so the observer cannot apply
the ambiguity (several candidate frames) and truncated-report checks of the
specification. A gateway that must do so should read raw reports (HCI or
the mgmt socket) and use `vscp_ble.find_frame()` or the C library.

### vscp-ble-g1-server.py — G1 peripheral

```bash
./vscp-ble-g1-server.py --guid 00:01:02:03:04:05:06:07:08:09:0A:0B:0C:0D:0E:0F \
    --authorize AA:BB:CC:DD:EE:FF
```

Registers the G1 service and connectable advertising, prints events from
the client and sends it a heartbeat. Protected characteristics use BlueZ's
`encrypt-authenticated-*` flags, so only links with authenticated (MITM)
pairing reach them; event access is only for the `--authorize`d addresses
(admin for `--admin`). One client at a time.

### vscp-ble-g1-client.py — G1 central

```bash
bluetoothctl            # agent KeyboardDisplay; scan le; pair <address>; enter the passkey
./vscp-ble-g1-client.py <address> --class 20 --type 9 --data 0,0,0
```

Reads Capabilities and the GUID, enables Control indications, sends HELLO,
writes one event and prints EVENT_RESULT, TX_RESULT and events from the
server.

## Key file

```json
{
  "key_id": 1,
  "guid": "00:01:02:03:04:05:06:07:08:09:0A:0B:0C:0D:0E:0F",
  "key": "<32 hex digits>",
  "nonce_prefix": "<10 hex digits>"
}
```

`key.example.json` holds the **public test key** of the vectors. Generate
real keys with `python3 -c "import secrets; print(secrets.token_hex(16))"`,
give every sender its own nonce prefix, and keep key files private
(`chmod 600`).

## The codec

```python
from vscp_ble import Event, e1_encode, e1_decode, A2Key, A2Receiver, a2_encode

frame = e1_encode(Event(guid, 10, 6, b"\x89\x02\x1a"), sequence=7)
event, seq = e1_decode(frame)
```

`vscp_ble.g1session` has `G1Server` and `G1Client`, the transport
independent G1 session logic the BlueZ programs use.

## Tests

```bash
python3 -m unittest discover -s examples/linux-bluez/tests -v
```

No Bluetooth hardware is needed: the codec is checked against the shared
vectors and a G1 server and client talk to each other at several ATT MTUs.
