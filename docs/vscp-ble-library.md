# vscp-ble library guide

The library in `src/` implements the frame formats and state machines of the
draft VSCP Bluetooth LE transport. It is portable C99 with no dynamic
allocation, no operating system calls and no Bluetooth stack dependency: the
application (or the examples) connects it to NimBLE, Zephyr, BlueZ or any
other stack.

Code size on a Cortex-M4 (`-Os`): about 7.4 KB for everything, plus 1.5 KB
for the reference AES-CCM (or nothing when the platform's PSA/Mbed TLS AES is
used).

## Common definitions (`vscp-ble.h`)

```c
typedef struct {
  uint8_t guid[16];      // Sender GUID, canonical order, never all zero
  uint16_t head;         // Full 16-bit VSCP head
  uint16_t vscp_class;
  uint16_t vscp_type;
  uint16_t size;         // Event data length
  const uint8_t *data;
} vscp_ble_event_t;
```

Every function returns `VSCP_BLE_OK` (0), a positive informational code
(`VSCP_BLE_PENDING`, `VSCP_BLE_DUPLICATE`) or a negative `VSCP_BLE_ERR_*`
code; `vscp_ble_strerror()` names them. Decoders never accept a frame they
cannot fully validate, and never touch state before validation.

All frames are **complete AD structures** starting with the AD Length octet.
Stacks that add the AD Length/Type and Company Identifier themselves (BlueZ
`ManufacturerData`, Zephyr `BT_DATA_MANUFACTURER_DATA`) get `frame + 4` or
`frame + 2`; see the examples.

## Receiving advertising (`vscp-ble-ad.h`)

```c
int vscp_ble_e1_decode_dataset(data, len, company, &seq, &ev);
int vscp_ble_a2_receive_dataset(&rx, data, len, &ev, plain, sizeof(plain), &epoch, &seq, &rec);
int vscp_ble_ad_frame_version(data, len, company);   // which profile is it?
```

Pass the **complete** advertising data set of an extended advertising
report. Do not pass incomplete (truncated) reports; the controller marks
them. `vscp_ble_ad_find_frame()` rejects data sets with more than one
candidate frame (`VSCP_BLE_ERR_AMBIGUOUS`), and structures that overrun the
data (`VSCP_BLE_ERR_TRUNCATED`).

## E1 - cleartext events (`vscp-ble-e1.h`)

`vscp_ble_e1_encode()` / `vscp_ble_e1_decode()`. Data 0-222 octets, frame
34 + N octets. E1 data is public and unauthenticated: never act on it for
anything privileged.

Receivers may drop duplicates by (GUID, sequence) — the sender retransmits
the same frame until the next event.

## The sequence counter (`vscp-ble-counter.h`)

E1 and A2 senders must never reuse a sequence number (A2: a nonce), also
after a reset, power loss or firmware update. `vscp_ble_counter_t` reserves
blocks of values in nonvolatile storage *before* using them:

```c
static int persist(void *ctx, uint32_t epoch, uint64_t reserved_until)
{
  // Write both values durably (flash, NVS, settings). Return 0 on success.
}

// At startup, from what persist() stored last (0, 0 for a new device):
vscp_ble_counter_init(&ctr, epoch, reserved_until, 256 /* block */, use_epoch, persist, ctx);

uint32_t epoch, seq;
if (VSCP_BLE_OK == vscp_ble_counter_next(&ctr, &epoch, &seq)) { ... }
```

- One flash write per block (256 values in the examples). After a restart
  the unused rest of the last block is skipped.
- If `persist()` fails, `vscp_ble_counter_next()` fails: sending stops
  rather than risking reuse.
- E1 (`use_epoch = 0`): after 0xFFFFFFFF the counter is exhausted (wrap is
  forbidden); a new sender identity is needed.
- A2 (`use_epoch = 1`): the epoch advances (and is persisted before use).
  When the epochs run out, provision a new key and nonce prefix.
- Never restore the counter from a backup or roll it back.

## A2 - authenticated encryption (`vscp-ble-a2.h`)

Sender:

```c
vscp_ble_a2_encode(frame, sizeof(frame), company, key_id, epoch, seq, key, nonce_prefix, &ev, &len);
```

Receiver: a key store returns provisioned records, and their replay state
must be stored durably:

```c
static vscp_ble_a2_key_t *lookup(void *ctx, uint16_t company, uint16_t key_id);
static int persist_replay(void *ctx, const vscp_ble_a2_key_t *rec); // store last_epoch/last_sequence

vscp_ble_a2_receiver_t rx = { company, lookup, persist_replay, ctx };
int rv = vscp_ble_a2_receive(&rx, frame, len, &ev, plain, sizeof(plain), &epoch, &seq, &rec);
if (VSCP_BLE_OK == rv) {
  // Authenticated. Now validate the VSCP event and AUTHORIZE it (by
  // rec, class/type, target) before acting on it.
}
```

The receiver follows the specification's order: framing; zero GUID; key
record lookup with the GUID checked against the record (a known Key ID
never vouches for a different GUID); revocation and epoch range; the full
16-octet tag is verified before any plaintext is released (the buffer is
cleared on failure); the (epoch, sequence) must be strictly greater than the
last accepted one; the new replay state is persisted before the event is
returned. If persisting fails, the event is rejected and the old state kept
(fail closed).

`vscp_ble_a2_receive()` is not thread safe: serialize calls per receiver.

Keys: 16 random octets from a CSPRNG, a unique 5-octet nonce prefix per
sender and key, provisioned over an authenticated, confidential channel and
kept in protected storage. Never use the test key of the examples.

## F1 - fragmented public events (`vscp-ble-f1.h`)

Sender: `vscp_ble_f1_fragment_count(T)` fragments, each from
`vscp_ble_f1_encode(..., index, ...)`, sent as separate extended
advertising data sets. Use a new nonzero Message ID per event.

Receiver: `vscp_ble_f1_rx_t` (about 2.4 KB, no allocation) and
`vscp_ble_f1_rx_feed()` per fragment. At most two messages are reassembled
at once (a third gets `VSCP_BLE_ERR_BUSY`, nothing is evicted); each has an
absolute 3-second deadline; conflicting fragments drop the whole message;
a completed message is delivered once and then reported as
`VSCP_BLE_DUPLICATE` for at least 3 seconds. F1 is public data, like E1.

## G1 - GATT (`vscp-ble-g1.h`)

The G1 server session `vscp_ble_g1_server_t` holds all per-connection
state. The platform glue calls it for every GATT event and supplies three
callbacks:

| Platform event | Call |
| --- | --- |
| Connected / disconnected | `vscp_ble_g1_server_connected(s, mtu)` / `_disconnected(s)` |
| ATT MTU exchanged | `vscp_ble_g1_server_set_mtu(s, mtu)` |
| Encryption/pairing changed, authorization decided | `vscp_ble_g1_server_set_security(s, pairing, authorization)` |
| CCCD written | `_set_control_indicate(s, on)`, `_set_event_notify(s, on)` |
| Read of Capabilities, GUID, Security, Configuration | `vscp_ble_g1_server_read_*()` |
| Write to Control, Event RX, Configuration | `vscp_ble_g1_server_write_*()` returns 0 or the ATT error code |
| Every second | `vscp_ble_g1_server_tick(s, now_ms)` |

| Callback | Does |
| --- | --- |
| `indicate(ctx, data, len)` | Send a Control indication. ATT allows one outstanding indication: queue them (the examples do) |
| `notify(ctx, data, len)` | Send an Event TX notification |
| `on_event(ctx, ev, tid)` | A complete event from the client: validate and authorize it, return a G1 status |

`vscp_ble_g1_server_send_event()` sends an event to the client (only after
HELLO, with notifications enabled, on an authenticated link with event
authorization) and reports the attempt with TX_RESULT. Stack use is about
`VSCP_BLE_G1_TX_MAX_MTU` (default 247) + 130 octets.

Security: give `pairing = VSCP_BLE_G1_PAIRING_AUTHENTICATED` only for an
encrypted link with authenticated (MITM) pairing — LE Secure Connections
recommended. Authorization (`VSCP_BLE_G1_AUTH_EVENT`/`_ADMIN`) is the
application's decision: bonding alone is not authorization. Use the stack's
attribute permissions too (encrypt + authenticate on the protected
characteristics).

For clients (and tests) the building blocks are public:
`vscp_ble_g1_record_encode/decode`, `vscp_ble_g1_frag_tx_*`,
`vscp_ble_g1_frag_rx_*`, `vscp_ble_g1_control_encode/decode` and
`vscp_ble_g1_limits_*`.

## L0 - legacy advertising (`vscp-ble-l0.h`)

The proposed canonical 21-octet layout, plaintext only. The historic
encrypted L0 (AES-ECB) is neither authenticated nor replay protected and is
rejected. `vscp_ble_l0_guid()` builds the derived legacy GUID
`FF:FF:FF:FF:FF:FF:FF:F8:<address>:<node id>`, which changes with private
address rotation and must not be merged with a stable GUID.

## AES-128-CCM backends (`vscp-ble-crypto.h`)

Compile exactly one:

| File | Use |
| --- | --- |
| `vscp-ble-crypto-psa.c` | PSA Crypto API: ESP-IDF 6, Zephyr, nRF Connect SDK (hardware AES where present) |
| `vscp-ble-crypto-mbedtls.c` | Mbed TLS 2.x/3.x (ESP-IDF 5 and others) |
| `vscp-ble-crypto-openssl.c` | OpenSSL 1.1/3 (Linux) |
| `vscp-ble-crypto-reference.c` | Portable RFC 3610 implementation for tests and cross-checks; its table AES is not hardened against timing attacks |

Another library can be used by implementing the four functions in
`vscp-ble-crypto.h`. The tests check any backend against the shared
vectors.

## Building

- CMake: `add_subdirectory(vscp-ble)` and link `vscp-ble`
  (`-DVSCP_BLE_CRYPTO=openssl|reference|mbedtls|psa`).
- ESP-IDF: depend on `components/vscp-ble` (see [esp32.md](esp32.md)).
- Zephyr / nRF Connect SDK: add the repository as a module and set
  `CONFIG_VSCP_BLE=y` (see [zephyr-nordic.md](zephyr-nordic.md)).
- Anything else: compile the `src/*.c` files you need plus one crypto
  backend, with `src/` on the include path.

## Version

`src/vscp-ble-version.h` holds the library version as year.month.patch
(`VSCP_BLE_LIB_VERSION_STR`, `VSCP_BLE_LIB_VERSION`). It is updated
automatically on every push to master. It is not the wire format version:
those are in the frames (E1 = 1, A2 = 2, F1 = 3, G1 protocol 1).
