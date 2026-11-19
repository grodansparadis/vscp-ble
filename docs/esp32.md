# ESP32 reference node (ESP-IDF 6.1, NimBLE)

`examples/esp32` is a complete VSCP BLE node:

- reads the on-chip temperature sensor every 10 s and sends it as
  CLASS1.MEASUREMENT / TEMPERATURE (32-bit float, Celsius)
  - as **E1** extended advertising (public),
  - as **A2** extended advertising (authenticated and encrypted) when a key
    is provisioned,
  - as a **G1** notification to a connected, authorized central;
- runs the **G1 GATT server** with LE Secure Connections, MITM protection
  (passkey printed on the console) and bonding;
- keeps the E1 and A2 counters in NVS, reserving 256 values per flash write.

It needs a chip with Bluetooth 5 extended advertising: **ESP32-S3, -C3,
-C6, -H2** and newer. The original ESP32 cannot send E1/A2 frames.

## Build and flash

```bash
. ~/.espressif/v6.1/esp-idf/export.sh      # or your ESP-IDF 6.1 install
cd examples/esp32
idf.py set-target esp32s3
idf.py menuconfig        # "VSCP BLE node": company id, interval, profiles
idf.py build flash monitor
```

The library comes in as the ESP-IDF component `components/vscp-ble`
(`main/idf_component.yml`). In your own project:

```yaml
dependencies:
  vscp-ble:
    path: <path to vscp-ble>/components/vscp-ble
```

IDF 6 uses the PSA Crypto API for AES-CCM (hardware AES). For IDF 5 build
with `-DVSCP_BLE_IDF_CRYPTO=mbedtls`.

## Configuration (menuconfig → VSCP BLE node)

| Option | Default | |
| --- | --- | --- |
| Company Identifier | 0xFFFF | **Test only.** Set your Bluetooth SIG assigned identifier |
| Measurement interval | 10000 ms | |
| E1 / A2 / G1 | on | Which profiles to use |
| Insecure test key | off | Uses the public test key when none is provisioned: never in products |
| Authorize bonded centrals | on | Demo policy: every authenticated, bonded central gets event access |

## Provisioning the A2 key

The key is a 23-octet blob `a2_key` in the NVS namespace `vscp_ble`:
2 octets key id (big-endian, nonzero), 16 octets AES key, 5 octets nonce
prefix. Generate the key with a CSPRNG and give each device its own prefix.
For example with the NVS partition generator:

```csv
key,type,encoding,value
vscp_ble,namespace,,
a2_key,data,hex2bin,0001<32 hex digits key><10 hex digits prefix>
```

```bash
python $IDF_PATH/components/nvs_flash/nvs_partition_generator/nvs_partition_gen.py \
    generate a2key.csv a2key.bin 0x6000
```

Flash it to the `nvs` partition with an *empty* `e1_ctr`/`a2_ctr` only for a
new device. The receiver needs the same key id, key, prefix and the node's
GUID (see the Linux observer's key file).

Use flash encryption and NVS encryption in products so the key cannot be
read from flash.

## Talking to it

- Observe E1/A2 from Linux: `examples/linux-bluez/vscp-ble-observe.py`
  (`--a2 key.json` for A2).
- Connect with G1: pair with `bluetoothctl` (agent `KeyboardDisplay`, enter
  the passkey from the ESP32 console), then
  `examples/linux-bluez/vscp-ble-g1-client.py <address>`.

## Notes

- The GUID is `FF:FF:FF:FF:FF:FF:FF:FE` + Bluetooth MAC + `00:00`.
- If NVS must be erased (version change, no free pages) the node refuses to
  start rather than erasing silently: the counters would start again from
  zero and reuse sequence numbers and A2 nonces. Erase deliberately and then
  provision a new A2 key.
- NimBLE does not encrypt-protect CCCD writes; the node only sends G1 events
  after an authenticated HELLO to an authorized peer.
