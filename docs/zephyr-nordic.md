# Zephyr and Nordic nRF reference nodes

The repository is a **Zephyr module** (`zephyr/module.yml`): add it to a
workspace and set `CONFIG_VSCP_BLE=y`. The AES-CCM backend is chosen with
`CONFIG_VSCP_BLE_CRYPTO_PSA` (default) or `CONFIG_VSCP_BLE_CRYPTO_REFERENCE`
(tests only).

Two applications share one node implementation
(`examples/zephyr/src/vscp_node.c`):

| Example | SDK | Boards |
| --- | --- | --- |
| `examples/zephyr` | Zephyr 4.2 (upstream controller, Mbed TLS PSA) | nRF52840 DK and other boards with LE extended advertising |
| `examples/nordic` | nRF Connect SDK 3.1 (SoftDevice Controller, nrf_security) | nRF52840 DK, nRF5340 DK, nRF54L15 DK |

Both send the die temperature as CLASS1.MEASUREMENT / TEMPERATURE every
10 s over E1, A2 (with a provisioned key) and G1, and run the G1 GATT
server with LE Secure Connections only, MITM protection (passkey in the
log) and bonding. The Nordic example also uses the DK buttons and LEDs.

## Zephyr

The open-source Zephyr controller sends at most 191 octets of extended
advertising data (more needs its experimental `BT_CTLR_ADV_DATA_CHAIN`), so
with it E1 events carry at most 157 data octets and A2 events 135. The
SoftDevice Controller in the Nordic example takes full-size frames.

```bash
west init -m https://github.com/grodansparadis/vscp-ble vscp-ws
cd vscp-ws && west update
west build -b nrf52840dk/nrf52840 vscp-ble/examples/zephyr
west flash
```

`west.yml` pins Zephyr v4.2.0 and the modules the example needs. To use the
library in another workspace add the repository to its `west.yml`, or from
an application `CMakeLists.txt`:

```cmake
list(APPEND EXTRA_ZEPHYR_MODULES <path to vscp-ble>)
```

## nRF Connect SDK

```bash
# In an nRF Connect SDK v3.1 workspace (nrfutil sdk-manager or the VS Code extension)
west build -b nrf52840dk/nrf52840 --sysbuild <path>/vscp-ble/examples/nordic
west build -b nrf5340dk/nrf5340/cpuapp --sysbuild <path>/vscp-ble/examples/nordic
west build -b nrf54l15dk/nrf54l15/cpuapp --sysbuild <path>/vscp-ble/examples/nordic
west flash
```

- nRF5340: sysbuild adds the `ipc_radio` network core image
  (`sysbuild.conf`); `sysbuild/ipc_radio.conf` gives its controller three
  extended advertising sets with up to 512 octets of data (a maximum E1 frame is 256).
- nRF54L15: settings are stored with ZMS (`boards/*.conf`).
- AES-CCM runs on the CryptoCell (nRF52840) or CRACEN (nRF54L) through
  `nrf_security`'s PSA API.

| DK | |
| --- | --- |
| Button 1 | Sends CLASS1.INFORMATION BUTTON (pressed / released) |
| Button 2 held at reset | Erases all bonds |
| LED 1 | Blinks while advertising, on while connected |
| LED 2 | On when the central is authorized |

## Configuration (Kconfig, `Kconfig.node`)

| Option | Default | |
| --- | --- | --- |
| `CONFIG_VSCP_NODE_COMPANY_ID` | 0xFFFF | **Test only**: set your assigned identifier |
| `CONFIG_VSCP_NODE_PERIOD_MS` | 10000 | |
| `CONFIG_VSCP_NODE_E1/A2/G1` | y | Profiles |
| `CONFIG_VSCP_NODE_A2_INSECURE_TEST_KEY` | n | Public test key when none is provisioned: never in products |
| `CONFIG_VSCP_NODE_AUTHORIZE_BONDED` | y | Demo policy: authenticated bonded centrals get event access |

## Provisioning

The A2 key is the setting `vscp_ble/a2key` (23 octets: key id big-endian,
16-octet key, 5-octet nonce prefix). Write it during production, e.g. from
a provisioning image or with the settings shell
(`CONFIG_SETTINGS_SHELL=y`, `settings write hex vscp_ble/a2key <46 hex digits>`),
then disable the shell.

The counters are the settings `vscp_ble/e1` and `vscp_ble/a2`. Do not erase
them on a deployed device: sequence numbers and A2 nonces would be reused.

## Threads

GATT callbacks run in the Bluetooth RX thread, `vscp_node_send()` in the
caller's thread and the timers in the system work queue; one mutex protects
the G1 session. Indications are sent from the work queue one at a time.

## The GUID

The examples use a development GUID, `FF:FF:FF:FF:FF:FF:FF:FD` + 8 octets
of the chip's device id (`hwinfo`). Use GUIDs from your own range in
products.
