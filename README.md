![License](https://img.shields.io/badge/license-MIT-blue.svg)
[![Tests](https://github.com/grodansparadis/vscp-ble/actions/workflows/tests.yml/badge.svg)](https://github.com/grodansparadis/vscp-ble/actions/workflows/tests.yml)
[![Project Status: WIP – Initial development is in progress, but there has not yet been a stable, usable release suitable for the public.](https://www.repostatus.org/badges/latest/wip.svg)](https://www.repostatus.org/#wip)

# VSCP over Bluetooth LE

Reference implementation of the draft VSCP Bluetooth LE transport
([vscp-doc-spec, *VSCP over Bluetooth Low Energy*](https://github.com/grodansparadis/vscp-doc-spec/pull/18)):
a portable C library, and reference nodes and tools for ESP32, Zephyr,
Nordic nRF and Linux (BlueZ).

| Profile | What | Security | Event data |
| --- | --- | --- | --- |
| **E1** (version 1) | One event per Bluetooth 5 extended advertising data set | Public, unauthenticated (S0) | 0–222 octets |
| **A2** (version 2) | Same, with AES-128-CCM authenticated encryption and replay protection | Authenticated (S1/S2) | 0–200 octets |
| **F1** (version 3) | One event fragmented over 2–5 advertising data sets | Public (S0) | 223–1024 octets |
| **G1** | Connected GATT service, events in both directions | LE Secure Connections with MITM, application authorization | 0–487 octets |
| **L0** (version 0) | Legacy 31-octet advertising (compatibility) | Public | 0–8 octets |

> The transport specification is a **draft**. Frame layouts, GATT UUIDs and
> security rules can still change. Company Identifier `0xFFFF` used in the
> examples is for tests only: products need an assigned Bluetooth SIG
> Company Identifier.

## Contents

```text
src/                     The C99 library (no dynamic allocation, no OS)
  vscp-ble.h             Common types, error codes, byte order helpers
  vscp-ble-ad.h          Advertising data parsing, frame lookup
  vscp-ble-e1.h          E1 encode/decode
  vscp-ble-a2.h          A2 encode, receiver with key lookup and replay state
  vscp-ble-f1.h          F1 fragmenter and bounded reassembler
  vscp-ble-g1.h          G1 records, fragments, control, transport independent server
  vscp-ble-l0.h          L0 legacy layout
  vscp-ble-counter.h     Persistent sequence/epoch counter (never reuses a value)
  vscp-ble-crypto*.{h,c} AES-128-CCM backends: OpenSSL, PSA, Mbed TLS, reference
components/vscp-ble/     ESP-IDF component
zephyr/                  Zephyr module (also used by nRF Connect SDK)
examples/
  esp32/                 ESP-IDF 6.1 + NimBLE node: E1, A2, G1 server
  zephyr/                Zephyr 4.x node: E1, A2, G1 server
  nordic/                nRF Connect SDK 3.x node for nRF52840/nRF5340/nRF54L15 DKs
  linux-bluez/           Python: codec, advertiser, observer, G1 server and client
tests/                   GoogleTest suite, shared vectors, libFuzzer target
tools/                   Vector generator, version updater
docs/                    Documentation
```

## Quick start

Library and tests on Linux:

```bash
sudo apt install cmake g++ libgtest-dev libssl-dev python3-cryptography
cmake -S . -B build && cmake --build build -j
ctest --test-dir build --output-on-failure
```

Send a VSCP event from Linux as an E1 extended advertisement:

```bash
cd examples/linux-bluez
./vscp-ble-advertise.py --guid 00:01:02:03:04:05:06:07:08:09:0A:0B:0C:0D:0E:0F \
    --class 10 --type 6 --data 0x89,0x02,0x1A --period 10
```

Encode an E1 frame in C:

```c
#include "vscp-ble-e1.h"

uint8_t data[] = { 0x89, 0x02, 0x1A };
vscp_ble_event_t ev = { .guid = { ... }, .vscp_class = 10, .vscp_type = 6,
                        .size = sizeof(data), .data = data };
uint8_t frame[VSCP_BLE_E1_MAX_SIZE];
size_t len;
uint32_t seq;
vscp_ble_counter_next(&counter, NULL, &seq);       // persisted, never reused
vscp_ble_e1_encode(frame, sizeof(frame), company, seq, &ev, &len);
// frame is one complete Manufacturer Specific Data AD structure
```

## Documentation

- [Library guide](docs/vscp-ble-library.md) - API, persistence, crypto backends, porting
- API reference: run `doxygen Doxyfile` and open `doxygen/html/index.html` (also built by CI as the `vscp-ble-api-docs` artifact)
- [ESP32](docs/esp32.md) - ESP-IDF 6.1 / NimBLE node
- [Zephyr and Nordic](docs/zephyr-nordic.md) - Zephyr module, nRF Connect SDK node
- [Linux BlueZ](docs/linux-bluez.md) - Python tools and codec
- [Conformance and tests](docs/conformance.md) - vectors, test coverage, fuzzing
- [Specification notes](docs/spec-notes.md) - issues found in the draft while implementing it

## Verification status

| Part | Verified with |
| --- | --- |
| C library | 68 GoogleTests with the OpenSSL and the reference AES-CCM (CI also with Mbed TLS), ASan/UBSan, libFuzzer; compiles warning-free for Cortex-M4 with `-Wconversion -Werror` |
| PSA AES-CCM backend | Compiled in the ESP-IDF builds; not yet run against the vectors on a device |
| Interoperability | C and Python implementations both reproduce the shared vectors; the spec's E1 A/B, L0 and F1 vectors; AES-CCM checked against python3-cryptography, OpenSSL and NIST SP 800-38C |
| Linux BlueZ | Codec and G1 session tests; E1/A2 extended advertising and the G1 GATT service registered on BlueZ 5.82 |
| ESP32 | Builds with ESP-IDF 6.1 for esp32s3, esp32c3 and esp32c6 |
| Zephyr / Nordic | Built by CI (Zephyr 4.2 container, nRF Connect SDK 3.1 container) |

Over-the-air interoperability between different devices has not been tested
yet.

## License

MIT, see [LICENSE](LICENSE).
