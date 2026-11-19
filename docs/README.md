# Documentation

[![Tests](https://github.com/grodansparadis/vscp-ble/actions/workflows/tests.yml/badge.svg)](https://github.com/grodansparadis/vscp-ble/actions/workflows/tests.yml)

The transport is specified in *VSCP over Bluetooth Low Energy* in the
[VSCP specification](https://grodansparadis.github.io/vscp-doc-spec/#/)
(draft: vscp-doc-spec pull request #18).

- [vscp-ble-library](vscp-ble-library.md) - the C library: API, counters, A2 keys and replay state, G1 glue, crypto backends
- [esp32](esp32.md) - ESP-IDF 6.1 / NimBLE reference node
- [zephyr-nordic](zephyr-nordic.md) - Zephyr module, Zephyr and nRF Connect SDK reference nodes
- [linux-bluez](linux-bluez.md) - Python codec and BlueZ tools
- [conformance](conformance.md) - vectors, tests, sanitizers, fuzzing
- [spec-notes](spec-notes.md) - issues found in the draft specification
