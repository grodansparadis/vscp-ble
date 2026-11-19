# VSCP over Bluetooth LE

[![Tests](https://github.com/grodansparadis/vscp-ble/actions/workflows/tests.yml/badge.svg)](https://github.com/grodansparadis/vscp-ble/actions/workflows/tests.yml)

Reference implementation of the draft VSCP Bluetooth LE transport. The
transport is specified in
[VSCP over Bluetooth Low Energy](https://grodansparadis.github.io/vscp-doc-spec/#/).

## Guides

- [C library](vscp-ble-library.md) - API, counters, A2 keys and replay
  state, G1 glue, and crypto backends
- [ESP32](esp32.md) - ESP-IDF 6.1 / NimBLE reference node
- [Zephyr and Nordic](zephyr-nordic.md) - Zephyr module and Zephyr / nRF
  Connect SDK reference nodes
- [Linux BlueZ](linux-bluez.md) - Python codec and BlueZ tools
- [Conformance and tests](conformance.md) - vectors, test coverage, sanitizers, and fuzzing
- [Specification notes](spec-notes.md) - issues found in the draft specification

## API reference

Run `doxygen Doxyfile` from the repository root to generate the API reference
in `doxygen/html`. CI builds it and fails on Doxygen warnings.
