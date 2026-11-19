# VSCP BLE node for Nordic nRF52/nRF53/nRF54L (nRF Connect SDK 3.x)
cmake_minimum_required(VERSION 3.20.0)

# This repository is the vscp-ble Zephyr module
list(APPEND EXTRA_ZEPHYR_MODULES ${CMAKE_CURRENT_SOURCE_DIR}/../..)

find_package(Zephyr REQUIRED HINTS $ENV{ZEPHYR_BASE})
project(vscp_ble_nordic)

# The BLE node itself is shared with the Zephyr example
target_include_directories(app PRIVATE ../zephyr/src)
target_sources(app PRIVATE src/main.c ../zephyr/src/vscp_node.c)
