# vscp-ble as an ESP-IDF component.
#
#   main/idf_component.yml:
#     dependencies:
#       vscp-ble:
#         path: <vscp-ble checkout>/components/vscp-ble
#
# IDF 6 provides the PSA Crypto API (hardware AES where available). For
# IDF 5 select Mbed TLS: idf.py -DVSCP_BLE_IDF_CRYPTO=mbedtls build

if(NOT DEFINED VSCP_BLE_IDF_CRYPTO)
  if(IDF_VERSION_MAJOR GREATER_EQUAL 6)
    set(VSCP_BLE_IDF_CRYPTO psa)
  else()
    set(VSCP_BLE_IDF_CRYPTO mbedtls)
  endif()
endif()

set(src ${CMAKE_CURRENT_LIST_DIR}/../../src)

idf_component_register(
  SRCS ${src}/vscp-ble-common.c
       ${src}/vscp-ble-counter.c
       ${src}/vscp-ble-e1.c
       ${src}/vscp-ble-l0.c
       ${src}/vscp-ble-a2.c
       ${src}/vscp-ble-f1.c
       ${src}/vscp-ble-g1.c
       ${src}/vscp-ble-crypto-${VSCP_BLE_IDF_CRYPTO}.c
  INCLUDE_DIRS ${src}
  PRIV_REQUIRES mbedtls)
