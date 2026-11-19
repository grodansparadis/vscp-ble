# vscp-ble Zephyr module
if(CONFIG_VSCP_BLE)
  set(VSCP_BLE_SRC ${CMAKE_CURRENT_LIST_DIR}/../src)
  zephyr_include_directories(${VSCP_BLE_SRC})
  zephyr_library()
  zephyr_library_sources(
    ${VSCP_BLE_SRC}/vscp-ble-common.c
    ${VSCP_BLE_SRC}/vscp-ble-counter.c
    ${VSCP_BLE_SRC}/vscp-ble-e1.c
    ${VSCP_BLE_SRC}/vscp-ble-l0.c
    ${VSCP_BLE_SRC}/vscp-ble-a2.c
    ${VSCP_BLE_SRC}/vscp-ble-f1.c
    ${VSCP_BLE_SRC}/vscp-ble-g1.c)
  zephyr_library_sources_ifdef(CONFIG_VSCP_BLE_CRYPTO_PSA ${VSCP_BLE_SRC}/vscp-ble-crypto-psa.c)
  zephyr_library_sources_ifdef(CONFIG_VSCP_BLE_CRYPTO_REFERENCE ${VSCP_BLE_SRC}/vscp-ble-crypto-reference.c)
  # Upstream Zephyr: the PSA API comes from the Mbed TLS module (nRF Connect
  # SDK's nrf_security provides it to every library itself)
  if(CONFIG_VSCP_BLE_CRYPTO_PSA AND CONFIG_MBEDTLS AND NOT CONFIG_NRF_SECURITY)
    zephyr_library_link_libraries(mbedTLS)
  endif()
endif()
