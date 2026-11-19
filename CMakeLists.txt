# vscp-ble - VSCP over Bluetooth LE reference library
#
# Portable C99, no dynamic allocation. Pick the AES-CCM backend with
# VSCP_BLE_CRYPTO: openssl (default when found), reference, mbedtls or psa.
# ESP-IDF and Zephyr builds use their own component/module files instead.

cmake_minimum_required(VERSION 3.16)

# ESP-IDF: use components/vscp-ble. Zephyr: zephyr/ (module).

project(vscp-ble LANGUAGES C)

set(VSCP_BLE_CRYPTO "" CACHE STRING "AES-CCM backend: openssl, reference, mbedtls or psa")
option(VSCP_BLE_BUILD_TESTS "Build the tests" ON)
option(VSCP_BLE_SANITIZE "Build with address and undefined behavior sanitizers" OFF)

if(VSCP_BLE_CRYPTO STREQUAL "")
  find_package(OpenSSL QUIET COMPONENTS Crypto)
  if(OpenSSL_FOUND)
    set(VSCP_BLE_CRYPTO openssl)
  else()
    set(VSCP_BLE_CRYPTO reference)
  endif()
endif()
message(STATUS "vscp-ble crypto backend: ${VSCP_BLE_CRYPTO}")

if(VSCP_BLE_SANITIZE)
  add_compile_options(-fsanitize=address,undefined -fno-omit-frame-pointer -fno-sanitize-recover=all)
  add_link_options(-fsanitize=address,undefined)
endif()

set(VSCP_BLE_SRC ${CMAKE_CURRENT_SOURCE_DIR}/src)

function(vscp_ble_add_library name backend)
  add_library(${name} STATIC
    ${VSCP_BLE_SRC}/vscp-ble-common.c
    ${VSCP_BLE_SRC}/vscp-ble-counter.c
    ${VSCP_BLE_SRC}/vscp-ble-e1.c
    ${VSCP_BLE_SRC}/vscp-ble-l0.c
    ${VSCP_BLE_SRC}/vscp-ble-a2.c
    ${VSCP_BLE_SRC}/vscp-ble-f1.c
    ${VSCP_BLE_SRC}/vscp-ble-g1.c
    ${VSCP_BLE_SRC}/vscp-ble-crypto-${backend}.c)
  target_include_directories(${name} PUBLIC ${VSCP_BLE_SRC})
  set_target_properties(${name} PROPERTIES C_STANDARD 99 C_STANDARD_REQUIRED ON)
  if(CMAKE_C_COMPILER_ID MATCHES "GNU|Clang")
    target_compile_options(${name} PRIVATE -Wall -Wextra -Wpedantic -Wshadow -Wconversion -Werror)
  endif()
  if(backend STREQUAL "openssl")
    find_package(OpenSSL REQUIRED COMPONENTS Crypto)
    target_link_libraries(${name} PUBLIC OpenSSL::Crypto)
  elseif(backend STREQUAL "mbedtls")
    find_package(MbedTLS QUIET)
    if(TARGET MbedTLS::mbedcrypto)
      target_link_libraries(${name} PUBLIC MbedTLS::mbedcrypto)
    else()
      # Distribution packages (libmbedtls-dev) without a CMake package
      find_library(VSCP_BLE_MBEDCRYPTO mbedcrypto)
      if(NOT VSCP_BLE_MBEDCRYPTO)
        message(FATAL_ERROR "Mbed TLS (mbedcrypto) not found")
      endif()
      target_link_libraries(${name} PUBLIC ${VSCP_BLE_MBEDCRYPTO})
    endif()
  endif()
endfunction()

vscp_ble_add_library(vscp-ble ${VSCP_BLE_CRYPTO})

if(VSCP_BLE_BUILD_TESTS)
  enable_testing()
  add_subdirectory(tests)
endif()
