# vscp-ble tests (GoogleTest)
#
# The suite is built twice: against the library's configured backend and
# against the portable reference AES-CCM, so two AES-CCM implementations
# are checked against the vectors made by a third (python3-cryptography).

enable_language(CXX)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

find_package(GTest QUIET)
if(NOT GTest_FOUND)
  include(FetchContent)
  message(STATUS "GTest not found. Fetching googletest.")
  FetchContent_Declare(googletest
    URL https://github.com/google/googletest/archive/refs/tags/v1.14.0.zip
    DOWNLOAD_EXTRACT_TIMESTAMP TRUE)
  set(gtest_force_shared_crt ON CACHE BOOL "" FORCE)
  FetchContent_MakeAvailable(googletest)
endif()

set(VSCP_BLE_TEST_SOURCES
  test-ad.cpp
  test-e1.cpp
  test-l0.cpp
  test-counter.cpp
  test-crypto.cpp
  test-a2.cpp
  test-f1.cpp
  test-g1.cpp)

function(vscp_ble_add_test name lib)
  add_executable(${name} ${VSCP_BLE_TEST_SOURCES})
  target_include_directories(${name} PRIVATE ${CMAKE_CURRENT_SOURCE_DIR} ${CMAKE_CURRENT_SOURCE_DIR}/vectors)
  target_link_libraries(${name} PRIVATE ${lib} GTest::gtest_main)
  add_test(NAME ${name} COMMAND ${name})
endfunction()

vscp_ble_add_test(test-vscp-ble vscp-ble)
if(NOT VSCP_BLE_CRYPTO STREQUAL "reference")
  vscp_ble_add_library(vscp-ble-ref reference)
  vscp_ble_add_test(test-vscp-ble-ref vscp-ble-ref)
endif()
