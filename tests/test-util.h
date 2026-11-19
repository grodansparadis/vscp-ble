// test-util.h - helpers shared by the vscp-ble tests
#ifndef VSCP_BLE_TEST_UTIL_H
#define VSCP_BLE_TEST_UTIL_H

#include <cstring>
#include <string>
#include <vector>

#include "vscp-ble.h"

static const uint8_t TEST_GUID[16]  = { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15 };
static const uint8_t TEST_KEY[16]   = { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15 };
static const uint8_t TEST_PREFIX[5] = { 0xa0, 0xa1, 0xa2, 0xa3, 0xa4 };

typedef std::vector<uint8_t> bytes;

inline bytes
B(const uint8_t *p, size_t n)
{
  return bytes(p, p + n);
}

inline bytes
ramp(size_t n)
{
  bytes v(n);
  for (size_t i = 0; i < n; i++) {
    v[i] = (uint8_t) (i & 0xff);
  }
  return v;
}

inline vscp_ble_event_t
make_event(uint16_t cls, uint16_t type, const bytes &data, uint16_t head = 0)
{
  vscp_ble_event_t ev;
  memcpy(ev.guid, TEST_GUID, 16);
  ev.head       = head;
  ev.vscp_class = cls;
  ev.vscp_type  = type;
  ev.size       = (uint16_t) data.size();
  ev.data       = data.empty() ? nullptr : data.data();
  return ev;
}

#endif
