// test-l0.cpp - L0 legacy layout (spec 4)
#include <gtest/gtest.h>

#include "test-util.h"
#include "vectors.h"
#include "vscp-ble-l0.h"

TEST(L0, SpecExample)
{
  vscp_ble_l0_event_t ev = {};
  ev.node_id             = 0x1234;
  ev.head                = 0x10;
  ev.vscp_class          = 0x0a;
  ev.vscp_type           = 6;
  ev.size                = 2;
  ev.data[0]             = 0xaa;
  ev.data[1]             = 0xbb;
  uint8_t buf[21];
  size_t len = 0;
  ASSERT_EQ(VSCP_BLE_OK, vscp_ble_l0_encode(buf, sizeof(buf), 0xFFFF, &ev, &len));
  EXPECT_EQ(B(v_l0_spec_frame, v_l0_spec_frame_len), B(buf, len));

  vscp_ble_l0_event_t out;
  ASSERT_EQ(VSCP_BLE_OK, vscp_ble_l0_decode(buf, len, 0xFFFF, &out));
  EXPECT_EQ(0x1234, out.node_id);
  EXPECT_EQ(2, out.size);
  EXPECT_EQ(0xbb, out.data[1]);
}

TEST(L0, RejectsEncryptedAndBadLength)
{
  bytes f = B(v_l0_spec_frame, v_l0_spec_frame_len);
  vscp_ble_l0_event_t out;
  f[4] = 0x80;
  EXPECT_EQ(VSCP_BLE_ERR_FLAGS, vscp_ble_l0_decode(f.data(), f.size(), 0xFFFF, &out));
  f[4] = 0x01;
  EXPECT_EQ(VSCP_BLE_ERR_VERSION, vscp_ble_l0_decode(f.data(), f.size(), 0xFFFF, &out));
  f[4]  = 0;
  f[12] = 9;
  EXPECT_EQ(VSCP_BLE_ERR_LENGTH, vscp_ble_l0_decode(f.data(), f.size(), 0xFFFF, &out));
  EXPECT_EQ(VSCP_BLE_ERR_LENGTH, vscp_ble_l0_decode(f.data(), 20, 0xFFFF, &out));
}

TEST(L0, LegacyGuid)
{
  const uint8_t addr[6] = { 0xc0, 0x11, 0x22, 0x33, 0x44, 0x55 };
  uint8_t g[16];
  vscp_ble_l0_guid(g, addr, 0x1234);
  const uint8_t expect[16] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xf8,
                               0xc0, 0x11, 0x22, 0x33, 0x44, 0x55, 0x12, 0x34 };
  EXPECT_EQ(0, memcmp(expect, g, 16));
}
