// test-e1.cpp - E1 version 1 (spec 5)
#include <gtest/gtest.h>

#include "test-util.h"
#include "vectors.h"
#include "vscp-ble-e1.h"

static bytes
encode(uint32_t seq, const vscp_ble_event_t &ev)
{
  uint8_t buf[256];
  size_t len = 0;
  EXPECT_EQ(VSCP_BLE_OK, vscp_ble_e1_encode(buf, sizeof(buf), 0xFFFF, seq, &ev, &len));
  return B(buf, len);
}

TEST(E1, SpecVectorA)
{
  EXPECT_EQ(B(v_e1_a_frame, v_e1_a_frame_len), encode(0, make_event(0, 0, {})));
}

TEST(E1, SpecVectorB)
{
  EXPECT_EQ(B(v_e1_b_frame, v_e1_b_frame_len), encode(1, make_event(0x0a, 6, { 0x11, 0x22 })));
}

TEST(E1, MaximumVector)
{
  bytes d = ramp(222);
  EXPECT_EQ(B(v_e1_max_frame, v_e1_max_frame_len), encode(0xFFFFFFFF, make_event(0x0a, 6, d, 0x1234)));
  EXPECT_EQ(256u, v_e1_max_frame_len);
}

TEST(E1, DecodeVectors)
{
  vscp_ble_event_t ev;
  uint32_t seq = 0;
  ASSERT_EQ(VSCP_BLE_OK, vscp_ble_e1_decode(v_e1_b_frame, v_e1_b_frame_len, 0xFFFF, &seq, &ev));
  EXPECT_EQ(1u, seq);
  EXPECT_EQ(0, memcmp(ev.guid, TEST_GUID, 16));
  EXPECT_EQ(0x0a, ev.vscp_class);
  EXPECT_EQ(6, ev.vscp_type);
  ASSERT_EQ(2, ev.size);
  EXPECT_EQ(0x22, ev.data[1]);
  ASSERT_EQ(VSCP_BLE_OK, vscp_ble_e1_decode(v_e1_max_frame, v_e1_max_frame_len, 0xFFFF, &seq, &ev));
  EXPECT_EQ(0xFFFFFFFFu, seq);
  EXPECT_EQ(0x1234, ev.head);
  EXPECT_EQ(222, ev.size);
}

TEST(E1, EncodeRejects)
{
  uint8_t buf[256];
  size_t len;
  bytes d             = ramp(223);
  vscp_ble_event_t ev = make_event(0, 0, d);
  EXPECT_EQ(VSCP_BLE_ERR_TOO_LARGE, vscp_ble_e1_encode(buf, sizeof(buf), 0xFFFF, 0, &ev, &len));
  ev = make_event(0, 0, {});
  memset(ev.guid, 0, 16);
  EXPECT_EQ(VSCP_BLE_ERR_GUID, vscp_ble_e1_encode(buf, sizeof(buf), 0xFFFF, 0, &ev, &len));
  ev = make_event(0, 0, {});
  EXPECT_EQ(VSCP_BLE_ERR_BUFFER, vscp_ble_e1_encode(buf, 33, 0xFFFF, 0, &ev, &len));
}

// Spec 5.7 negative tests
class E1Negative : public ::testing::Test {
protected:
  bytes f = B(v_e1_b_frame, v_e1_b_frame_len);
  int decode(const bytes &b, uint16_t company = 0xFFFF)
  {
    vscp_ble_event_t ev;
    return vscp_ble_e1_decode(b.data(), b.size(), company, nullptr, &ev);
  }
};

TEST_F(E1Negative, Version2)
{
  f[4] = 0x02;
  EXPECT_EQ(VSCP_BLE_ERR_VERSION, decode(f));
}

TEST_F(E1Negative, Flags)
{
  f[5] = 0x01;
  EXPECT_EQ(VSCP_BLE_ERR_FLAGS, decode(f));
  f[5] = 0x80;
  EXPECT_EQ(VSCP_BLE_ERR_FLAGS, decode(f));
}

TEST_F(E1Negative, ZeroGuid)
{
  memset(&f[10], 0, 16);
  EXPECT_EQ(VSCP_BLE_ERR_GUID, decode(f));
}

TEST_F(E1Negative, N223)
{
  bytes g = B(v_e1_max_frame, v_e1_max_frame_len);
  g[33]   = 223;
  EXPECT_EQ(VSCP_BLE_ERR_LENGTH, decode(g));
}

TEST_F(E1Negative, AdLengthMismatch)
{
  f[0]++;
  EXPECT_EQ(VSCP_BLE_ERR_LENGTH, decode(f));
  f[0] -= 2;
  EXPECT_EQ(VSCP_BLE_ERR_LENGTH, decode(f));
}

TEST_F(E1Negative, ExtraBytesInStructure)
{
  f.push_back(0x00);
  f[0]++;
  EXPECT_EQ(VSCP_BLE_ERR_LENGTH, decode(f));
}

TEST_F(E1Negative, DataLengthMismatch)
{
  f[33] = 3;
  EXPECT_EQ(VSCP_BLE_ERR_LENGTH, decode(f));
}

TEST_F(E1Negative, Truncated)
{
  f.pop_back();
  EXPECT_EQ(VSCP_BLE_ERR_LENGTH, decode(f));
}

TEST_F(E1Negative, OtherCompanyAndType)
{
  EXPECT_EQ(VSCP_BLE_ERR_COMPANY, decode(f, 0x02E5));
  f[1] = 0x16;
  EXPECT_EQ(VSCP_BLE_ERR_TYPE, decode(f));
}
