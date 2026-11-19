// test-f1.cpp - F1 connectionless fragmentation (spec 9)
#include <gtest/gtest.h>

#include "test-util.h"
#include "vectors.h"
#include "vscp-ble-f1.h"

static std::vector<bytes>
fragments(const bytes &data, uint32_t mid = 1, uint16_t cls = 0x0a)
{
  vscp_ble_event_t ev = make_event(cls, 6, data);
  std::vector<bytes> out;
  unsigned k = vscp_ble_f1_fragment_count(data.size());
  for (unsigned i = 0; i < k; i++) {
    uint8_t buf[256];
    size_t len = 0;
    EXPECT_EQ(VSCP_BLE_OK, vscp_ble_f1_encode(buf, sizeof(buf), 0xFFFF, mid, &ev, i, &len));
    out.push_back(B(buf, len));
  }
  return out;
}

class F1 : public ::testing::Test {
protected:
  vscp_ble_f1_rx_t *rx = new vscp_ble_f1_rx_t;
  uint8_t out[1024];
  vscp_ble_event_t ev;
  void SetUp() override { vscp_ble_f1_rx_init(rx, 0xFFFF); }
  void TearDown() override { delete rx; }
  int feed(const bytes &f, uint32_t t = 0)
  {
    return vscp_ble_f1_rx_feed(rx, f.data(), f.size(), t, &ev, out, sizeof(out));
  }
};

TEST_F(F1, Vector223)
{
  auto f = fragments(ramp(223));
  ASSERT_EQ((size_t) V_F1_223_COUNT, f.size());
  EXPECT_EQ(B(v_f1_223_frag0, v_f1_223_frag0_len), f[0]);
  EXPECT_EQ(B(v_f1_223_frag1, v_f1_223_frag1_len), f[1]);
  EXPECT_EQ(0xFD, f[0][0]);
  EXPECT_EQ(0x01, f[0][5]);
  EXPECT_EQ(0x34, f[1][0]); // 0x29 + 11 (the draft's 9.5 text says 0x35)
  EXPECT_EQ(0x02, f[1][5]);
  EXPECT_EQ(VSCP_BLE_PENDING, feed(f[0]));
  ASSERT_EQ(VSCP_BLE_OK, feed(f[1]));
  EXPECT_EQ(223, ev.size);
  EXPECT_EQ(ramp(223), B(ev.data, ev.size));
  EXPECT_EQ(VSCP_BLE_DUPLICATE, feed(f[0])); // Delivered exactly once
  EXPECT_EQ(VSCP_BLE_DUPLICATE, feed(f[1]));
}

TEST_F(F1, Vector1024OutOfOrderWithDuplicates)
{
  auto f = fragments(ramp(1024));
  ASSERT_EQ(5u, f.size());
  bytes v0 = B(v_f1_1024_frag0, v_f1_1024_frag0_len), v4 = B(v_f1_1024_frag4, v_f1_1024_frag4_len);
  EXPECT_EQ(v0, f[0]);
  EXPECT_EQ(v4, f[4]);
  const size_t sizes[5] = { 212, 212, 212, 212, 176 };
  for (int i = 0; i < 5; i++) {
    EXPECT_EQ(42 + sizes[i], f[i].size());
    EXPECT_EQ(i * 212, (f[i][36] << 8) | f[i][37]);
  }
  EXPECT_EQ(VSCP_BLE_PENDING, feed(f[3]));
  EXPECT_EQ(VSCP_BLE_PENDING, feed(f[1]));
  EXPECT_EQ(VSCP_BLE_PENDING, feed(f[1])); // Identical duplicate
  EXPECT_EQ(VSCP_BLE_PENDING, feed(f[4]));
  EXPECT_EQ(VSCP_BLE_PENDING, feed(f[0]));
  ASSERT_EQ(VSCP_BLE_OK, feed(f[2]));
  EXPECT_EQ(ramp(1024), B(ev.data, ev.size));
}

TEST_F(F1, ConflictsDropTheMessage)
{
  auto f = fragments(ramp(300));
  EXPECT_EQ(VSCP_BLE_PENDING, feed(f[0]));
  bytes changed = f[0];
  changed.back() ^= 1;
  EXPECT_EQ(VSCP_BLE_ERR_CONFLICT, feed(changed));
  EXPECT_EQ(VSCP_BLE_PENDING, feed(f[1])); // Starts over: nothing delivered

  vscp_ble_f1_rx_init(rx, 0xFFFF);
  auto other = fragments(ramp(300), 1, 0x0b); // Same message id, other class
  EXPECT_EQ(VSCP_BLE_PENDING, feed(f[0]));
  EXPECT_EQ(VSCP_BLE_ERR_CONFLICT, feed(other[1]));
}

TEST_F(F1, AbsoluteDeadline)
{
  auto f = fragments(ramp(700));
  EXPECT_EQ(VSCP_BLE_PENDING, feed(f[0], 0));
  EXPECT_EQ(VSCP_BLE_PENDING, feed(f[1], 2000));
  EXPECT_EQ(VSCP_BLE_PENDING, feed(f[2], 2999));
  EXPECT_EQ(VSCP_BLE_PENDING, feed(f[3], 3000)); // Deadline not extended: old message dropped, new one started
  EXPECT_EQ(1u, (unsigned) __builtin_popcount(rx->slot[0].received | rx->slot[1].received));
}

TEST_F(F1, ClockWrap)
{
  auto f = fragments(ramp(300));
  EXPECT_EQ(VSCP_BLE_PENDING, feed(f[0], 0xFFFFFF00u));
  EXPECT_EQ(VSCP_BLE_OK, feed(f[1], 0x00000100u)); // 512 ms later
}

TEST_F(F1, TwoConcurrentMessagesMax)
{
  auto a = fragments(ramp(300), 1), b = fragments(ramp(300), 2), c = fragments(ramp(300), 3);
  EXPECT_EQ(VSCP_BLE_PENDING, feed(a[0]));
  EXPECT_EQ(VSCP_BLE_PENDING, feed(b[0]));
  EXPECT_EQ(VSCP_BLE_ERR_BUSY, feed(c[0])); // No eviction
  EXPECT_EQ(VSCP_BLE_OK, feed(a[1]));
  EXPECT_EQ(VSCP_BLE_OK, feed(b[1]));
  EXPECT_EQ(VSCP_BLE_PENDING, feed(c[0]));
}

TEST_F(F1, CompletionCacheExpires)
{
  auto f = fragments(ramp(300));
  feed(f[0], 0);
  EXPECT_EQ(VSCP_BLE_OK, feed(f[1], 10));
  EXPECT_EQ(VSCP_BLE_DUPLICATE, feed(f[0], 3010)); // Kept at least 3 s
  EXPECT_EQ(VSCP_BLE_PENDING, feed(f[0], 6020));
}

TEST_F(F1, NoncanonicalFragmentsRejected)
{
  auto f  = fragments(ramp(300));
  bytes g = f[0];
  g[5]    = 0x03; // FIRST|LAST on a non-final fragment
  EXPECT_EQ(VSCP_BLE_ERR_FLAGS, feed(g));
  g     = f[0];
  g[40] = 1; // Reserved
  EXPECT_EQ(VSCP_BLE_ERR_FLAGS, feed(g));
  g     = f[1];
  g[37] = 0; // Offset 212 -> 0
  g[36] = 0;
  EXPECT_EQ(VSCP_BLE_ERR_SEQUENCE, feed(g));
  g     = f[0];
  g[35] = 9; // K
  EXPECT_EQ(VSCP_BLE_ERR_LENGTH, feed(g));
  g     = f[0];
  g[32] = 0x04; // T = 1025
  g[33] = 0x01;
  EXPECT_EQ(VSCP_BLE_ERR_LENGTH, feed(g));
  g     = f[0];
  g[33] = 222; // T too small for F1
  g[32] = 0;
  EXPECT_EQ(VSCP_BLE_ERR_LENGTH, feed(g));
  g = f[0];
  g.pop_back(); // Truncated
  EXPECT_EQ(VSCP_BLE_ERR_LENGTH, feed(g));
  g = f[0];
  memset(&g[6], 0, 4); // Message id 0
  EXPECT_EQ(VSCP_BLE_ERR_GUID, feed(g));
  g    = f[0];
  g[4] = 1; // Never interpreted as E1
  EXPECT_EQ(VSCP_BLE_ERR_VERSION, feed(g));
}

TEST(F1Encode, Limits)
{
  EXPECT_EQ(0u, vscp_ble_f1_fragment_count(222));
  EXPECT_EQ(2u, vscp_ble_f1_fragment_count(223));
  EXPECT_EQ(2u, vscp_ble_f1_fragment_count(424));
  EXPECT_EQ(3u, vscp_ble_f1_fragment_count(425));
  EXPECT_EQ(5u, vscp_ble_f1_fragment_count(1024));
  EXPECT_EQ(0u, vscp_ble_f1_fragment_count(1025));
  bytes d             = ramp(1025);
  vscp_ble_event_t ev = make_event(0x0a, 6, d);
  uint8_t buf[256];
  size_t len;
  EXPECT_EQ(VSCP_BLE_ERR_TOO_LARGE, vscp_ble_f1_encode(buf, sizeof(buf), 0xFFFF, 1, &ev, 0, &len));
  ev.size = 300;
  EXPECT_EQ(VSCP_BLE_ERR_PARAM, vscp_ble_f1_encode(buf, sizeof(buf), 0xFFFF, 0, &ev, 0, &len));
  EXPECT_EQ(VSCP_BLE_ERR_PARAM, vscp_ble_f1_encode(buf, sizeof(buf), 0xFFFF, 1, &ev, 2, &len));
}
