// test-counter.cpp - persistent sequence/epoch counter
#include <gtest/gtest.h>

#include "test-util.h"
#include "vscp-ble-counter.h"

struct Store {
  uint32_t epoch          = 0;
  uint64_t reserved_until = 0;
  int writes              = 0;
  bool fail               = false;
};

static int
persist(void *ctx, uint32_t epoch, uint64_t until)
{
  Store *s = (Store *) ctx;
  if (s->fail) {
    return -1;
  }
  s->epoch          = epoch;
  s->reserved_until = until;
  s->writes++;
  return 0;
}

TEST(Counter, ReservesBlocksBeforeUse)
{
  Store st;
  vscp_ble_counter_t c;
  vscp_ble_counter_init(&c, 0, 0, 100, 0, persist, &st);
  uint32_t e, s;
  for (uint32_t i = 0; i < 250; i++) {
    ASSERT_EQ(VSCP_BLE_OK, vscp_ble_counter_next(&c, &e, &s));
    EXPECT_EQ(i, s);
    EXPECT_LT((uint64_t) s, st.reserved_until); // Durable before use
  }
  EXPECT_EQ(3, st.writes);
}

TEST(Counter, RestartNeverReusesValues)
{
  Store st;
  vscp_ble_counter_t c;
  vscp_ble_counter_init(&c, 0, 0, 16, 0, persist, &st);
  uint32_t e, s, last = 0;
  for (int i = 0; i < 5; i++) {
    vscp_ble_counter_next(&c, &e, &last);
  }
  // Power loss: restart from what was persisted
  vscp_ble_counter_init(&c, st.epoch, st.reserved_until, 16, 0, persist, &st);
  ASSERT_EQ(VSCP_BLE_OK, vscp_ble_counter_next(&c, &e, &s));
  EXPECT_GT(s, last);
  EXPECT_EQ(16u, s);
}

TEST(Counter, PersistFailureStops)
{
  Store st;
  st.fail = true;
  vscp_ble_counter_t c;
  vscp_ble_counter_init(&c, 0, 0, 16, 0, persist, &st);
  uint32_t e, s;
  EXPECT_EQ(VSCP_BLE_ERR_PERSIST, vscp_ble_counter_next(&c, &e, &s));
  st.fail = false;
  EXPECT_EQ(VSCP_BLE_OK, vscp_ble_counter_next(&c, &e, &s));
  EXPECT_EQ(0u, s);
}

TEST(Counter, E1ExhaustsWithoutWrap)
{
  Store st;
  vscp_ble_counter_t c;
  vscp_ble_counter_init(&c, 0, 0xFFFFFFFEull, 16, 0, persist, &st);
  uint32_t e, s;
  ASSERT_EQ(VSCP_BLE_OK, vscp_ble_counter_next(&c, &e, &s));
  EXPECT_EQ(0xFFFFFFFEu, s);
  ASSERT_EQ(VSCP_BLE_OK, vscp_ble_counter_next(&c, &e, &s));
  EXPECT_EQ(0xFFFFFFFFu, s); // Final allowed value
  EXPECT_EQ(VSCP_BLE_ERR_EXHAUSTED, vscp_ble_counter_next(&c, &e, &s));
  EXPECT_EQ(VSCP_BLE_ERR_EXHAUSTED, vscp_ble_counter_next(&c, &e, &s));
  // Restart after exhaustion stays exhausted
  vscp_ble_counter_init(&c, st.epoch, st.reserved_until, 16, 0, persist, &st);
  EXPECT_EQ(VSCP_BLE_ERR_EXHAUSTED, vscp_ble_counter_next(&c, &e, &s));
}

TEST(Counter, A2AdvancesEpochDurably)
{
  Store st;
  vscp_ble_counter_t c;
  vscp_ble_counter_init(&c, 3, 0xFFFFFFFFull, 16, 1, persist, &st);
  uint32_t e, s;
  ASSERT_EQ(VSCP_BLE_OK, vscp_ble_counter_next(&c, &e, &s));
  EXPECT_EQ(3u, e);
  EXPECT_EQ(0xFFFFFFFFu, s);
  ASSERT_EQ(VSCP_BLE_OK, vscp_ble_counter_next(&c, &e, &s));
  EXPECT_EQ(4u, e);
  EXPECT_EQ(0u, s);
  EXPECT_EQ(4u, st.epoch); // New epoch persisted before its first use
  // Restart with the exhausted epoch persisted moves to the next epoch
  vscp_ble_counter_init(&c, 9, 0x100000000ull, 16, 1, persist, &st);
  ASSERT_EQ(VSCP_BLE_OK, vscp_ble_counter_next(&c, &e, &s));
  EXPECT_EQ(10u, e);
  EXPECT_EQ(10u, st.epoch);
}

TEST(Counter, EpochExhaustionNeedsRekey)
{
  Store st;
  vscp_ble_counter_t c;
  vscp_ble_counter_init(&c, 0xFFFFFFFFu, 0xFFFFFFFFull, 16, 1, persist, &st);
  uint32_t e, s;
  ASSERT_EQ(VSCP_BLE_OK, vscp_ble_counter_next(&c, &e, &s));
  EXPECT_EQ(VSCP_BLE_ERR_EXHAUSTED, vscp_ble_counter_next(&c, &e, &s));
}
