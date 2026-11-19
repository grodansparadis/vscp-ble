// test-ad.cpp - advertising data set parsing
#include <gtest/gtest.h>

#include "test-util.h"
#include "vectors.h"
#include "vscp-ble-ad.h"
#include "vscp-ble-e1.h"

TEST(Ad, IteratesAndStopsAtZeroLength)
{
  const uint8_t data[] = { 0x02, 0x01, 0x06, 0x03, 0xff, 0x34, 0x12, 0x00, 0xaa };
  size_t off = 0, n = 0;
  const uint8_t *ad;
  EXPECT_EQ(VSCP_BLE_OK, vscp_ble_ad_next(data, sizeof(data), &off, &ad, &n));
  EXPECT_EQ(3u, n);
  EXPECT_EQ(VSCP_BLE_OK, vscp_ble_ad_next(data, sizeof(data), &off, &ad, &n));
  EXPECT_EQ(4u, n);
  EXPECT_EQ(VSCP_BLE_ERR_NOT_FOUND, vscp_ble_ad_next(data, sizeof(data), &off, &ad, &n));
}

TEST(Ad, OverrunIsTruncated)
{
  const uint8_t data[] = { 0x02, 0x01, 0x06, 0x05, 0xff, 0xff, 0xff };
  size_t off = 0, n = 0;
  const uint8_t *ad;
  EXPECT_EQ(VSCP_BLE_OK, vscp_ble_ad_next(data, sizeof(data), &off, &ad, &n));
  EXPECT_EQ(VSCP_BLE_ERR_TRUNCATED, vscp_ble_ad_next(data, sizeof(data), &off, &ad, &n));
}

TEST(Ad, FindsFrameAmongOtherStructures)
{
  bytes set = { 0x02, 0x01, 0x06, 0x05, 0x09, 'V', 'S', 'C', 'P' };
  set.insert(set.end(), v_e1_b_frame, v_e1_b_frame + v_e1_b_frame_len);
  const uint8_t *f = nullptr;
  size_t fl        = 0;
  ASSERT_EQ(VSCP_BLE_OK, vscp_ble_ad_find_frame(set.data(), set.size(), 0xFFFF, 1, &f, &fl));
  EXPECT_EQ(v_e1_b_frame_len, fl);
  EXPECT_EQ(1, vscp_ble_ad_frame_version(set.data(), set.size(), 0xFFFF));
  EXPECT_EQ(VSCP_BLE_ERR_NOT_FOUND, vscp_ble_ad_find_frame(set.data(), set.size(), 0x02E5, 1, &f, &fl));
  EXPECT_EQ(VSCP_BLE_ERR_NOT_FOUND, vscp_ble_ad_find_frame(set.data(), set.size(), 0xFFFF, 2, &f, &fl));
}

TEST(Ad, MultipleCandidatesAreAmbiguous)
{
  bytes set(v_e1_a_frame, v_e1_a_frame + v_e1_a_frame_len);
  set.insert(set.end(), v_e1_b_frame, v_e1_b_frame + v_e1_b_frame_len);
  vscp_ble_event_t ev;
  EXPECT_EQ(VSCP_BLE_ERR_AMBIGUOUS, vscp_ble_e1_decode_dataset(set.data(), set.size(), 0xFFFF, nullptr, &ev));
}

TEST(Ad, TruncatedReportIsRejected)
{
  bytes set(v_e1_b_frame, v_e1_b_frame + v_e1_b_frame_len - 1);
  vscp_ble_event_t ev;
  EXPECT_EQ(VSCP_BLE_ERR_TRUNCATED, vscp_ble_e1_decode_dataset(set.data(), set.size(), 0xFFFF, nullptr, &ev));
}

TEST(Ad, StrerrorCoversAllCodes)
{
  for (int i = -24; i <= 2; i++) {
    EXPECT_NE(nullptr, vscp_ble_strerror(i));
    EXPECT_STRNE("", vscp_ble_strerror(i));
  }
}
