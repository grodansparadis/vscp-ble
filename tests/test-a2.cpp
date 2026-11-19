// test-a2.cpp - A2 version 2 authenticated encryption (spec 7)
#include <gtest/gtest.h>

#include <map>

#include "test-util.h"
#include "vectors.h"
#include "vscp-ble-a2.h"

namespace {

struct KeyStore {
  std::map<uint16_t, vscp_ble_a2_key_t> keys;
  int persists      = 0;
  bool fail_persist = false;
};

vscp_ble_a2_key_t *
lookup(void *ctx, uint16_t company, uint16_t key_id)
{
  KeyStore *ks = (KeyStore *) ctx;
  auto it      = ks->keys.find(key_id);
  return ((it == ks->keys.end()) || (it->second.company != company)) ? nullptr : &it->second;
}

int
persist(void *ctx, const vscp_ble_a2_key_t *)
{
  KeyStore *ks = (KeyStore *) ctx;
  if (ks->fail_persist) {
    return -1;
  }
  ks->persists++;
  return 0;
}

vscp_ble_a2_key_t
record(uint16_t key_id)
{
  vscp_ble_a2_key_t r = {};
  r.company           = 0xFFFF;
  r.key_id            = key_id;
  memcpy(r.guid, TEST_GUID, 16);
  memcpy(r.key, TEST_KEY, 16);
  memcpy(r.nonce_prefix, TEST_PREFIX, 5);
  r.min_epoch = 0;
  r.max_epoch = 0xFFFFFFFF;
  return r;
}

class A2 : public ::testing::Test {
protected:
  KeyStore ks;
  vscp_ble_a2_receiver_t rx;
  uint8_t plain[200];
  vscp_ble_event_t ev;

  void SetUp() override
  {
    ks.keys[1]      = record(1);
    ks.keys[0x0102] = record(0x0102);
    rx              = { 0xFFFF, lookup, persist, &ks };
  }

  int receive(const bytes &f)
  {
    return vscp_ble_a2_receive(&rx, f.data(), f.size(), &ev, plain, sizeof(plain), nullptr, nullptr, nullptr);
  }

  bytes encode(uint16_t kid, uint32_t epoch, uint32_t seq, const bytes &data = { 1, 2, 3 })
  {
    vscp_ble_event_t e = make_event(0x0a, 6, data);
    uint8_t buf[256];
    size_t len = 0;
    EXPECT_EQ(VSCP_BLE_OK,
              vscp_ble_a2_encode(buf, sizeof(buf), 0xFFFF, kid, epoch, seq, TEST_KEY, TEST_PREFIX, &e, &len));
    return B(buf, len);
  }
};

} // namespace

TEST_F(A2, KnownAnswerVectors)
{
  bytes d3 = { 0x11, 0x22, 0x33 };
  EXPECT_EQ(B(v_a2_n3_frame, v_a2_n3_frame_len), encode(1, 1, 2, d3));
  // N = 0 (class 0x14 type 3)
  vscp_ble_event_t e = make_event(0x14, 3, {});
  uint8_t buf[256];
  size_t len;
  ASSERT_EQ(VSCP_BLE_OK, vscp_ble_a2_encode(buf, sizeof(buf), 0xFFFF, 1, 0, 0, TEST_KEY, TEST_PREFIX, &e, &len));
  EXPECT_EQ(B(v_a2_n0_frame, v_a2_n0_frame_len), B(buf, len));
  EXPECT_EQ(56u, len);
  // N = 200
  bytes d = ramp(200);
  e       = make_event(0x0a, 6, d, 0x00e0);
  ASSERT_EQ(VSCP_BLE_OK,
            vscp_ble_a2_encode(buf, sizeof(buf), 0xFFFF, 0x0102, 7, 0xFFFFFFFF, TEST_KEY, TEST_PREFIX, &e, &len));
  EXPECT_EQ(B(v_a2_max_frame, v_a2_max_frame_len), B(buf, len));
  EXPECT_EQ(256u, len);
}

TEST_F(A2, ReceiveVectors)
{
  uint32_t epoch = 0, seq = 0;
  vscp_ble_a2_key_t *rec = nullptr;
  ASSERT_EQ(VSCP_BLE_OK,
            vscp_ble_a2_receive(&rx, v_a2_n3_frame, v_a2_n3_frame_len, &ev, plain, sizeof(plain), &epoch, &seq, &rec));
  EXPECT_EQ(1u, epoch);
  EXPECT_EQ(2u, seq);
  EXPECT_EQ(&ks.keys[1], rec);
  ASSERT_EQ(3, ev.size);
  EXPECT_EQ(0x33, ev.data[2]);
  EXPECT_EQ(1, ks.persists);
  ASSERT_EQ(VSCP_BLE_OK, receive(B(v_a2_max_frame, v_a2_max_frame_len)));
  EXPECT_EQ(200, ev.size);
  EXPECT_EQ(0x00e0, ev.head);
}

TEST_F(A2, EveryModifiedOctetIsRejected)
{
  bytes good = B(v_a2_n3_frame, v_a2_n3_frame_len);
  for (size_t i = 0; i < good.size(); i++) {
    bytes f = good;
    f[i] ^= 0x01;
    ks.keys[1].have_replay = 0;
    EXPECT_NE(VSCP_BLE_OK, receive(f)) << "octet " << i;
  }
  EXPECT_EQ(0, ks.persists); // Nothing accepted, replay state untouched
  EXPECT_EQ(0, ks.keys[1].have_replay);
}

TEST_F(A2, FramingErrors)
{
  bytes f = encode(1, 0, 1);
  bytes g = f;
  g[5]    = 0x03;
  EXPECT_EQ(VSCP_BLE_ERR_FLAGS, receive(g));
  g    = f;
  g[5] = 0x00;
  EXPECT_EQ(VSCP_BLE_ERR_FLAGS, receive(g));
  g    = f;
  g[4] = 0x01;
  EXPECT_EQ(VSCP_BLE_ERR_VERSION, receive(g));
  g = f;
  g.pop_back();
  EXPECT_EQ(VSCP_BLE_ERR_LENGTH, receive(g));
  g     = f;
  g[39] = 4;
  EXPECT_EQ(VSCP_BLE_ERR_LENGTH, receive(g));
  g = f;
  memset(&g[16], 0, 16);
  EXPECT_EQ(VSCP_BLE_ERR_GUID, receive(g));
  vscp_ble_event_t e = make_event(0x0a, 6, ramp(201));
  uint8_t buf[300];
  size_t len;
  EXPECT_EQ(VSCP_BLE_ERR_TOO_LARGE,
            vscp_ble_a2_encode(buf, sizeof(buf), 0xFFFF, 1, 0, 0, TEST_KEY, TEST_PREFIX, &e, &len));
}

TEST_F(A2, KeyRecordChecks)
{
  EXPECT_EQ(VSCP_BLE_ERR_KEY, receive(encode(7, 0, 1))); // Unknown Key ID
  ks.keys[1].revoked = 1;
  EXPECT_EQ(VSCP_BLE_ERR_KEY, receive(encode(1, 0, 1)));
  ks.keys[1].revoked = 0;
  ks.keys[1].guid[15] ^= 1; // Key provisioned for another GUID
  EXPECT_EQ(VSCP_BLE_ERR_KEY, receive(encode(1, 0, 1)));
  ks.keys[1].guid[15] ^= 1;
  ks.keys[1].min_epoch = 2;
  ks.keys[1].max_epoch = 3;
  EXPECT_EQ(VSCP_BLE_ERR_REPLAY, receive(encode(1, 1, 1)));
  EXPECT_EQ(VSCP_BLE_ERR_REPLAY, receive(encode(1, 4, 1)));
  EXPECT_EQ(VSCP_BLE_OK, receive(encode(1, 2, 1)));
  ks.keys[1].key[0] ^= 1; // Wrong key
  EXPECT_EQ(VSCP_BLE_ERR_AUTH, receive(encode(1, 2, 2)));
  ks.keys[1].key[0] ^= 1;
  ks.keys[1].nonce_prefix[0] ^= 1; // Wrong nonce prefix
  EXPECT_EQ(VSCP_BLE_ERR_AUTH, receive(encode(1, 2, 3)));
}

TEST_F(A2, ReplayAndOrdering)
{
  EXPECT_EQ(VSCP_BLE_OK, receive(encode(1, 5, 10)));
  EXPECT_EQ(VSCP_BLE_ERR_REPLAY, receive(encode(1, 5, 10)));         // Duplicate
  EXPECT_EQ(VSCP_BLE_ERR_REPLAY, receive(encode(1, 5, 9)));          // Out of order
  EXPECT_EQ(VSCP_BLE_OK, receive(encode(1, 5, 20)));                 // Gaps are allowed
  EXPECT_EQ(VSCP_BLE_OK, receive(encode(1, 6, 0)));                  // Higher epoch
  EXPECT_EQ(VSCP_BLE_ERR_REPLAY, receive(encode(1, 5, 0xFFFFFFFF))); // Lower epoch after advancing
  EXPECT_EQ(6u, ks.keys[1].last_epoch);
  EXPECT_EQ(0u, ks.keys[1].last_sequence);
  // Replay state is per key record
  EXPECT_EQ(VSCP_BLE_OK, receive(encode(0x0102, 0, 0)));
}

TEST_F(A2, PersistFailureFailsClosed)
{
  EXPECT_EQ(VSCP_BLE_OK, receive(encode(1, 0, 1)));
  ks.fail_persist = true;
  EXPECT_EQ(VSCP_BLE_ERR_PERSIST, receive(encode(1, 0, 2)));
  EXPECT_EQ(1u, ks.keys[1].last_sequence); // Unchanged
  for (int i = 0; i < 3; i++) {
    EXPECT_EQ(0, plain[i]); // Plaintext cleared
  }
  ks.fail_persist = false;
  EXPECT_EQ(VSCP_BLE_OK, receive(encode(1, 0, 2)));
}

TEST_F(A2, RestartWithPersistedReplayState)
{
  EXPECT_EQ(VSCP_BLE_OK, receive(encode(1, 0, 100)));
  vscp_ble_a2_key_t saved  = ks.keys[1]; // What persist() stored
  ks.keys[1]               = record(1);  // Receiver restarts ...
  ks.keys[1].have_replay   = saved.have_replay;
  ks.keys[1].last_epoch    = saved.last_epoch;
  ks.keys[1].last_sequence = saved.last_sequence;
  EXPECT_EQ(VSCP_BLE_ERR_REPLAY, receive(encode(1, 0, 100)));
}

TEST_F(A2, DatasetAndAmbiguity)
{
  bytes set = { 0x02, 0x01, 0x06 };
  bytes f   = encode(1, 0, 1);
  set.insert(set.end(), f.begin(), f.end());
  EXPECT_EQ(
    VSCP_BLE_OK,
    vscp_ble_a2_receive_dataset(&rx, set.data(), set.size(), &ev, plain, sizeof(plain), nullptr, nullptr, nullptr));
  bytes f2 = encode(1, 0, 2);
  set.insert(set.end(), f2.begin(), f2.end());
  EXPECT_EQ(
    VSCP_BLE_ERR_AMBIGUOUS,
    vscp_ble_a2_receive_dataset(&rx, set.data(), set.size(), &ev, plain, sizeof(plain), nullptr, nullptr, nullptr));
}
