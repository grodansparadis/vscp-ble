// test-g1.cpp - G1 connected GATT profile (spec 6)
#include <gtest/gtest.h>

#include "test-util.h"
#include "vectors.h"
#include "vscp-ble-g1.h"

static bytes
record(uint32_t tid, const bytes &data, uint16_t head = 0)
{
  vscp_ble_event_t ev = make_event(0x0a, 6, data, head);
  uint8_t buf[VSCP_BLE_G1_MAX_RECORD];
  size_t len = 0;
  EXPECT_EQ(VSCP_BLE_OK, vscp_ble_g1_record_encode(buf, sizeof(buf), tid, &ev, &len));
  return B(buf, len);
}

static std::vector<bytes>
fragment(const bytes &rec, uint16_t mtu)
{
  vscp_ble_g1_frag_tx_t tx;
  EXPECT_EQ(VSCP_BLE_OK, vscp_ble_g1_frag_tx_begin(&tx, rec.data(), rec.size(), mtu));
  std::vector<bytes> out;
  uint8_t buf[600];
  size_t len;
  while (VSCP_BLE_OK == vscp_ble_g1_frag_tx_next(&tx, buf, sizeof(buf), &len)) {
    EXPECT_LE(len, (size_t) mtu - 3);
    out.push_back(B(buf, len));
  }
  return out;
}

TEST(G1Record, Vectors)
{
  EXPECT_EQ(B(v_g1_n3_record, v_g1_n3_record_len), record(1, { 0x11, 0x22, 0x33 }));
  EXPECT_EQ(B(v_g1_max_record, v_g1_max_record_len), record(0xA5A5A5A5, ramp(487), 3));
  EXPECT_EQ(521u, v_g1_max_record_len);
  vscp_ble_event_t ev;
  uint32_t tid;
  ASSERT_EQ(VSCP_BLE_OK, vscp_ble_g1_record_decode(v_g1_max_record, v_g1_max_record_len, 487, &tid, &ev));
  EXPECT_EQ(0xA5A5A5A5u, tid);
  EXPECT_EQ(487, ev.size);
  EXPECT_EQ(3, ev.head);
  EXPECT_EQ(VSCP_BLE_ERR_TOO_LARGE, vscp_ble_g1_record_decode(v_g1_max_record, v_g1_max_record_len, 486, &tid, &ev));
}

TEST(G1Record, Rejects)
{
  bytes r = record(1, { 1, 2 });
  vscp_ble_event_t ev;
  auto dec = [&](const bytes &b) { return vscp_ble_g1_record_decode(b.data(), b.size(), 487, nullptr, &ev); };
  bytes g  = r;
  g[0]     = 2;
  EXPECT_EQ(VSCP_BLE_ERR_VERSION, dec(g));
  g    = r;
  g[1] = 2;
  EXPECT_EQ(VSCP_BLE_ERR_TYPE, dec(g));
  g    = r;
  g[2] = 1;
  EXPECT_EQ(VSCP_BLE_ERR_FLAGS, dec(g));
  g = r;
  g[9]++; // L
  EXPECT_EQ(VSCP_BLE_ERR_LENGTH, dec(g));
  g     = r;
  g[33] = 3; // N
  EXPECT_EQ(VSCP_BLE_ERR_LENGTH, dec(g));
  g = r;
  memset(&g[10], 0, 16);
  EXPECT_EQ(VSCP_BLE_ERR_GUID, dec(g));
  g = r;
  memset(&g[4], 0, 4);
  EXPECT_NE(VSCP_BLE_OK, dec(g));
  vscp_ble_event_t big = make_event(0, 0, ramp(488));
  uint8_t buf[600];
  size_t len;
  EXPECT_EQ(VSCP_BLE_ERR_TOO_LARGE, vscp_ble_g1_record_encode(buf, sizeof(buf), 1, &big, &len));
}

TEST(G1Fragment, Vectors)
{
  bytes r = record(1, { 0x11, 0x22, 0x33 });
  auto f  = fragment(r, 23);
  ASSERT_EQ((size_t) V_G1_N3_MTU23_COUNT, f.size());
  EXPECT_EQ(B(v_g1_n3_mtu23_frag0, v_g1_n3_mtu23_frag0_len), f[0]);
  EXPECT_EQ(B(v_g1_n3_mtu23_frag2, v_g1_n3_mtu23_frag2_len), f[2]);
  EXPECT_EQ(20u, f[0].size()); // ATT_MTU - 3, 12 payload octets
  auto one = fragment(r, 247);
  ASSERT_EQ(1u, one.size());
  EXPECT_EQ(0x03, one[0][1]); // FIRST|LAST
  EXPECT_EQ(B(v_g1_n3_mtu247_frag0, v_g1_n3_mtu247_frag0_len), one[0]);
  bytes m = B(v_g1_max_record, v_g1_max_record_len);
  EXPECT_EQ((size_t) V_G1_MAX_MTU23_COUNT, fragment(m, 23).size());
  EXPECT_EQ((size_t) V_G1_MAX_MTU185_COUNT, fragment(m, 185).size());
  auto big = fragment(m, 517);
  ASSERT_EQ((size_t) V_G1_MAX_MTU517_COUNT, big.size());
  EXPECT_EQ(B(v_g1_max_mtu517_frag1, v_g1_max_mtu517_frag1_len), big[1]);
}

class G1Rx : public ::testing::Test {
protected:
  vscp_ble_g1_frag_rx_t rx;
  size_t reclen = 0;
  uint8_t status;
  uint32_t tid;
  void SetUp() override { vscp_ble_g1_frag_rx_init(&rx, VSCP_BLE_G1_MAX_RECORD); }
  int feed(const bytes &f, uint32_t t = 0)
  {
    return vscp_ble_g1_frag_rx_feed(&rx, f.data(), f.size(), t, &tid, &reclen, &status);
  }
};

TEST_F(G1Rx, ReassemblesAtEveryMtu)
{
  bytes r = B(v_g1_max_record, v_g1_max_record_len);
  for (uint16_t mtu : { 23, 24, 50, 185, 247, 517, 527 }) {
    auto f = fragment(r, mtu);
    for (size_t i = 0; i + 1 < f.size(); i++) {
      ASSERT_EQ(VSCP_BLE_PENDING, feed(f[i])) << mtu;
    }
    ASSERT_EQ(VSCP_BLE_OK, feed(f.back())) << mtu;
    EXPECT_EQ(r, B(rx.buf, reclen));
  }
}

TEST_F(G1Rx, OrderingErrors)
{
  auto f = fragment(record(1, ramp(40)), 23);
  ASSERT_GE(f.size(), 4u);
  // Gap
  EXPECT_EQ(VSCP_BLE_PENDING, feed(f[0]));
  EXPECT_EQ(VSCP_BLE_ERR_SEQUENCE, feed(f[2]));
  EXPECT_EQ(VSCP_BLE_G1_BAD_SEQUENCE, status);
  // A fresh FIRST is required afterwards
  EXPECT_EQ(VSCP_BLE_ERR_SEQUENCE, feed(f[1]));
  // Duplicate / overlap
  EXPECT_EQ(VSCP_BLE_PENDING, feed(f[0]));
  EXPECT_EQ(VSCP_BLE_PENDING, feed(f[1]));
  EXPECT_EQ(VSCP_BLE_ERR_SEQUENCE, feed(f[1]));
  // Missing LAST: a final fragment without the LAST flag
  EXPECT_EQ(VSCP_BLE_PENDING, feed(f[0]));
  for (size_t i = 1; i + 1 < f.size(); i++) {
    feed(f[i]);
  }
  bytes last = f.back();
  last[1]    = 0;
  EXPECT_EQ(VSCP_BLE_ERR_LENGTH, feed(last));
  // LAST too early
  EXPECT_EQ(VSCP_BLE_PENDING, feed(f[0]));
  bytes early = f[1];
  early[1]    = 0x02;
  EXPECT_EQ(VSCP_BLE_ERR_LENGTH, feed(early));
}

TEST_F(G1Rx, OneTransactionAtATime)
{
  auto a = fragment(record(1, ramp(40)), 23), b = fragment(record(2, ramp(40)), 23);
  EXPECT_EQ(VSCP_BLE_PENDING, feed(a[0]));
  EXPECT_EQ(VSCP_BLE_ERR_BUSY, feed(b[0]));
  EXPECT_EQ(VSCP_BLE_G1_BUSY, status);
  EXPECT_EQ(2u, tid);
  EXPECT_EQ(VSCP_BLE_ERR_BUSY, feed(b[1]));
  for (size_t i = 1; i + 1 < a.size(); i++) {
    EXPECT_EQ(VSCP_BLE_PENDING, feed(a[i])); // The first one goes on
  }
  EXPECT_EQ(VSCP_BLE_OK, feed(a.back()));
}

TEST_F(G1Rx, HeaderChecks)
{
  bytes r = record(1, ramp(10));
  auto f  = fragment(r, 23);
  bytes g = f[0];
  g[15]   = 9; // Record transaction ID differs from the fragment's
  EXPECT_EQ(VSCP_BLE_ERR_SEQUENCE, feed(g));
  g    = f[0];
  g[1] = 0x05;
  EXPECT_EQ(VSCP_BLE_ERR_FLAGS, feed(g));
  g    = f[0];
  g[0] = 2;
  EXPECT_EQ(VSCP_BLE_ERR_VERSION, feed(g));
  EXPECT_EQ(VSCP_BLE_G1_UNSUPPORTED_VERSION, status);
  g    = f[0];
  g[7] = 1; // FIRST at offset 1
  EXPECT_EQ(VSCP_BLE_ERR_SEQUENCE, feed(g));
  g.assign(f[0].begin(), f[0].begin() + 8); // Empty payload
  g[1] = 0x01;
  EXPECT_EQ(VSCP_BLE_ERR_LENGTH, feed(g));
  // Record larger than the negotiated maximum
  vscp_ble_g1_frag_rx_init(&rx, 40);
  EXPECT_EQ(VSCP_BLE_ERR_TOO_LARGE, feed(f[0]));
  EXPECT_EQ(VSCP_BLE_G1_TOO_LARGE, status);
}

TEST_F(G1Rx, Timeout)
{
  auto f = fragment(record(1, ramp(40)), 23);
  EXPECT_EQ(VSCP_BLE_PENDING, feed(f[0], 1000));
  EXPECT_EQ(0, vscp_ble_g1_frag_rx_expired(&rx, 5999));
  EXPECT_EQ(1, vscp_ble_g1_frag_rx_expired(&rx, 6000));
  EXPECT_EQ(VSCP_BLE_ERR_SEQUENCE, feed(f[1], 6001));
}

TEST(G1Control, Codec)
{
  vscp_ble_g1_control_t c;
  ASSERT_EQ(VSCP_BLE_OK, vscp_ble_g1_control_decode(v_g1_hello, v_g1_hello_len, &c));
  EXPECT_EQ(VSCP_BLE_G1_OP_HELLO, c.opcode);
  vscp_ble_g1_limits_t l;
  ASSERT_EQ(6, c.plen);
  ASSERT_EQ(VSCP_BLE_OK, vscp_ble_g1_limits_decode(c.payload, &l));
  EXPECT_EQ(487, l.max_event_data);
  EXPECT_EQ(521, l.max_record_size);
  uint8_t buf[20];
  size_t len;
  ASSERT_EQ(VSCP_BLE_OK, vscp_ble_g1_control_encode(buf, sizeof(buf), &c, &len));
  EXPECT_EQ(B(v_g1_hello, v_g1_hello_len), B(buf, len));
  bytes bad = B(v_g1_hello, v_g1_hello_len);
  bad.push_back(0);
  EXPECT_EQ(VSCP_BLE_ERR_LENGTH, vscp_ble_g1_control_decode(bad.data(), bad.size(), &c));
  bad    = B(v_g1_hello, v_g1_hello_len);
  bad[1] = 0x03;
  EXPECT_EQ(VSCP_BLE_ERR_TYPE, vscp_ble_g1_control_decode(bad.data(), bad.size(), &c));
  bad    = B(v_g1_hello, v_g1_hello_len);
  bad[6] = 0x0C;
  EXPECT_EQ(VSCP_BLE_ERR_PARAM, vscp_ble_g1_control_decode(bad.data(), bad.size(), &c));
}

// ---------------------------------------------------------------------------
//                             Server session
// ---------------------------------------------------------------------------

namespace {

struct Peer {
  std::vector<bytes> indications, notifications;
  std::vector<bytes> events;
  uint8_t verdict  = VSCP_BLE_G1_OK;
  bool fail_notify = false;
};

int
indicate(void *ctx, const uint8_t *d, size_t n)
{
  ((Peer *) ctx)->indications.push_back(B(d, n));
  return 0;
}

int
notify(void *ctx, const uint8_t *d, size_t n)
{
  Peer *p = (Peer *) ctx;
  if (p->fail_notify) {
    return -1;
  }
  p->notifications.push_back(B(d, n));
  return 0;
}

uint8_t
on_event(void *ctx, const vscp_ble_event_t *ev, uint32_t)
{
  Peer *p = (Peer *) ctx;
  p->events.push_back(B(ev->data, ev->size));
  return p->verdict;
}

const vscp_ble_g1_ops_t ops = { indicate, notify, on_event };

class G1Server : public ::testing::Test {
protected:
  Peer peer;
  vscp_ble_g1_server_t *s = new vscp_ble_g1_server_t;

  void SetUp() override { vscp_ble_g1_server_init(s, &ops, &peer, TEST_GUID, 487); }
  void TearDown() override { delete s; }

  void ready(uint16_t mtu = 23)
  {
    vscp_ble_g1_server_connected(s, mtu);
    vscp_ble_g1_server_set_security(s, VSCP_BLE_G1_PAIRING_AUTHENTICATED, VSCP_BLE_G1_AUTH_EVENT);
    vscp_ble_g1_server_set_control_indicate(s, 1);
  }

  uint8_t hello(uint16_t data, uint16_t rec, uint16_t features = 0)
  {
    uint8_t p[6];
    vscp_ble_g1_limits_t l = { data, rec, features };
    vscp_ble_g1_limits_encode(p, &l);
    vscp_ble_g1_control_t c = { VSCP_BLE_G1_OP_HELLO, 0, 0, 6, p };
    uint8_t buf[14];
    size_t len;
    vscp_ble_g1_control_encode(buf, sizeof(buf), &c, &len);
    return vscp_ble_g1_server_write_control(s, buf, len, 0);
  }

  vscp_ble_g1_control_t last_control()
  {
    vscp_ble_g1_control_t c = {};
    EXPECT_FALSE(peer.indications.empty());
    if (!peer.indications.empty()) {
      EXPECT_EQ(VSCP_BLE_OK,
                vscp_ble_g1_control_decode(peer.indications.back().data(), peer.indications.back().size(), &c));
    }
    return c;
  }

  void write_record(const bytes &rec, uint16_t mtu = 23, uint32_t t = 0)
  {
    for (auto &f : fragment(rec, mtu)) {
      ASSERT_EQ(0, vscp_ble_g1_server_write_event_rx(s, f.data(), f.size(), t));
    }
  }
};

} // namespace

TEST_F(G1Server, Reads)
{
  uint8_t buf[16];
  ASSERT_EQ(12u, vscp_ble_g1_server_read_capabilities(s, buf));
  const uint8_t cap[12] = { 0x01, 0x00, 0x01, 0xe7, 0x02, 0x09, 0x00, 0x00, 0, 0, 0, 0 };
  EXPECT_EQ(0, memcmp(cap, buf, 12));
  ready(247);
  vscp_ble_g1_server_read_capabilities(s, buf);
  EXPECT_EQ(236, (buf[6] << 8) | buf[7]);
  ASSERT_EQ(16u, vscp_ble_g1_server_read_guid(s, buf));
  EXPECT_EQ(0, memcmp(TEST_GUID, buf, 16));
  ASSERT_EQ(4u, vscp_ble_g1_server_read_security(s, buf));
  const uint8_t sec[4] = { 1, 1, 1, 0 };
  EXPECT_EQ(0, memcmp(sec, buf, 4));
  ASSERT_EQ(2u, vscp_ble_g1_server_read_configuration(s, buf));
  uint8_t tlv[4] = { 1, 1, 0x10, 0 };
  EXPECT_EQ(VSCP_BLE_ATT_ERR_INSUFFICIENT_AUTHZ, vscp_ble_g1_server_write_configuration(s, tlv, 4));
  vscp_ble_g1_server_set_security(s, 1, VSCP_BLE_G1_AUTH_ADMIN);
  EXPECT_EQ(VSCP_BLE_ATT_ERR_REQUEST_NOT_SUPP, vscp_ble_g1_server_write_configuration(s, tlv, 4));
}

TEST_F(G1Server, SecurityIsEnforced)
{
  vscp_ble_g1_server_connected(s, 23);
  vscp_ble_g1_server_set_control_indicate(s, 1);
  EXPECT_EQ(VSCP_BLE_ATT_ERR_INSUFFICIENT_AUTHN, hello(487, 521));
  vscp_ble_g1_server_set_security(s, VSCP_BLE_G1_PAIRING_AUTHENTICATED, VSCP_BLE_G1_AUTH_NONE);
  EXPECT_EQ(VSCP_BLE_ATT_ERR_INSUFFICIENT_AUTHZ, hello(487, 521));
  // Unauthenticated link cannot hold any authorization
  vscp_ble_g1_server_set_security(s, VSCP_BLE_G1_PAIRING_NONE, VSCP_BLE_G1_AUTH_ADMIN);
  EXPECT_EQ(VSCP_BLE_G1_AUTH_NONE, s->authorization);
  EXPECT_TRUE(peer.indications.empty());
}

TEST_F(G1Server, NeedsControlIndications)
{
  vscp_ble_g1_server_connected(s, 23);
  vscp_ble_g1_server_set_security(s, 1, 1);
  EXPECT_EQ(VSCP_BLE_ATT_ERR_CCCD_IMPROPER, hello(487, 521));
}

TEST_F(G1Server, HelloNegotiatesMinima)
{
  ready();
  EXPECT_EQ(0, hello(100, 521));
  auto c = last_control();
  EXPECT_EQ(VSCP_BLE_G1_OP_HELLO_RESULT, c.opcode);
  EXPECT_EQ(VSCP_BLE_G1_OK, c.status);
  vscp_ble_g1_limits_t l;
  ASSERT_EQ(VSCP_BLE_OK, vscp_ble_g1_limits_decode(c.payload, &l));
  EXPECT_EQ(100, l.max_event_data);
  EXPECT_EQ(134, l.max_record_size);
  EXPECT_EQ(0, hello(487, 60)); // Record size limits the data
  ASSERT_EQ(VSCP_BLE_OK, vscp_ble_g1_limits_decode(last_control().payload, &l));
  EXPECT_EQ(26, l.max_event_data);
  EXPECT_EQ(0, hello(487, 521, 1));
  EXPECT_EQ(VSCP_BLE_G1_BAD_FLAGS, last_control().status);
  EXPECT_EQ(0, hello(488, 521));
  EXPECT_EQ(VSCP_BLE_G1_BAD_LENGTH, last_control().status);
  EXPECT_FALSE(s->hello_done);
}

TEST_F(G1Server, EventRxFlow)
{
  ready();
  bytes rec = record(77, ramp(50));
  auto f    = fragment(rec, 23);
  EXPECT_EQ(0, vscp_ble_g1_server_write_event_rx(s, f[0].data(), f[0].size(), 0));
  EXPECT_EQ(VSCP_BLE_G1_NOT_READY, last_control().status); // Before HELLO
  EXPECT_EQ(77u, last_control().tid);

  ASSERT_EQ(0, hello(487, 521));
  write_record(rec);
  ASSERT_EQ(1u, peer.events.size());
  EXPECT_EQ(ramp(50), peer.events[0]);
  auto c = last_control();
  EXPECT_EQ(VSCP_BLE_G1_OP_EVENT_RESULT, c.opcode);
  EXPECT_EQ(77u, c.tid);
  EXPECT_EQ(VSCP_BLE_G1_OK, c.status);

  peer.verdict = VSCP_BLE_G1_NOT_AUTHORIZED;
  write_record(record(78, ramp(5)));
  EXPECT_EQ(VSCP_BLE_G1_NOT_AUTHORIZED, last_control().status);
}

TEST_F(G1Server, EventRxLimitsAndErrors)
{
  ready();
  ASSERT_EQ(0, hello(20, 521));
  write_record(record(5, ramp(21)));
  EXPECT_EQ(VSCP_BLE_G1_TOO_LARGE, last_control().status);
  EXPECT_TRUE(peer.events.empty());
  auto f = fragment(record(6, ramp(10)), 23);
  vscp_ble_g1_server_write_event_rx(s, f[0].data(), f[0].size(), 0);
  vscp_ble_g1_server_write_event_rx(s, f[2].data(), f[2].size(), 0);
  EXPECT_EQ(VSCP_BLE_G1_BAD_SEQUENCE, last_control().status);
  EXPECT_EQ(6u, last_control().tid);
  // Larger than the ATT MTU allows
  bytes big(30, 0);
  EXPECT_EQ(VSCP_BLE_ATT_ERR_VALUE_NOT_ALLOWED, vscp_ble_g1_server_write_event_rx(s, big.data(), big.size(), 0));
}

TEST_F(G1Server, TimeoutResetAndDisconnect)
{
  ready();
  ASSERT_EQ(0, hello(487, 521));
  auto f = fragment(record(9, ramp(30)), 23);
  vscp_ble_g1_server_write_event_rx(s, f[0].data(), f[0].size(), 100);
  vscp_ble_g1_server_tick(s, 5099);
  size_t n = peer.indications.size();
  vscp_ble_g1_server_tick(s, 5100);
  ASSERT_EQ(n + 1, peer.indications.size());
  EXPECT_EQ(VSCP_BLE_G1_TIMEOUT, last_control().status);
  EXPECT_EQ(9u, last_control().tid);

  // RESET cancels the inbound record
  vscp_ble_g1_server_write_event_rx(s, f[0].data(), f[0].size(), 6000);
  const uint8_t reset[8] = { 1, VSCP_BLE_G1_OP_RESET, 0, 0, 0, 0, 0, 0 };
  EXPECT_EQ(0, vscp_ble_g1_server_write_control(s, reset, 8, 6000));
  EXPECT_FALSE(s->rx.active);

  // Disconnect discards everything; reconnect starts a new scope
  vscp_ble_g1_server_write_event_rx(s, f[0].data(), f[0].size(), 6000);
  vscp_ble_g1_server_disconnected(s);
  EXPECT_FALSE(s->rx.active);
  EXPECT_FALSE(s->hello_done);
  ready();
  vscp_ble_g1_server_write_event_rx(s, f[1].data(), f[1].size(), 7000);
  EXPECT_EQ(VSCP_BLE_G1_NOT_READY, last_control().status);
  EXPECT_TRUE(peer.events.empty());
}

TEST_F(G1Server, ClientMayNotSendServerOpcodes)
{
  ready();
  const uint8_t c[8] = { 1, VSCP_BLE_G1_OP_EVENT_RESULT, 0, 0, 0, 1, 0, 0 };
  EXPECT_EQ(VSCP_BLE_ATT_ERR_VALUE_NOT_ALLOWED, vscp_ble_g1_server_write_control(s, c, 8, 0));
  const uint8_t v2[8] = { 2, VSCP_BLE_G1_OP_HELLO, 0, 0, 0, 0, 0, 0 };
  EXPECT_EQ(0, vscp_ble_g1_server_write_control(s, v2, 8, 0));
  EXPECT_EQ(VSCP_BLE_G1_UNSUPPORTED_VERSION, last_control().status);
}

TEST_F(G1Server, SendEvent)
{
  bytes d             = ramp(100);
  vscp_ble_event_t ev = make_event(0x0a, 6, d);
  EXPECT_EQ(VSCP_BLE_ERR_STATE, vscp_ble_g1_server_send_event(s, &ev));
  ready(23);
  ASSERT_EQ(0, hello(487, 521));
  EXPECT_EQ(VSCP_BLE_ERR_STATE, vscp_ble_g1_server_send_event(s, &ev)); // Not subscribed
  vscp_ble_g1_server_set_event_notify(s, 1);
  ASSERT_EQ(VSCP_BLE_OK, vscp_ble_g1_server_send_event(s, &ev));
  EXPECT_EQ(VSCP_BLE_G1_OP_TX_RESULT, last_control().opcode);
  EXPECT_EQ(VSCP_BLE_G1_OK, last_control().status);
  // The client side reassembles the notifications into the same event
  vscp_ble_g1_frag_rx_t rx;
  vscp_ble_g1_frag_rx_init(&rx, 521);
  size_t reclen = 0;
  int rv        = VSCP_BLE_PENDING;
  for (auto &f : peer.notifications) {
    EXPECT_LE(f.size(), 20u);
    rv = vscp_ble_g1_frag_rx_feed(&rx, f.data(), f.size(), 0, nullptr, &reclen, nullptr);
  }
  ASSERT_EQ(VSCP_BLE_OK, rv);
  vscp_ble_event_t out;
  ASSERT_EQ(VSCP_BLE_OK, vscp_ble_g1_record_decode(rx.buf, reclen, 487, nullptr, &out));
  EXPECT_EQ(d, B(out.data, out.size));

  peer.fail_notify = true;
  EXPECT_EQ(VSCP_BLE_ERR_STATE, vscp_ble_g1_server_send_event(s, &ev));
  EXPECT_EQ(VSCP_BLE_G1_INTERNAL_ERROR, last_control().status);
  // Losing authorization stops event traffic
  peer.fail_notify = false;
  vscp_ble_g1_server_set_security(s, 1, VSCP_BLE_G1_AUTH_NONE);
  EXPECT_EQ(VSCP_BLE_ERR_STATE, vscp_ble_g1_server_send_event(s, &ev));
  ev = make_event(0x0a, 6, ramp(488));
  EXPECT_EQ(VSCP_BLE_ERR_STATE, vscp_ble_g1_server_send_event(s, &ev));
}

TEST_F(G1Server, SendEventCapsFragmentSizeAtLargeMtu)
{
  ready(517);
  ASSERT_EQ(0, hello(487, 521));
  vscp_ble_g1_server_set_event_notify(s, 1);
  bytes d             = ramp(487);
  vscp_ble_event_t ev = make_event(0x0a, 6, d, 0x0102);
  ASSERT_EQ(VSCP_BLE_OK, vscp_ble_g1_server_send_event(s, &ev));
  ASSERT_EQ(3u, peer.notifications.size()); // 521 octets in 236-octet payloads
  vscp_ble_g1_frag_rx_t rx;
  vscp_ble_g1_frag_rx_init(&rx, 521);
  size_t reclen = 0;
  int rv        = VSCP_BLE_PENDING;
  for (auto &f : peer.notifications) {
    EXPECT_LE(f.size(), (size_t) VSCP_BLE_G1_TX_MAX_MTU - 3);
    rv = vscp_ble_g1_frag_rx_feed(&rx, f.data(), f.size(), 0, nullptr, &reclen, nullptr);
  }
  ASSERT_EQ(VSCP_BLE_OK, rv);
  // Byte identical to the record vscp_ble_g1_record_encode() makes
  uint32_t tid = (uint32_t) ((peer.notifications[0][2] << 24) | (peer.notifications[0][3] << 16) |
                             (peer.notifications[0][4] << 8) | peer.notifications[0][5]);
  EXPECT_EQ(record(tid, d, 0x0102), B(rx.buf, reclen));
}
