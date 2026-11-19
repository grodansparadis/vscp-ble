/*
 * fuzz-receive.c - libFuzzer target for every vscp-ble receive path
 *
 *   clang -g -O1 -fsanitize=fuzzer,address,undefined -Isrc \
 *     tests/fuzz/fuzz-receive.c src/vscp-ble-*.c (one crypto backend)
 *
 * The first input octet selects the path; the rest is the untrusted data.
 * Stateful paths (F1, G1) cut the data into a sequence of frames.
 */

#include <stdint.h>
#include <string.h>

#include "vscp-ble-a2.h"
#include "vscp-ble-ad.h"
#include "vscp-ble-e1.h"
#include "vscp-ble-f1.h"
#include "vscp-ble-g1.h"
#include "vscp-ble-l0.h"

static vscp_ble_a2_key_t key_rec;

static vscp_ble_a2_key_t *
lookup(void *ctx, uint16_t company, uint16_t key_id)
{
  (void) ctx;
  return ((company == key_rec.company) && (key_id == key_rec.key_id)) ? &key_rec : NULL;
}

static int
indicate(void *ctx, const uint8_t *d, size_t n)
{
  (void) ctx;
  (void) d;
  return (n > 0) ? 0 : -1;
}

static uint8_t
on_event(void *ctx, const vscp_ble_event_t *ev, uint32_t tid)
{
  (void) ctx;
  (void) tid;
  volatile uint8_t sum = 0;
  for (size_t i = 0; i < ev->size; i++) {
    sum = (uint8_t) (sum + ev->data[i]); // Touch every delivered octet
  }
  return VSCP_BLE_G1_OK;
}

static const vscp_ble_g1_ops_t ops = { indicate, indicate, on_event };

// Next frame of a sequence: one length octet, then that many octets
static int
next_frame(const uint8_t **p, size_t *left, const uint8_t **frame, size_t *len)
{
  if (*left < 1) {
    return 0;
  }
  size_t n = (*p)[0];
  if (n > *left - 1) {
    n = *left - 1;
  }
  *frame = *p + 1;
  *len   = n;
  *p += 1 + n;
  *left -= 1 + n;
  return 1;
}

int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
  if (size < 1) {
    return 0;
  }
  uint8_t sel      = data[0];
  const uint8_t *p = data + 1;
  size_t left      = size - 1;
  vscp_ble_event_t ev;
  uint32_t seq;
  static uint8_t buf[1024];

  switch (sel % 7) {
    case 0: {
      size_t off = 0, n;
      const uint8_t *ad;
      while (VSCP_BLE_OK == vscp_ble_ad_next(p, left, &off, &ad, &n)) {}
      vscp_ble_e1_decode_dataset(p, left, 0xFFFF, &seq, &ev);
      vscp_ble_ad_frame_version(p, left, 0xFFFF);
      break;
    }
    case 1: {
      vscp_ble_l0_event_t l0;
      vscp_ble_l0_decode(p, left, 0xFFFF, &l0);
      vscp_ble_e1_decode(p, left, 0xFFFF, &seq, &ev);
      break;
    }
    case 2: {
      memset(&key_rec, 0, sizeof(key_rec));
      key_rec.company   = 0xFFFF;
      key_rec.key_id    = 1;
      key_rec.max_epoch = 0xFFFFFFFF;
      for (int i = 0; i < 16; i++) {
        key_rec.guid[i] = (uint8_t) i;
        key_rec.key[i]  = (uint8_t) i;
      }
      vscp_ble_a2_receiver_t rx = { 0xFFFF, lookup, NULL, NULL };
      const uint8_t *f;
      size_t n;
      while (next_frame(&p, &left, &f, &n)) {
        vscp_ble_a2_receive_dataset(&rx, f, n, &ev, buf, 200, NULL, NULL, NULL);
      }
      break;
    }
    case 3: {
      static vscp_ble_f1_rx_t rx;
      vscp_ble_f1_rx_init(&rx, 0xFFFF);
      const uint8_t *f;
      size_t n;
      uint32_t t = 0;
      while (next_frame(&p, &left, &f, &n)) {
        t += (n & 0x0F) * 300u; // Let time pass now and then
        vscp_ble_f1_rx_feed(&rx, f, n, t, &ev, buf, sizeof(buf));
      }
      break;
    }
    case 4: {
      static vscp_ble_g1_frag_rx_t rx;
      vscp_ble_g1_frag_rx_init(&rx, VSCP_BLE_G1_MAX_RECORD);
      const uint8_t *f;
      size_t n, reclen;
      uint8_t status;
      while (next_frame(&p, &left, &f, &n)) {
        if (VSCP_BLE_OK == vscp_ble_g1_frag_rx_feed(&rx, f, n, 0, NULL, &reclen, &status)) {
          vscp_ble_g1_record_decode(rx.buf, reclen, 487, NULL, &ev);
        }
      }
      break;
    }
    case 5: {
      vscp_ble_g1_control_t c;
      vscp_ble_g1_limits_t l;
      if ((VSCP_BLE_OK == vscp_ble_g1_control_decode(p, left, &c)) && (6 == c.plen)) {
        vscp_ble_g1_limits_decode(c.payload, &l);
      }
      vscp_ble_g1_record_decode(p, left, 487, NULL, &ev);
      break;
    }
    default: {
      // A whole G1 server session; the selector's upper bits choose MTU/rights
      static vscp_ble_g1_server_t s;
      static const uint8_t guid[16] = { 1 };
      vscp_ble_g1_server_init(&s, &ops, NULL, guid, 487);
      vscp_ble_g1_server_connected(&s, (uint16_t) (23 + (sel >> 3) * 16));
      vscp_ble_g1_server_set_security(&s, 1, (uint8_t) ((sel >> 6) & 3));
      vscp_ble_g1_server_set_control_indicate(&s, 1);
      vscp_ble_g1_server_set_event_notify(&s, 1);
      const uint8_t *f;
      size_t n;
      uint32_t t = 0;
      while (next_frame(&p, &left, &f, &n)) {
        t += 700;
        if (n && (f[0] & 1)) {
          vscp_ble_g1_server_write_control(&s, f + 1, n - 1, t);
        }
        else if (n) {
          vscp_ble_g1_server_write_event_rx(&s, f + 1, n - 1, t);
        }
        vscp_ble_g1_server_tick(&s, t);
        uint8_t out[16];
        vscp_ble_g1_server_read_capabilities(&s, out);
      }
      vscp_ble_event_t e = { { 1 }, 0, 10, 6, (uint16_t) (left & 0xFF), buf };
      vscp_ble_g1_server_send_event(&s, &e);
      vscp_ble_g1_server_disconnected(&s);
      break;
    }
  }
  return 0;
}
