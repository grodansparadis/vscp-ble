/*
 * vscp-ble-f1.c - F1 connectionless fragmentation
 *
 * The MIT License (MIT)
 * Copyright (c) 2000-2026 Ake Hedman, the VSCP Project <info@grodansparadis.com>
 */

#include <string.h>

#include "vscp-ble-f1.h"

#define FLAG_FIRST 0x01u
#define FLAG_LAST  0x02u

unsigned
vscp_ble_f1_fragment_count(size_t total)
{
  if ((total < VSCP_BLE_F1_MIN_DATA) || (total > VSCP_BLE_F1_MAX_DATA)) {
    return 0;
  }
  return (unsigned) ((total + VSCP_BLE_F1_CHUNK - 1) / VSCP_BLE_F1_CHUNK);
}

int
vscp_ble_f1_encode(uint8_t *out,
                   size_t cap,
                   uint16_t company,
                   uint32_t message_id,
                   const vscp_ble_event_t *ev,
                   unsigned index,
                   size_t *outlen)
{
  if ((NULL == out) || (NULL == ev) || (NULL == outlen) || (NULL == ev->data) || (0 == message_id)) {
    return VSCP_BLE_ERR_PARAM;
  }
  unsigned k = vscp_ble_f1_fragment_count(ev->size);
  if (0 == k) {
    return VSCP_BLE_ERR_TOO_LARGE;
  }
  if (index >= k) {
    return VSCP_BLE_ERR_PARAM;
  }
  if (vscp_ble_guid_is_zero(ev->guid)) {
    return VSCP_BLE_ERR_GUID;
  }
  size_t offset = (size_t) index * VSCP_BLE_F1_CHUNK;
  size_t c      = ev->size - offset;
  if (c > VSCP_BLE_F1_CHUNK) {
    c = VSCP_BLE_F1_CHUNK;
  }
  if (cap < VSCP_BLE_F1_HEADER_SIZE + c) {
    return VSCP_BLE_ERR_BUFFER;
  }
  out[0] = (uint8_t) (41u + c);
  out[1] = VSCP_BLE_AD_TYPE_MANUFACTURER;
  out[2] = (uint8_t) company;
  out[3] = (uint8_t) (company >> 8);
  out[4] = VSCP_BLE_VERSION_F1;
  out[5] = (uint8_t) ((0 == index ? FLAG_FIRST : 0) | (k - 1 == index ? FLAG_LAST : 0));
  vscp_ble_put32(out + 6, message_id);
  memcpy(out + 10, ev->guid, 16);
  vscp_ble_put16(out + 26, ev->head);
  vscp_ble_put16(out + 28, ev->vscp_class);
  vscp_ble_put16(out + 30, ev->vscp_type);
  vscp_ble_put16(out + 32, ev->size);
  out[34] = (uint8_t) index;
  out[35] = (uint8_t) k;
  vscp_ble_put16(out + 36, (uint16_t) offset);
  vscp_ble_put16(out + 38, (uint16_t) c);
  out[40] = 0;
  out[41] = 0;
  memcpy(out + 42, ev->data + offset, c);
  *outlen = VSCP_BLE_F1_HEADER_SIZE + c;
  return VSCP_BLE_OK;
}

void
vscp_ble_f1_rx_init(vscp_ble_f1_rx_t *rx, uint16_t company)
{
  memset(rx, 0, sizeof(*rx));
  rx->company = company;
}

static int
expired(uint32_t start, uint32_t now, uint32_t limit)
{
  return (uint32_t) (now - start) >= limit; // Correct across clock wrap
}

unsigned
vscp_ble_f1_rx_expire(vscp_ble_f1_rx_t *rx, uint32_t now_ms)
{
  unsigned dropped = 0;
  for (unsigned i = 0; i < VSCP_BLE_F1_SLOTS; i++) {
    if (rx->slot[i].active && expired(rx->slot[i].start_ms, now_ms, VSCP_BLE_F1_DEADLINE_MS)) {
      rx->slot[i].active = 0;
      dropped++;
    }
  }
  for (unsigned i = 0; i < VSCP_BLE_F1_DONE_CACHE; i++) {
    // Keep completed messages for at least the deadline (duplicate suppression)
    if (rx->done[i].used && expired(rx->done[i].time_ms, now_ms, 2 * VSCP_BLE_F1_DEADLINE_MS)) {
      rx->done[i].used = 0;
    }
  }
  return dropped;
}

int
vscp_ble_f1_rx_feed(vscp_ble_f1_rx_t *rx,
                    const uint8_t *ad,
                    size_t len,
                    uint32_t now_ms,
                    vscp_ble_event_t *ev,
                    uint8_t *out,
                    size_t outcap)
{
  if ((NULL == rx) || (NULL == ad) || (NULL == ev) || (NULL == out)) {
    return VSCP_BLE_ERR_PARAM;
  }
  vscp_ble_f1_rx_expire(rx, now_ms);

  // 1-2. Validate everything before any state is touched
  if ((len < VSCP_BLE_F1_HEADER_SIZE + 1) || ((size_t) ad[0] + 1 != len)) {
    return VSCP_BLE_ERR_LENGTH;
  }
  if (VSCP_BLE_AD_TYPE_MANUFACTURER != ad[1]) {
    return VSCP_BLE_ERR_TYPE;
  }
  if ((ad[2] != (uint8_t) rx->company) || (ad[3] != (uint8_t) (rx->company >> 8))) {
    return VSCP_BLE_ERR_COMPANY;
  }
  if (VSCP_BLE_VERSION_F1 != ad[4]) {
    return VSCP_BLE_ERR_VERSION;
  }
  uint8_t flags       = ad[5];
  uint32_t message_id = vscp_ble_get32(ad + 6);
  const uint8_t *guid = ad + 10;
  uint16_t total      = vscp_ble_get16(ad + 32);
  unsigned index      = ad[34];
  unsigned k          = ad[35];
  size_t offset       = vscp_ble_get16(ad + 36);
  size_t c            = vscp_ble_get16(ad + 38);
  if ((0 != ad[40]) || (0 != ad[41]) || (0 != (flags & 0xFC))) {
    return VSCP_BLE_ERR_FLAGS;
  }
  if ((0 == message_id) || vscp_ble_guid_is_zero(guid)) {
    return VSCP_BLE_ERR_GUID;
  }
  unsigned expect_k = vscp_ble_f1_fragment_count(total);
  if ((0 == expect_k) || (k != expect_k) || (index >= k)) {
    return VSCP_BLE_ERR_LENGTH;
  }
  size_t expect_off = (size_t) index * VSCP_BLE_F1_CHUNK;
  size_t expect_c   = total - expect_off;
  if (expect_c > VSCP_BLE_F1_CHUNK) {
    expect_c = VSCP_BLE_F1_CHUNK;
  }
  if ((offset != expect_off) || (c != expect_c) || (len != VSCP_BLE_F1_HEADER_SIZE + c)) {
    return VSCP_BLE_ERR_SEQUENCE; // Noncanonical fragment
  }
  uint8_t expect_flags = (uint8_t) ((0 == index ? FLAG_FIRST : 0) | (k - 1 == index ? FLAG_LAST : 0));
  if (flags != expect_flags) {
    return VSCP_BLE_ERR_FLAGS;
  }

  // Already completed: suppress repeated delivery
  for (unsigned i = 0; i < VSCP_BLE_F1_DONE_CACHE; i++) {
    if (rx->done[i].used && (rx->done[i].message_id == message_id) && (0 == memcmp(rx->done[i].guid, guid, 16))) {
      return VSCP_BLE_DUPLICATE;
    }
  }

  // 3. Find or start the reassembly (company is fixed per receiver)
  vscp_ble_f1_slot_t *s = NULL;
  for (unsigned i = 0; i < VSCP_BLE_F1_SLOTS; i++) {
    if (rx->slot[i].active && (rx->slot[i].message_id == message_id) && (0 == memcmp(rx->slot[i].guid, guid, 16))) {
      s = &rx->slot[i];
    }
  }
  uint16_t head = vscp_ble_get16(ad + 26);
  uint16_t cls  = vscp_ble_get16(ad + 28);
  uint16_t type = vscp_ble_get16(ad + 30);
  if (NULL == s) {
    for (unsigned i = 0; i < VSCP_BLE_F1_SLOTS; i++) {
      if (!rx->slot[i].active) {
        s = &rx->slot[i];
        break;
      }
    }
    if (NULL == s) {
      return VSCP_BLE_ERR_BUSY; // Never evict an active message
    }
    memset(s, 0, sizeof(*s));
    s->active = 1;
    memcpy(s->guid, guid, 16);
    s->message_id = message_id;
    s->head       = head;
    s->vscp_class = cls;
    s->vscp_type  = type;
    s->total      = total;
    s->count      = (uint8_t) k;
    s->start_ms   = now_ms;
  }

  // 4. All fragments must agree
  if ((s->head != head) || (s->vscp_class != cls) || (s->vscp_type != type) || (s->total != total) || (s->count != k)) {
    s->active = 0;
    return VSCP_BLE_ERR_CONFLICT;
  }
  if (s->received & (1u << index)) {
    if (0 != memcmp(s->data + offset, ad + 42, c)) {
      s->active = 0; // Same index, other bytes: drop the whole message
      return VSCP_BLE_ERR_CONFLICT;
    }
    return VSCP_BLE_PENDING; // Identical duplicate (deadline not extended)
  }

  // 5. Store the slice
  memcpy(s->data + offset, ad + 42, c);
  s->received |= (uint8_t) (1u << index);
  if (s->received != (uint8_t) ((1u << k) - 1)) {
    return VSCP_BLE_PENDING;
  }

  // Complete: deliver once
  if (outcap < total) {
    s->active = 0;
    return VSCP_BLE_ERR_BUFFER;
  }
  memcpy(out, s->data, total);
  memcpy(ev->guid, s->guid, 16);
  ev->head       = s->head;
  ev->vscp_class = s->vscp_class;
  ev->vscp_type  = s->vscp_type;
  ev->size       = total;
  ev->data       = out;
  s->active      = 0;

  vscp_ble_f1_done_t *d = &rx->done[rx->done_next];
  rx->done_next         = (rx->done_next + 1) % VSCP_BLE_F1_DONE_CACHE;
  d->used               = 1;
  memcpy(d->guid, guid, 16);
  d->message_id = message_id;
  d->time_ms    = now_ms;
  return VSCP_BLE_OK;
}
