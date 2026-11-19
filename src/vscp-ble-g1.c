/*
 * vscp-ble-g1.c - G1 connected GATT profile (records, fragments, control,
 *                 transport independent server)
 *
 * Note: the draft gives the record's VSCP event length as L = 22 + N while
 * the record is 34 + N octets. This implementation uses L = 22 + N as in
 * the record table, i.e. total record length = L + 12.
 *
 * The MIT License (MIT)
 * Copyright (c) 2000-2026 Ake Hedman, the VSCP Project <info@grodansparadis.com>
 */

#include <string.h>

#include "vscp-ble-g1.h"

#define FLAG_FIRST 0x01u
#define FLAG_LAST  0x02u

#define RECORD_KIND_EVENT 0x01u
#define L_TO_TOTAL        12u // Total record length = L + 12 (see note above)
#define L_BASE            22u

// ---------------------------------------------------------------------------
//                                 Records
// ---------------------------------------------------------------------------

int
vscp_ble_g1_record_encode(uint8_t *out, size_t cap, uint32_t tid, const vscp_ble_event_t *ev, size_t *outlen)
{
  if ((NULL == out) || (NULL == ev) || (NULL == outlen) || (ev->size && (NULL == ev->data)) || (0 == tid)) {
    return VSCP_BLE_ERR_PARAM;
  }
  if (ev->size > VSCP_BLE_G1_MAX_DATA) {
    return VSCP_BLE_ERR_TOO_LARGE;
  }
  if (vscp_ble_guid_is_zero(ev->guid)) {
    return VSCP_BLE_ERR_GUID;
  }
  size_t n = ev->size;
  if (cap < VSCP_BLE_G1_RECORD_HEADER + n) {
    return VSCP_BLE_ERR_BUFFER;
  }
  out[0] = VSCP_BLE_G1_VERSION;
  out[1] = RECORD_KIND_EVENT;
  out[2] = 0x00;
  out[3] = 0x00;
  vscp_ble_put32(out + 4, tid);
  vscp_ble_put16(out + 8, (uint16_t) (L_BASE + n));
  memcpy(out + 10, ev->guid, 16);
  vscp_ble_put16(out + 26, ev->head);
  vscp_ble_put16(out + 28, ev->vscp_class);
  vscp_ble_put16(out + 30, ev->vscp_type);
  vscp_ble_put16(out + 32, (uint16_t) n);
  if (n) {
    memcpy(out + 34, ev->data, n);
  }
  *outlen = VSCP_BLE_G1_RECORD_HEADER + n;
  return VSCP_BLE_OK;
}

// Checks the first 10 record octets; total record length in *total
static int
record_prefix(const uint8_t *rec, size_t max_record, size_t *total)
{
  if (VSCP_BLE_G1_VERSION != rec[0]) {
    return VSCP_BLE_ERR_VERSION;
  }
  if (RECORD_KIND_EVENT != rec[1]) {
    return VSCP_BLE_ERR_TYPE;
  }
  if ((0 != rec[2]) || (0 != rec[3])) {
    return VSCP_BLE_ERR_FLAGS;
  }
  if (0 == vscp_ble_get32(rec + 4)) {
    return VSCP_BLE_ERR_PARAM;
  }
  size_t l = vscp_ble_get16(rec + 8);
  if ((l < L_BASE) || (l - L_BASE > VSCP_BLE_G1_MAX_DATA)) {
    return VSCP_BLE_ERR_LENGTH;
  }
  *total = l + L_TO_TOTAL;
  if (*total > max_record) {
    return VSCP_BLE_ERR_TOO_LARGE;
  }
  return VSCP_BLE_OK;
}

int
vscp_ble_g1_record_decode(const uint8_t *rec, size_t len, uint16_t max_data, uint32_t *tid, vscp_ble_event_t *ev)
{
  if ((NULL == rec) || (NULL == ev)) {
    return VSCP_BLE_ERR_PARAM;
  }
  if (len < VSCP_BLE_G1_RECORD_HEADER) {
    return VSCP_BLE_ERR_LENGTH;
  }
  size_t total = 0;
  int rv       = record_prefix(rec, VSCP_BLE_G1_MAX_RECORD, &total);
  if (VSCP_BLE_OK != rv) {
    return rv;
  }
  size_t n = vscp_ble_get16(rec + 32);
  if ((total != len) || (VSCP_BLE_G1_RECORD_HEADER + n != len)) {
    return VSCP_BLE_ERR_LENGTH;
  }
  if (n > max_data) {
    return VSCP_BLE_ERR_TOO_LARGE;
  }
  if (vscp_ble_guid_is_zero(rec + 10)) {
    return VSCP_BLE_ERR_GUID;
  }
  if (NULL != tid) {
    *tid = vscp_ble_get32(rec + 4);
  }
  memcpy(ev->guid, rec + 10, 16);
  ev->head       = vscp_ble_get16(rec + 26);
  ev->vscp_class = vscp_ble_get16(rec + 28);
  ev->vscp_type  = vscp_ble_get16(rec + 30);
  ev->size       = (uint16_t) n;
  ev->data       = rec + 34;
  return VSCP_BLE_OK;
}

// ---------------------------------------------------------------------------
//                               Fragments
// ---------------------------------------------------------------------------

int
vscp_ble_g1_frag_tx_begin(vscp_ble_g1_frag_tx_t *tx, const uint8_t *record, size_t len, uint16_t att_mtu)
{
  if ((NULL == tx) || (NULL == record) || (len < VSCP_BLE_G1_RECORD_HEADER) || (len > VSCP_BLE_G1_MAX_RECORD)) {
    return VSCP_BLE_ERR_PARAM;
  }
  if (att_mtu < VSCP_BLE_G1_MIN_ATT_MTU) {
    return VSCP_BLE_ERR_PARAM;
  }
  tx->record  = record;
  tx->len     = len;
  tx->pos     = 0;
  tx->tid     = vscp_ble_get32(record + 4);
  tx->payload = (size_t) att_mtu - 3 - VSCP_BLE_G1_FRAG_HEADER;
  return (0 == tx->tid) ? VSCP_BLE_ERR_PARAM : VSCP_BLE_OK;
}

int
vscp_ble_g1_frag_tx_next(vscp_ble_g1_frag_tx_t *tx, uint8_t *out, size_t cap, size_t *outlen)
{
  if ((NULL == tx) || (NULL == out) || (NULL == outlen)) {
    return VSCP_BLE_ERR_PARAM;
  }
  if (tx->pos >= tx->len) {
    return VSCP_BLE_ERR_NOT_FOUND;
  }
  size_t c = tx->len - tx->pos;
  if (c > tx->payload) {
    c = tx->payload;
  }
  if (cap < VSCP_BLE_G1_FRAG_HEADER + c) {
    return VSCP_BLE_ERR_BUFFER;
  }
  out[0] = 0x01;
  out[1] = (uint8_t) ((0 == tx->pos ? FLAG_FIRST : 0) | (tx->pos + c == tx->len ? FLAG_LAST : 0));
  vscp_ble_put32(out + 2, tx->tid);
  vscp_ble_put16(out + 6, (uint16_t) tx->pos);
  memcpy(out + 8, tx->record + tx->pos, c);
  tx->pos += c;
  *outlen = VSCP_BLE_G1_FRAG_HEADER + c;
  return VSCP_BLE_OK;
}

void
vscp_ble_g1_frag_rx_init(vscp_ble_g1_frag_rx_t *rx, size_t max_record)
{
  memset(rx, 0, sizeof(*rx));
  rx->max_record = (max_record > VSCP_BLE_G1_MAX_RECORD) ? VSCP_BLE_G1_MAX_RECORD : max_record;
}

void
vscp_ble_g1_frag_rx_reset(vscp_ble_g1_frag_rx_t *rx)
{
  rx->active = 0;
  rx->tid    = 0;
  rx->total  = 0;
  rx->pos    = 0;
}

int
vscp_ble_g1_frag_rx_expired(vscp_ble_g1_frag_rx_t *rx, uint32_t now_ms)
{
  if (rx->active && ((uint32_t) (now_ms - rx->last_ms) >= VSCP_BLE_G1_REASSEMBLY_MS)) {
    vscp_ble_g1_frag_rx_reset(rx);
    return 1;
  }
  return 0;
}

static int
frag_fail(vscp_ble_g1_frag_rx_t *rx, uint8_t *status, uint8_t code, int rv)
{
  vscp_ble_g1_frag_rx_reset(rx);
  if (NULL != status) {
    *status = code;
  }
  return rv;
}

int
vscp_ble_g1_frag_rx_feed(vscp_ble_g1_frag_rx_t *rx,
                         const uint8_t *frag,
                         size_t len,
                         uint32_t now_ms,
                         uint32_t *tid_out,
                         size_t *reclen,
                         uint8_t *status)
{
  if (NULL != tid_out) {
    *tid_out = 0;
  }
  if (NULL != status) {
    *status = VSCP_BLE_G1_OK;
  }
  if ((NULL == rx) || (NULL == frag) || (NULL == reclen)) {
    return VSCP_BLE_ERR_PARAM;
  }
  if (len < VSCP_BLE_G1_FRAG_HEADER + 1) {
    // Zero-length payloads are invalid
    return frag_fail(rx, status, VSCP_BLE_G1_BAD_LENGTH, VSCP_BLE_ERR_LENGTH);
  }
  uint32_t tid = vscp_ble_get32(frag + 2);
  if (NULL != tid_out) {
    *tid_out = tid;
  }
  if (0x01 != frag[0]) {
    return frag_fail(rx, status, VSCP_BLE_G1_UNSUPPORTED_VERSION, VSCP_BLE_ERR_VERSION);
  }
  uint8_t flags = frag[1];
  if (flags & 0xFC) {
    return frag_fail(rx, status, VSCP_BLE_G1_BAD_FLAGS, VSCP_BLE_ERR_FLAGS);
  }
  if (0 == tid) {
    return frag_fail(rx, status, VSCP_BLE_G1_BAD_SEQUENCE, VSCP_BLE_ERR_SEQUENCE);
  }
  size_t offset        = vscp_ble_get16(frag + 6);
  const uint8_t *chunk = frag + VSCP_BLE_G1_FRAG_HEADER;
  size_t c             = len - VSCP_BLE_G1_FRAG_HEADER;

  if (flags & FLAG_FIRST) {
    if (rx->active) {
      if (NULL != status) {
        *status = VSCP_BLE_G1_BUSY;
      }
      return VSCP_BLE_ERR_BUSY; // One transaction per direction; keep the current one
    }
    if ((0 != offset) || (c < 10)) {
      return frag_fail(rx, status, VSCP_BLE_G1_BAD_SEQUENCE, VSCP_BLE_ERR_SEQUENCE);
    }
    size_t total = 0;
    int rv       = record_prefix(chunk, rx->max_record, &total);
    if (VSCP_BLE_OK != rv) {
      uint8_t code = (VSCP_BLE_ERR_VERSION == rv)     ? VSCP_BLE_G1_UNSUPPORTED_VERSION
                     : (VSCP_BLE_ERR_FLAGS == rv)     ? VSCP_BLE_G1_BAD_FLAGS
                     : (VSCP_BLE_ERR_TOO_LARGE == rv) ? VSCP_BLE_G1_TOO_LARGE
                     : (VSCP_BLE_ERR_TYPE == rv)      ? VSCP_BLE_G1_INVALID_EVENT
                                                      : VSCP_BLE_G1_BAD_LENGTH;
      return frag_fail(rx, status, code, rv);
    }
    if (vscp_ble_get32(chunk + 4) != tid) {
      return frag_fail(rx, status, VSCP_BLE_G1_BAD_SEQUENCE, VSCP_BLE_ERR_SEQUENCE);
    }
    rx->active = 1;
    rx->tid    = tid;
    rx->total  = total;
    rx->pos    = 0;
  }
  else {
    if (!rx->active) {
      return frag_fail(rx, status, VSCP_BLE_G1_BAD_SEQUENCE, VSCP_BLE_ERR_SEQUENCE);
    }
    if (tid != rx->tid) {
      // A fragment of another transaction while one is in progress
      if (NULL != status) {
        *status = VSCP_BLE_G1_BUSY;
      }
      return VSCP_BLE_ERR_BUSY;
    }
    if (offset != rx->pos) {
      return frag_fail(rx, status, VSCP_BLE_G1_BAD_SEQUENCE, VSCP_BLE_ERR_SEQUENCE); // Gap/overlap/duplicate
    }
  }

  size_t end = rx->pos + c;
  if (end > rx->total) {
    return frag_fail(rx, status, VSCP_BLE_G1_BAD_LENGTH, VSCP_BLE_ERR_LENGTH);
  }
  int last = (0 != (flags & FLAG_LAST));
  if (last != (end == rx->total)) {
    // LAST must end exactly at the record length (and only LAST may)
    return frag_fail(rx, status, VSCP_BLE_G1_BAD_LENGTH, VSCP_BLE_ERR_LENGTH);
  }
  memcpy(rx->buf + rx->pos, chunk, c);
  rx->pos     = end;
  rx->last_ms = now_ms;
  if (!last) {
    return VSCP_BLE_PENDING;
  }
  *reclen    = rx->total;
  rx->active = 0; // Complete; buffer stays valid until the next FIRST
  return VSCP_BLE_OK;
}

// ---------------------------------------------------------------------------
//                                Control
// ---------------------------------------------------------------------------

static int
known_opcode(uint8_t op)
{
  return (VSCP_BLE_G1_OP_HELLO == op) || (VSCP_BLE_G1_OP_RESET == op) || (VSCP_BLE_G1_OP_HELLO_RESULT == op) ||
         (VSCP_BLE_G1_OP_EVENT_RESULT == op) || (VSCP_BLE_G1_OP_TX_RESULT == op);
}

int
vscp_ble_g1_control_encode(uint8_t *out, size_t cap, const vscp_ble_g1_control_t *c, size_t *outlen)
{
  if ((NULL == out) || (NULL == c) || (NULL == outlen) || (c->plen && (NULL == c->payload))) {
    return VSCP_BLE_ERR_PARAM;
  }
  if (!known_opcode(c->opcode) || (c->status > VSCP_BLE_G1_INTERNAL_ERROR)) {
    return VSCP_BLE_ERR_PARAM;
  }
  if (cap < 8u + c->plen) {
    return VSCP_BLE_ERR_BUFFER;
  }
  out[0] = 0x01;
  out[1] = c->opcode;
  vscp_ble_put32(out + 2, c->tid);
  out[6] = c->status;
  out[7] = c->plen;
  if (c->plen) {
    memcpy(out + 8, c->payload, c->plen);
  }
  *outlen = 8u + c->plen;
  return VSCP_BLE_OK;
}

int
vscp_ble_g1_control_decode(const uint8_t *in, size_t len, vscp_ble_g1_control_t *c)
{
  if ((NULL == in) || (NULL == c)) {
    return VSCP_BLE_ERR_PARAM;
  }
  if ((len < 8) || (len != 8u + in[7])) {
    return VSCP_BLE_ERR_LENGTH;
  }
  if (0x01 != in[0]) {
    return VSCP_BLE_ERR_VERSION;
  }
  if (!known_opcode(in[1])) {
    return VSCP_BLE_ERR_TYPE;
  }
  if (in[6] > VSCP_BLE_G1_INTERNAL_ERROR) {
    return VSCP_BLE_ERR_PARAM; // Reserved status value
  }
  c->opcode  = in[1];
  c->tid     = vscp_ble_get32(in + 2);
  c->status  = in[6];
  c->plen    = in[7];
  c->payload = in + 8;
  return VSCP_BLE_OK;
}

void
vscp_ble_g1_limits_encode(uint8_t out[6], const vscp_ble_g1_limits_t *l)
{
  vscp_ble_put16(out, l->max_event_data);
  vscp_ble_put16(out + 2, l->max_record_size);
  vscp_ble_put16(out + 4, l->features);
}

int
vscp_ble_g1_limits_decode(const uint8_t in[6], vscp_ble_g1_limits_t *l)
{
  l->max_event_data  = vscp_ble_get16(in);
  l->max_record_size = vscp_ble_get16(in + 2);
  l->features        = vscp_ble_get16(in + 4);
  if ((l->max_event_data > VSCP_BLE_G1_MAX_DATA) || (l->max_record_size < VSCP_BLE_G1_RECORD_HEADER) ||
      (l->max_record_size > VSCP_BLE_G1_MAX_RECORD)) {
    return VSCP_BLE_ERR_LENGTH;
  }
  if (0 != l->features) {
    return VSCP_BLE_ERR_FLAGS; // All bits zero in version 1
  }
  return VSCP_BLE_OK;
}

// ---------------------------------------------------------------------------
//                                 Server
// ---------------------------------------------------------------------------

void
vscp_ble_g1_server_init(vscp_ble_g1_server_t *s,
                        const vscp_ble_g1_ops_t *ops,
                        void *ctx,
                        const uint8_t guid[16],
                        uint16_t max_event_data)
{
  memset(s, 0, sizeof(*s));
  s->ops = ops;
  s->ctx = ctx;
  memcpy(s->guid, guid, 16);
  if (max_event_data > VSCP_BLE_G1_MAX_DATA) {
    max_event_data = VSCP_BLE_G1_MAX_DATA;
  }
  s->local.max_event_data  = max_event_data;
  s->local.max_record_size = (uint16_t) (VSCP_BLE_G1_RECORD_HEADER + max_event_data);
  s->local.features        = 0;
  vscp_ble_g1_frag_rx_init(&s->rx, s->local.max_record_size);
}

static void
reset_connection(vscp_ble_g1_server_t *s)
{
  s->att_mtu          = VSCP_BLE_G1_MIN_ATT_MTU;
  s->pairing          = VSCP_BLE_G1_PAIRING_NONE;
  s->authorization    = VSCP_BLE_G1_AUTH_NONE;
  s->control_indicate = 0;
  s->event_notify     = 0;
  s->hello_done       = 0;
  memset(&s->negotiated, 0, sizeof(s->negotiated));
  s->next_tid   = 1;
  s->failed_tid = 0;
  vscp_ble_g1_frag_rx_init(&s->rx, s->local.max_record_size);
}

void
vscp_ble_g1_server_connected(vscp_ble_g1_server_t *s, uint16_t att_mtu)
{
  reset_connection(s);
  s->connected = 1;
  vscp_ble_g1_server_set_mtu(s, att_mtu);
}

void
vscp_ble_g1_server_disconnected(vscp_ble_g1_server_t *s)
{
  reset_connection(s); // Incomplete records and negotiation are discarded
  s->connected = 0;
}

void
vscp_ble_g1_server_set_mtu(vscp_ble_g1_server_t *s, uint16_t att_mtu)
{
  s->att_mtu = (att_mtu < VSCP_BLE_G1_MIN_ATT_MTU) ? VSCP_BLE_G1_MIN_ATT_MTU : att_mtu;
}

void
vscp_ble_g1_server_set_security(vscp_ble_g1_server_t *s, uint8_t pairing, uint8_t authorization)
{
  s->pairing = pairing ? VSCP_BLE_G1_PAIRING_AUTHENTICATED : VSCP_BLE_G1_PAIRING_NONE;
  // Authorization never exceeds what an authenticated link allows
  s->authorization = s->pairing ? ((authorization > VSCP_BLE_G1_AUTH_ADMIN) ? VSCP_BLE_G1_AUTH_NONE : authorization)
                                : VSCP_BLE_G1_AUTH_NONE;
  if (s->authorization < VSCP_BLE_G1_AUTH_EVENT) {
    s->event_notify = 0;
    vscp_ble_g1_frag_rx_reset(&s->rx);
  }
}

void
vscp_ble_g1_server_set_control_indicate(vscp_ble_g1_server_t *s, int enabled)
{
  s->control_indicate = enabled ? 1 : 0;
}

void
vscp_ble_g1_server_set_event_notify(vscp_ble_g1_server_t *s, int enabled)
{
  s->event_notify = enabled ? 1 : 0;
}

size_t
vscp_ble_g1_server_read_capabilities(const vscp_ble_g1_server_t *s, uint8_t out[12])
{
  const vscp_ble_g1_limits_t *l = s->hello_done ? &s->negotiated : &s->local;
  out[0]                        = VSCP_BLE_G1_VERSION;
  out[1]                        = 0x00;
  vscp_ble_put16(out + 2, l->max_event_data);
  vscp_ble_put16(out + 4, l->max_record_size);
  vscp_ble_put16(out + 6, s->connected ? (uint16_t) (s->att_mtu - 3 - VSCP_BLE_G1_FRAG_HEADER) : 0);
  vscp_ble_put16(out + 8, 0x0000);
  vscp_ble_put16(out + 10, 0x0000);
  return VSCP_BLE_G1_CAPABILITIES_LEN;
}

size_t
vscp_ble_g1_server_read_guid(const vscp_ble_g1_server_t *s, uint8_t out[16])
{
  memcpy(out, s->guid, 16);
  return 16;
}

size_t
vscp_ble_g1_server_read_security(const vscp_ble_g1_server_t *s, uint8_t out[4])
{
  out[0] = 0x01;
  out[1] = s->pairing;
  out[2] = s->authorization;
  out[3] = 0x00;
  return VSCP_BLE_G1_SECURITY_LEN;
}

size_t
vscp_ble_g1_server_read_configuration(const vscp_ble_g1_server_t *s, uint8_t out[2])
{
  (void) s;
  out[0] = 0x01; // TLV envelope version
  out[1] = 0x00; // No TLVs defined in version 1
  return 2;
}

static int
send_control(vscp_ble_g1_server_t *s, uint8_t opcode, uint32_t tid, uint8_t status, const uint8_t *p, uint8_t plen)
{
  if (!s->control_indicate || (NULL == s->ops) || (NULL == s->ops->indicate)) {
    return VSCP_BLE_ERR_STATE;
  }
  uint8_t buf[8 + 6];
  vscp_ble_g1_control_t c = { opcode, tid, status, plen, p };
  size_t len              = 0;
  int rv                  = vscp_ble_g1_control_encode(buf, sizeof(buf), &c, &len);
  if (VSCP_BLE_OK != rv) {
    return rv;
  }
  if (len > (size_t) s->att_mtu - 3) {
    return VSCP_BLE_ERR_BUFFER;
  }
  return (0 == s->ops->indicate(s->ctx, buf, len)) ? VSCP_BLE_OK : VSCP_BLE_ERR_STATE;
}

static uint8_t
check_link(const vscp_ble_g1_server_t *s, uint8_t min_auth)
{
  if (!s->connected) {
    return VSCP_BLE_ATT_ERR_WRITE_NOT_PERM;
  }
  if (VSCP_BLE_G1_PAIRING_AUTHENTICATED != s->pairing) {
    return VSCP_BLE_ATT_ERR_INSUFFICIENT_AUTHN; // Never downgrade silently
  }
  if (s->authorization < min_auth) {
    return VSCP_BLE_ATT_ERR_INSUFFICIENT_AUTHZ;
  }
  return 0;
}

uint8_t
vscp_ble_g1_server_write_control(vscp_ble_g1_server_t *s, const uint8_t *data, size_t len, uint32_t now_ms)
{
  (void) now_ms;
  uint8_t att = check_link(s, VSCP_BLE_G1_AUTH_EVENT);
  if (att) {
    return att;
  }
  if (!s->control_indicate) {
    return VSCP_BLE_ATT_ERR_CCCD_IMPROPER; // Results could not be delivered
  }
  vscp_ble_g1_control_t c;
  int rv = vscp_ble_g1_control_decode(data, len, &c);
  if (VSCP_BLE_ERR_VERSION == rv) {
    // Answer in our version so the client learns what is supported
    send_control(s, VSCP_BLE_G1_OP_HELLO_RESULT, 0, VSCP_BLE_G1_UNSUPPORTED_VERSION, NULL, 0);
    return 0;
  }
  if (VSCP_BLE_OK != rv) {
    return VSCP_BLE_ATT_ERR_VALUE_NOT_ALLOWED;
  }

  switch (c.opcode) {
    case VSCP_BLE_G1_OP_HELLO: {
      vscp_ble_g1_limits_t req;
      uint8_t status = VSCP_BLE_G1_OK;
      if ((6 != c.plen) || (VSCP_BLE_G1_OK != c.status)) {
        status = VSCP_BLE_G1_BAD_LENGTH;
      }
      else {
        rv = vscp_ble_g1_limits_decode(c.payload, &req);
        if (VSCP_BLE_ERR_FLAGS == rv) {
          status = VSCP_BLE_G1_BAD_FLAGS;
        }
        else if (VSCP_BLE_OK != rv) {
          status = VSCP_BLE_G1_BAD_LENGTH;
        }
      }
      if (VSCP_BLE_G1_OK != status) {
        s->hello_done = 0;
        send_control(s, VSCP_BLE_G1_OP_HELLO_RESULT, c.tid, status, NULL, 0);
        return 0;
      }
      vscp_ble_g1_limits_t n;
      n.max_event_data = (req.max_event_data < s->local.max_event_data) ? req.max_event_data : s->local.max_event_data;
      n.max_record_size =
        (req.max_record_size < s->local.max_record_size) ? req.max_record_size : s->local.max_record_size;
      if (n.max_event_data > n.max_record_size - VSCP_BLE_G1_RECORD_HEADER) {
        n.max_event_data = (uint16_t) (n.max_record_size - VSCP_BLE_G1_RECORD_HEADER);
      }
      n.max_record_size = (uint16_t) (VSCP_BLE_G1_RECORD_HEADER + n.max_event_data);
      n.features        = 0;
      s->negotiated     = n;
      s->hello_done     = 1;
      vscp_ble_g1_frag_rx_init(&s->rx, n.max_record_size); // New negotiation: new scope
      uint8_t p[6];
      vscp_ble_g1_limits_encode(p, &n);
      send_control(s, VSCP_BLE_G1_OP_HELLO_RESULT, c.tid, VSCP_BLE_G1_OK, p, 6);
      return 0;
    }

    case VSCP_BLE_G1_OP_RESET:
      if (0 != c.plen) {
        return VSCP_BLE_ATT_ERR_VALUE_NOT_ALLOWED;
      }
      vscp_ble_g1_frag_rx_reset(&s->rx);
      return 0;

    default:
      return VSCP_BLE_ATT_ERR_VALUE_NOT_ALLOWED; // Server-to-client opcodes
  }
}

uint8_t
vscp_ble_g1_server_write_event_rx(vscp_ble_g1_server_t *s, const uint8_t *data, size_t len, uint32_t now_ms)
{
  uint8_t att = check_link(s, VSCP_BLE_G1_AUTH_EVENT);
  if (att) {
    return att;
  }
  if (!s->control_indicate) {
    return VSCP_BLE_ATT_ERR_CCCD_IMPROPER;
  }
  if ((NULL == data) || (len < VSCP_BLE_G1_FRAG_HEADER) || (len > (size_t) s->att_mtu - 3)) {
    return VSCP_BLE_ATT_ERR_VALUE_NOT_ALLOWED;
  }
  if (!s->hello_done) {
    send_control(s, VSCP_BLE_G1_OP_EVENT_RESULT, vscp_ble_get32(data + 2), VSCP_BLE_G1_NOT_READY, NULL, 0);
    return 0;
  }

  vscp_ble_g1_frag_rx_expired(&s->rx, now_ms);
  if (!(data[1] & FLAG_FIRST) && !s->rx.active && s->failed_tid && (vscp_ble_get32(data + 2) == s->failed_tid)) {
    return 0; // Rest of a transaction that already got its error result
  }
  uint32_t tid   = 0;
  size_t reclen  = 0;
  uint8_t status = VSCP_BLE_G1_OK;
  int rv         = vscp_ble_g1_frag_rx_feed(&s->rx, data, len, now_ms, &tid, &reclen, &status);
  if (VSCP_BLE_PENDING == rv) {
    return 0;
  }
  if (VSCP_BLE_OK != rv) {
    if (VSCP_BLE_ERR_BUSY != rv) {
      s->failed_tid = tid;
    }
    send_control(s, VSCP_BLE_G1_OP_EVENT_RESULT, tid, status, NULL, 0);
    return 0;
  }
  s->failed_tid = 0;

  vscp_ble_event_t ev;
  rv = vscp_ble_g1_record_decode(s->rx.buf, reclen, s->negotiated.max_event_data, &tid, &ev);
  if (VSCP_BLE_OK != rv) {
    status = (VSCP_BLE_ERR_TOO_LARGE == rv) ? VSCP_BLE_G1_TOO_LARGE
             : (VSCP_BLE_ERR_GUID == rv)    ? VSCP_BLE_G1_INVALID_EVENT
                                            : VSCP_BLE_G1_BAD_LENGTH;
  }
  else if ((NULL == s->ops) || (NULL == s->ops->on_event)) {
    status = VSCP_BLE_G1_INTERNAL_ERROR;
  }
  else {
    status = s->ops->on_event(s->ctx, &ev, tid);
    if (status > VSCP_BLE_G1_INTERNAL_ERROR) {
      status = VSCP_BLE_G1_INTERNAL_ERROR;
    }
  }
  memset(s->rx.buf, 0, reclen);
  send_control(s, VSCP_BLE_G1_OP_EVENT_RESULT, tid, status, NULL, 0);
  return 0;
}

uint8_t
vscp_ble_g1_server_write_configuration(vscp_ble_g1_server_t *s, const uint8_t *data, size_t len)
{
  (void) data;
  (void) len;
  uint8_t att = check_link(s, VSCP_BLE_G1_AUTH_ADMIN);
  if (att) {
    return att;
  }
  // Version 1 defines no writable TLV types
  return VSCP_BLE_ATT_ERR_REQUEST_NOT_SUPP;
}

int
vscp_ble_g1_server_send_event(vscp_ble_g1_server_t *s, const vscp_ble_event_t *ev)
{
  if ((NULL == s) || (NULL == ev)) {
    return VSCP_BLE_ERR_PARAM;
  }
  if (!s->connected || !s->hello_done || !s->event_notify || (VSCP_BLE_G1_PAIRING_AUTHENTICATED != s->pairing) ||
      (s->authorization < VSCP_BLE_G1_AUTH_EVENT) || (NULL == s->ops) || (NULL == s->ops->notify)) {
    return VSCP_BLE_ERR_STATE;
  }
  if (ev->size > s->negotiated.max_event_data) {
    return VSCP_BLE_ERR_TOO_LARGE;
  }
  uint32_t tid = s->next_tid++;
  if (0 == s->next_tid) {
    s->next_tid = 1;
  }
  if (vscp_ble_guid_is_zero(ev->guid) || (ev->size && (NULL == ev->data))) {
    return VSCP_BLE_ERR_PARAM;
  }

  // Fragments are built straight from the event: the record is the 34-octet
  // header followed by the event data (no record-sized buffer)
  uint8_t hdr[VSCP_BLE_G1_RECORD_HEADER];
  vscp_ble_event_t empty = *ev;
  empty.size             = 0;
  size_t hlen            = 0;
  int rv                 = vscp_ble_g1_record_encode(hdr, sizeof(hdr), tid, &empty, &hlen);
  if (VSCP_BLE_OK != rv) {
    return rv;
  }
  vscp_ble_put16(hdr + 8, (uint16_t) (L_BASE + ev->size));
  vscp_ble_put16(hdr + 32, ev->size);

  uint16_t mtu = (s->att_mtu > VSCP_BLE_G1_TX_MAX_MTU) ? (uint16_t) VSCP_BLE_G1_TX_MAX_MTU : s->att_mtu;
  size_t cap   = (size_t) mtu - 3 - VSCP_BLE_G1_FRAG_HEADER;
  size_t total = VSCP_BLE_G1_RECORD_HEADER + ev->size;
  uint8_t frag[VSCP_BLE_G1_TX_MAX_MTU - 3];
  for (size_t pos = 0; pos < total;) {
    size_t c = total - pos;
    if (c > cap) {
      c = cap;
    }
    frag[0] = 0x01;
    frag[1] = (uint8_t) ((0 == pos ? FLAG_FIRST : 0) | (pos + c == total ? FLAG_LAST : 0));
    vscp_ble_put32(frag + 2, tid);
    vscp_ble_put16(frag + 6, (uint16_t) pos);
    for (size_t i = 0; i < c; i++) {
      size_t at = pos + i;
      frag[VSCP_BLE_G1_FRAG_HEADER + i] =
        (at < VSCP_BLE_G1_RECORD_HEADER) ? hdr[at] : ev->data[at - VSCP_BLE_G1_RECORD_HEADER];
    }
    if (0 != s->ops->notify(s->ctx, frag, VSCP_BLE_G1_FRAG_HEADER + c)) {
      send_control(s, VSCP_BLE_G1_OP_TX_RESULT, tid, VSCP_BLE_G1_INTERNAL_ERROR, NULL, 0);
      return VSCP_BLE_ERR_STATE;
    }
    pos += c;
  }
  // TX_RESULT reports the attempt, it is not a client acknowledgment
  send_control(s, VSCP_BLE_G1_OP_TX_RESULT, tid, VSCP_BLE_G1_OK, NULL, 0);
  return VSCP_BLE_OK;
}

void
vscp_ble_g1_server_tick(vscp_ble_g1_server_t *s, uint32_t now_ms)
{
  uint32_t tid = s->rx.tid;
  if (vscp_ble_g1_frag_rx_expired(&s->rx, now_ms)) {
    s->failed_tid = tid;
    send_control(s, VSCP_BLE_G1_OP_EVENT_RESULT, tid, VSCP_BLE_G1_TIMEOUT, NULL, 0);
  }
}
