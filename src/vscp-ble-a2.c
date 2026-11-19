/*
 * vscp-ble-a2.c - A2 version 2 authenticated encryption (AES-128-CCM)
 *
 * The MIT License (MIT)
 * Copyright (c) 2000-2026 Ake Hedman, the VSCP Project <info@grodansparadis.com>
 */

#include <string.h>

#include "vscp-ble-a2.h"
#include "vscp-ble-ad.h"
#include "vscp-ble-crypto.h"

static const uint8_t A2_DOMAIN[11] = { 'V', 'S', 'C', 'P', '-', 'B', 'L', 'E', '-', 'A', '2' };

static void
make_nonce(uint8_t nonce[13], const uint8_t prefix[5], uint32_t epoch, uint32_t sequence)
{
  memcpy(nonce, prefix, 5);
  vscp_ble_put32(nonce + 5, epoch);
  vscp_ble_put32(nonce + 9, sequence);
}

static void
make_aad(uint8_t aad[VSCP_BLE_A2_AAD_SIZE], const uint8_t *frame)
{
  memcpy(aad, A2_DOMAIN, sizeof(A2_DOMAIN));
  memcpy(aad + sizeof(A2_DOMAIN), frame + 2, 38); // Company Identifier .. data length
}

int
vscp_ble_a2_encode(uint8_t *out,
                   size_t cap,
                   uint16_t company,
                   uint16_t key_id,
                   uint32_t epoch,
                   uint32_t sequence,
                   const uint8_t key[16],
                   const uint8_t nonce_prefix[5],
                   const vscp_ble_event_t *ev,
                   size_t *outlen)
{
  if ((NULL == out) || (NULL == key) || (NULL == nonce_prefix) || (NULL == ev) || (NULL == outlen) ||
      (ev->size && (NULL == ev->data)) || (0 == key_id)) {
    return VSCP_BLE_ERR_PARAM;
  }
  if (ev->size > VSCP_BLE_A2_MAX_DATA) {
    return VSCP_BLE_ERR_TOO_LARGE;
  }
  if (vscp_ble_guid_is_zero(ev->guid)) {
    return VSCP_BLE_ERR_GUID;
  }
  size_t n = ev->size;
  if (cap < VSCP_BLE_A2_OVERHEAD + n) {
    return VSCP_BLE_ERR_BUFFER;
  }

  out[0] = (uint8_t) (55u + n);
  out[1] = VSCP_BLE_AD_TYPE_MANUFACTURER;
  out[2] = (uint8_t) company;
  out[3] = (uint8_t) (company >> 8);
  out[4] = VSCP_BLE_VERSION_A2;
  out[5] = 0x01;
  vscp_ble_put16(out + 6, key_id);
  vscp_ble_put32(out + 8, epoch);
  vscp_ble_put32(out + 12, sequence);
  memcpy(out + 16, ev->guid, 16);
  vscp_ble_put16(out + 32, ev->head);
  vscp_ble_put16(out + 34, ev->vscp_class);
  vscp_ble_put16(out + 36, ev->vscp_type);
  vscp_ble_put16(out + 38, (uint16_t) n);

  uint8_t nonce[13], aad[VSCP_BLE_A2_AAD_SIZE];
  make_nonce(nonce, nonce_prefix, epoch, sequence);
  make_aad(aad, out);
  int rv = vscp_ble_ccm_encrypt(key, nonce, aad, sizeof(aad), ev->data, n, out + 40, out + 40 + n);
  vscp_ble_secure_zero(nonce, sizeof(nonce));
  if (VSCP_BLE_OK != rv) {
    vscp_ble_secure_zero(out, VSCP_BLE_A2_OVERHEAD + n);
    return rv;
  }
  *outlen = VSCP_BLE_A2_OVERHEAD + n;
  return VSCP_BLE_OK;
}

int
vscp_ble_a2_receive(const vscp_ble_a2_receiver_t *rx,
                    const uint8_t *ad,
                    size_t len,
                    vscp_ble_event_t *ev,
                    uint8_t *plain,
                    size_t plaincap,
                    uint32_t *epoch_out,
                    uint32_t *sequence_out,
                    vscp_ble_a2_key_t **rec_out)
{
  if ((NULL == rx) || (NULL == rx->lookup) || (NULL == ad) || (NULL == ev) || (NULL == plain)) {
    return VSCP_BLE_ERR_PARAM;
  }

  // 1. Framing: complete structure, type, company, version, flags, length
  if ((len < VSCP_BLE_A2_OVERHEAD) || (len > VSCP_BLE_A2_MAX_SIZE) || ((size_t) ad[0] + 1 != len)) {
    return VSCP_BLE_ERR_LENGTH;
  }
  if (VSCP_BLE_AD_TYPE_MANUFACTURER != ad[1]) {
    return VSCP_BLE_ERR_TYPE;
  }
  if ((ad[2] != (uint8_t) rx->company) || (ad[3] != (uint8_t) (rx->company >> 8))) {
    return VSCP_BLE_ERR_COMPANY;
  }
  if (VSCP_BLE_VERSION_A2 != ad[4]) {
    return VSCP_BLE_ERR_VERSION;
  }
  if (0x01 != ad[5]) {
    return VSCP_BLE_ERR_FLAGS; // No fallback to cleartext
  }
  size_t n = vscp_ble_get16(ad + 38);
  if ((n > VSCP_BLE_A2_MAX_DATA) || (len != VSCP_BLE_A2_OVERHEAD + n)) {
    return VSCP_BLE_ERR_LENGTH;
  }
  if (plaincap < n) {
    return VSCP_BLE_ERR_BUFFER;
  }

  // 2. Identity and key record
  const uint8_t *guid = ad + 16;
  if (vscp_ble_guid_is_zero(guid)) {
    return VSCP_BLE_ERR_GUID;
  }
  uint16_t key_id = vscp_ble_get16(ad + 6);
  uint32_t epoch  = vscp_ble_get32(ad + 8);
  uint32_t seq    = vscp_ble_get32(ad + 12);
  if (0 == key_id) {
    return VSCP_BLE_ERR_KEY;
  }
  vscp_ble_a2_key_t *rec = rx->lookup(rx->ctx, rx->company, key_id);
  if ((NULL == rec) || rec->revoked || (rec->company != rx->company) || (rec->key_id != key_id) ||
      (0 != memcmp(rec->guid, guid, 16))) {
    return VSCP_BLE_ERR_KEY; // Never trust a claimed GUID because the Key ID is known
  }
  if ((epoch < rec->min_epoch) || (epoch > rec->max_epoch)) {
    return VSCP_BLE_ERR_REPLAY;
  }

  // 3-4. Nonce, AAD, verify the full tag and decrypt (nothing released on failure)
  uint8_t nonce[13], aad[VSCP_BLE_A2_AAD_SIZE];
  make_nonce(nonce, rec->nonce_prefix, epoch, seq);
  make_aad(aad, ad);
  int rv = vscp_ble_ccm_decrypt(rec->key, nonce, aad, sizeof(aad), ad + 40, n, ad + 40 + n, plain);
  vscp_ble_secure_zero(nonce, sizeof(nonce));
  if (VSCP_BLE_OK != rv) {
    return rv; // Replay state unchanged
  }

  // 5. Replay: strictly increasing (epoch, sequence); no out of order
  if (rec->have_replay) {
    if ((epoch < rec->last_epoch) || ((epoch == rec->last_epoch) && (seq <= rec->last_sequence))) {
      vscp_ble_secure_zero(plain, n);
      return VSCP_BLE_ERR_REPLAY;
    }
  }
  vscp_ble_a2_key_t saved = *rec;
  rec->have_replay        = 1;
  rec->last_epoch         = epoch;
  rec->last_sequence      = seq;
  if ((NULL != rx->persist_replay) && (0 != rx->persist_replay(rx->ctx, rec))) {
    // Could not make the replay state durable: fail closed
    rec->have_replay   = saved.have_replay;
    rec->last_epoch    = saved.last_epoch;
    rec->last_sequence = saved.last_sequence;
    vscp_ble_secure_zero(plain, n);
    return VSCP_BLE_ERR_PERSIST;
  }

  // 6. The event (VSCP semantic validation and authorization follow in the caller)
  memcpy(ev->guid, guid, 16);
  ev->head       = vscp_ble_get16(ad + 32);
  ev->vscp_class = vscp_ble_get16(ad + 34);
  ev->vscp_type  = vscp_ble_get16(ad + 36);
  ev->size       = (uint16_t) n;
  ev->data       = plain;
  if (NULL != epoch_out) {
    *epoch_out = epoch;
  }
  if (NULL != sequence_out) {
    *sequence_out = seq;
  }
  if (NULL != rec_out) {
    *rec_out = rec;
  }
  return VSCP_BLE_OK;
}

int
vscp_ble_a2_receive_dataset(const vscp_ble_a2_receiver_t *rx,
                            const uint8_t *data,
                            size_t len,
                            vscp_ble_event_t *ev,
                            uint8_t *plain,
                            size_t plaincap,
                            uint32_t *epoch,
                            uint32_t *sequence,
                            vscp_ble_a2_key_t **rec)
{
  if (NULL == rx) {
    return VSCP_BLE_ERR_PARAM;
  }
  const uint8_t *frame = NULL;
  size_t framelen      = 0;
  int rv               = vscp_ble_ad_find_frame(data, len, rx->company, VSCP_BLE_VERSION_A2, &frame, &framelen);
  if (VSCP_BLE_OK != rv) {
    return rv;
  }
  return vscp_ble_a2_receive(rx, frame, framelen, ev, plain, plaincap, epoch, sequence, rec);
}
