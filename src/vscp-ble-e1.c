/*
 * vscp-ble-e1.c - E1 version 1 encoding/decoding
 *
 * The MIT License (MIT)
 * Copyright (c) 2000-2026 Ake Hedman, the VSCP Project <info@grodansparadis.com>
 */

#include <string.h>

#include "vscp-ble-ad.h"
#include "vscp-ble-e1.h"

int
vscp_ble_e1_encode(uint8_t *out,
                   size_t cap,
                   uint16_t company,
                   uint32_t sequence,
                   const vscp_ble_event_t *ev,
                   size_t *outlen)
{
  if ((NULL == out) || (NULL == ev) || (NULL == outlen) || (ev->size && (NULL == ev->data))) {
    return VSCP_BLE_ERR_PARAM;
  }
  if (ev->size > VSCP_BLE_E1_MAX_DATA) {
    return VSCP_BLE_ERR_TOO_LARGE;
  }
  if (vscp_ble_guid_is_zero(ev->guid)) {
    return VSCP_BLE_ERR_GUID;
  }
  size_t n = ev->size;
  if (cap < VSCP_BLE_E1_HEADER_SIZE + n) {
    return VSCP_BLE_ERR_BUFFER;
  }

  out[0] = (uint8_t) (33u + n);
  out[1] = VSCP_BLE_AD_TYPE_MANUFACTURER;
  out[2] = (uint8_t) company; // Little-endian
  out[3] = (uint8_t) (company >> 8);
  out[4] = VSCP_BLE_VERSION_E1;
  out[5] = 0x00;
  vscp_ble_put32(out + 6, sequence);
  memcpy(out + 10, ev->guid, 16);
  vscp_ble_put16(out + 26, ev->head);
  vscp_ble_put16(out + 28, ev->vscp_class);
  vscp_ble_put16(out + 30, ev->vscp_type);
  vscp_ble_put16(out + 32, (uint16_t) n);
  if (n) {
    memcpy(out + 34, ev->data, n);
  }
  *outlen = VSCP_BLE_E1_HEADER_SIZE + n;
  return VSCP_BLE_OK;
}

int
vscp_ble_e1_decode(const uint8_t *ad, size_t len, uint16_t company, uint32_t *sequence, vscp_ble_event_t *ev)
{
  if ((NULL == ad) || (NULL == ev)) {
    return VSCP_BLE_ERR_PARAM;
  }
  if ((len < VSCP_BLE_E1_HEADER_SIZE) || (len > VSCP_BLE_E1_MAX_SIZE) || ((size_t) ad[0] + 1 != len)) {
    return VSCP_BLE_ERR_LENGTH;
  }
  if (VSCP_BLE_AD_TYPE_MANUFACTURER != ad[1]) {
    return VSCP_BLE_ERR_TYPE;
  }
  if ((ad[2] != (uint8_t) company) || (ad[3] != (uint8_t) (company >> 8))) {
    return VSCP_BLE_ERR_COMPANY;
  }
  if (VSCP_BLE_VERSION_E1 != ad[4]) {
    return VSCP_BLE_ERR_VERSION; // Never interpreted as another version
  }
  if (0x00 != ad[5]) {
    return VSCP_BLE_ERR_FLAGS;
  }
  size_t n = vscp_ble_get16(ad + 32);
  if ((n > VSCP_BLE_E1_MAX_DATA) || (len != VSCP_BLE_E1_HEADER_SIZE + n)) {
    return VSCP_BLE_ERR_LENGTH;
  }
  if (vscp_ble_guid_is_zero(ad + 10)) {
    return VSCP_BLE_ERR_GUID;
  }

  if (NULL != sequence) {
    *sequence = vscp_ble_get32(ad + 6);
  }
  memcpy(ev->guid, ad + 10, 16);
  ev->head       = vscp_ble_get16(ad + 26);
  ev->vscp_class = vscp_ble_get16(ad + 28);
  ev->vscp_type  = vscp_ble_get16(ad + 30);
  ev->size       = (uint16_t) n;
  ev->data       = ad + 34;
  return VSCP_BLE_OK;
}

int
vscp_ble_e1_decode_dataset(const uint8_t *data, size_t len, uint16_t company, uint32_t *sequence, vscp_ble_event_t *ev)
{
  const uint8_t *frame = NULL;
  size_t framelen      = 0;
  int rv               = vscp_ble_ad_find_frame(data, len, company, VSCP_BLE_VERSION_E1, &frame, &framelen);
  if (VSCP_BLE_OK != rv) {
    return rv;
  }
  return vscp_ble_e1_decode(frame, framelen, company, sequence, ev);
}
