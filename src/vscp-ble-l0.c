/*
 * vscp-ble-l0.c - L0 legacy advertising (proposed canonical layout)
 *
 * The MIT License (MIT)
 * Copyright (c) 2000-2026 Ake Hedman, the VSCP Project <info@grodansparadis.com>
 */

#include <string.h>

#include "vscp-ble-l0.h"

int
vscp_ble_l0_encode(uint8_t *out, size_t cap, uint16_t company, const vscp_ble_l0_event_t *ev, size_t *outlen)
{
  if ((NULL == out) || (NULL == ev) || (NULL == outlen)) {
    return VSCP_BLE_ERR_PARAM;
  }
  if (ev->size > VSCP_BLE_L0_MAX_DATA) {
    return VSCP_BLE_ERR_TOO_LARGE;
  }
  if (cap < VSCP_BLE_L0_SIZE) {
    return VSCP_BLE_ERR_BUFFER;
  }
  memset(out, 0, VSCP_BLE_L0_SIZE);
  out[0] = 0x14;
  out[1] = VSCP_BLE_AD_TYPE_MANUFACTURER;
  out[2] = (uint8_t) company;
  out[3] = (uint8_t) (company >> 8);
  out[4] = 0x00; // Version 0, plaintext
  vscp_ble_put16(out + 5, ev->node_id);
  out[7] = ev->head;
  vscp_ble_put16(out + 8, ev->vscp_class);
  vscp_ble_put16(out + 10, ev->vscp_type);
  out[12] = ev->size;
  memcpy(out + 13, ev->data, ev->size);
  *outlen = VSCP_BLE_L0_SIZE;
  return VSCP_BLE_OK;
}

int
vscp_ble_l0_decode(const uint8_t *ad, size_t len, uint16_t company, vscp_ble_l0_event_t *ev)
{
  if ((NULL == ad) || (NULL == ev)) {
    return VSCP_BLE_ERR_PARAM;
  }
  if ((VSCP_BLE_L0_SIZE != len) || (0x14 != ad[0])) {
    return VSCP_BLE_ERR_LENGTH;
  }
  if (VSCP_BLE_AD_TYPE_MANUFACTURER != ad[1]) {
    return VSCP_BLE_ERR_TYPE;
  }
  if ((ad[2] != (uint8_t) company) || (ad[3] != (uint8_t) (company >> 8))) {
    return VSCP_BLE_ERR_COMPANY;
  }
  if (0 != (ad[4] & 0x0F)) {
    return VSCP_BLE_ERR_VERSION;
  }
  if (0 != (ad[4] & 0xF0)) {
    return VSCP_BLE_ERR_FLAGS; // Reserved bits, or encrypted (not supported)
  }
  if (ad[12] > VSCP_BLE_L0_MAX_DATA) {
    return VSCP_BLE_ERR_LENGTH;
  }
  ev->node_id    = vscp_ble_get16(ad + 5);
  ev->head       = ad[7];
  ev->vscp_class = vscp_ble_get16(ad + 8);
  ev->vscp_type  = vscp_ble_get16(ad + 10);
  ev->size       = ad[12];
  memset(ev->data, 0, sizeof(ev->data));
  memcpy(ev->data, ad + 13, ev->size);
  return VSCP_BLE_OK;
}

void
vscp_ble_l0_guid(uint8_t guid[16], const uint8_t addr[6], uint16_t node_id)
{
  static const uint8_t prefix[8] = { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xF8 };
  memcpy(guid, prefix, 8);
  memcpy(guid + 8, addr, 6);
  vscp_ble_put16(guid + 14, node_id);
}
