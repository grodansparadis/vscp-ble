/*
 * vscp-ble-common.c - common helpers and AD parsing
 *
 * The MIT License (MIT)
 * Copyright (c) 2000-2026 Ake Hedman, the VSCP Project <info@grodansparadis.com>
 */

#include "vscp-ble.h"
#include "vscp-ble-ad.h"

const char *
vscp_ble_strerror(int result)
{
  switch (result) {
    case VSCP_BLE_OK:
      return "ok";
    case VSCP_BLE_PENDING:
      return "pending";
    case VSCP_BLE_DUPLICATE:
      return "duplicate";
    case VSCP_BLE_ERR_PARAM:
      return "invalid argument";
    case VSCP_BLE_ERR_BUFFER:
      return "buffer too small";
    case VSCP_BLE_ERR_TOO_LARGE:
      return "too large";
    case VSCP_BLE_ERR_LENGTH:
      return "bad length";
    case VSCP_BLE_ERR_TYPE:
      return "not manufacturer data";
    case VSCP_BLE_ERR_COMPANY:
      return "wrong company identifier";
    case VSCP_BLE_ERR_VERSION:
      return "unsupported version";
    case VSCP_BLE_ERR_FLAGS:
      return "invalid flags";
    case VSCP_BLE_ERR_GUID:
      return "zero GUID";
    case VSCP_BLE_ERR_AMBIGUOUS:
      return "ambiguous (more than one frame)";
    case VSCP_BLE_ERR_NOT_FOUND:
      return "not found";
    case VSCP_BLE_ERR_TRUNCATED:
      return "truncated";
    case VSCP_BLE_ERR_AUTH:
      return "authentication failed";
    case VSCP_BLE_ERR_KEY:
      return "unknown or revoked key";
    case VSCP_BLE_ERR_REPLAY:
      return "replay";
    case VSCP_BLE_ERR_EXHAUSTED:
      return "counter exhausted";
    case VSCP_BLE_ERR_PERSIST:
      return "persist failed";
    case VSCP_BLE_ERR_CRYPTO:
      return "crypto error";
    case VSCP_BLE_ERR_BUSY:
      return "busy";
    case VSCP_BLE_ERR_SEQUENCE:
      return "bad fragment sequence";
    case VSCP_BLE_ERR_CONFLICT:
      return "conflict";
    case VSCP_BLE_ERR_TIMEOUT:
      return "timeout";
    case VSCP_BLE_ERR_STATE:
      return "invalid state";
    case VSCP_BLE_ERR_POLICY:
      return "refused by policy";
    default:
      return "unknown error";
  }
}

int
vscp_ble_guid_is_zero(const uint8_t guid[16])
{
  uint8_t any = 0;
  for (int i = 0; i < 16; i++) {
    any |= guid[i];
  }
  return 0 == any;
}

int
vscp_ble_ad_next(const uint8_t *data, size_t len, size_t *offset, const uint8_t **ad, size_t *adlen)
{
  if ((NULL == data && len) || (NULL == offset) || (NULL == ad) || (NULL == adlen)) {
    return VSCP_BLE_ERR_PARAM;
  }
  if (*offset >= len) {
    return VSCP_BLE_ERR_NOT_FOUND;
  }
  size_t l = data[*offset];
  if (0 == l) {
    // A zero Length ends the AD structures; what follows is not parsed
    *offset = len;
    return VSCP_BLE_ERR_NOT_FOUND;
  }
  if (l + 1 > len - *offset) {
    return VSCP_BLE_ERR_TRUNCATED;
  }
  *ad    = data + *offset;
  *adlen = l + 1;
  *offset += l + 1;
  return VSCP_BLE_OK;
}

static int
is_candidate(const uint8_t *ad, size_t adlen, uint16_t company, uint8_t version)
{
  return (adlen >= 5) && (VSCP_BLE_AD_TYPE_MANUFACTURER == ad[1]) && (ad[2] == (uint8_t) company) &&
         (ad[3] == (uint8_t) (company >> 8)) && (ad[4] == version);
}

int
vscp_ble_ad_find_frame(const uint8_t *data,
                       size_t len,
                       uint16_t company,
                       uint8_t version,
                       const uint8_t **frame,
                       size_t *framelen)
{
  if ((NULL == frame) || (NULL == framelen)) {
    return VSCP_BLE_ERR_PARAM;
  }
  size_t offset     = 0;
  const uint8_t *ad = NULL;
  size_t adlen      = 0;
  int found         = 0;
  int rv;
  while (VSCP_BLE_OK == (rv = vscp_ble_ad_next(data, len, &offset, &ad, &adlen))) {
    if (is_candidate(ad, adlen, company, version)) {
      if (found) {
        return VSCP_BLE_ERR_AMBIGUOUS;
      }
      *frame    = ad;
      *framelen = adlen;
      found     = 1;
    }
  }
  if (VSCP_BLE_ERR_TRUNCATED == rv) {
    return rv; // A malformed data set is rejected as a whole
  }
  return found ? VSCP_BLE_OK : VSCP_BLE_ERR_NOT_FOUND;
}

int
vscp_ble_ad_frame_version(const uint8_t *data, size_t len, uint16_t company)
{
  size_t offset     = 0;
  const uint8_t *ad = NULL;
  size_t adlen      = 0;
  while (VSCP_BLE_OK == vscp_ble_ad_next(data, len, &offset, &ad, &adlen)) {
    if ((adlen >= 5) && (VSCP_BLE_AD_TYPE_MANUFACTURER == ad[1]) && (ad[2] == (uint8_t) company) &&
        (ad[3] == (uint8_t) (company >> 8))) {
      return ad[4];
    }
  }
  return -1;
}
