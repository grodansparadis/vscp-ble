/*
 * vscp-ble-e1.h - E1 version 1: cleartext VSCP event in extended advertising
 *
 * One Manufacturer Specific Data AD structure (spec section 5):
 *
 *   0      AD Length (33 + N)          1      AD Type 0xFF
 *   2-3    Company Identifier (LE)     4      Version 0x01
 *   5      Flags 0x00                  6-9    Sequence (BE)
 *   10-25  Sender GUID                 26-27  VSCP head (BE)
 *   28-29  VSCP class (BE)             30-31  VSCP type (BE)
 *   32-33  Data length N (BE)          34...  N data octets (0 <= N <= 222)
 *
 * E1 is unauthenticated public data (security policy S0). Never authorize
 * privileged actions from it.
 *
 * The MIT License (MIT)
 * Copyright (c) 2000-2026 Ake Hedman, the VSCP Project <info@grodansparadis.com>
 */

#ifndef VSCP_BLE_E1_H
#define VSCP_BLE_E1_H

#include "vscp-ble.h"

#ifdef __cplusplus
extern "C" {
#endif

#define VSCP_BLE_E1_HEADER_SIZE 34u  ///< AD structure size without event data
#define VSCP_BLE_E1_MAX_DATA    222u ///< Max event data (one-octet AD Length)
#define VSCP_BLE_E1_MAX_SIZE    256u ///< Max AD structure size

/*!
  Encode an E1 frame (complete AD structure, starting with AD Length).
  @return VSCP_BLE_OK and *outlen = 34 + N, or an error (zero GUID, too
          much data, small buffer).
*/
int
vscp_ble_e1_encode(uint8_t *out,
                   size_t cap,
                   uint16_t company,
                   uint32_t sequence,
                   const vscp_ble_event_t *ev,
                   size_t *outlen);

/*!
  Decode and validate one E1 AD structure (spec 5.6, steps 3-8).
  ev->data points into ad.
*/
int
vscp_ble_e1_decode(const uint8_t *ad, size_t len, uint16_t company, uint32_t *sequence, vscp_ble_event_t *ev);

/*!
  Find and decode the E1 frame in a complete advertising data set (spec 5.6
  including the ambiguity rule). Truncated reports must not be passed in.
*/
int
vscp_ble_e1_decode_dataset(const uint8_t *data, size_t len, uint16_t company, uint32_t *sequence, vscp_ble_event_t *ev);

#ifdef __cplusplus
}
#endif

#endif
