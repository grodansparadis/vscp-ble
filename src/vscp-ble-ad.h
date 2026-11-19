/*
 * vscp-ble-ad.h - Bluetooth advertising data (AD structure) parsing
 *
 * The MIT License (MIT)
 * Copyright (c) 2000-2026 Ake Hedman, the VSCP Project <info@grodansparadis.com>
 */

#ifndef VSCP_BLE_AD_H
#define VSCP_BLE_AD_H

#include "vscp-ble.h"

#ifdef __cplusplus
extern "C" {
#endif

/*!
  Walk the AD structures of a complete advertising data set.

  @param data Advertising data set (as reassembled by the controller).
  @param len Its length.
  @param offset In: offset to continue from (start with 0). Out: offset of
         the next structure.
  @param ad Out: the AD structure (starting with its Length octet).
  @param adlen Out: size of the structure (Length + 1).
  @return VSCP_BLE_OK for a structure, VSCP_BLE_ERR_NOT_FOUND at the end
          (end of data or a zero Length octet), VSCP_BLE_ERR_TRUNCATED if a
          structure runs past the end of the data.
*/
int
vscp_ble_ad_next(const uint8_t *data, size_t len, size_t *offset, const uint8_t **ad, size_t *adlen);

/*!
  Find the one VSCP frame of a given version in an advertising data set:
  a Manufacturer Specific Data structure with the configured Company
  Identifier whose version octet (offset 4) is version.

  @return VSCP_BLE_OK (frame/framelen set), VSCP_BLE_ERR_NOT_FOUND,
          VSCP_BLE_ERR_AMBIGUOUS (more than one candidate; multi-event
          packing is not defined) or VSCP_BLE_ERR_TRUNCATED (a malformed
          data set is rejected as a whole).
*/
int
vscp_ble_ad_find_frame(const uint8_t *data,
                       size_t len,
                       uint16_t company,
                       uint8_t version,
                       const uint8_t **frame,
                       size_t *framelen);

/*!
  Version octet of the VSCP frame for the configured company in a data set
  (to dispatch to E1/A2/F1 decoding), or -1 if there is none. If several
  VSCP structures are present the first one is used for dispatch; the
  decoder then rejects ambiguous sets.
*/
int
vscp_ble_ad_frame_version(const uint8_t *data, size_t len, uint16_t company);

#ifdef __cplusplus
}
#endif

#endif
