/*
 * vscp-ble.h - common definitions for VSCP over Bluetooth LE
 *
 * Implements the draft "VSCP over Bluetooth Low Energy" transport
 * (vscp-doc-spec vscp_over_bt_ble.md, proposed revision): L0, E1, A2, F1, G1.
 * The formats are proposals under review, not ratified standards.
 *
 * The MIT License (MIT)
 * Copyright (c) 2000-2026 Ake Hedman, the VSCP Project <info@grodansparadis.com>
 */

#ifndef VSCP_BLE_H
#define VSCP_BLE_H

#include <stddef.h>
#include <stdint.h>

#include "vscp-ble-version.h"

#ifdef __cplusplus
extern "C" {
#endif

/*!
  Bluetooth SIG Company Identifier reserved for tests. It MUST NOT be used in
  production; a deployment configures its assigned identifier.
*/
#define VSCP_BLE_TEST_COMPANY_ID 0xFFFFu

/// AD Type of Manufacturer Specific Data
#define VSCP_BLE_AD_TYPE_MANUFACTURER 0xFFu

/// Frame versions (byte 4 of the manufacturer AD structure)
#define VSCP_BLE_VERSION_E1 0x01u
#define VSCP_BLE_VERSION_A2 0x02u
#define VSCP_BLE_VERSION_F1 0x03u

/*!
  Result codes. Zero is success; positive values are informational,
  negative values are errors.
*/
typedef enum {
  VSCP_BLE_OK            = 0,
  VSCP_BLE_PENDING       = 1,   ///< More fragments needed
  VSCP_BLE_DUPLICATE     = 2,   ///< Already delivered (identical repeat)
  VSCP_BLE_ERR_PARAM     = -1,  ///< Invalid argument
  VSCP_BLE_ERR_BUFFER    = -2,  ///< Output buffer too small
  VSCP_BLE_ERR_TOO_LARGE = -3,  ///< Event data larger than the format allows
  VSCP_BLE_ERR_LENGTH    = -4,  ///< Malformed or inconsistent length
  VSCP_BLE_ERR_TYPE      = -5,  ///< Not a manufacturer AD structure
  VSCP_BLE_ERR_COMPANY   = -6,  ///< Not the configured Company Identifier
  VSCP_BLE_ERR_VERSION   = -7,  ///< Unsupported frame version
  VSCP_BLE_ERR_FLAGS     = -8,  ///< Reserved or invalid flag bits
  VSCP_BLE_ERR_GUID      = -9,  ///< All-zero (invalid) GUID
  VSCP_BLE_ERR_AMBIGUOUS = -10, ///< More than one candidate frame
  VSCP_BLE_ERR_NOT_FOUND = -11, ///< No candidate frame
  VSCP_BLE_ERR_TRUNCATED = -12, ///< Truncated AD structure or report
  VSCP_BLE_ERR_AUTH      = -13, ///< Authentication (CCM tag) failed
  VSCP_BLE_ERR_KEY       = -14, ///< Unknown, revoked or mismatching key
  VSCP_BLE_ERR_REPLAY    = -15, ///< Stale or repeated sequence/epoch
  VSCP_BLE_ERR_EXHAUSTED = -16, ///< Sequence/epoch space used up
  VSCP_BLE_ERR_PERSIST   = -17, ///< Persisting counter/replay state failed
  VSCP_BLE_ERR_CRYPTO    = -18, ///< Crypto backend failure
  VSCP_BLE_ERR_BUSY      = -19, ///< No free reassembly slot / in progress
  VSCP_BLE_ERR_SEQUENCE  = -20, ///< Fragment offset/order/index mismatch
  VSCP_BLE_ERR_CONFLICT  = -21, ///< Conflicting fragment or duplicate data
  VSCP_BLE_ERR_TIMEOUT   = -22, ///< Reassembly expired
  VSCP_BLE_ERR_STATE     = -23, ///< Not allowed in the current state
  VSCP_BLE_ERR_POLICY    = -24  ///< Refused by security/authorization policy
} vscp_ble_result_t;

/*!
  A VSCP event as carried by E1/A2/F1/G1 (no timestamp or obid on the air).
  When decoded, data points into the buffer that was decoded (or into the
  caller's plaintext/reassembly buffer).
*/
typedef struct {
  uint8_t guid[16];    ///< Sender GUID, canonical VSCP order (MSB first)
  uint16_t head;       ///< Full 16-bit VSCP head
  uint16_t vscp_class; ///< VSCP class
  uint16_t vscp_type;  ///< VSCP type
  uint16_t size;       ///< Number of data octets
  const uint8_t *data; ///< Event data (size octets)
} vscp_ble_event_t;

/// Text for a result code
const char *
vscp_ble_strerror(int result);

/// True if all 16 GUID octets are zero (an invalid sender GUID)
int
vscp_ble_guid_is_zero(const uint8_t guid[16]);

/// Big-endian helpers
static inline void
vscp_ble_put16(uint8_t *p, uint16_t v)
{
  p[0] = (uint8_t) (v >> 8);
  p[1] = (uint8_t) v;
}

static inline void
vscp_ble_put32(uint8_t *p, uint32_t v)
{
  p[0] = (uint8_t) (v >> 24);
  p[1] = (uint8_t) (v >> 16);
  p[2] = (uint8_t) (v >> 8);
  p[3] = (uint8_t) v;
}

static inline uint16_t
vscp_ble_get16(const uint8_t *p)
{
  return (uint16_t) (((uint16_t) p[0] << 8) | p[1]);
}

static inline uint32_t
vscp_ble_get32(const uint8_t *p)
{
  return ((uint32_t) p[0] << 24) | ((uint32_t) p[1] << 16) | ((uint32_t) p[2] << 8) | p[3];
}

#ifdef __cplusplus
}
#endif

#endif
