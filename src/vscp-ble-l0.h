/*
 * vscp-ble-l0.h - L0 version 0: legacy advertising (compatibility)
 *
 * The proposed canonical 21-octet layout of spec section 4.1:
 *
 *   0 AD Length 0x14    1 AD Type 0xFF     2-3 Company Identifier (LE)
 *   4 VSCP flags (bits 0-3 version 0, 4-6 zero, 7 encrypted)
 *   5-6 Node id (BE)    7 VSCP head (low 8 bits)
 *   8-9 class (BE)      10-11 type (BE)    12 data length (0-8)
 *   13-20 data, zero padded
 *
 * This is a proposal; verify against deployed devices before relying on
 * it. Encrypted L0 (historic AES-ECB) is neither authenticated nor replay
 * protected and is not supported here: such frames are reported, not
 * decoded.
 *
 * The MIT License (MIT)
 * Copyright (c) 2000-2026 Ake Hedman, the VSCP Project <info@grodansparadis.com>
 */

#ifndef VSCP_BLE_L0_H
#define VSCP_BLE_L0_H

#include "vscp-ble.h"

#ifdef __cplusplus
extern "C" {
#endif

#define VSCP_BLE_L0_SIZE     21u
#define VSCP_BLE_L0_MAX_DATA 8u

typedef struct {
  uint16_t node_id; ///< Node id (part of the derived legacy GUID)
  uint8_t head;     ///< Low eight bits of the VSCP head
  uint16_t vscp_class;
  uint16_t vscp_type;
  uint8_t size; ///< 0-8
  uint8_t data[8];
} vscp_ble_l0_event_t;

/// Encode a plaintext L0 structure (21 octets)
int
vscp_ble_l0_encode(uint8_t *out, size_t cap, uint16_t company, const vscp_ble_l0_event_t *ev, size_t *outlen);

/*!
  Decode a plaintext L0 structure. An encrypted frame (flag bit 7) gives
  VSCP_BLE_ERR_FLAGS (historic AES-ECB is not supported).
*/
int
vscp_ble_l0_decode(const uint8_t *ad, size_t len, uint16_t company, vscp_ble_l0_event_t *ev);

/*!
  The legacy derived GUID FF:FF:FF:FF:FF:FF:FF:F8:<6-octet BLE address>:<node id>.
  It changes with BLE private-address rotation and MUST NOT be merged with a
  stable E1/A2/G1 GUID without a trusted provisioning record.
  @param addr BLE address, most significant octet first.
*/
void
vscp_ble_l0_guid(uint8_t guid[16], const uint8_t addr[6], uint16_t node_id);

#ifdef __cplusplus
}
#endif

#endif
