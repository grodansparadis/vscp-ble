/*
 * vscp-ble-f1.h - F1 version 3: connectionless fragmentation (S0 only)
 *
 * A public VSCP event of 223-1024 data octets sent as 2-8 extended
 * advertising data sets, one fragment AD structure each (spec section 9):
 *
 *   0      AD Length (41 + C)          1      AD Type 0xFF
 *   2-3    Company Identifier (LE)     4      Version 0x03
 *   5      Flags: bit 0 FIRST, bit 1 LAST
 *   6-9    Message ID (BE, nonzero)    10-25  Sender GUID
 *   26-31  head, class, type (BE)      32-33  Total data length T (BE)
 *   34     Fragment index              35     Fragment count K
 *   36-37  Fragment offset (BE)        38-39  Chunk length C (BE, 1-212)
 *   40-41  Reserved (0)                42...  C chunk octets
 *
 * Canonical layout: K = ceil(T / 212), chunk i at offset i * 212, all but
 * the last exactly 212 octets. F1 is unauthenticated and unencrypted: never
 * use it for S1/S2 or privileged events.
 *
 * The MIT License (MIT)
 * Copyright (c) 2000-2026 Ake Hedman, the VSCP Project <info@grodansparadis.com>
 */

#ifndef VSCP_BLE_F1_H
#define VSCP_BLE_F1_H

#include "vscp-ble.h"

#ifdef __cplusplus
extern "C" {
#endif

#define VSCP_BLE_F1_HEADER_SIZE   42u   ///< AD structure size without chunk
#define VSCP_BLE_F1_CHUNK         212u  ///< Max (and non-final) chunk size
#define VSCP_BLE_F1_MIN_DATA      223u  ///< Smaller events fit E1
#define VSCP_BLE_F1_MAX_DATA      1024u ///< Baseline maximum event data
#define VSCP_BLE_F1_MAX_FRAGMENTS 8u
#define VSCP_BLE_F1_SLOTS         2u    ///< Concurrent reassemblies
#define VSCP_BLE_F1_DEADLINE_MS   3000u ///< First fragment to completion
#define VSCP_BLE_F1_DONE_CACHE    8u    ///< Completed-message cache entries

/// Number of fragments for T octets of event data (0 if T is out of range)
unsigned
vscp_ble_f1_fragment_count(size_t total);

/*!
  Encode fragment index of an event (ev->size = T, 223-1024).
  @return VSCP_BLE_OK and *outlen = 42 + C.
*/
int
vscp_ble_f1_encode(uint8_t *out,
                   size_t cap,
                   uint16_t company,
                   uint32_t message_id,
                   const vscp_ble_event_t *ev,
                   unsigned index,
                   size_t *outlen);

typedef struct {
  int active;
  uint8_t guid[16];
  uint32_t message_id;
  uint16_t head, vscp_class, vscp_type;
  uint16_t total;
  uint8_t count;
  uint8_t received; ///< Bitmap of received fragment indexes
  uint32_t start_ms;
  uint8_t data[VSCP_BLE_F1_MAX_DATA];
} vscp_ble_f1_slot_t;

typedef struct {
  int used;
  uint8_t guid[16];
  uint32_t message_id;
  uint32_t time_ms;
} vscp_ble_f1_done_t;

/// Receiver state (no dynamic allocation; about 2.4 KB)
typedef struct {
  uint16_t company;
  vscp_ble_f1_slot_t slot[VSCP_BLE_F1_SLOTS];
  vscp_ble_f1_done_t done[VSCP_BLE_F1_DONE_CACHE];
  unsigned done_next;
} vscp_ble_f1_rx_t;

void
vscp_ble_f1_rx_init(vscp_ble_f1_rx_t *rx, uint16_t company);

/*!
  Feed one F1 AD structure (from a complete extended advertising report).
  @param rx Receiver state.
  @param ad One F1 AD structure (from AD Length).
  @param len Its length.
  @param now_ms A millisecond clock (wraps are handled).
  @param ev, out, outcap On VSCP_BLE_OK the complete event; its data is
         copied to out (outcap >= T).
  @return VSCP_BLE_OK (complete, delivered once), VSCP_BLE_PENDING,
          VSCP_BLE_DUPLICATE (already completed), or an error (the message
          is dropped on VSCP_BLE_ERR_CONFLICT/VSCP_BLE_ERR_TIMEOUT).
*/
int
vscp_ble_f1_rx_feed(vscp_ble_f1_rx_t *rx,
                    const uint8_t *ad,
                    size_t len,
                    uint32_t now_ms,
                    vscp_ble_event_t *ev,
                    uint8_t *out,
                    size_t outcap);

/// Drop reassemblies past their deadline; returns how many were dropped
unsigned
vscp_ble_f1_rx_expire(vscp_ble_f1_rx_t *rx, uint32_t now_ms);

#ifdef __cplusplus
}
#endif

#endif
