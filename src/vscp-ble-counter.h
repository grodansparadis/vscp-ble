/*
 * vscp-ble-counter.h - persistent sender sequence/epoch counter
 *
 * E1 and A2 senders must never reuse a sequence number under the same GUID
 * (E1) or nonce (A2), also across reboot, power loss and firmware update.
 * The counter reserves blocks of values in nonvolatile storage *before*
 * they are used, so a flash write is needed only once per block. After a
 * restart the unused rest of the last block is skipped.
 *
 *   E1: sequence 0..0xFFFFFFFF, then exhausted (wrap is forbidden).
 *   A2: when the sequence is exhausted the epoch advances (and is persisted
 *       before use); epoch exhaustion means a new key must be provisioned.
 *
 * The MIT License (MIT)
 * Copyright (c) 2000-2026 Ake Hedman, the VSCP Project <info@grodansparadis.com>
 */

#ifndef VSCP_BLE_COUNTER_H
#define VSCP_BLE_COUNTER_H

#include "vscp-ble.h"

#ifdef __cplusplus
extern "C" {
#endif

/*!
  Persist the reservation: values up to (but not including) reserved_until
  in epoch may be used after a restart no more. Must be durable when it
  returns. Return 0 on success.
*/
typedef int (*vscp_ble_counter_persist_t)(void *ctx, uint32_t epoch, uint64_t reserved_until);

typedef struct {
  uint32_t epoch;          ///< Current epoch (A2), always 0 for E1
  uint64_t next;           ///< Next sequence to use
  uint64_t reserved_until; ///< First value not yet reserved
  uint32_t block;          ///< Values reserved per persist
  int use_epoch;           ///< 1 for A2 (advance epoch on exhaustion)
  int exhausted;
  vscp_ble_counter_persist_t persist;
  void *ctx;
} vscp_ble_counter_t;

/*!
  Start a counter from its persisted state (epoch and reserved_until as last
  persisted; 0/0 for a new sender). Values below reserved_until are never
  used again.
*/
void
vscp_ble_counter_init(vscp_ble_counter_t *c,
                      uint32_t epoch,
                      uint64_t reserved_until,
                      uint32_t block,
                      int use_epoch,
                      vscp_ble_counter_persist_t persist,
                      void *ctx);

/*!
  Take the next sequence number (and its epoch). Persists a new reservation
  first when the current block is used up.
  @return VSCP_BLE_OK, VSCP_BLE_ERR_EXHAUSTED or VSCP_BLE_ERR_PERSIST.
*/
int
vscp_ble_counter_next(vscp_ble_counter_t *c, uint32_t *epoch, uint32_t *sequence);

#ifdef __cplusplus
}
#endif

#endif
