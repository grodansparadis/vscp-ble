/*
 * vscp-ble-counter.c - persistent sender sequence/epoch counter
 *
 * The MIT License (MIT)
 * Copyright (c) 2000-2026 Ake Hedman, the VSCP Project <info@grodansparadis.com>
 */

#include "vscp-ble-counter.h"

#define SEQ_SPACE 0x100000000ULL // Sequence values 0..0xFFFFFFFF

void
vscp_ble_counter_init(vscp_ble_counter_t *c,
                      uint32_t epoch,
                      uint64_t reserved_until,
                      uint32_t block,
                      int use_epoch,
                      vscp_ble_counter_persist_t persist,
                      void *ctx)
{
  c->epoch          = epoch;
  c->next           = reserved_until; // Skip whatever may have been used
  c->reserved_until = reserved_until;
  c->block          = block ? block : 1;
  c->use_epoch      = use_epoch;
  c->exhausted      = 0;
  c->persist        = persist;
  c->ctx            = ctx;
  if (c->next >= SEQ_SPACE) {
    if (use_epoch && (epoch < 0xFFFFFFFFu)) {
      c->epoch++;
      c->next           = 0;
      c->reserved_until = 0;
    }
    else {
      c->exhausted = 1;
    }
  }
}

int
vscp_ble_counter_next(vscp_ble_counter_t *c, uint32_t *epoch, uint32_t *sequence)
{
  if ((NULL == c) || (NULL == sequence)) {
    return VSCP_BLE_ERR_PARAM;
  }
  if (c->exhausted) {
    return VSCP_BLE_ERR_EXHAUSTED;
  }
  if (c->next >= SEQ_SPACE) {
    // Sequence space of this epoch used up
    if (!c->use_epoch || (0xFFFFFFFFu == c->epoch)) {
      c->exhausted = 1;
      return VSCP_BLE_ERR_EXHAUSTED; // E1: stop; A2: rekey needed
    }
    c->epoch++;
    c->next           = 0;
    c->reserved_until = 0;
  }
  if (c->next >= c->reserved_until) {
    // Reserve (and persist) the next block before any value of it is used
    uint64_t until = c->next + c->block;
    if (until > SEQ_SPACE) {
      until = SEQ_SPACE;
    }
    if ((NULL != c->persist) && (0 != c->persist(c->ctx, c->epoch, until))) {
      return VSCP_BLE_ERR_PERSIST;
    }
    c->reserved_until = until;
  }
  if (NULL != epoch) {
    *epoch = c->epoch;
  }
  *sequence = (uint32_t) c->next;
  c->next++;
  return VSCP_BLE_OK;
}
