/*
 * vscp_node.h - VSCP BLE node for Zephyr (shared by the Zephyr and the
 * nRF Connect SDK examples)
 *
 * E1/A2 extended advertising, G1 GATT server, persistent counters and the
 * A2 key in the settings subsystem.
 *
 * The MIT License (MIT)
 * Copyright (c) 2000-2026 Ake Hedman, the VSCP Project <info@grodansparadis.com>
 */

#ifndef VSCP_NODE_H
#define VSCP_NODE_H

#include <stdbool.h>
#include <stdint.h>

#include "vscp-ble.h"

/// Node state changes (for LEDs and logs)
typedef enum {
  VSCP_NODE_ADVERTISING,
  VSCP_NODE_CONNECTED,
  VSCP_NODE_SECURED,    ///< Authenticated (MITM) encryption
  VSCP_NODE_AUTHORIZED, ///< G1 event access granted
  VSCP_NODE_DISCONNECTED
} vscp_node_state_t;

typedef struct {
  uint8_t guid[16];
  uint16_t company;
  /// Every new link state (may be NULL)
  void (*on_state)(vscp_node_state_t state);
  /*!
    A G1 event written by the central. Validate and authorize it, return a
    VSCP_BLE_G1_* status. Runs in the Bluetooth RX thread: do not block.
  */
  uint8_t (*on_event)(const vscp_ble_event_t *ev);
  /*!
    Authorization of an authenticated, bonded peer (VSCP_BLE_G1_AUTH_*).
    Bonding is not authorization: decide here. NULL: no access.
  */
  uint8_t (*authorize)(const void *peer_addr);
} vscp_node_config_t;

/*!
  Start Bluetooth, load settings (bonds, counters, A2 key) and start
  advertising. Call once.
*/
int
vscp_node_start(const vscp_node_config_t *cfg);

/*!
  Send an event: E1 broadcast (public), A2 broadcast (if a key is
  provisioned) and a G1 notification (if an authorized client subscribes),
  as enabled in Kconfig. Call from a thread (not an ISR).
*/
int
vscp_node_send(uint16_t vscp_class, uint16_t vscp_type, const uint8_t *data, uint16_t len);

/// Forget all bonds (and drop the connection)
int
vscp_node_unpair_all(void);

#endif
