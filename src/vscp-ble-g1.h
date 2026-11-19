/*
 * vscp-ble-g1.h - G1 version 1: VSCP over a connected GATT service
 *
 * Transport independent: the platform GATT code (NimBLE, Zephyr, BlueZ ...)
 * passes characteristic writes/reads to these functions and sends the
 * notifications/indications they produce (spec section 6).
 *
 *   Service        9b7a0000-6e44-4b8a-9d64-565343502001
 *   Capabilities   ...0001  Read                      (12 octets)
 *   Device GUID    ...0002  Read                      (16 octets)
 *   Event TX       ...0003  Notify                    (record fragments)
 *   Event RX       ...0004  Write with response       (record fragments)
 *   Control        ...0005  Write with response, Indicate
 *   Configuration  ...0006  Read, Write with response (TLV)
 *   Security       ...0007  Read                      (4 octets)
 *
 * The UUIDs are allocated by the draft VSCP specification, not by the
 * Bluetooth SIG. Protected characteristics need an encrypted, authenticated
 * (MITM) link; the application decides authorization (event access, admin).
 *
 * The MIT License (MIT)
 * Copyright (c) 2000-2026 Ake Hedman, the VSCP Project <info@grodansparadis.com>
 */

#ifndef VSCP_BLE_G1_H
#define VSCP_BLE_G1_H

#include "vscp-ble.h"

#ifdef __cplusplus
extern "C" {
#endif

/// 128-bit UUIDs in little-endian octet order (as most BLE stacks want them)
#define VSCP_BLE_G1_UUID128(n)                                                                                         \
  { 0x01, 0x20, 0x50, 0x43, 0x53, 0x56, 0x64, 0x9d, 0x8a, 0x4b, 0x44, 0x6e, (n), 0x00, 0x7a, 0x9b }
#define VSCP_BLE_G1_UUID_SERVICE       0x00
#define VSCP_BLE_G1_UUID_CAPABILITIES  0x01
#define VSCP_BLE_G1_UUID_GUID          0x02
#define VSCP_BLE_G1_UUID_EVENT_TX      0x03
#define VSCP_BLE_G1_UUID_EVENT_RX      0x04
#define VSCP_BLE_G1_UUID_CONTROL       0x05
#define VSCP_BLE_G1_UUID_CONFIGURATION 0x06
#define VSCP_BLE_G1_UUID_SECURITY      0x07
/// Text form: "9b7a00NN-6e44-4b8a-9d64-565343502001"
#define VSCP_BLE_G1_UUID_STR(nn) "9b7a00" nn "-6e44-4b8a-9d64-565343502001"

#define VSCP_BLE_G1_VERSION          0x01u
#define VSCP_BLE_G1_RECORD_HEADER    34u  ///< Record size without event data
#define VSCP_BLE_G1_MAX_DATA         487u ///< Max event data in G1 v1
#define VSCP_BLE_G1_MAX_RECORD       521u ///< 34 + 487
#define VSCP_BLE_G1_FRAG_HEADER      8u
#define VSCP_BLE_G1_MIN_ATT_MTU      23u
#define VSCP_BLE_G1_REASSEMBLY_MS    5000u
#define VSCP_BLE_G1_CAPABILITIES_LEN 12u

/*!
  Largest ATT MTU used for Event TX notifications. Fragments are built for
  min(ATT_MTU, this), which bounds the stack used by
  vscp_ble_g1_server_send_event() to about this many octets. Smaller
  fragments than the negotiated MTU allows are valid.
*/
#ifndef VSCP_BLE_G1_TX_MAX_MTU
#define VSCP_BLE_G1_TX_MAX_MTU 247u
#endif
#define VSCP_BLE_G1_SECURITY_LEN 4u

/// Control opcodes
#define VSCP_BLE_G1_OP_HELLO        0x01u
#define VSCP_BLE_G1_OP_RESET        0x02u
#define VSCP_BLE_G1_OP_HELLO_RESULT 0x81u
#define VSCP_BLE_G1_OP_EVENT_RESULT 0x82u
#define VSCP_BLE_G1_OP_TX_RESULT    0x83u

/// Control status codes
typedef enum {
  VSCP_BLE_G1_OK                  = 0x00,
  VSCP_BLE_G1_UNSUPPORTED_VERSION = 0x01,
  VSCP_BLE_G1_BAD_LENGTH          = 0x02,
  VSCP_BLE_G1_BAD_FLAGS           = 0x03,
  VSCP_BLE_G1_BAD_SEQUENCE        = 0x04,
  VSCP_BLE_G1_BUSY                = 0x05,
  VSCP_BLE_G1_NOT_AUTHORIZED      = 0x06,
  VSCP_BLE_G1_TOO_LARGE           = 0x07,
  VSCP_BLE_G1_TIMEOUT             = 0x08,
  VSCP_BLE_G1_INVALID_EVENT       = 0x09,
  VSCP_BLE_G1_NOT_READY           = 0x0A,
  VSCP_BLE_G1_INTERNAL_ERROR      = 0x0B
} vscp_ble_g1_status_t;

/// Standard ATT error codes the platform glue returns for refused writes
#define VSCP_BLE_ATT_ERR_VALUE_NOT_ALLOWED  0x13u
#define VSCP_BLE_ATT_ERR_CCCD_IMPROPER      0xFDu
#define VSCP_BLE_ATT_ERR_WRITE_NOT_PERM     0x03u
#define VSCP_BLE_ATT_ERR_INSUFFICIENT_AUTHN 0x05u
#define VSCP_BLE_ATT_ERR_INSUFFICIENT_AUTHZ 0x08u
#define VSCP_BLE_ATT_ERR_REQUEST_NOT_SUPP   0x06u

// ---------------------------------------------------------------------------
//                       Records, fragments, control
// ---------------------------------------------------------------------------

/// Encode a G1 record (34 + N octets). tid must be nonzero.
int
vscp_ble_g1_record_encode(uint8_t *out, size_t cap, uint32_t tid, const vscp_ble_event_t *ev, size_t *outlen);

/*!
  Decode a complete G1 record. ev->data points into rec.
  @param max_data Negotiated max_event_data.
*/
int
vscp_ble_g1_record_decode(const uint8_t *rec, size_t len, uint16_t max_data, uint32_t *tid, vscp_ble_event_t *ev);

/// Splits one record into ATT-sized fragments
typedef struct {
  const uint8_t *record;
  size_t len;
  size_t pos;
  uint32_t tid;
  size_t payload; ///< ATT_MTU - 11
} vscp_ble_g1_frag_tx_t;

int
vscp_ble_g1_frag_tx_begin(vscp_ble_g1_frag_tx_t *tx, const uint8_t *record, size_t len, uint16_t att_mtu);

/*!
  Next fragment into out (cap >= ATT_MTU - 3).
  @return VSCP_BLE_OK (a fragment), VSCP_BLE_ERR_NOT_FOUND when done.
*/
int
vscp_ble_g1_frag_tx_next(vscp_ble_g1_frag_tx_t *tx, uint8_t *out, size_t cap, size_t *outlen);

/// Reassembles one record (one transaction per direction per connection)
typedef struct {
  int active;
  uint32_t tid;
  size_t total; ///< Known from the FIRST fragment
  size_t pos;
  uint32_t last_ms;
  size_t max_record;
  uint8_t buf[VSCP_BLE_G1_MAX_RECORD];
} vscp_ble_g1_frag_rx_t;

void
vscp_ble_g1_frag_rx_init(vscp_ble_g1_frag_rx_t *rx, size_t max_record);
void
vscp_ble_g1_frag_rx_reset(vscp_ble_g1_frag_rx_t *rx);

/*!
  Feed one fragment.
  @param tid Out: transaction ID of the fragment (also on error, if the
         header could be read; 0 otherwise).
  @param status Out: G1 status code for an error.
  @return VSCP_BLE_OK (record complete: rx->buf, *reclen), VSCP_BLE_PENDING,
          VSCP_BLE_ERR_BUSY (a FIRST fragment of another transaction while
          one is in progress; the current one is kept), or another error
          (the reassembly is discarded; a fresh FIRST fragment is needed).
*/
int
vscp_ble_g1_frag_rx_feed(vscp_ble_g1_frag_rx_t *rx,
                         const uint8_t *frag,
                         size_t len,
                         uint32_t now_ms,
                         uint32_t *tid,
                         size_t *reclen,
                         uint8_t *status);

/// True (and reassembly discarded) if no fragment arrived for 5 s
int
vscp_ble_g1_frag_rx_expired(vscp_ble_g1_frag_rx_t *rx, uint32_t now_ms);

/// A Control characteristic value
typedef struct {
  uint8_t opcode;
  uint32_t tid;
  uint8_t status;
  uint8_t plen;
  const uint8_t *payload;
} vscp_ble_g1_control_t;

int
vscp_ble_g1_control_encode(uint8_t *out, size_t cap, const vscp_ble_g1_control_t *c, size_t *outlen);
int
vscp_ble_g1_control_decode(const uint8_t *in, size_t len, vscp_ble_g1_control_t *c);

/// HELLO / HELLO_RESULT payload
typedef struct {
  uint16_t max_event_data;  ///< 0-487
  uint16_t max_record_size; ///< 34-521
  uint16_t features;        ///< 0 in v1
} vscp_ble_g1_limits_t;

void
vscp_ble_g1_limits_encode(uint8_t out[6], const vscp_ble_g1_limits_t *l);
int
vscp_ble_g1_limits_decode(const uint8_t in[6], vscp_ble_g1_limits_t *l);

// ---------------------------------------------------------------------------
//                               Server
// ---------------------------------------------------------------------------

/// Pairing state for the Security Status characteristic
#define VSCP_BLE_G1_PAIRING_NONE          0u
#define VSCP_BLE_G1_PAIRING_AUTHENTICATED 1u
/// Authorization state
#define VSCP_BLE_G1_AUTH_NONE  0u
#define VSCP_BLE_G1_AUTH_EVENT 1u
#define VSCP_BLE_G1_AUTH_ADMIN 2u

typedef struct vscp_ble_g1_server vscp_ble_g1_server_t;

typedef struct {
  /// Send a Control indication (queue it if one is outstanding). 0 = ok.
  int (*indicate)(void *ctx, const uint8_t *data, size_t len);
  /// Send an Event TX notification. 0 = ok.
  int (*notify)(void *ctx, const uint8_t *data, size_t len);
  /*!
    A complete event arrived on Event RX and passed framing. Admit it
    (validate VSCP semantics, authorization) and return a G1 status:
    VSCP_BLE_G1_OK, VSCP_BLE_G1_INVALID_EVENT, VSCP_BLE_G1_NOT_AUTHORIZED ...
    The data is only valid during the call.
  */
  uint8_t (*on_event)(void *ctx, const vscp_ble_event_t *ev, uint32_t tid);
} vscp_ble_g1_ops_t;

struct vscp_ble_g1_server {
  const vscp_ble_g1_ops_t *ops;
  void *ctx;
  uint8_t guid[16];
  vscp_ble_g1_limits_t local; ///< What this server supports
  // Connection state
  int connected;
  uint16_t att_mtu;
  uint8_t pairing;       ///< VSCP_BLE_G1_PAIRING_*
  uint8_t authorization; ///< VSCP_BLE_G1_AUTH_*
  int control_indicate;  ///< Control CCCD indications enabled
  int event_notify;      ///< Event TX CCCD notifications enabled
  int hello_done;
  vscp_ble_g1_limits_t negotiated;
  uint32_t next_tid;
  uint32_t failed_tid; ///< Inbound transaction already answered with an error
  vscp_ble_g1_frag_rx_t rx;
};

/*!
  Initialize. max_event_data/max_record_size are this server's limits
  (<= 487/521).
*/
void
vscp_ble_g1_server_init(vscp_ble_g1_server_t *s,
                        const vscp_ble_g1_ops_t *ops,
                        void *ctx,
                        const uint8_t guid[16],
                        uint16_t max_event_data);

/// A central connected / disconnected (all state is per connection)
void
vscp_ble_g1_server_connected(vscp_ble_g1_server_t *s, uint16_t att_mtu);
void
vscp_ble_g1_server_disconnected(vscp_ble_g1_server_t *s);
void
vscp_ble_g1_server_set_mtu(vscp_ble_g1_server_t *s, uint16_t att_mtu);
/// Link security / application authorization changed
void
vscp_ble_g1_server_set_security(vscp_ble_g1_server_t *s, uint8_t pairing, uint8_t authorization);
/// CCCD writes
void
vscp_ble_g1_server_set_control_indicate(vscp_ble_g1_server_t *s, int enabled);
void
vscp_ble_g1_server_set_event_notify(vscp_ble_g1_server_t *s, int enabled);

/// Characteristic reads (out must hold the value)
size_t
vscp_ble_g1_server_read_capabilities(const vscp_ble_g1_server_t *s, uint8_t out[12]);
size_t
vscp_ble_g1_server_read_guid(const vscp_ble_g1_server_t *s, uint8_t out[16]);
size_t
vscp_ble_g1_server_read_security(const vscp_ble_g1_server_t *s, uint8_t out[4]);
size_t
vscp_ble_g1_server_read_configuration(const vscp_ble_g1_server_t *s, uint8_t out[2]);

/*!
  Characteristic writes. Return 0 to accept the ATT write, or a standard
  ATT error code to refuse it (VSCP_BLE_ATT_ERR_*). Protocol results go
  back as Control indications.
*/
uint8_t
vscp_ble_g1_server_write_control(vscp_ble_g1_server_t *s, const uint8_t *data, size_t len, uint32_t now_ms);
uint8_t
vscp_ble_g1_server_write_event_rx(vscp_ble_g1_server_t *s, const uint8_t *data, size_t len, uint32_t now_ms);
uint8_t
vscp_ble_g1_server_write_configuration(vscp_ble_g1_server_t *s, const uint8_t *data, size_t len);

/*!
  Send an event to the client (Event TX notifications) and report the
  attempt with TX_RESULT. A successful notification is not delivery.
  @return VSCP_BLE_OK, VSCP_BLE_ERR_STATE (not negotiated/subscribed/
          authorized), VSCP_BLE_ERR_TOO_LARGE or a notify failure.
*/
int
vscp_ble_g1_server_send_event(vscp_ble_g1_server_t *s, const vscp_ble_event_t *ev);

/// Call periodically: expires an incomplete Event RX record (EVENT_RESULT TIMEOUT)
void
vscp_ble_g1_server_tick(vscp_ble_g1_server_t *s, uint32_t now_ms);

#ifdef __cplusplus
}
#endif

#endif
