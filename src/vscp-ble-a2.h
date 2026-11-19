/*
 * vscp-ble-a2.h - A2 version 2: authenticated, encrypted VSCP event
 *
 * One Manufacturer Specific Data AD structure (spec section 7):
 *
 *   0      AD Length (55 + N)          1      AD Type 0xFF
 *   2-3    Company Identifier (LE)     4      Version 0x02
 *   5      Flags 0x01 (AES-128-CCM)    6-7    Key ID (BE, nonzero)
 *   8-11   Key epoch (BE)              12-15  Sequence (BE)
 *   16-31  Sender GUID                 32-37  head, class, type (BE)
 *   38-39  Data length N (BE)          40...  N ciphertext octets
 *   40+N   16-octet CCM tag            (0 <= N <= 200)
 *
 *   nonce = provisioned 5-octet prefix | epoch | sequence (13 octets)
 *   AAD   = "VSCP-BLE-A2" | AD structure octets 2-39 (49 octets)
 *
 * A2 satisfies security policies S1 and S2. Authorization is separate:
 * check it (by GUID, class/type ...) before acting on an event.
 *
 * The MIT License (MIT)
 * Copyright (c) 2000-2026 Ake Hedman, the VSCP Project <info@grodansparadis.com>
 */

#ifndef VSCP_BLE_A2_H
#define VSCP_BLE_A2_H

#include "vscp-ble.h"

#ifdef __cplusplus
extern "C" {
#endif

#define VSCP_BLE_A2_HEADER_SIZE 40u  ///< Octets before the ciphertext
#define VSCP_BLE_A2_OVERHEAD    56u  ///< AD structure size without event data
#define VSCP_BLE_A2_MAX_DATA    200u ///< Max event data
#define VSCP_BLE_A2_MAX_SIZE    256u ///< Max AD structure size
#define VSCP_BLE_A2_AAD_SIZE    49u  ///< "VSCP-BLE-A2" + 38 header octets

/*!
  A provisioned key record (receiver side). The receiver's key store holds
  one per (Company Identifier, Sender GUID, Key ID), with the replay state.
*/
typedef struct {
  uint16_t company;
  uint16_t key_id;         ///< Nonzero, not secret
  uint8_t guid[16];        ///< The only GUID this key may authenticate
  uint8_t key[16];         ///< AES-128 key (secret)
  uint8_t nonce_prefix[5]; ///< Unique per sender/key (secret, not sent)
  uint32_t min_epoch;      ///< Accepted epoch range
  uint32_t max_epoch;
  int revoked; ///< Revoked records never authenticate anything
  // Replay state: highest accepted (epoch, sequence). Must survive restart.
  int have_replay;
  uint32_t last_epoch;
  uint32_t last_sequence;
  void *user; ///< Application data (authorization policy ...)
} vscp_ble_a2_key_t;

/*!
  Encode an A2 frame. The (epoch, sequence) pair must never have been used
  with this key and prefix before (use vscp_ble_counter_t).
*/
int
vscp_ble_a2_encode(uint8_t *out,
                   size_t cap,
                   uint16_t company,
                   uint16_t key_id,
                   uint32_t epoch,
                   uint32_t sequence,
                   const uint8_t key[16],
                   const uint8_t nonce_prefix[5],
                   const vscp_ble_event_t *ev,
                   size_t *outlen);

/// Receiver configuration
typedef struct {
  uint16_t company; ///< Configured Company Identifier
  /// Find the key record for a Key ID (NULL if unknown)
  vscp_ble_a2_key_t *(*lookup)(void *ctx, uint16_t company, uint16_t key_id);
  /*!
    Durably store the record's new replay state (last_epoch/last_sequence)
    before the event is accepted. Return 0 on success; on failure the event
    is rejected (fail closed). NULL only for tests/non-sensitive use.
  */
  int (*persist_replay)(void *ctx, const vscp_ble_a2_key_t *rec);
  void *ctx;
} vscp_ble_a2_receiver_t;

/*!
  Receive one A2 AD structure (spec 7.6): framing checks, key lookup, GUID
  match, epoch range, tag verification and decryption, replay check and
  persisted replay update. Not thread safe: serialize calls per receiver.

  @param plain Buffer for the decrypted data (at least N octets, max 200).
               ev->data points into it on success.
  @param rec Out (optional): the key record that authenticated the frame,
             for the authorization decision.
  @return VSCP_BLE_OK or an error. Nothing is delivered on error and the
          replay state is unchanged.
*/
int
vscp_ble_a2_receive(const vscp_ble_a2_receiver_t *rx,
                    const uint8_t *ad,
                    size_t len,
                    vscp_ble_event_t *ev,
                    uint8_t *plain,
                    size_t plaincap,
                    uint32_t *epoch,
                    uint32_t *sequence,
                    vscp_ble_a2_key_t **rec);

/*!
  Find the A2 frame in a complete advertising data set and receive it
  (rejects ambiguous sets).
*/
int
vscp_ble_a2_receive_dataset(const vscp_ble_a2_receiver_t *rx,
                            const uint8_t *data,
                            size_t len,
                            vscp_ble_event_t *ev,
                            uint8_t *plain,
                            size_t plaincap,
                            uint32_t *epoch,
                            uint32_t *sequence,
                            vscp_ble_a2_key_t **rec);

#ifdef __cplusplus
}
#endif

#endif
