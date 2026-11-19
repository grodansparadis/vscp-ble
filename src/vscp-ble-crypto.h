/*
 * vscp-ble-crypto.h - AES-128-CCM for A2 (13-octet nonce, 16-octet tag)
 *
 * One backend is compiled in:
 *   vscp-ble-crypto-openssl.c   OpenSSL EVP (Linux, tests)
 *   vscp-ble-crypto-psa.c       PSA Crypto API (ESP-IDF 6, Zephyr, nRF Connect SDK)
 *   vscp-ble-crypto-mbedtls.c   Mbed TLS 2/3 CCM (ESP-IDF 5 and others)
 *   vscp-ble-crypto-reference.c       Portable reference (RFC 3610). For tests and
 *                               cross-checks: its AES uses table lookups and
 *                               is not hardened against timing attacks. Use a
 *                               vetted/hardware backend in products.
 *
 * The MIT License (MIT)
 * Copyright (c) 2000-2026 Ake Hedman, the VSCP Project <info@grodansparadis.com>
 */

#ifndef VSCP_BLE_CRYPTO_H
#define VSCP_BLE_CRYPTO_H

#include "vscp-ble.h"

#ifdef __cplusplus
extern "C" {
#endif

#define VSCP_BLE_CCM_KEY_SIZE   16u
#define VSCP_BLE_CCM_NONCE_SIZE 13u
#define VSCP_BLE_CCM_TAG_SIZE   16u

/*!
  Encrypt len octets and compute the 16-octet tag over aad and the plaintext.
  @return VSCP_BLE_OK or VSCP_BLE_ERR_CRYPTO.
*/
int
vscp_ble_ccm_encrypt(const uint8_t key[16],
                     const uint8_t nonce[13],
                     const uint8_t *aad,
                     size_t aadlen,
                     const uint8_t *plaintext,
                     size_t len,
                     uint8_t *ciphertext,
                     uint8_t tag[16]);

/*!
  Verify the tag and decrypt. The plaintext buffer holds nothing usable (it
  is cleared) unless VSCP_BLE_OK is returned.
  @return VSCP_BLE_OK, VSCP_BLE_ERR_AUTH or VSCP_BLE_ERR_CRYPTO.
*/
int
vscp_ble_ccm_decrypt(const uint8_t key[16],
                     const uint8_t nonce[13],
                     const uint8_t *aad,
                     size_t aadlen,
                     const uint8_t *ciphertext,
                     size_t len,
                     const uint8_t tag[16],
                     uint8_t *plaintext);

/// Name of the compiled-in backend ("openssl", "psa", "mbedtls", "reference")
const char *
vscp_ble_crypto_backend(void);

/// Clear sensitive memory (not optimized away)
void
vscp_ble_secure_zero(void *p, size_t n);

#ifdef __cplusplus
}
#endif

#endif
