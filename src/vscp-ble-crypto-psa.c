/*
 * vscp-ble-crypto-psa.c - AES-128-CCM with the PSA Crypto API
 *
 * For ESP-IDF 6 (Mbed TLS 4), Zephyr and nRF Connect SDK (nrf_security),
 * which use hardware AES where available.
 *
 * The MIT License (MIT)
 * Copyright (c) 2000-2026 Ake Hedman, the VSCP Project <info@grodansparadis.com>
 */

#include <string.h>

#include <psa/crypto.h>

#include "vscp-ble-crypto.h"

// Largest message: G1 max event data plus room; A2 needs at most 200
#define CCM_MAX_LEN 512u

static int
import_key(const uint8_t key[16], psa_key_id_t *id)
{
  if (PSA_SUCCESS != psa_crypto_init()) {
    return VSCP_BLE_ERR_CRYPTO;
  }
  psa_key_attributes_t attr = PSA_KEY_ATTRIBUTES_INIT;
  psa_set_key_type(&attr, PSA_KEY_TYPE_AES);
  psa_set_key_bits(&attr, 128);
  psa_set_key_usage_flags(&attr, PSA_KEY_USAGE_ENCRYPT | PSA_KEY_USAGE_DECRYPT);
  psa_set_key_algorithm(&attr, PSA_ALG_CCM);
  psa_status_t st = psa_import_key(&attr, key, 16, id);
  psa_reset_key_attributes(&attr);
  return (PSA_SUCCESS == st) ? VSCP_BLE_OK : VSCP_BLE_ERR_CRYPTO;
}

int
vscp_ble_ccm_encrypt(const uint8_t key[16],
                     const uint8_t nonce[13],
                     const uint8_t *aad,
                     size_t aadlen,
                     const uint8_t *plaintext,
                     size_t len,
                     uint8_t *ciphertext,
                     uint8_t tag[16])
{
  if (len > CCM_MAX_LEN) {
    return VSCP_BLE_ERR_CRYPTO;
  }
  psa_key_id_t id;
  int rv = import_key(key, &id);
  if (VSCP_BLE_OK != rv) {
    return rv;
  }
  uint8_t out[CCM_MAX_LEN + 16];
  size_t outlen   = 0;
  psa_status_t st = psa_aead_encrypt(id, PSA_ALG_CCM, nonce, 13, aad, aadlen, plaintext, len, out, len + 16, &outlen);
  psa_destroy_key(id);
  if ((PSA_SUCCESS != st) || (len + 16 != outlen)) {
    vscp_ble_secure_zero(out, sizeof(out));
    return VSCP_BLE_ERR_CRYPTO;
  }
  memcpy(ciphertext, out, len);
  memcpy(tag, out + len, 16);
  vscp_ble_secure_zero(out, sizeof(out));
  return VSCP_BLE_OK;
}

int
vscp_ble_ccm_decrypt(const uint8_t key[16],
                     const uint8_t nonce[13],
                     const uint8_t *aad,
                     size_t aadlen,
                     const uint8_t *ciphertext,
                     size_t len,
                     const uint8_t tag[16],
                     uint8_t *plaintext)
{
  if (len > CCM_MAX_LEN) {
    return VSCP_BLE_ERR_CRYPTO;
  }
  psa_key_id_t id;
  int rv = import_key(key, &id);
  if (VSCP_BLE_OK != rv) {
    return rv;
  }
  uint8_t in[CCM_MAX_LEN + 16];
  memcpy(in, ciphertext, len);
  memcpy(in + len, tag, 16);
  size_t outlen   = 0;
  psa_status_t st = psa_aead_decrypt(id, PSA_ALG_CCM, nonce, 13, aad, aadlen, in, len + 16, plaintext, len, &outlen);
  psa_destroy_key(id);
  if (PSA_SUCCESS != st) {
    vscp_ble_secure_zero(plaintext, len);
    return (PSA_ERROR_INVALID_SIGNATURE == st) ? VSCP_BLE_ERR_AUTH : VSCP_BLE_ERR_CRYPTO;
  }
  return VSCP_BLE_OK;
}

const char *
vscp_ble_crypto_backend(void)
{
  return "psa";
}

void
vscp_ble_secure_zero(void *p, size_t n)
{
  volatile uint8_t *v = (volatile uint8_t *) p;
  while (n--) {
    *v++ = 0;
  }
}
