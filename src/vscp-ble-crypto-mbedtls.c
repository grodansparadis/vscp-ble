/*
 * vscp-ble-crypto-mbedtls.c - AES-128-CCM with Mbed TLS 2.x/3.x
 *
 * The MIT License (MIT)
 * Copyright (c) 2000-2026 Ake Hedman, the VSCP Project <info@grodansparadis.com>
 */

#include <string.h>

#include <mbedtls/ccm.h>
#include <mbedtls/platform_util.h>

#include "vscp-ble-crypto.h"

static int
setkey(mbedtls_ccm_context *ctx, const uint8_t key[16])
{
  mbedtls_ccm_init(ctx);
  return (0 == mbedtls_ccm_setkey(ctx, MBEDTLS_CIPHER_ID_AES, key, 128)) ? VSCP_BLE_OK : VSCP_BLE_ERR_CRYPTO;
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
  mbedtls_ccm_context ctx;
  int rv = setkey(&ctx, key);
  if ((VSCP_BLE_OK == rv) &&
      (0 != mbedtls_ccm_encrypt_and_tag(&ctx, len, nonce, 13, aad, aadlen, plaintext, ciphertext, tag, 16))) {
    rv = VSCP_BLE_ERR_CRYPTO;
  }
  mbedtls_ccm_free(&ctx);
  return rv;
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
  mbedtls_ccm_context ctx;
  int rv = setkey(&ctx, key);
  if (VSCP_BLE_OK == rv) {
    int ret = mbedtls_ccm_auth_decrypt(&ctx, len, nonce, 13, aad, aadlen, ciphertext, plaintext, tag, 16);
    if (MBEDTLS_ERR_CCM_AUTH_FAILED == ret) {
      rv = VSCP_BLE_ERR_AUTH;
    }
    else if (0 != ret) {
      rv = VSCP_BLE_ERR_CRYPTO;
    }
  }
  mbedtls_ccm_free(&ctx);
  if (VSCP_BLE_OK != rv) {
    vscp_ble_secure_zero(plaintext, len);
  }
  return rv;
}

const char *
vscp_ble_crypto_backend(void)
{
  return "mbedtls";
}

void
vscp_ble_secure_zero(void *p, size_t n)
{
  mbedtls_platform_zeroize(p, n);
}
