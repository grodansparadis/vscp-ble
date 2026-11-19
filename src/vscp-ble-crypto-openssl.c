/*
 * vscp-ble-crypto-openssl.c - AES-128-CCM with OpenSSL EVP
 *
 * The MIT License (MIT)
 * Copyright (c) 2000-2026 Ake Hedman, the VSCP Project <info@grodansparadis.com>
 */

#include <string.h>

#include <openssl/crypto.h>
#include <openssl/evp.h>

#include "vscp-ble-crypto.h"

static int
ccm(int enc,
    const uint8_t key[16],
    const uint8_t nonce[13],
    const uint8_t *aad,
    size_t aadlen,
    const uint8_t *in,
    size_t len,
    uint8_t *out,
    uint8_t tag[16])
{
  int rv        = VSCP_BLE_ERR_CRYPTO;
  int outl      = 0;
  uint8_t dummy = 0;
  if (0 == len) {
    // A NULL output buffer means AAD to OpenSSL: never pass NULL for the data
    in  = &dummy;
    out = &dummy;
  }
  EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
  if (NULL == ctx) {
    return VSCP_BLE_ERR_CRYPTO;
  }
  if ((1 != EVP_CipherInit_ex(ctx, EVP_aes_128_ccm(), NULL, NULL, NULL, enc)) ||
      (1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN, 13, NULL)) ||
      (1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, 16, enc ? NULL : (void *) tag)) ||
      (1 != EVP_CipherInit_ex(ctx, NULL, NULL, key, nonce, enc)) ||
      // CCM needs the total length before the AAD
      (1 != EVP_CipherUpdate(ctx, NULL, &outl, NULL, (int) len)) ||
      (aadlen && (1 != EVP_CipherUpdate(ctx, NULL, &outl, aad, (int) aadlen)))) {
    goto done;
  }
  // For decryption this also verifies the tag
  if (1 != EVP_CipherUpdate(ctx, out, &outl, in, (int) len)) {
    rv = enc ? VSCP_BLE_ERR_CRYPTO : VSCP_BLE_ERR_AUTH;
    goto done;
  }
  if (enc && (1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, 16, tag))) {
    goto done;
  }
  rv = VSCP_BLE_OK;
done:
  EVP_CIPHER_CTX_free(ctx);
  return rv;
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
  return ccm(1, key, nonce, aad, aadlen, plaintext, len, ciphertext, tag);
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
  int rv = ccm(0, key, nonce, aad, aadlen, ciphertext, len, plaintext, (uint8_t *) tag);
  if (VSCP_BLE_OK != rv) {
    vscp_ble_secure_zero(plaintext, len);
  }
  return rv;
}

const char *
vscp_ble_crypto_backend(void)
{
  return "openssl";
}

void
vscp_ble_secure_zero(void *p, size_t n)
{
  OPENSSL_cleanse(p, n);
}
