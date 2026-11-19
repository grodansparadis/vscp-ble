// test-crypto.cpp - AES-128-CCM backend
#include <gtest/gtest.h>

#include "test-util.h"
#include "vscp-ble-crypto.h"

// The A2 known-answer vectors (16-octet tag, 13-octet nonce) are in
// test-a2.cpp. Here: round trips over the block boundaries, tamper checks
// and one more known answer.

TEST(Crypto, RoundTripAndTamper)
{
  printf("backend: %s\n", vscp_ble_crypto_backend());
  uint8_t nonce[13] = { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13 };
  for (size_t aadlen : { (size_t) 0, (size_t) 1, (size_t) 14, (size_t) 49, (size_t) 100 }) {
    for (size_t len : { (size_t) 0, (size_t) 1, (size_t) 15, (size_t) 16, (size_t) 17, (size_t) 200 }) {
      bytes aad = ramp(aadlen), pt = ramp(len), ct(len + 1), back(len + 1);
      uint8_t tag[16];
      ASSERT_EQ(VSCP_BLE_OK, vscp_ble_ccm_encrypt(TEST_KEY, nonce, aad.data(), aadlen, pt.data(), len, ct.data(), tag));
      ASSERT_EQ(VSCP_BLE_OK,
                vscp_ble_ccm_decrypt(TEST_KEY, nonce, aad.data(), aadlen, ct.data(), len, tag, back.data()));
      EXPECT_TRUE((0 == len) || (0 == memcmp(pt.data(), back.data(), len)));
      tag[0] ^= 0x80;
      EXPECT_EQ(VSCP_BLE_ERR_AUTH,
                vscp_ble_ccm_decrypt(TEST_KEY, nonce, aad.data(), aadlen, ct.data(), len, tag, back.data()));
      tag[0] ^= 0x80;
      if (aadlen) {
        aad[aadlen - 1] ^= 1;
        EXPECT_EQ(VSCP_BLE_ERR_AUTH,
                  vscp_ble_ccm_decrypt(TEST_KEY, nonce, aad.data(), aadlen, ct.data(), len, tag, back.data()));
        aad[aadlen - 1] ^= 1;
      }
      if (len) {
        ct[len / 2] ^= 4;
        EXPECT_EQ(VSCP_BLE_ERR_AUTH,
                  vscp_ble_ccm_decrypt(TEST_KEY, nonce, aad.data(), aadlen, ct.data(), len, tag, back.data()));
        for (size_t i = 0; i < len; i++) {
          ASSERT_EQ(0, back[i]); // No unauthenticated plaintext released
        }
      }
    }
  }
}

// NIST SP 800-38C Appendix C Example 3 inputs (its ciphertext; the 16-octet
// tag computed with python3-cryptography, the example uses an 8-octet tag):
//   key 404142434445464748494a4b4c4d4e4f, nonce 101112131415161718191a1b1c,
//   aad 000102030405060708090a0b0c0d0e0f10111213, pt 202122232425262728292a2b2c2d2e2f3031323334353637
TEST(Crypto, IndependentKnownAnswer)
{
  uint8_t key[16], nonce[13], aad[20], pt[24], ct[24], tag[16];
  for (int i = 0; i < 16; i++)
    key[i] = (uint8_t) (0x40 + i);
  for (int i = 0; i < 13; i++)
    nonce[i] = (uint8_t) (0x10 + i);
  for (int i = 0; i < 20; i++)
    aad[i] = (uint8_t) i;
  for (int i = 0; i < 24; i++)
    pt[i] = (uint8_t) (0x20 + i);
  ASSERT_EQ(VSCP_BLE_OK, vscp_ble_ccm_encrypt(key, nonce, aad, 20, pt, 24, ct, tag));
  const uint8_t expect_ct[24]  = { 0x69, 0x91, 0x5d, 0xad, 0x1e, 0x84, 0xc6, 0x37, 0x6a, 0x68, 0xc2, 0x96,
                                   0x7e, 0x4d, 0xab, 0x61, 0x5a, 0xe0, 0xfd, 0x1f, 0xae, 0xc4, 0x4c, 0xc4 };
  const uint8_t expect_tag[16] = { 0x09, 0x86, 0x31, 0xcb, 0x0c, 0xd1, 0xe0, 0x31,
                                   0x53, 0xfb, 0x69, 0xa9, 0x06, 0xe2, 0xf1, 0x3c };
  EXPECT_EQ(0, memcmp(expect_ct, ct, 24));
  EXPECT_EQ(0, memcmp(expect_tag, tag, 16));
}
