#include "../include/crypto_v.h"
#include <string.h>
#include "../lib/micro-ecc/uECC.h"
#include "mbedtls/aes.h"
#include "mbedtls/sha256.h"
#include <stdio.h>
#include <stddef.h>
// Simple KDF: SHA256(shared_secret) -> AES key
static void derive_aes_key(const uint8_t shared_secret[ECC_SHARED_SECRET_SIZE],
                           uint8_t key[AES_KEY_SIZE]) {
    mbedtls_sha256(shared_secret, ECC_SHARED_SECRET_SIZE, key, 0); // 0 = SHA-256
}

// ECIES Encrypt
bool crypto_ecies_encrypt(const uint8_t receiver_pub[ECC_PUBLIC_KEY_SIZE],
                          const uint8_t *plaintext, size_t plaintext_len,
                          uint8_t *ephemeral_pub, uint8_t *ciphertext, size_t *ciphertext_len) {

    uint8_t ephemeral_priv[ECC_PRIVATE_KEY_SIZE];
    uint8_t shared_secret[ECC_SHARED_SECRET_SIZE];
    uint8_t aes_key[AES_KEY_SIZE];
    uint8_t iv[AES_IV_SIZE] = {0}; // simple IV, can be randomized

    // Generate ephemeral key
    if (!ecc_generate_keypair(ephemeral_pub, ephemeral_priv)) return false;

    // Debug: print ephemeral keys
    printf("Ephemeral private key: ");
    for (int i = 0; i < ECC_PRIVATE_KEY_SIZE; i++) {
        printf("%02X", ephemeral_priv[i]);
    }
    printf("\n");
    
    printf("Ephemeral public key: ");
    for (int i = 0; i < ECC_PUBLIC_KEY_SIZE; i++) {
        printf("%02X", ephemeral_pub[i]);
    }
    printf("\n");
    
    // Debug: print receiver public key
    printf("Receiver public key: ");
    for (int i = 0; i < ECC_PUBLIC_KEY_SIZE; i++) {
        printf("%02X", receiver_pub[i]);
    }
    printf("\n");

    // Compute shared secret
    printf("Computing shared secret for encryption...\n");
    if (!ecc_shared_secret(ephemeral_priv, receiver_pub, shared_secret)) return false;
    
    // Debug: print shared secret
    printf("Shared secret: ");
    for (int i = 0; i < ECC_SHARED_SECRET_SIZE; i++) {
        printf("%02X", shared_secret[i]);
    }
    printf("\n");

    // Derive AES key
    derive_aes_key(shared_secret, aes_key);
    
    // Debug: print AES key
    printf("AES key: ");
    for (int i = 0; i < AES_KEY_SIZE; i++) {
        printf("%02X", aes_key[i]);
    }
    printf("\n");

    // AES encrypt
    mbedtls_aes_context aes;
    mbedtls_aes_init(&aes);
    if (mbedtls_aes_setkey_enc(&aes, aes_key, AES_KEY_SIZE * 8) != 0) return false;

    // Simple CBC encryption (plaintext must be multiple of 16, pad if needed)
    size_t padded_len = ((plaintext_len + 15) / 16) * 16;
    uint8_t buf[padded_len];
    memcpy(buf, plaintext, plaintext_len);
    memset(buf + plaintext_len, padded_len - plaintext_len, padded_len - plaintext_len); // PKCS7 padding

    if (mbedtls_aes_crypt_cbc(&aes, MBEDTLS_AES_ENCRYPT, padded_len, iv, buf, ciphertext) != 0) return false;
    mbedtls_aes_free(&aes);

    *ciphertext_len = padded_len;
    return true;
}

// ECIES Decrypt
bool crypto_ecies_decrypt(const uint8_t receiver_priv[ECC_PRIVATE_KEY_SIZE],
                          const uint8_t ephemeral_pub[ECC_PUBLIC_KEY_SIZE],
                          const uint8_t *ciphertext, size_t ciphertext_len,
                          uint8_t *plaintext, size_t *plaintext_len) {

    uint8_t shared_secret[ECC_SHARED_SECRET_SIZE];
    uint8_t aes_key[AES_KEY_SIZE];
    uint8_t iv[AES_IV_SIZE] = {0};

    // Compute shared secret
    if (!ecc_shared_secret(receiver_priv, ephemeral_pub, shared_secret)) return false;

    // Derive AES key
    derive_aes_key(shared_secret, aes_key);

    // AES decrypt
    mbedtls_aes_context aes;
    mbedtls_aes_init(&aes);
    if (mbedtls_aes_setkey_dec(&aes, aes_key, AES_KEY_SIZE * 8) != 0) return false;

    if (mbedtls_aes_crypt_cbc(&aes, MBEDTLS_AES_DECRYPT, ciphertext_len, iv, ciphertext, plaintext) != 0) return false;
    mbedtls_aes_free(&aes);

    // Remove PKCS7 padding
    uint8_t pad = plaintext[ciphertext_len - 1];
    if (pad > 16) return false; // invalid padding
    *plaintext_len = ciphertext_len - pad;

    return true;
}
