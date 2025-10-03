#ifndef CRYPTO_H
#define CRYPTO_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include "ecc.h" 

#define AES_KEY_SIZE 32
#define AES_IV_SIZE 16

bool crypto_ecies_encrypt(const uint8_t receiver_pub[ECC_PUBLIC_KEY_SIZE],
                          const uint8_t *plaintext, size_t plaintext_len,
                          uint8_t *ephemeral_pub, uint8_t *ciphertext, size_t *ciphertext_len);

bool crypto_ecies_decrypt(const uint8_t receiver_priv[ECC_PRIVATE_KEY_SIZE],
                          const uint8_t ephemeral_pub[ECC_PUBLIC_KEY_SIZE],
                          const uint8_t *ciphertext, size_t ciphertext_len,
                          uint8_t *plaintext, size_t *plaintext_len);

#endif // CRYPTO_H
