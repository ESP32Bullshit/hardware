#ifndef ECC_H
#define ECC_H

#include <stdint.h>
#include <stdbool.h>
#include "../lib/micro-ecc/uECC.h"
// Forward declarations for micro-ECC
struct uECC_Curve_t;
typedef const struct uECC_Curve_t * uECC_Curve;

// Function to get the curve (defined in implementation)
uECC_Curve uECC_secp256k1(void);

#define ECC_CURVE uECC_secp256k1()

#define ECC_PRIVATE_KEY_SIZE 32
#define ECC_PUBLIC_KEY_SIZE 64
#define ECC_SIGNATURE_SIZE 64
#define ECC_SHARED_SECRET_SIZE 32

void ecc_init(void);

bool ecc_generate_keypair(uint8_t pub[ECC_PUBLIC_KEY_SIZE], uint8_t priv[ECC_PRIVATE_KEY_SIZE]);

bool ecc_sign(const uint8_t priv[ECC_PRIVATE_KEY_SIZE], const uint8_t  *msg, unsigned msg_len, uint8_t sig[ECC_SIGNATURE_SIZE]);

bool ecc_verify(const uint8_t pub[ECC_PUBLIC_KEY_SIZE], const uint8_t *msg, unsigned msg_len, const uint8_t sig[ECC_SIGNATURE_SIZE]);

bool ecc_shared_secret(const uint8_t priv[ECC_PRIVATE_KEY_SIZE], const uint8_t pub[ECC_PUBLIC_KEY_SIZE], uint8_t secret[ECC_SHARED_SECRET_SIZE]);

#endif // ECC_H