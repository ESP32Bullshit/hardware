#include <stdio.h>
#include "../include/ecc.h"
#include "../lib/micro-ecc/uECC.h"
#include "esp_random.h"

// RNG function for ESP32
static int esp32_rng(uint8_t *dest, unsigned size) {
    esp_fill_random(dest, size);
    return 1; // success
}

void ecc_init(void) {
    uECC_set_rng(&esp32_rng);
}

bool ecc_generate_keypair(uint8_t pub[ECC_PUBLIC_KEY_SIZE], uint8_t priv[ECC_PRIVATE_KEY_SIZE]) {
    ecc_init(); // Ensure RNG is initialized
    return uECC_make_key(pub, priv, ECC_CURVE);
}

bool ecc_sign(const uint8_t priv[ECC_PRIVATE_KEY_SIZE], const uint8_t *msg, unsigned msg_len, uint8_t sig[ECC_SIGNATURE_SIZE]) {
    ecc_init(); // Ensure RNG is initialized
    // Arguments properly ordered to match uECC_sign signature
    return uECC_sign(priv, msg, msg_len, sig, ECC_CURVE);
}

bool ecc_verify(const uint8_t pub[ECC_PUBLIC_KEY_SIZE], const uint8_t *msg, unsigned msg_len, const uint8_t sig[ECC_SIGNATURE_SIZE]) {
    // Arguments reordered to match uECC_verify signature
    return uECC_verify(pub, msg, msg_len, sig, ECC_CURVE);
}

bool ecc_shared_secret(const uint8_t priv[ECC_PRIVATE_KEY_SIZE], const uint8_t pub[ECC_PUBLIC_KEY_SIZE], uint8_t secret[ECC_SHARED_SECRET_SIZE]) {
    // uECC_shared_secret expects: public_key, private_key, secret, curve
    return uECC_shared_secret(pub, priv, secret, ECC_CURVE);
}
