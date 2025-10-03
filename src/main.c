#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include "../include/ecc.h"
#include "../include/crypto_v.h"

void print_hex(const char *label, const uint8_t *data, size_t len) {
    printf("%s: ", label);
    for (size_t i = 0; i < len; i++) {
        printf("%02X", data[i]);
    }
    printf("\n");
}
void app_main() {
    uint8_t private_key[ECC_PRIVATE_KEY_SIZE];
    uint8_t public_key[ECC_PUBLIC_KEY_SIZE];
    uint8_t shared_secret[ECC_SHARED_SECRET_SIZE];
    uint8_t signature[ECC_SIGNATURE_SIZE];

    const char *message = "Hello, ECC!";
    uint8_t ciphertext[256];
    uint8_t decrypted[256];
    uint8_t ephemeral_pub[ECC_PUBLIC_KEY_SIZE];
    size_t ct_len = 0, pt_len = 0;


    if (!ecc_generate_keypair(public_key, private_key)) {
        printf("Key pair generation failed\n");
        return; // just return, no value
    }

    print_hex("Private Key", private_key, ECC_PRIVATE_KEY_SIZE);
    print_hex("Public Key", public_key, ECC_PUBLIC_KEY_SIZE);

    if (!ecc_sign(private_key, (const uint8_t *)message, strlen(message), signature)) {
        printf("Signing failed\n");
        return;
    }
    print_hex("Signature", signature, ECC_SIGNATURE_SIZE);

    if (ecc_verify(public_key, (const uint8_t *)message, strlen(message), signature)) {
        printf("Signature is valid\n");
    } else {
        printf("Signature is invalid\n");
    }

    if (!ecc_shared_secret(private_key, public_key, shared_secret)) {
        printf("Shared secret computation failed\n");
        return;
    }
    print_hex("Shared Secret", shared_secret, ECC_SHARED_SECRET_SIZE);
    
    if (!crypto_ecies_encrypt(public_key, (const uint8_t *)message, strlen(message),
                        ephemeral_pub, ciphertext, &ct_len)) {
        printf("Encryption failed\n");
        return;
    }
    print_hex("Ephemeral Public Key", ephemeral_pub, ECC_PUBLIC_KEY_SIZE);
    print_hex("Ciphertext", ciphertext, ct_len);

    if (!crypto_ecies_decrypt(private_key, ephemeral_pub, ciphertext, ct_len, decrypted, &pt_len)) {
        printf("Decryption failed\n");
        return;
    }

    if (pt_len < sizeof(decrypted)) {
        decrypted[pt_len] = '\0';
    } else {
        decrypted[sizeof(decrypted) - 1] = '\0';
    }

    printf("Decrypted Message: %s\n", decrypted);

}