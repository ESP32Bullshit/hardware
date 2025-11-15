#ifndef UTILS_H
#define UTILS_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

void bytes_to_hex(const uint8_t *in, size_t inlen, char *out, size_t outlen);
bool hex_to_bytes(const char *hex, uint8_t *out, size_t outlen);
void print_hex(const char *label, const uint8_t *data, size_t len);

#endif // UTILS_H
