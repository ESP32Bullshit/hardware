#include <stdio.h>
#include <string.h>
#include "../include/utils.h"

/* ---------- helper: hex encode/decode ---------- */
void bytes_to_hex(const uint8_t *in, size_t inlen, char *out, size_t outlen)
{
    const char hex[] = "0123456789ABCDEF";
    for (size_t i = 0; i < inlen && (i*2+1) < outlen; i++) {
        out[i*2]   = hex[(in[i] >> 4) & 0xF];
        out[i*2+1] = hex[in[i] & 0xF];
    }
    if (outlen > 0) out[inlen*2 < outlen ? inlen*2 : outlen-1] = '\0';
}

bool hex_to_bytes(const char *hex, uint8_t *out, size_t outlen)
{
    size_t hexlen = strlen(hex);
    if (hexlen % 2 != 0) return false;
    size_t need = hexlen/2;
    if (need > outlen) return false;
    for (size_t i = 0; i < need; i++) {
        char hi = hex[i*2];
        char lo = hex[i*2+1];
        int hi_val, lo_val;
        if (hi >= '0' && hi <= '9') hi_val = hi - '0';
        else if (hi >= 'a' && hi <= 'f') hi_val = 10 + (hi - 'a');
        else if (hi >= 'A' && hi <= 'F') hi_val = 10 + (hi - 'A');
        else return false;

        if (lo >= '0' && lo <= '9') lo_val = lo - '0';
        else if (lo >= 'a' && lo <= 'f') lo_val = 10 + (lo - 'a');
        else if (lo >= 'A' && lo <= 'F') lo_val = 10 + (lo - 'A');
        else return false;

        out[i] = (uint8_t)((hi_val << 4) | lo_val);
    }
    return true;
}

/* ---------- Helper to print hex ---------- */
void print_hex(const char *label, const uint8_t *data, size_t len) {
    printf("%s: ", label);
    for (size_t i = 0; i < len; i++) printf("%02X", data[i]);
    printf("\n");
}
