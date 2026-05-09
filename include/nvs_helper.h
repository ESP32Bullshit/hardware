#ifndef NVS_HELPER_H
#define NVS_HELPER_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

void store_keys_in_nvs(uint8_t *public_key, size_t pub_len, uint8_t *private_key, size_t priv_len);
bool load_keys_from_nvs(uint8_t *public_key, size_t pub_len, uint8_t *private_key, size_t priv_len);
bool store_peer_publickey(const char *user_id, const char *receiver_id, const uint8_t *pub, size_t pub_len);
bool load_peer_publickey(const char *user_id, const char *receiver_id, uint8_t *out, size_t out_len);
bool store_device_uid(const char *uid);
bool load_device_uid(char *uid_out, size_t max_len);

#endif // NVS_HELPER_H
