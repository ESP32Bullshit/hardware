#include <stdio.h>
#include <string.h>
#include "nvs.h"
#include "nvs_flash.h"
#include "esp_log.h"
#include "../include/nvs_helper.h"

static const char *TAG = "nvs_helper";

/* ---------- helper: hash for NVS key shortening ---------- */
static uint32_t fnv1a_hash32(const char *s)
{
    uint32_t hash = 0x811C9DC5u; // FNV offset basis
    while (*s) {
        hash ^= (uint8_t)(*s++);
        hash *= 0x01000193u; // FNV prime
    }
    return hash;
}

/* ---------- NVS helpers for device keys ---------- */
void store_keys_in_nvs(uint8_t *public_key, size_t pub_len, uint8_t *private_key, size_t priv_len) {
    nvs_handle_t handle;
    esp_err_t err = nvs_open("ecc_keys", NVS_READWRITE, &handle);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "Error opening NVS handle!");
        return;
    }
    nvs_set_blob(handle, "public_key", public_key, pub_len);
    nvs_set_blob(handle, "private_key", private_key, priv_len);
    nvs_commit(handle);
    nvs_close(handle);
    ESP_LOGI(TAG, "Keys stored in NVS");
}

bool load_keys_from_nvs(uint8_t *public_key, size_t pub_len, uint8_t *private_key, size_t priv_len) {
    nvs_handle_t handle;
    esp_err_t err = nvs_open("ecc_keys", NVS_READONLY, &handle);
    if (err != ESP_OK) return false;
    size_t rlen = pub_len;
    if (nvs_get_blob(handle, "public_key", public_key, &rlen) != ESP_OK || rlen != pub_len) {
        nvs_close(handle);
        return false;
    }
    rlen = priv_len;
    if (nvs_get_blob(handle, "private_key", private_key, &rlen) != ESP_OK || rlen != priv_len) {
        nvs_close(handle);
        return false;
    }
    nvs_close(handle);
    return true;
}

/* ---------- NVS helpers for peer public keys ---------- */
bool store_peer_publickey(const char *user_id, const char *receiver_id, const uint8_t *pub, size_t pub_len)
{
    char keyname[16]; // short key to avoid NVS key too long
    char combined[128];
    snprintf(combined, sizeof(combined), "%s:%s", user_id, receiver_id);
    uint32_t h = fnv1a_hash32(combined);
    snprintf(keyname, sizeof(keyname), "p_%08lX", h);

    nvs_handle_t handle;
    if (nvs_open("peers", NVS_READWRITE, &handle) != ESP_OK) return false;
    if (nvs_set_blob(handle, keyname, pub, pub_len) != ESP_OK) {
        nvs_close(handle);
        return false;
    }
    nvs_commit(handle);
    nvs_close(handle);
    ESP_LOGI(TAG, "Stored peer public key for %s -> %s as %s", user_id, receiver_id, keyname);
    return true;
}

bool load_peer_publickey(const char *user_id, const char *receiver_id, uint8_t *out, size_t out_len)
{
    char keyname[16];
    char combined[128];
    snprintf(combined, sizeof(combined), "%s:%s", user_id, receiver_id);
    uint32_t h = fnv1a_hash32(combined);
    snprintf(keyname, sizeof(keyname), "p_%08lX", h);

    nvs_handle_t handle;
    if (nvs_open("peers", NVS_READONLY, &handle) != ESP_OK) return false;
    size_t rlen = out_len;
    esp_err_t err = nvs_get_blob(handle, keyname, out, &rlen);
    nvs_close(handle);
    return (err == ESP_OK && rlen == out_len);
}
