// #include <stdio.h>
// #include <stdint.h>
// #include <string.h>
// #include <stdlib.h>
// #include"freertos/FreeRTOS.h"
// #include"freertos/task.h"
// #include "esp_wifi.h"
// #include "esp_event.h"
// #include "nvs_flash.h"
// #include "esp_netif.h"
// #include "esp_system.h"
// #include "esp_log.h"
// #include "esp_http_server.h"
// #include "esp_timer.h"
// #include "nvs.h"
// #include "../include/ecc.h"
// #include "../include/crypto_v.h"
// #include "cJSON.h"     // make sure cJSON is available in your project

// #define AP_SSID "KISUKE"
// #define AP_PASSWORD "12345678"

// static const char *TAG = "wifi_ap";

// /* ---------- helper: hex encode/decode ---------- */
// static void bytes_to_hex(const uint8_t *in, size_t inlen, char *out, size_t outlen)
// {
//     // outlen must be >= inlen*2 + 1
//     const char hex[] = "0123456789ABCDEF";
//     for (size_t i = 0; i < inlen && (i*2+1) < outlen; i++) {
//         out[i*2]   = hex[(in[i] >> 4) & 0xF];
//         out[i*2+1] = hex[in[i] & 0xF];
//     }
//     if (outlen > 0) out[inlen*2 < outlen ? inlen*2 : outlen-1] = '\0';
// }

// static bool hex_to_bytes(const char *hex, uint8_t *out, size_t outlen)
// {
//     size_t hexlen = strlen(hex);
//     if (hexlen % 2 != 0) return false;
//     size_t need = hexlen/2;
//     if (need > outlen) return false;
//     for (size_t i = 0; i < need; i++) {
//         char hi = hex[i*2];
//         char lo = hex[i*2+1];
//         int hi_val, lo_val;
//         if (hi >= '0' && hi <= '9') hi_val = hi - '0';
//         else if (hi >= 'a' && hi <= 'f') hi_val = 10 + (hi - 'a');
//         else if (hi >= 'A' && hi <= 'F') hi_val = 10 + (hi - 'A');
//         else return false;

//         if (lo >= '0' && lo <= '9') lo_val = lo - '0';
//         else if (lo >= 'a' && lo <= 'f') lo_val = 10 + (lo - 'a');
//         else if (lo >= 'A' && lo <= 'F') lo_val = 10 + (lo - 'A');
//         else return false;

//         out[i] = (uint8_t)((hi_val << 4) | lo_val);
//     }
//     return true;
// }
// /* ------------------------------------------------ */

// static void wifi_init_softap(void) {
//     esp_netif_init();
//     esp_event_loop_create_default();
//     esp_netif_create_default_wifi_ap();
//     wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
//     esp_wifi_init(&cfg);
//     esp_wifi_set_mode(WIFI_MODE_AP);
//     wifi_config_t wifi_config = {
//         .ap = {
//             .ssid = AP_SSID,
//             .ssid_len = strlen(AP_SSID),
//             .password = AP_PASSWORD,
//             .max_connection = 1,
//             .authmode = WIFI_AUTH_WPA_WPA2_PSK
//         },
//     };
//     if (strlen(AP_PASSWORD) == 0) {
//         wifi_config.ap.authmode = WIFI_AUTH_OPEN;
//     }
//     esp_wifi_set_config(ESP_IF_WIFI_AP, &wifi_config);
//     esp_wifi_start();
//     ESP_LOGI(TAG, "WiFi AP started. SSID:%s password:%s", AP_SSID, AP_PASSWORD);
// }

// // API
// esp_err_t hello_get_handler(httpd_req_t *req) {
//     const char resp[] = "Hello, World!";
//     httpd_resp_send(req, resp, HTTPD_RESP_USE_STRLEN);
//     return ESP_OK;
// }

// esp_err_t status_get_handler(httpd_req_t *req) {
//     char resp[128];
//     snprintf(resp, sizeof(resp), "Device is running. Free heap: %ld bytes", esp_get_free_heap_size());
//     httpd_resp_set_type(req, "application/json");
//     httpd_resp_send(req, resp, HTTPD_RESP_USE_STRLEN);
//     return ESP_OK;
// }

// /* ---------- NVS helpers for device keys and peers ---------- */
// void store_keys_in_nvs(uint8_t *public_key, size_t pub_len, uint8_t *private_key, size_t priv_len) {
//     nvs_handle_t handle;
//     esp_err_t err = nvs_open("ecc_keys", NVS_READWRITE, &handle);
//     if (err != ESP_OK) {
//         ESP_LOGE(TAG, "Error opening NVS handle!");
//         return;
//     }

//     // Store public key
//     err = nvs_set_blob(handle, "public_key", public_key, pub_len);
//     if (err != ESP_OK) {
//         ESP_LOGE(TAG, "Failed to write public key: %s", esp_err_to_name(err));
//     }

//     // Store private key
//     err = nvs_set_blob(handle, "private_key", private_key, priv_len);
//     if (err != ESP_OK) {
//         ESP_LOGE(TAG, "Failed to write private key: %s", esp_err_to_name(err));
//     }

//     // Commit changes
//     nvs_commit(handle);
//     nvs_close(handle);
//     ESP_LOGI(TAG, "Keys stored in NVS");
// }

// bool load_keys_from_nvs(uint8_t *public_key, size_t pub_len, uint8_t *private_key, size_t priv_len) {
//     nvs_handle_t handle;
//     esp_err_t err = nvs_open("ecc_keys", NVS_READONLY, &handle);
//     if (err != ESP_OK) {
//         ESP_LOGW(TAG, "No ECC keys found in NVS");
//         return false;
//     }

//     size_t required_len = pub_len;
//     err = nvs_get_blob(handle, "public_key", public_key, &required_len);
//     if (err != ESP_OK || required_len != pub_len) {
//         ESP_LOGW(TAG, "Public key not found or wrong size");
//         nvs_close(handle);
//         return false;
//     }

//     required_len = priv_len;
//     err = nvs_get_blob(handle, "private_key", private_key, &required_len);
//     if (err != ESP_OK || required_len != priv_len) {
//         ESP_LOGW(TAG, "Private key not found or wrong size");
//         nvs_close(handle);
//         return false;
//     }

//     nvs_close(handle);
//     ESP_LOGI(TAG, "Keys loaded from NVS");
//     return true;
// }

// /* store peer's public key under key: peer_<user_id>_<receiver_id> */
// bool store_peer_publickey(const char *user_id, const char *receiver_id, const uint8_t *pub, size_t pub_len)
// {
//     char keyname[64];
//     snprintf(keyname, sizeof(keyname), "peer_%s_%s", user_id, receiver_id);
//     nvs_handle_t handle;
//     esp_err_t err = nvs_open("peers", NVS_READWRITE, &handle);
//     if (err != ESP_OK) {
//         ESP_LOGE(TAG, "Failed to open peers NVS: %s", esp_err_to_name(err));
//         return false;
//     }
//     err = nvs_set_blob(handle, keyname, pub, pub_len);
//     if (err != ESP_OK) {
//         ESP_LOGE(TAG, "Failed to write peer blob: %s", esp_err_to_name(err));
//         nvs_close(handle);
//         return false;
//     }
//     nvs_commit(handle);
//     nvs_close(handle);
//     ESP_LOGI(TAG, "Stored peer public key for %s -> %s", user_id, receiver_id);
//     return true;
// }

// bool load_peer_publickey(const char *user_id, const char *receiver_id, uint8_t *out, size_t out_len)
// {
//     char keyname[64];
//     snprintf(keyname, sizeof(keyname), "peer_%s_%s", user_id, receiver_id);
//     nvs_handle_t handle;
//     esp_err_t err = nvs_open("peers", NVS_READONLY, &handle);
//     if (err != ESP_OK) {
//         ESP_LOGW(TAG, "No peers namespace");
//         return false;
//     }
//     size_t required = out_len;
//     err = nvs_get_blob(handle, keyname, out, &required);
//     nvs_close(handle);
//     if (err != ESP_OK || required != out_len) {
//         ESP_LOGW(TAG, "Peer key not found or wrong size: %s", esp_err_to_name(err));
//         return false;
//     }
//     return true;
// }

// /* ---------- HTTP helpers ---------- */
// static int http_read_body(httpd_req_t *req, char **buf, size_t *buf_len)
// {
//     // allocate a buffer large enough for the content
//     size_t content_len = req->content_len;
//     if (content_len == 0) {
//         *buf = NULL;
//         *buf_len = 0;
//         return 0;
//     }
//     char *body = malloc(content_len + 1);
//     if (!body) return -1;
//     size_t received = 0;
//     while (received < content_len) {
//         int ret = httpd_req_recv(req, body + received, content_len - received);
//         if (ret <= 0) {
//             free(body);
//             return -1;
//         }
//         received += ret;
//     }
//     body[content_len] = '\0';
//     *buf = body;
//     *buf_len = content_len;
//     return 0;
// }

// /* ---------- /api/public_key (GET) ---------- */
// esp_err_t public_key_get_handler(httpd_req_t *req)
// {
//     uint8_t device_pub[ECC_PUBLIC_KEY_SIZE];
//     uint8_t device_priv[ECC_PRIVATE_KEY_SIZE];

//     if (!load_keys_from_nvs(device_pub, sizeof(device_pub), device_priv, sizeof(device_priv))) {
//         httpd_resp_set_status(req, "500 Internal Server Error");
//         httpd_resp_sendstr(req, "{\"error\":\"device keys not available\"}");
//         return ESP_FAIL;
//     }

//     char hexpub[ECC_PUBLIC_KEY_SIZE * 2 + 1];
//     bytes_to_hex(device_pub, sizeof(device_pub), hexpub, sizeof(hexpub));

//     // create simple JSON manually
//     char resp[ ECC_PUBLIC_KEY_SIZE*2 + 64 ];
//     snprintf(resp, sizeof(resp), "{\"public_key\":\"%s\"}", hexpub);
//     httpd_resp_set_type(req, "application/json");
//     httpd_resp_send(req, resp, HTTPD_RESP_USE_STRLEN);
//     return ESP_OK;
// }

// /* ---------- /api/store_peer (POST)
//    Expected JSON:
//    {
//      "user_id":"alice",
//      "receiver_id":"server1",
//      "receiver_public_key":"ABCDEF... (hex, uppercase or lowercase)"
//    }
// */
// esp_err_t store_peer_post_handler(httpd_req_t *req)
// {
//     char *body = NULL;
//     size_t blen = 0;
//     if (http_read_body(req, &body, &blen) != 0) {
//         httpd_resp_set_status(req, "400 Bad Request");
//         httpd_resp_sendstr(req, "{\"error\":\"unable to read body\"}");
//         return ESP_FAIL;
//     }

//     cJSON *root = cJSON_Parse(body);
//     free(body);
//     if (!root) {
//         httpd_resp_set_status(req, "400 Bad Request");
//         httpd_resp_sendstr(req, "{\"error\":\"invalid json\"}");
//         return ESP_FAIL;
//     }
//     const cJSON *j_user = cJSON_GetObjectItem(root, "user_id");
//     const cJSON *j_receiver = cJSON_GetObjectItem(root, "receiver_id");
//     const cJSON *j_pub = cJSON_GetObjectItem(root, "receiver_public_key");
//     if (!cJSON_IsString(j_user) || !cJSON_IsString(j_receiver) || !cJSON_IsString(j_pub)) {
//         cJSON_Delete(root);
//         httpd_resp_set_status(req, "400 Bad Request");
//         httpd_resp_sendstr(req, "{\"error\":\"missing fields\"}");
//         return ESP_FAIL;
//     }

//     const char *user_id = j_user->valuestring;
//     const char *receiver_id = j_receiver->valuestring;
//     const char *pub_hex = j_pub->valuestring;

//     uint8_t peer_pub[ECC_PUBLIC_KEY_SIZE];
//     if (!hex_to_bytes(pub_hex, peer_pub, sizeof(peer_pub))) {
//         cJSON_Delete(root);
//         httpd_resp_set_status(req, "400 Bad Request");
//         httpd_resp_sendstr(req, "{\"error\":\"invalid public key hex\"}");
//         return ESP_FAIL;
//     }

//     if (!store_peer_publickey(user_id, receiver_id, peer_pub, sizeof(peer_pub))) {
//         cJSON_Delete(root);
//         httpd_resp_set_status(req, "500 Internal Server Error");
//         httpd_resp_sendstr(req, "{\"error\":\"failed to store peer\"}");
//         return ESP_FAIL;
//     }

//     cJSON_Delete(root);
//     httpd_resp_set_type(req, "application/json");
//     httpd_resp_sendstr(req, "{\"status\":\"ok\"}");
//     return ESP_OK;
// }

// /* ---------- /api/send_location (POST)
//    Expected JSON:
//    {
//      "user_id":"alice",
//      "receiver_id":"server1",
//      "lat":12.3456,
//      "lon":78.9012
//    }

//    What this handler does:
//    - loads device keys from NVS
//    - loads receiver public key from NVS
//    - builds a plaintext JSON payload for coordinates + timestamp
//    - signs the plaintext with device private key (ecc_sign)
//    - encrypts plaintext using receiver public key (crypto_ecies_encrypt) -> ciphertext + ephemeral pub
//    - prints ephemeral pub, ciphertext, signature (hex)
//    - (commented) shows where you'd send via LoRa
//    - returns a JSON with status + printed hex strings for debugging
// */
// esp_err_t send_location_post_handler(httpd_req_t *req)
// {
//     char *body = NULL;
//     size_t blen = 0;
//     if (http_read_body(req, &body, &blen) != 0) {
//         httpd_resp_set_status(req, "400 Bad Request");
//         httpd_resp_sendstr(req, "{\"error\":\"unable to read body\"}");
//         return ESP_FAIL;
//     }

//     cJSON *root = cJSON_Parse(body);
//     free(body);
//     if (!root) {
//         httpd_resp_set_status(req, "400 Bad Request");
//         httpd_resp_sendstr(req, "{\"error\":\"invalid json\"}");
//         return ESP_FAIL;
//     }

//     const cJSON *j_user = cJSON_GetObjectItem(root, "user_id");
//     const cJSON *j_receiver = cJSON_GetObjectItem(root, "receiver_id");
//     const cJSON *j_lat = cJSON_GetObjectItem(root, "lat");
//     const cJSON *j_lon = cJSON_GetObjectItem(root, "lon");
//     if (!cJSON_IsString(j_user) || !cJSON_IsString(j_receiver) || !cJSON_IsNumber(j_lat) || !cJSON_IsNumber(j_lon)) {
//         cJSON_Delete(root);
//         httpd_resp_set_status(req, "400 Bad Request");
//         httpd_resp_sendstr(req, "{\"error\":\"missing fields\"}");
//         return ESP_FAIL;
//     }

//     const char *user_id = j_user->valuestring;
//     const char *receiver_id = j_receiver->valuestring;
//     double lat = j_lat->valuedouble;
//     double lon = j_lon->valuedouble;

//     // load device keys
//     uint8_t device_pub[ECC_PUBLIC_KEY_SIZE];
//     uint8_t device_priv[ECC_PRIVATE_KEY_SIZE];
//     if (!load_keys_from_nvs(device_pub, sizeof(device_pub), device_priv, sizeof(device_priv))) {
//         cJSON_Delete(root);
//         httpd_resp_set_status(req, "500 Internal Server Error");
//         httpd_resp_sendstr(req, "{\"error\":\"device keys not available\"}");
//         return ESP_FAIL;
//     }

//     // load receiver pub
//     uint8_t recv_pub[ECC_PUBLIC_KEY_SIZE];
//     if (!load_peer_publickey(user_id, receiver_id, recv_pub, sizeof(recv_pub))) {
//         cJSON_Delete(root);
//         httpd_resp_set_status(req, "400 Bad Request");
//         httpd_resp_sendstr(req, "{\"error\":\"receiver public key not found\"}");
//         return ESP_FAIL;
//     }

//     // build plaintext JSON payload to encrypt and sign
//     cJSON *payload = cJSON_CreateObject();
//     cJSON_AddStringToObject(payload, "user_id", user_id);
//     cJSON_AddNumberToObject(payload, "lat", lat);
//     cJSON_AddNumberToObject(payload, "lon", lon);
//     cJSON_AddNumberToObject(payload, "timestamp", (double)esp_timer_get_time()/1000.0); // ms
//     char *payload_str = cJSON_PrintUnformatted(payload);
//     size_t payload_len = strlen(payload_str);

//     // signature
//     uint8_t signature[ECC_SIGNATURE_SIZE];
//     if (!ecc_sign(device_priv, (const uint8_t *)payload_str, payload_len, signature)) {
//         ESP_LOGE(TAG, "Signing failed");
//         cJSON_Delete(payload);
//         free(payload_str);
//         cJSON_Delete(root);
//         httpd_resp_set_status(req, "500 Internal Server Error");
//         httpd_resp_sendstr(req, "{\"error\":\"signing failed\"}");
//         return ESP_FAIL;
//     }

//     // encryption using receiver public key (ECIES)
//     uint8_t ciphertext[512];
//     uint8_t ephemeral_pub[ECC_PUBLIC_KEY_SIZE];
//     size_t ct_len = 0;
//     if (!crypto_ecies_encrypt(recv_pub, (const uint8_t *)payload_str, payload_len,
//                               ephemeral_pub, ciphertext, &ct_len)) {
//         ESP_LOGE(TAG, "Encryption failed");
//         cJSON_Delete(payload);
//         free(payload_str);
//         cJSON_Delete(root);
//         httpd_resp_set_status(req, "500 Internal Server Error");
//         httpd_resp_sendstr(req, "{\"error\":\"encryption failed\"}");
//         return ESP_FAIL;
//     }

//     // print hex outputs
//     char hex_ephemeral[ECC_PUBLIC_KEY_SIZE*2 + 1];
//     char hex_cipher[1024];
//     char hex_sig[ECC_SIGNATURE_SIZE*2 + 1];
//     bytes_to_hex(ephemeral_pub, sizeof(ephemeral_pub), hex_ephemeral, sizeof(hex_ephemeral));
//     // ciphertext maybe variable length
//     bytes_to_hex(ciphertext, ct_len, hex_cipher, sizeof(hex_cipher));
//     bytes_to_hex(signature, sizeof(signature), hex_sig, sizeof(hex_sig));

//     ESP_LOGI(TAG, "Ephemeral Pub: %s", hex_ephemeral);
//     ESP_LOGI(TAG, "Ciphertext (%d): %s", (int)ct_len, hex_cipher);
//     ESP_LOGI(TAG, "Signature: %s", hex_sig);

//     // HERE: send via LoRa (commented for now)
//     /*
//     // Example pseudocode:
//     lora_send_packet(ephemeral_pub, sizeof(ephemeral_pub)); // ephemeral public key
//     lora_send_packet(ciphertext, ct_len); // ciphertext
//     lora_send_packet(signature, sizeof(signature)); // signature
//     */
//     // For now just printing is sufficient for debugging/testing

//     // Build response JSON (with hex strings for debug)
//     cJSON *resp = cJSON_CreateObject();
//     cJSON_AddStringToObject(resp, "status", "encrypted_sent_printed");
//     cJSON_AddStringToObject(resp, "ephemeral_pub", hex_ephemeral);
//     cJSON_AddStringToObject(resp, "ciphertext", hex_cipher);
//     cJSON_AddStringToObject(resp, "signature", hex_sig);
//     char *resp_str = cJSON_PrintUnformatted(resp);

//     // cleanup
//     cJSON_Delete(resp);
//     cJSON_Delete(payload);
//     cJSON_Delete(root);
//     free(payload_str);

//     httpd_resp_set_type(req, "application/json");
//     httpd_resp_send(req, resp_str, HTTPD_RESP_USE_STRLEN);
//     free(resp_str);
//     return ESP_OK;
// }

// /* ---------- start_webserver with new endpoints ---------- */
// httpd_handle_t start_webserver(void)
// {
//     httpd_config_t config = HTTPD_DEFAULT_CONFIG();
//     httpd_handle_t server = NULL;

//     if (httpd_start(&server, &config) == ESP_OK) {
//         httpd_uri_t hello_uri = {
//             .uri = "/api/hello",
//             .method = HTTP_GET,
//             .handler = hello_get_handler,
//             .user_ctx = NULL
//         };
//         httpd_register_uri_handler(server, &hello_uri);

//         httpd_uri_t status_uri = {
//             .uri = "/api/status",
//             .method = HTTP_GET,
//             .handler = status_get_handler,
//             .user_ctx = NULL
//         };
//         httpd_register_uri_handler(server, &status_uri);

//         httpd_uri_t pubkey_uri = {
//             .uri = "/api/public_key",
//             .method = HTTP_GET,
//             .handler = public_key_get_handler,
//             .user_ctx = NULL
//         };
//         httpd_register_uri_handler(server, &pubkey_uri);

//         httpd_uri_t store_peer_uri = {
//             .uri = "/api/store_peer",
//             .method = HTTP_POST,
//             .handler = store_peer_post_handler,
//             .user_ctx = NULL
//         };
//         httpd_register_uri_handler(server, &store_peer_uri);

//         httpd_uri_t send_loc_uri = {
//             .uri = "/api/send_location",
//             .method = HTTP_POST,
//             .handler = send_location_post_handler,
//             .user_ctx = NULL
//         };
//         httpd_register_uri_handler(server, &send_loc_uri);
//     }
//     return server;
// }

// void print_hex(const char *label, const uint8_t *data, size_t len) {
//     printf("%s: ", label);
//     for (size_t i = 0; i < len; i++) {
//         printf("%02X", data[i]);
//     }
//     printf("\n");
// }

// void app_main() {
//     uint8_t private_key[ECC_PRIVATE_KEY_SIZE];
//     uint8_t public_key[ECC_PUBLIC_KEY_SIZE];

//     // const char *message = "Hello, ECC!";
//     // uint8_t ciphertext[256];
//     // uint8_t decrypted[256];
//     // uint8_t ephemeral_pub[ECC_PUBLIC_KEY_SIZE];
//     // size_t ct_len = 0, pt_len = 0;


//     // if (!ecc_generate_keypair(public_key, private_key)) {
//     //     printf("Key pair generation failed\n");
//     //     return; // just return, no value
//     // }

//     // print_hex("Private Key", private_key, ECC_PRIVATE_KEY_SIZE);
//     // print_hex("Public Key", public_key, ECC_PUBLIC_KEY_SIZE);

//     // if (!ecc_sign(private_key, (const uint8_t *)message, strlen(message), signature)) {
//     //     printf("Signing failed\n");
//     //     return;
//     // }
//     // print_hex("Signature", signature, ECC_SIGNATURE_SIZE);

//     // if (ecc_verify(public_key, (const uint8_t *)message, strlen(message), signature)) {
//     //     printf("Signature is valid\n");
//     // } else {
//     //     printf("Signature is invalid\n");
//     // }

//     // if (!ecc_shared_secret(private_key, public_key, shared_secret)) {
//     //     printf("Shared secret computation failed\n");
//     //     return;
//     // }
//     // print_hex("Shared Secret", shared_secret, ECC_SHARED_SECRET_SIZE);
    
//     // if (!crypto_ecies_encrypt(public_key, (const uint8_t *)message, strlen(message),
//     //                     ephemeral_pub, ciphertext, &ct_len)) {
//     //     printf("Encryption failed\n");
//     //     return;
//     // }
//     // print_hex("Ephemeral Public Key", ephemeral_pub, ECC_PUBLIC_KEY_SIZE);
//     // print_hex("Ciphertext", ciphertext, ct_len);

//     // if (!crypto_ecies_decrypt(private_key, ephemeral_pub, ciphertext, ct_len, decrypted, &pt_len)) {
//     //     printf("Decryption failed\n");
//     //     return;
//     // }

//     // if (pt_len < sizeof(decrypted)) {
//     //     decrypted[pt_len] = '\0';
//     // } else {
//     //     decrypted[sizeof(decrypted) - 1] = '\0';
//     // }

//     // printf("Decrypted Message: %s\n", decrypted);
//     ESP_ERROR_CHECK(nvs_flash_init());

//     // Try to load existing keys
//     if (!load_keys_from_nvs(public_key, sizeof(public_key), private_key, sizeof(private_key))) {
//         ESP_LOGI(TAG, "Generating new ECC keypair...");
//         if (!ecc_generate_keypair(public_key, private_key)) {
//             printf("Key pair generation failed\n");
//             return;
//         }
//         print_hex("Private Key", private_key, ECC_PRIVATE_KEY_SIZE);
//         print_hex("Public Key", public_key, ECC_PUBLIC_KEY_SIZE);

//         // Store keys for future use
//         store_keys_in_nvs(public_key, sizeof(public_key), private_key, sizeof(private_key));
//     } else {
//         ESP_LOGI(TAG, "Using stored ECC keys");
//         print_hex("Private Key", private_key, ECC_PRIVATE_KEY_SIZE);
//         print_hex("Public Key", public_key, ECC_PUBLIC_KEY_SIZE);
//     }

//     wifi_init_softap();
//     start_webserver();
// }

// /* ---------------- NOTES on decryption verification & client deletion ----------------

// When the receiver obtains ephemeral_pub + ciphertext + signature, receiver should:

// 1) Decrypt:
//    // pseudo:
//    uint8_t decrypted[512];
//    size_t pt_len = 0;
//    if (!crypto_ecies_decrypt(receiver_private_key, ephemeral_pub, ciphertext, ct_len, decrypted, &pt_len)) {
//        // decryption failed
//    }
//    // decrypted[pt_len] = '\0';

// 2) Verify signature (using sender's public key which receiver should have):
//    if (ecc_verify(sender_public_key, decrypted, pt_len, signature)) {
//        // valid
//        // After successful verification, the receiver (client) MUST delete plaintext from memory/storage (zero it out)
//    } else {
//        // invalid signature -> discard
//    }

// Make sure your client deletes any plaintext coordinates immediately after verification:
//    explicit_bzero(decrypted, pt_len); // or overwrite with zeros before freeing

// ------------------------------------------------------------------------------------- */


#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include"freertos/FreeRTOS.h"
#include"freertos/task.h"
#include "esp_wifi.h"
#include "esp_event.h"
#include "nvs_flash.h"
#include "esp_netif.h"
#include "esp_system.h"
#include "esp_log.h"
#include "esp_http_server.h"
#include "esp_timer.h"
#include "nvs.h"
#include "../include/ecc.h"
#include "../include/crypto_v.h"
#include "cJSON.h"     // make sure cJSON is available in your project

#define AP_SSID "KISUKE"
#define AP_PASSWORD "12345678"

static const char *TAG = "wifi_ap";

/* ---------- helper: hex encode/decode ---------- */
static void bytes_to_hex(const uint8_t *in, size_t inlen, char *out, size_t outlen)
{
    const char hex[] = "0123456789ABCDEF";
    for (size_t i = 0; i < inlen && (i*2+1) < outlen; i++) {
        out[i*2]   = hex[(in[i] >> 4) & 0xF];
        out[i*2+1] = hex[in[i] & 0xF];
    }
    if (outlen > 0) out[inlen*2 < outlen ? inlen*2 : outlen-1] = '\0';
}

static bool hex_to_bytes(const char *hex, uint8_t *out, size_t outlen)
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
/* ------------------------------------------------ */

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

/* ---------- WiFi SoftAP init ---------- */
static void wifi_init_softap(void) {
    esp_netif_init();
    esp_event_loop_create_default();
    esp_netif_create_default_wifi_ap();
    wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
    esp_wifi_init(&cfg);
    esp_wifi_set_mode(WIFI_MODE_AP);
    wifi_config_t wifi_config = {
        .ap = {
            .ssid = AP_SSID,
            .ssid_len = strlen(AP_SSID),
            .password = AP_PASSWORD,
            .max_connection = 1,
            .authmode = WIFI_AUTH_WPA_WPA2_PSK
        },
    };
    if (strlen(AP_PASSWORD) == 0) {
        wifi_config.ap.authmode = WIFI_AUTH_OPEN;
    }
    esp_wifi_set_config(ESP_IF_WIFI_AP, &wifi_config);
    esp_wifi_start();
    ESP_LOGI(TAG, "WiFi AP started. SSID:%s password:%s", AP_SSID, AP_PASSWORD);
}

/* ---------- HTTP Handlers ---------- */
esp_err_t hello_get_handler(httpd_req_t *req) {
    const char resp[] = "Hello, World!";
    httpd_resp_send(req, resp, HTTPD_RESP_USE_STRLEN);
    return ESP_OK;
}

esp_err_t status_get_handler(httpd_req_t *req) {
    char resp[128];
    snprintf(resp, sizeof(resp), "Device is running. Free heap: %ld bytes", esp_get_free_heap_size());
    httpd_resp_set_type(req, "application/json");
    httpd_resp_send(req, resp, HTTPD_RESP_USE_STRLEN);
    return ESP_OK;
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

/* ---------- HTTP Body helper ---------- */
static int http_read_body(httpd_req_t *req, char **buf, size_t *buf_len)
{
    size_t content_len = req->content_len;
    if (content_len == 0) { *buf=NULL; *buf_len=0; return 0; }
    char *body = malloc(content_len + 1);
    if (!body) return -1;
    size_t received = 0;
    while (received < content_len) {
        int ret = httpd_req_recv(req, body + received, content_len - received);
        if (ret <= 0) { free(body); return -1; }
        received += ret;
    }
    body[content_len] = '\0';
    *buf = body;
    *buf_len = content_len;
    return 0;
}

/* ---------- /api/public_key ---------- */
esp_err_t public_key_get_handler(httpd_req_t *req)
{
    uint8_t pub[ECC_PUBLIC_KEY_SIZE], priv[ECC_PRIVATE_KEY_SIZE];
    if (!load_keys_from_nvs(pub, sizeof(pub), priv, sizeof(priv))) {
        httpd_resp_set_status(req,"500 Internal Server Error");
        httpd_resp_sendstr(req,"{\"error\":\"device keys not available\"}");
        return ESP_FAIL;
    }
    char hexpub[ECC_PUBLIC_KEY_SIZE*2 + 1];
    bytes_to_hex(pub,sizeof(pub),hexpub,sizeof(hexpub));
    char resp[ECC_PUBLIC_KEY_SIZE*2 + 64];
    snprintf(resp,sizeof(resp),"{\"public_key\":\"%s\"}",hexpub);
    httpd_resp_set_type(req,"application/json");
    httpd_resp_send(req,resp,HTTPD_RESP_USE_STRLEN);
    return ESP_OK;
}

/* ---------- /api/store_peer ---------- */
esp_err_t store_peer_post_handler(httpd_req_t *req)
{
    char *body=NULL; size_t blen=0;
    if (http_read_body(req,&body,&blen)!=0) {
        httpd_resp_set_status(req,"400 Bad Request");
        httpd_resp_sendstr(req,"{\"error\":\"unable to read body\"}"); return ESP_FAIL;
    }
    cJSON *root = cJSON_Parse(body);
    free(body);
    if (!root) { httpd_resp_set_status(req,"400 Bad Request"); httpd_resp_sendstr(req,"{\"error\":\"invalid json\"}"); return ESP_FAIL; }
    const cJSON *j_user = cJSON_GetObjectItem(root,"user_id");
    const cJSON *j_receiver = cJSON_GetObjectItem(root,"receiver_id");
    const cJSON *j_pub = cJSON_GetObjectItem(root,"receiver_public_key");
    if (!cJSON_IsString(j_user)||!cJSON_IsString(j_receiver)||!cJSON_IsString(j_pub)) {
        cJSON_Delete(root); httpd_resp_set_status(req,"400 Bad Request"); httpd_resp_sendstr(req,"{\"error\":\"missing fields\"}"); return ESP_FAIL;
    }
    const char *user_id = j_user->valuestring;
    const char *receiver_id = j_receiver->valuestring;
    const char *pub_hex = j_pub->valuestring;
    uint8_t peer_pub[ECC_PUBLIC_KEY_SIZE];
    if (!hex_to_bytes(pub_hex,peer_pub,sizeof(peer_pub))) {
        cJSON_Delete(root); httpd_resp_set_status(req,"400 Bad Request"); httpd_resp_sendstr(req,"{\"error\":\"invalid public key hex\"}"); return ESP_FAIL;
    }
    if (!store_peer_publickey(user_id,receiver_id,peer_pub,sizeof(peer_pub))) {
        cJSON_Delete(root); httpd_resp_set_status(req,"500 Internal Server Error"); httpd_resp_sendstr(req,"{\"error\":\"failed to store peer\"}"); return ESP_FAIL;
    }
    cJSON_Delete(root);
    httpd_resp_set_type(req,"application/json");
    httpd_resp_sendstr(req,"{\"status\":\"ok\"}");
    return ESP_OK;
}

/* ---------- /api/send_location ---------- */
esp_err_t send_location_post_handler(httpd_req_t *req)
{
    char *body = NULL;
    size_t blen = 0;
    cJSON *root = NULL;
    cJSON *payload = NULL;
    char *payload_str = NULL;
    cJSON *resp = NULL;
    char *resp_str = NULL;
    
    // Read request body
    if (http_read_body(req, &body, &blen) != 0) {
        httpd_resp_set_status(req, "400 Bad Request");
        httpd_resp_sendstr(req, "{\"error\":\"unable to read body\"}");
        return ESP_FAIL;
    }
    
    // Parse JSON
    root = cJSON_Parse(body);
    free(body);
    body = NULL;
    
    if (!root) {
        httpd_resp_set_status(req, "400 Bad Request");
        httpd_resp_sendstr(req, "{\"error\":\"invalid json\"}");
        return ESP_FAIL;
    }
    
    // Extract JSON fields
    const cJSON *j_user = cJSON_GetObjectItem(root, "user_id");
    const cJSON *j_receiver = cJSON_GetObjectItem(root, "receiver_id");
    const cJSON *j_lat = cJSON_GetObjectItem(root, "lat");
    const cJSON *j_lon = cJSON_GetObjectItem(root, "lon");
    
    if (!cJSON_IsString(j_user) || !cJSON_IsString(j_receiver) || 
        !cJSON_IsNumber(j_lat) || !cJSON_IsNumber(j_lon)) {
        cJSON_Delete(root);
        httpd_resp_set_status(req, "400 Bad Request");
        httpd_resp_sendstr(req, "{\"error\":\"missing fields\"}");
        return ESP_FAIL;
    }
    
    const char *user_id = j_user->valuestring;
    const char *receiver_id = j_receiver->valuestring;
    double lat = j_lat->valuedouble;
    double lon = j_lon->valuedouble;
    
    // Load device keys
    uint8_t device_pub[ECC_PUBLIC_KEY_SIZE];
    uint8_t device_priv[ECC_PRIVATE_KEY_SIZE];
    if (!load_keys_from_nvs(device_pub, sizeof(device_pub), device_priv, sizeof(device_priv))) {
        cJSON_Delete(root);
        httpd_resp_set_status(req, "500 Internal Server Error");
        httpd_resp_sendstr(req, "{\"error\":\"device keys not available\"}");
        return ESP_FAIL;
    }
    
    // Load receiver public key
    uint8_t recv_pub[ECC_PUBLIC_KEY_SIZE];
    if (!load_peer_publickey(user_id, receiver_id, recv_pub, sizeof(recv_pub))) {
        cJSON_Delete(root);
        httpd_resp_set_status(req, "400 Bad Request");
        httpd_resp_sendstr(req, "{\"error\":\"receiver public key not found\"}");
        return ESP_FAIL;
    }
    
    // Create payload JSON
    payload = cJSON_CreateObject();
    if (!payload) {
        cJSON_Delete(root);
        httpd_resp_set_status(req, "500 Internal Server Error");
        httpd_resp_sendstr(req, "{\"error\":\"memory allocation failed\"}");
        return ESP_FAIL;
    }
    
    cJSON_AddStringToObject(payload, "user_id", user_id);
    cJSON_AddNumberToObject(payload, "lat", lat);
    cJSON_AddNumberToObject(payload, "lon", lon);
    cJSON_AddNumberToObject(payload, "timestamp", (double)esp_timer_get_time() / 1000.0);
    
    payload_str = cJSON_PrintUnformatted(payload);
    if (!payload_str) {
        cJSON_Delete(payload);
        cJSON_Delete(root);
        httpd_resp_set_status(req, "500 Internal Server Error");
        httpd_resp_sendstr(req, "{\"error\":\"payload serialization failed\"}");
        return ESP_FAIL;
    }
    
    size_t payload_len = strlen(payload_str);
    
    // Sign the payload
    uint8_t signature[ECC_SIGNATURE_SIZE];
    if (!ecc_sign(device_priv, (const uint8_t *)payload_str, payload_len, signature)) {
        ESP_LOGE(TAG, "Signing failed");
        free(payload_str);
        cJSON_Delete(payload);
        cJSON_Delete(root);
        httpd_resp_set_status(req, "500 Internal Server Error");
        httpd_resp_sendstr(req, "{\"error\":\"signing failed\"}");
        return ESP_FAIL;
    }
    
    // Encrypt the payload
    uint8_t ciphertext[512];
    uint8_t ephemeral_pub[ECC_PUBLIC_KEY_SIZE];
    size_t ct_len = 0;
    
    if (!crypto_ecies_encrypt(recv_pub, (const uint8_t *)payload_str, payload_len,
                              ephemeral_pub, ciphertext, &ct_len)) {
        ESP_LOGE(TAG, "Encryption failed");
        free(payload_str);
        cJSON_Delete(payload);
        cJSON_Delete(root);
        httpd_resp_set_status(req, "500 Internal Server Error");
        httpd_resp_sendstr(req, "{\"error\":\"encryption failed\"}");
        return ESP_FAIL;
    }
    
    // Convert to hex (allocate sufficient buffer size)
    char hex_ephemeral[ECC_PUBLIC_KEY_SIZE * 2 + 1];
    char *hex_cipher = malloc(ct_len * 2 + 1);  // Dynamic allocation based on actual size
    char hex_sig[ECC_SIGNATURE_SIZE * 2 + 1];
    
    if (!hex_cipher) {
        free(payload_str);
        cJSON_Delete(payload);
        cJSON_Delete(root);
        httpd_resp_set_status(req, "500 Internal Server Error");
        httpd_resp_sendstr(req, "{\"error\":\"memory allocation failed\"}");
        return ESP_FAIL;
    }
    
    bytes_to_hex(ephemeral_pub, sizeof(ephemeral_pub), hex_ephemeral, sizeof(hex_ephemeral));
    bytes_to_hex(ciphertext, ct_len, hex_cipher, ct_len * 2 + 1);
    bytes_to_hex(signature, sizeof(signature), hex_sig, sizeof(hex_sig));
    
    ESP_LOGI(TAG, "Ephemeral Pub: %s", hex_ephemeral);
    ESP_LOGI(TAG, "Ciphertext (%d): %.100s...", (int)ct_len, hex_cipher);  // Truncate log output
    ESP_LOGI(TAG, "Signature: %s", hex_sig);
    
    // Create response JSON
    resp = cJSON_CreateObject();
    if (!resp) {
        free(hex_cipher);
        free(payload_str);
        cJSON_Delete(payload);
        cJSON_Delete(root);
        httpd_resp_set_status(req, "500 Internal Server Error");
        httpd_resp_sendstr(req, "{\"error\":\"response creation failed\"}");
        return ESP_FAIL;
    }
    
    cJSON_AddStringToObject(resp, "status", "encrypted_sent_printed");
    cJSON_AddStringToObject(resp, "ephemeral_pub", hex_ephemeral);
    cJSON_AddStringToObject(resp, "ciphertext", hex_cipher);
    cJSON_AddStringToObject(resp, "signature", hex_sig);
    
    resp_str = cJSON_PrintUnformatted(resp);
    if (!resp_str) {
        cJSON_Delete(resp);
        free(hex_cipher);
        free(payload_str);
        cJSON_Delete(payload);
        cJSON_Delete(root);
        httpd_resp_set_status(req, "500 Internal Server Error");
        httpd_resp_sendstr(req, "{\"error\":\"response serialization failed\"}");
        return ESP_FAIL;
    }
    
    // Send response
    httpd_resp_set_type(req, "application/json");
    esp_err_t result = httpd_resp_send(req, resp_str, HTTPD_RESP_USE_STRLEN);
    
    // Cleanup
    free(resp_str);
    cJSON_Delete(resp);
    free(hex_cipher);
    free(payload_str);
    cJSON_Delete(payload);
    cJSON_Delete(root);
    
    return result;
}

/* ---------- Start Webserver ---------- */
httpd_handle_t start_webserver(void)
{
    httpd_config_t config = HTTPD_DEFAULT_CONFIG();
    config.max_resp_headers = 8;
    config.max_uri_handlers = 8;
    config.stack_size = 8192;  // Increase stack size
    config.recv_wait_timeout = 10;
    config.send_wait_timeout = 10;
    
    httpd_handle_t server = NULL;
    if (httpd_start(&server, &config) == ESP_OK) {
        httpd_uri_t uris[] = {
            {.uri = "/api/hello", .method = HTTP_GET, .handler = hello_get_handler, .user_ctx = NULL},
            {.uri = "/api/status", .method = HTTP_GET, .handler = status_get_handler, .user_ctx = NULL},
            {.uri = "/api/public_key", .method = HTTP_GET, .handler = public_key_get_handler, .user_ctx = NULL},
            {.uri = "/api/store_peer", .method = HTTP_POST, .handler = store_peer_post_handler, .user_ctx = NULL},
            {.uri = "/api/send_location", .method = HTTP_POST, .handler = send_location_post_handler, .user_ctx = NULL}
        };
        for (int i = 0; i < sizeof(uris) / sizeof(uris[0]); i++) {
            httpd_register_uri_handler(server, &uris[i]);
        }
        ESP_LOGI(TAG, "HTTP server started successfully");
    } else {
        ESP_LOGE(TAG, "Failed to start HTTP server");
    }
    return server;
}

/* ---------- Helper to print hex ---------- */
void print_hex(const char *label,const uint8_t *data,size_t len){
    printf("%s: ",label); for(size_t i=0;i<len;i++) printf("%02X",data[i]); printf("\n");
}

/* ---------- app_main ---------- */
void app_main() {
    uint8_t private_key[ECC_PRIVATE_KEY_SIZE];
    uint8_t public_key[ECC_PUBLIC_KEY_SIZE];

    ESP_ERROR_CHECK(nvs_flash_init());
    
    // Initialize ECC library with ESP32 RNG
    ecc_init();

    if(!load_keys_from_nvs(public_key,sizeof(public_key),private_key,sizeof(private_key))){
        ESP_LOGI(TAG,"Generating new ECC keypair...");
        if(!ecc_generate_keypair(public_key,private_key)){
            printf("Key pair generation failed\n");
            return;
        }
        print_hex("Private Key",private_key,ECC_PRIVATE_KEY_SIZE);
        print_hex("Public Key",public_key,ECC_PUBLIC_KEY_SIZE);
        store_keys_in_nvs(public_key,sizeof(public_key),private_key,sizeof(private_key));
    }else{
        ESP_LOGI(TAG,"Using stored ECC keys");
        print_hex("Private Key",private_key,ECC_PRIVATE_KEY_SIZE);
        print_hex("Public Key",public_key,ECC_PUBLIC_KEY_SIZE);
    }

    wifi_init_softap();
    start_webserver();
}

