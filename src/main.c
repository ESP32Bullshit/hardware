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
#include "driver/gpio.h"

#define AP_SSID "KISUKE"
#define AP_PASSWORD "12345678"
#define BUTTON_PIN GPIO_NUM_9

static const char *TAG = "wifi_ap";
static int ws_fd = -1;  // store websocket client fd
static bool wifi_connected = false;

/* ---------- WiFi Event Handler ---------- */
static void wifi_event_handler(void *arg, esp_event_base_t event_base,
                                int32_t event_id, void *event_data)
{
    if (event_base == WIFI_EVENT && event_id == WIFI_EVENT_STA_START) {
        ESP_LOGI(TAG, "WiFi STA started, attempting to connect...");
        esp_wifi_connect();
    } else if (event_base == WIFI_EVENT && event_id == WIFI_EVENT_STA_DISCONNECTED) {
        wifi_connected = false;
        ESP_LOGW(TAG, "Disconnected from WiFi, retrying...");
        esp_wifi_connect();
    } else if (event_base == IP_EVENT && event_id == IP_EVENT_STA_GOT_IP) {
        ip_event_got_ip_t *event = (ip_event_got_ip_t *)event_data;
        ESP_LOGI(TAG, "✓ WiFi connected! Got IP: " IPSTR, IP2STR(&event->ip_info.ip));
        wifi_connected = true;
    } else if (event_base == WIFI_EVENT && event_id == WIFI_EVENT_AP_STACONNECTED) {
        wifi_event_ap_staconnected_t *event = (wifi_event_ap_staconnected_t *)event_data;
        ESP_LOGI(TAG, "Station connected to AP");
    } else if (event_base == WIFI_EVENT && event_id == WIFI_EVENT_AP_STADISCONNECTED) {
        wifi_event_ap_stadisconnected_t *event = (wifi_event_ap_stadisconnected_t *)event_data;
        ESP_LOGI(TAG, "Station disconnected from AP");
    }
}

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

/* ---------- WebSocket/HTTP helpers ---------- */
static httpd_handle_t server_handle = NULL;

// Simple notification mechanism using HTTP polling or persistent connection
typedef struct {
    bool button_pressed;
    TickType_t last_press_time;
} button_state_t;

static button_state_t button_state = {false, 0};

void trigger_location_request(void)
{
    button_state.button_pressed = true;  
    button_state.last_press_time = xTaskGetTickCount();
    ESP_LOGI(TAG, "Button press triggered - sending location request to mobile");
}

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
static void wifi_init_apsta(void)
{
    esp_netif_init();
    esp_event_loop_create_default();

    // Create both interfaces
    esp_netif_create_default_wifi_ap();
    esp_netif_create_default_wifi_sta();

    // Register event handlers
    esp_event_handler_instance_register(WIFI_EVENT, ESP_EVENT_ANY_ID, &wifi_event_handler, NULL, NULL);
    esp_event_handler_instance_register(IP_EVENT, IP_EVENT_STA_GOT_IP, &wifi_event_handler, NULL, NULL);

    wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
    esp_wifi_init(&cfg);

    wifi_config_t ap_config = {
        .ap = {
            .ssid = "KISUKE",
            .ssid_len = strlen("KISUKE"),
            .password = "12345678",
            .max_connection = 2,
            .authmode = WIFI_AUTH_WPA_WPA2_PSK
        },
    };

    wifi_config_t sta_config = {
        .sta = {
            .ssid = "JIOFIBER",
            .password = "12341234"
        },
    };

    esp_wifi_set_mode(WIFI_MODE_APSTA);
    esp_wifi_set_config(WIFI_IF_AP, &ap_config);
    esp_wifi_set_config(WIFI_IF_STA, &sta_config);
    esp_wifi_start();

    ESP_LOGI(TAG, "WiFi AP+STA started: AP=KISUKE, Connecting to STA=%s...", sta_config.sta.ssid);
}


/* ---------- HTTP Handlers ---------- */
esp_err_t hello_get_handler(httpd_req_t *req) {
    const char resp[] = "Hello, World!";
    httpd_resp_send(req, resp, HTTPD_RESP_USE_STRLEN);
    return ESP_OK;
}
/* ---------- WebSocket Event Handler ---------- */
esp_err_t websocket_handler(httpd_req_t *req)
{
    if (req->method == HTTP_GET) {
        ESP_LOGI(TAG, "Handshake done, the new WebSocket connection was opened");
        return ESP_OK;
    }
    return ESP_FAIL;
}

esp_err_t websocket_send_event(const char *msg)
{
    if (ws_fd < 0 || server_handle == NULL) {
        ESP_LOGW(TAG, "No active WebSocket connection to send event");
        return ESP_FAIL;
    }

    httpd_ws_frame_t ws_pkt;
    memset(&ws_pkt, 0, sizeof(ws_pkt));
    ws_pkt.type = HTTPD_WS_TYPE_TEXT;
    ws_pkt.payload = (uint8_t *)msg;
    ws_pkt.len = strlen(msg);

    esp_err_t ret = httpd_ws_send_frame_async(server_handle, ws_fd, &ws_pkt);
    if (ret != ESP_OK) {
        ESP_LOGE(TAG, "Failed to send WS message: %s", esp_err_to_name(ret));
    }
    return ret;
}

/* Called when WebSocket data or control frames are received */
esp_err_t websocket_data_handler(httpd_req_t *req)
{
    if (req->method == HTTP_GET) {
        ESP_LOGI(TAG, "WebSocket handshake done, new connection opened");
        ws_fd = httpd_req_to_sockfd(req);
        return ESP_OK;
    }

    httpd_ws_frame_t ws_pkt;
    memset(&ws_pkt, 0, sizeof(httpd_ws_frame_t));
    ws_pkt.type = HTTPD_WS_TYPE_TEXT;

    // Get the length of the data
    esp_err_t ret = httpd_ws_recv_frame(req, &ws_pkt, 0);
    if (ret != ESP_OK) {
        ESP_LOGE(TAG, "httpd_ws_recv_frame failed to get frame len with %d", ret);
        return ret;
    }

    if (ws_pkt.len) {
        uint8_t *buf = calloc(1, ws_pkt.len + 1);
        if (!buf) {
            ESP_LOGE(TAG, "Failed to allocate memory for WS frame");
            return ESP_ERR_NO_MEM;
        }

        ws_pkt.payload = buf;
        ret = httpd_ws_recv_frame(req, &ws_pkt, ws_pkt.len);
        if (ret == ESP_OK) {
            buf[ws_pkt.len] = '\0';
            ESP_LOGI(TAG, "Received WS message: %s", buf);
            // You can parse incoming commands here (e.g., client responses)
        }
        free(buf);
    }

    ws_fd = httpd_req_to_sockfd(req);  // track current connection
    return ret;
}

/* ---------- /test.html - Simple test page ---------- */
esp_err_t test_page_handler(httpd_req_t *req) {
    const char html[] = 
    "<!DOCTYPE html><html><head><title>ESP32 Location Test</title></head><body>"
    "<h1>ESP32 Location Request Test</h1>"
    "<p>This page uses WebSocket to receive button press events from ESP32.</p>"
    "<div id='status'>Waiting for WebSocket connection...</div>"
    "<div id='location-form' style='display:none;'>"
    "<h3>Send Location</h3>"
    "<input type='text' id='user_id' placeholder='User ID' value='test_user'><br><br>"
    "<input type='text' id='receiver_id' placeholder='Receiver ID' value='server1'><br><br>"
    "<input type='number' id='lat' placeholder='Latitude' value='37.7749' step='any'><br><br>"
    "<input type='number' id='lon' placeholder='Longitude' value='-122.4194' step='any'><br><br>"
    "<button onclick='sendLocation()'>Send Location</button>"
    "</div>"
    "<script>"
"var ws = new WebSocket('ws://' + location.host + '/ws');"
"ws.onopen = function() {"
"  document.getElementById('status').innerText = 'Connected to ESP32 WebSocket';"
"};"
"ws.onmessage = function(event) {"
"  var data = JSON.parse(event.data);"
"  console.log('Received WS message:', data);"
"  if (data.event === 'button_press') {"
"    document.getElementById('status').innerText = 'Button pressed! Getting your location...';"
"    getAndSendLocation();"
"  }"
"};"
"ws.onclose = function() {"
"  document.getElementById('status').innerText = 'WebSocket disconnected';"
"};"
"function getAndSendLocation() {"
"  document.getElementById('status').innerText = 'Getting your location...';"
"  if (navigator.geolocation && window.isSecureContext) {"
"    navigator.geolocation.getCurrentPosition(function(position) {"
"      var lat = position.coords.latitude;"
"      var lon = position.coords.longitude;"
"      sendLocationData(lat, lon, 'GPS');"
"    }, function(error) {"
"      console.warn('GPS failed:', error.message);"
"      document.getElementById('status').innerText = "
"        'GPS unavailable (HTTP not secure). Using IP-based location...';"
"      getLocationFromIP();"
"    });"
"  } else {"
"    document.getElementById('status').innerText = "
"      'Using IP-based location (HTTPS required for GPS)...';"
"    getLocationFromIP();"
"  }"
"}"
"function getLocationFromIP() {"
"  fetch('https://ipapi.co/json/')"
"    .then(response => response.json())"
"    .then(data => {"
"      if (data.latitude && data.longitude) {"
"        sendLocationData(data.latitude, data.longitude, 'IP');"
"      } else {"
"        document.getElementById('status').innerText = "
"          'Unable to determine location. Using default.';"
"        sendLocationData(0.0, 0.0, 'Default');"
"      }"
"    })"
"    .catch(error => {"
"      console.error('IP location failed:', error);"
"      document.getElementById('status').innerText = "
"        'Location service unavailable. Using default coordinates.';"
"      sendLocationData(0.0, 0.0, 'Default');"
"    });"
"}"
"function sendLocationData(lat, lon, source) {"
"  var data = {"
"    user_id: 'user1',"
"    receiver_id: 'receiver1',"
"    lat: lat,"
"    lon: lon"
"  };"
"  document.getElementById('status').innerText = "
"    'Sending location (' + source + '): ' + lat.toFixed(5) + ', ' + lon.toFixed(5);"
"  fetch('/api/send_location', {"
"    method: 'POST',"
"    headers: {'Content-Type': 'application/json'},"
"    body: JSON.stringify(data)"
"  })"
"  .then(response => response.json())"
"  .then(result => {"
"    console.log('Result:', result);"
"    document.getElementById('status').innerText = "
"      'Location sent successfully! (' + source + '): ' + lat.toFixed(5) + ', ' + lon.toFixed(5);"
"  })"
"  .catch(error => {"
"    console.error('Error sending location:', error);"
"    document.getElementById('status').innerText = "
"      'Failed to send location: ' + error;"
"  });"
"}"
"</script>"
"</body></html>";

    
    httpd_resp_set_type(req, "text/html");
    httpd_resp_send(req, html, HTTPD_RESP_USE_STRLEN);
    return ESP_OK;
}

esp_err_t status_get_handler(httpd_req_t *req) {
    char resp[128];
    snprintf(resp, sizeof(resp), "Device is running. Free heap: %ld bytes", esp_get_free_heap_size());
    httpd_resp_set_type(req, "application/json");
    httpd_resp_send(req, resp, HTTPD_RESP_USE_STRLEN);
    return ESP_OK;
}

/* Duplicate test_page_handler removed — function is already defined earlier in this file */

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
    config.max_uri_handlers = 10;  // Increased for new endpoint
    config.stack_size = 8192;  // Increase stack size
    config.recv_wait_timeout = 10;
    config.send_wait_timeout = 10;
    
    httpd_handle_t server = NULL;
    if (httpd_start(&server, &config) == ESP_OK) {
        server_handle = server;  // Store global reference
        
        httpd_uri_t uris[] = {
            {.uri = "/api/hello", .method = HTTP_GET, .handler = hello_get_handler, .user_ctx = NULL},
            {.uri = "/api/status", .method = HTTP_GET, .handler = status_get_handler, .user_ctx = NULL},
            {.uri = "/api/public_key", .method = HTTP_GET, .handler = public_key_get_handler, .user_ctx = NULL},
            {.uri = "/api/store_peer", .method = HTTP_POST, .handler = store_peer_post_handler, .user_ctx = NULL},
            {.uri = "/api/send_location", .method = HTTP_POST, .handler = send_location_post_handler, .user_ctx = NULL},
            {.uri = "/test.html", .method = HTTP_GET, .handler = test_page_handler, .user_ctx = NULL},
        };

        for (int i = 0; i < sizeof(uris) / sizeof(uris[0]); i++) {
            httpd_register_uri_handler(server, &uris[i]);
        }
        
        // Register WebSocket handler
        httpd_uri_t ws = {
            .uri = "/ws",
            .method = HTTP_GET,
            .handler = websocket_data_handler,
            .user_ctx = NULL,
            .is_websocket = true
        };
        httpd_register_uri_handler(server, &ws);
        
        ESP_LOGI(TAG, "HTTP server started successfully with WebSocket endpoint");
    } else {
        ESP_LOGE(TAG, "Failed to start HTTP server");
    }
    return server;
}

/* ---------- Button Task ---------- */
void button_task(void *arg)
{
    bool last_state = false;
    while (1) {
        bool pressed = (gpio_get_level(BUTTON_PIN) == 0);  // active low
        if (pressed && !last_state) {
            ESP_LOGI(TAG, "Button pressed -> sending WebSocket message");

            // Build JSON message
            char msg[128];
            snprintf(msg, sizeof(msg),
                     "{\"event\":\"button_press\",\"timestamp\":%lu}",
                     (unsigned long)(esp_timer_get_time() / 1000));

            websocket_send_event(msg);  // 🔥 send to connected WebSocket client
        }
        last_state = pressed;
        vTaskDelay(pdMS_TO_TICKS(200));  // debounce
    }
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

    wifi_init_apsta();
    start_webserver();
    
    // Configure GPIO9 as input with pull-up
    gpio_config_t io_conf = {
        .pin_bit_mask = (1ULL << BUTTON_PIN),
        .mode = GPIO_MODE_INPUT,
        .pull_up_en = GPIO_PULLUP_ENABLE,
        .pull_down_en = GPIO_PULLDOWN_DISABLE,
        .intr_type = GPIO_INTR_DISABLE
    };
    gpio_config(&io_conf);
    ESP_LOGI(TAG, "Button configured on GPIO%d", BUTTON_PIN);

    // Start button monitor task
    xTaskCreate(button_task, "button_task", 4096, NULL, 5, NULL);
    ESP_LOGI(TAG, "Button monitoring task started");
}
