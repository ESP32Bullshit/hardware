#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "esp_http_server.h"
#include "esp_log.h"
#include "esp_system.h"
#include "esp_timer.h"
#include "cJSON.h"
#include "../include/webserver.h"
#include "../include/ecc.h"
#include "../include/crypto_v.h"
#include "../include/nvs_helper.h"
#include "../include/utils.h"
#include "../include/lora_handler.h"

static const char *TAG = "webserver";
static int ws_fd = -1;  // store websocket client fd
static httpd_handle_t server_handle = NULL;

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

/* ---------- HTTP Handlers ---------- */
esp_err_t hello_get_handler(httpd_req_t *req) {
    const char resp[] = "Hello, World!";
    httpd_resp_send(req, resp, HTTPD_RESP_USE_STRLEN);
    return ESP_OK;
}

/* ---------- CORS Headers Helper ---------- */
static void add_cors_headers(httpd_req_t *req) {
    httpd_resp_set_hdr(req, "Access-Control-Allow-Origin", "*");
    httpd_resp_set_hdr(req, "Access-Control-Allow-Methods", "GET, POST, OPTIONS");
    httpd_resp_set_hdr(req, "Access-Control-Allow-Headers", "Content-Type");
}

/* ---------- OPTIONS Handler for CORS ---------- */
esp_err_t options_handler(httpd_req_t *req) {
    add_cors_headers(req);
    httpd_resp_set_status(req, "204 No Content");
    httpd_resp_send(req, NULL, 0);
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

// ...existing code...

esp_err_t status_get_handler(httpd_req_t *req) {
    add_cors_headers(req);
    
    // 🔥 Fixed: Proper JSON format
    char resp[256];
    snprintf(resp, sizeof(resp), 
             "{\"status\":\"ok\",\"free_heap\":%lu,\"timestamp\":%llu}",
             (unsigned long)esp_get_free_heap_size(),
             (unsigned long long)(esp_timer_get_time() / 1000));
    
    httpd_resp_set_type(req, "application/json");
    httpd_resp_send(req, resp, HTTPD_RESP_USE_STRLEN);
    return ESP_OK;
}

// ...existing code...

/* ---------- /api/public_key ---------- */
esp_err_t public_key_get_handler(httpd_req_t *req)
{
    add_cors_headers(req);
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
    add_cors_headers(req);
    
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

/* ---------- /api/send_location (GET - returns error) ---------- */
esp_err_t send_location_get_handler(httpd_req_t *req)
{
    add_cors_headers(req);
    ESP_LOGW(TAG, "GET request received for /api/send_location - POST required!");
    httpd_resp_set_status(req, "405 Method Not Allowed");
    httpd_resp_set_type(req, "application/json");
    const char *resp = "{\"error\":\"Method Not Allowed\",\"message\":\"Please use POST method\"}";
    httpd_resp_send(req, resp, HTTPD_RESP_USE_STRLEN);
    return ESP_OK;
}

/* ---------- /api/send_location ---------- */
esp_err_t send_location_post_handler(httpd_req_t *req)
{
    // Log incoming request
    ESP_LOGI(TAG, "Received request to /api/send_location");
    ESP_LOGI(TAG, "Method: %d, Content-Length: %d", req->method, (int)req->content_len);
    
    add_cors_headers(req);
    
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
    
    // Send encrypted data via LoRa
    ESP_LOGI(TAG, "Sending encrypted location data via LoRa...");
    
    // Create LoRa packet: ephemeral_pub + ciphertext + signature
    size_t lora_packet_len = sizeof(ephemeral_pub) + ct_len + sizeof(signature);
    uint8_t *lora_packet = malloc(lora_packet_len);
    
    if (lora_packet) {
        size_t offset = 0;
        memcpy(lora_packet + offset, ephemeral_pub, sizeof(ephemeral_pub));
        offset += sizeof(ephemeral_pub);
        memcpy(lora_packet + offset, ciphertext, ct_len);
        offset += ct_len;
        memcpy(lora_packet + offset, signature, sizeof(signature));
        
        ESP_LOGI(TAG, "LoRa packet size: %d bytes", (int)lora_packet_len);
        lora_send(lora_packet, lora_packet_len);
        free(lora_packet);
        ESP_LOGI(TAG, "✓ Location data sent via LoRa");
    } else {
        ESP_LOGE(TAG, "Failed to allocate memory for LoRa packet");
    }
    
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
    config.max_uri_handlers = 14;  // Increased for GET handler on send_location
    config.stack_size = 8192;  // Increase stack size
    config.recv_wait_timeout = 10;
    config.send_wait_timeout = 10;
    
    httpd_handle_t server = NULL;
    if (httpd_start(&server, &config) == ESP_OK) {
        server_handle = server;  // Store global reference
        
        // Register URIs - POST handlers BEFORE GET handlers for same URI
        httpd_uri_t uris[] = {
            {.uri = "/api/hello", .method = HTTP_GET, .handler = hello_get_handler, .user_ctx = NULL},
            {.uri = "/api/status", .method = HTTP_GET, .handler = status_get_handler, .user_ctx = NULL},
            {.uri = "/api/public_key", .method = HTTP_GET, .handler = public_key_get_handler, .user_ctx = NULL},
            {.uri = "/api/store_peer", .method = HTTP_POST, .handler = store_peer_post_handler, .user_ctx = NULL},
            {.uri = "/api/send_location", .method = HTTP_POST, .handler = send_location_post_handler, .user_ctx = NULL},
            {.uri = "/api/send_location", .method = HTTP_GET, .handler = send_location_get_handler, .user_ctx = NULL},
            {.uri = "/test.html", .method = HTTP_GET, .handler = test_page_handler, .user_ctx = NULL},
            // CORS OPTIONS handlers
            {.uri = "/api/store_peer", .method = HTTP_OPTIONS, .handler = options_handler, .user_ctx = NULL},
            {.uri = "/api/send_location", .method = HTTP_OPTIONS, .handler = options_handler, .user_ctx = NULL},
        };

        for (int i = 0; i < sizeof(uris) / sizeof(uris[0]); i++) {
            esp_err_t result = httpd_register_uri_handler(server, &uris[i]);
            if (result != ESP_OK) {
                ESP_LOGE(TAG, "Failed to register handler for %s (method %d): %s", 
                         uris[i].uri, uris[i].method, esp_err_to_name(result));
            } else {
                ESP_LOGI(TAG, "✓ Registered %s handler for %s", 
                         (uris[i].method == HTTP_GET ? "GET" : 
                          uris[i].method == HTTP_POST ? "POST" : "OPTIONS"), 
                         uris[i].uri);
            }
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
