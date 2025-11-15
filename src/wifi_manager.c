#include <string.h>
#include "esp_wifi.h"
#include "esp_event.h"
#include "esp_netif.h"
#include "esp_log.h"

#include "lwip/lwip_napt.h"   // NAPT functionality

#include "../include/wifi_manager.h"

static const char *TAG = "wifi_ap";
static bool wifi_connected = false;
static esp_netif_t *ap_netif = NULL;

bool is_wifi_connected(void) {
    return wifi_connected;
}

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
        
        // Enable NAT for internet passthrough
        if (ap_netif != NULL) {
            esp_netif_ip_info_t ap_ip_info;
            esp_netif_get_ip_info(ap_netif, &ap_ip_info);
            ip_napt_enable(ap_ip_info.ip.addr, 1);
            ESP_LOGI(TAG, "✓ NAT enabled - Clients can now access internet!");
        }
    } else if (event_base == WIFI_EVENT && event_id == WIFI_EVENT_AP_STACONNECTED) {
        ESP_LOGI(TAG, "Station connected to AP");
    } else if (event_base == WIFI_EVENT && event_id == WIFI_EVENT_AP_STADISCONNECTED) {
        ESP_LOGI(TAG, "Station disconnected from AP");
    }
}

/* ---------- WiFi SoftAP init ---------- */
void wifi_init_apsta(void)
{
    esp_netif_init();
    esp_event_loop_create_default();

        // Create network interfaces
    ap_netif = esp_netif_create_default_wifi_ap();
    esp_netif_create_default_wifi_sta();
    
    // Configure static IP for AP interface
    esp_netif_dhcps_stop(ap_netif);
    esp_netif_ip_info_t ip_info;
    IP4_ADDR(&ip_info.ip, 192, 168, 4, 1);
    IP4_ADDR(&ip_info.gw, 192, 168, 4, 1);
    IP4_ADDR(&ip_info.netmask, 255, 255, 255, 0);
    esp_netif_set_ip_info(ap_netif, &ip_info);
    
    esp_netif_dhcps_start(ap_netif);
    
    ESP_LOGI(TAG, "AP configured with IP: 192.168.4.1");

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
