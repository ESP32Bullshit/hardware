#include <stdio.h>
#include <stdint.h>
#include "nvs_flash.h"
#include "esp_log.h"
#include "../include/ecc.h"
#include "../include/crypto_v.h"
#include "../include/wifi_manager.h"
#include "../include/webserver.h"
#include "../include/nvs_helper.h"
#include "../include/utils.h"
#include "../include/button_handler.h"
#include "../include/lora_handler.h"

static const char *TAG = "main";

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
    lora_init();
    button_init();
}
