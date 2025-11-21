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
#include "../include/benchmark.h"

static const char *TAG = "main";

// Uncomment this line to run benchmarks on startup
// #define RUN_BENCHMARK_ON_STARTUP

/* ---------- app_main ---------- */
void app_main() {
    uint8_t private_key[ECC_PRIVATE_KEY_SIZE];
    uint8_t public_key[ECC_PUBLIC_KEY_SIZE];

    ESP_ERROR_CHECK(nvs_flash_init());
    
    // Initialize ECC library with ESP32 RNG
    ecc_init();

#ifdef RUN_BENCHMARK_ON_STARTUP
    ESP_LOGI(TAG, "\n\n*** RUNNING CRYPTO BENCHMARKS ***\n");
    
    // Initialize benchmark system
    benchmark_init();
    
    // Run complete benchmark suite
    crypto_benchmark_results_t results;
    
    // Test with 64-byte payload (typical use case)
    ESP_LOGI(TAG, "Starting benchmark with 64-byte payload...");
    if (benchmark_crypto_suite(20, 64, &results)) {  // Reduced to 20 iterations to avoid stack issues
        ESP_LOGI(TAG, "✓ Benchmark completed successfully!");
        
        // Optionally export to JSON
        char json_buffer[2048];
        int json_len = benchmark_export_json(&results, json_buffer, sizeof(json_buffer));
        if (json_len > 0 && json_len < sizeof(json_buffer)) {
            ESP_LOGI(TAG, "\n=== JSON EXPORT ===");
            printf("%s\n", json_buffer);
            ESP_LOGI(TAG, "===================\n");
        }
    } else {
        ESP_LOGE(TAG, "✗ Benchmark failed!");
    }
    
    ESP_LOGI(TAG, "*** BENCHMARK COMPLETE - Continuing normal operation ***\n\n");
#endif

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
