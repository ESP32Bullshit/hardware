/*
 * Crypto Benchmark Test Program
 * 
 * This file demonstrates how to use the benchmark module.
 * You can integrate this into your main.c or call it separately.
 */

#include <stdio.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "esp_log.h"
#include "nvs_flash.h"

#include "benchmark.h"
#include "ecc.h"

static const char *TAG = "BENCH_TEST";

void run_benchmark_tests(void) {
    ESP_LOGI(TAG, "Initializing benchmark system...");
    benchmark_init();
    
    crypto_benchmark_results_t results;
    
    // Test 1: Standard 64-byte payload (typical JSON location data)
    ESP_LOGI(TAG, "\n=== TEST 1: 64-byte payload ===");
    if (benchmark_crypto_suite(100, 64, &results)) {
        ESP_LOGI(TAG, "✓ Benchmark complete");
        
        // Export to JSON
        char json_buffer[2048];
        int json_len = benchmark_export_json(&results, json_buffer, sizeof(json_buffer));
        if (json_len > 0) {
            ESP_LOGI(TAG, "\nJSON Export:\n%s", json_buffer);
        }
    }
    
    // Test 2: Smaller 32-byte payload
    ESP_LOGI(TAG, "\n=== TEST 2: 32-byte payload ===");
    benchmark_crypto_suite(100, 32, &results);
    
    // Test 3: Larger 128-byte payload (stress test)
    ESP_LOGI(TAG, "\n=== TEST 3: 96-byte payload ===");
    benchmark_crypto_suite(100, 96, &results);
    
    ESP_LOGI(TAG, "\n✓ All benchmark tests complete!");
}

// Uncomment this to use as standalone app_main
/*
void app_main(void) {
    ESP_ERROR_CHECK(nvs_flash_init());
    ecc_init();
    
    run_benchmark_tests();
    
    ESP_LOGI(TAG, "Benchmark complete. System halted.");
    while(1) {
        vTaskDelay(pdMS_TO_TICKS(1000));
    }
}
*/
