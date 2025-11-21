#include "benchmark.h"
#include "esp_timer.h"
#include "esp_log.h"
#include "esp_heap_caps.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include <string.h>
#include <stdio.h>

#include "ecc.h"
#include "crypto_v.h"

static const char *TAG = "BENCHMARK";

// Test keys and data
static uint8_t test_private_key[32];
static uint8_t test_public_key[64];
static uint8_t peer_public_key[64];
static uint8_t peer_private_key[32];

/**
 * @brief Initialize benchmarking system
 */
void benchmark_init(void) {
    ESP_LOGI(TAG, "Initializing benchmark system...");
    
    // Initialize ECC
    ecc_init();
    
    // Generate test keypairs
    ecc_generate_keypair(test_public_key, test_private_key);
    ecc_generate_keypair(peer_public_key, peer_private_key);
    
    ESP_LOGI(TAG, "Benchmark system ready");
}

/**
 * @brief Helper to calculate statistics
 */
static void calculate_stats(int64_t *times, uint32_t count, benchmark_stats_t *stats) {
    if (count == 0) {
        memset(stats, 0, sizeof(benchmark_stats_t));
        return;
    }
    
    stats->min_us = times[0];
    stats->max_us = times[0];
    stats->total_us = 0;
    stats->iterations = count;
    
    for (uint32_t i = 0; i < count; i++) {
        if (times[i] < stats->min_us) stats->min_us = times[i];
        if (times[i] > stats->max_us) stats->max_us = times[i];
        stats->total_us += times[i];
    }
    
    stats->avg_us = stats->total_us / count;
}

/**
 * @brief Benchmark ECC key pair generation
 */
bool benchmark_key_generation(uint32_t iterations, benchmark_stats_t *stats) {
    ESP_LOGI(TAG, "Benchmarking key generation (%u iterations)...", iterations);
    
    int64_t *times = malloc(iterations * sizeof(int64_t));
    if (!times) {
        ESP_LOGE(TAG, "Failed to allocate memory for timing array");
        return false;
    }
    
    uint8_t priv[32], pub[64];
    uint32_t failures = 0;
    
    for (uint32_t i = 0; i < iterations; i++) {
        int64_t start = esp_timer_get_time();
        bool success = ecc_generate_keypair(pub, priv);
        int64_t end = esp_timer_get_time();
        
        times[i] = end - start;
        
        if (!success) {
            failures++;
        }
        
        // Small delay to prevent watchdog issues
        if (i % 10 == 0) {
            vTaskDelay(1);
        }
    }
    
    calculate_stats(times, iterations, stats);
    stats->failures = failures;
    
    free(times);
    
    ESP_LOGI(TAG, "Key generation: avg=%lld µs, min=%lld µs, max=%lld µs, failures=%u",
             stats->avg_us, stats->min_us, stats->max_us, stats->failures);
    
    return true;
}

/**
 * @brief Benchmark ECDSA signature generation
 */
bool benchmark_signature_generation(uint32_t iterations, size_t payload_size,
                                   benchmark_stats_t *stats) {
    ESP_LOGI(TAG, "Benchmarking signature generation (%u iterations, %u bytes)...",
             iterations, payload_size);
    
    int64_t *times = malloc(iterations * sizeof(int64_t));
    if (!times) {
        ESP_LOGE(TAG, "Failed to allocate memory for timing array");
        return false;
    }
    
    uint8_t *message = malloc(payload_size);
    uint8_t signature[64];
    uint32_t failures = 0;
    
    if (!message) {
        free(times);
        return false;
    }
    
    // Fill test message
    memset(message, 0xAB, payload_size);
    
    for (uint32_t i = 0; i < iterations; i++) {
        int64_t start = esp_timer_get_time();
        bool success = ecc_sign(test_private_key, message, payload_size, signature);
        int64_t end = esp_timer_get_time();
        
        times[i] = end - start;
        
        if (!success) {
            failures++;
        }
        
        if (i % 50 == 0) {
            vTaskDelay(1);
        }
    }
    
    calculate_stats(times, iterations, stats);
    stats->failures = failures;
    
    free(times);
    free(message);
    
    ESP_LOGI(TAG, "Signature generation: avg=%lld µs, min=%lld µs, max=%lld µs, failures=%u",
             stats->avg_us, stats->min_us, stats->max_us, stats->failures);
    
    return true;
}

/**
 * @brief Benchmark ECDSA signature verification
 */
bool benchmark_signature_verification(uint32_t iterations, size_t payload_size,
                                     benchmark_stats_t *stats) {
    ESP_LOGI(TAG, "Benchmarking signature verification (%u iterations, %u bytes)...",
             iterations, payload_size);
    
    int64_t *times = malloc(iterations * sizeof(int64_t));
    if (!times) {
        ESP_LOGE(TAG, "Failed to allocate memory for timing array");
        return false;
    }
    
    uint8_t *message = malloc(payload_size);
    uint8_t signature[64];
    uint32_t failures = 0;
    
    if (!message) {
        free(times);
        return false;
    }
    
    // Fill test message and create signature
    memset(message, 0xAB, payload_size);
    ecc_sign(test_private_key, message, payload_size, signature);
    
    for (uint32_t i = 0; i < iterations; i++) {
        int64_t start = esp_timer_get_time();
        bool success = ecc_verify(test_public_key, message, payload_size, signature);
        int64_t end = esp_timer_get_time();
        
        times[i] = end - start;
        
        if (!success) {
            failures++;
        }
        
        if (i % 50 == 0) {
            vTaskDelay(1);
        }
    }
    
    calculate_stats(times, iterations, stats);
    stats->failures = failures;
    
    free(times);
    free(message);
    
    ESP_LOGI(TAG, "Signature verification: avg=%lld µs, min=%lld µs, max=%lld µs, failures=%u",
             stats->avg_us, stats->min_us, stats->max_us, stats->failures);
    
    return true;
}

/**
 * @brief Benchmark ECIES encryption
 */
bool benchmark_encryption(uint32_t iterations, size_t payload_size,
                         benchmark_stats_t *stats) {
    ESP_LOGI(TAG, "Benchmarking encryption (%u iterations, %u bytes)...",
             iterations, payload_size);
    
    int64_t *times = malloc(iterations * sizeof(int64_t));
    if (!times) {
        ESP_LOGE(TAG, "Failed to allocate memory for timing array");
        return false;
    }
    
    uint8_t *plaintext = malloc(payload_size);
    uint8_t ciphertext[128];
    uint8_t ephemeral_pub[64];
    size_t cipher_len;
    uint32_t failures = 0;
    
    if (!plaintext) {
        free(times);
        return false;
    }
    
    // Fill test plaintext
    memset(plaintext, 0xCD, payload_size);
    
    for (uint32_t i = 0; i < iterations; i++) {
        int64_t start = esp_timer_get_time();
        bool success = crypto_ecies_encrypt(peer_public_key, plaintext, payload_size,
                                           ephemeral_pub, ciphertext, &cipher_len);
        int64_t end = esp_timer_get_time();
        
        times[i] = end - start;
        
        if (!success) {
            failures++;
        }
        
        if (i % 50 == 0) {
            vTaskDelay(1);
        }
    }
    
    calculate_stats(times, iterations, stats);
    stats->failures = failures;
    
    free(times);
    free(plaintext);
    
    ESP_LOGI(TAG, "Encryption: avg=%lld µs, min=%lld µs, max=%lld µs, failures=%u",
             stats->avg_us, stats->min_us, stats->max_us, stats->failures);
    
    return true;
}

/**
 * @brief Benchmark ECIES decryption
 */
bool benchmark_decryption(uint32_t iterations, size_t payload_size,
                         benchmark_stats_t *stats) {
    ESP_LOGI(TAG, "Benchmarking decryption (%u iterations, %u bytes)...",
             iterations, payload_size);
    
    int64_t *times = malloc(iterations * sizeof(int64_t));
    if (!times) {
        ESP_LOGE(TAG, "Failed to allocate memory for timing array");
        return false;
    }
    
    uint8_t *plaintext = malloc(payload_size);
    uint8_t ciphertext[128];
    uint8_t ephemeral_pub[64];
    uint8_t decrypted[128];
    size_t cipher_len, dec_len;
    uint32_t failures = 0;
    
    if (!plaintext) {
        free(times);
        return false;
    }
    
    // Fill test plaintext and encrypt it
    memset(plaintext, 0xCD, payload_size);
    uint8_t temp_ephemeral[64];
    crypto_ecies_encrypt(peer_public_key, plaintext, payload_size, temp_ephemeral, ciphertext, &cipher_len);
    
    // Use the ephemeral public key for decryption
    memcpy(ephemeral_pub, temp_ephemeral, 64);
    
    for (uint32_t i = 0; i < iterations; i++) {
        int64_t start = esp_timer_get_time();
        bool success = crypto_ecies_decrypt(peer_private_key, ephemeral_pub,
                                           ciphertext, cipher_len,
                                           decrypted, &dec_len);
        int64_t end = esp_timer_get_time();
        
        times[i] = end - start;
        
        if (!success) {
            failures++;
        }
        
        if (i % 50 == 0) {
            vTaskDelay(1);
        }
    }
    
    calculate_stats(times, iterations, stats);
    stats->failures = failures;
    
    free(times);
    free(plaintext);
    
    ESP_LOGI(TAG, "Decryption: avg=%lld µs, min=%lld µs, max=%lld µs, failures=%u",
             stats->avg_us, stats->min_us, stats->max_us, stats->failures);
    
    return true;
}

/**
 * @brief Benchmark ECDH shared secret computation
 */
bool benchmark_ecdh(uint32_t iterations, benchmark_stats_t *stats) {
    ESP_LOGI(TAG, "Benchmarking ECDH (%u iterations)...", iterations);
    
    int64_t *times = malloc(iterations * sizeof(int64_t));
    if (!times) {
        ESP_LOGE(TAG, "Failed to allocate memory for timing array");
        return false;
    }
    
    uint8_t shared_secret[32];
    uint32_t failures = 0;
    
    for (uint32_t i = 0; i < iterations; i++) {
        int64_t start = esp_timer_get_time();
        bool success = ecc_shared_secret(test_private_key, peer_public_key, shared_secret);
        int64_t end = esp_timer_get_time();
        
        times[i] = end - start;
        
        if (!success) {
            failures++;
        }
        
        if (i % 50 == 0) {
            vTaskDelay(1);
        }
    }
    
    calculate_stats(times, iterations, stats);
    stats->failures = failures;
    
    free(times);
    
    ESP_LOGI(TAG, "ECDH: avg=%lld µs, min=%lld µs, max=%lld µs, failures=%u",
             stats->avg_us, stats->min_us, stats->max_us, stats->failures);
    
    return true;
}

/**
 * @brief Benchmark full TX cycle (encrypt + sign)
 */
bool benchmark_full_tx_cycle(uint32_t iterations, size_t payload_size,
                            benchmark_stats_t *stats) {
    ESP_LOGI(TAG, "Benchmarking full TX cycle (%u iterations, %u bytes)...",
             iterations, payload_size);
    
    int64_t *times = malloc(iterations * sizeof(int64_t));
    if (!times) {
        ESP_LOGE(TAG, "Failed to allocate memory for timing array");
        return false;
    }
    
    uint8_t *plaintext = malloc(payload_size);
    uint8_t ciphertext[128];
    uint8_t ephemeral_pub[64];
    uint8_t signature[64];
    size_t cipher_len;
    uint32_t failures = 0;
    
    if (!plaintext) {
        free(times);
        return false;
    }
    
    // Fill test plaintext
    memset(plaintext, 0xEF, payload_size);
    
    for (uint32_t i = 0; i < iterations; i++) {
        int64_t start = esp_timer_get_time();
        
        // Step 1: Encrypt
        bool encrypt_ok = crypto_ecies_encrypt(peer_public_key, plaintext, payload_size,
                                              ephemeral_pub, ciphertext, &cipher_len);
        
        // Step 2: Sign the plaintext
        bool sign_ok = ecc_sign(test_private_key, plaintext, payload_size, signature);
        
        int64_t end = esp_timer_get_time();
        
        times[i] = end - start;
        
        if (!encrypt_ok || !sign_ok) {
            failures++;
        }
        
        if (i % 50 == 0) {
            vTaskDelay(1);
        }
    }
    
    calculate_stats(times, iterations, stats);
    stats->failures = failures;
    
    free(times);
    free(plaintext);
    
    ESP_LOGI(TAG, "Full TX cycle: avg=%lld µs, min=%lld µs, max=%lld µs, failures=%u",
             stats->avg_us, stats->min_us, stats->max_us, stats->failures);
    
    return true;
}

/**
 * @brief Benchmark full RX cycle (decrypt + verify)
 */
bool benchmark_full_rx_cycle(uint32_t iterations, size_t payload_size,
                            benchmark_stats_t *stats) {
    ESP_LOGI(TAG, "Benchmarking full RX cycle (%u iterations, %u bytes)...",
             iterations, payload_size);
    
    int64_t *times = malloc(iterations * sizeof(int64_t));
    if (!times) {
        ESP_LOGE(TAG, "Failed to allocate memory for timing array");
        return false;
    }
    
    uint8_t *plaintext = malloc(payload_size);
    uint8_t ciphertext[128];
    uint8_t signature[64];
    uint8_t ephemeral_pub[64];
    uint8_t decrypted[128];
    size_t cipher_len, dec_len;
    uint32_t failures = 0;
    
    if (!plaintext) {
        free(times);
        return false;
    }
    
    // Prepare encrypted and signed data
    memset(plaintext, 0xEF, payload_size);
    uint8_t temp_ephemeral[64];
    crypto_ecies_encrypt(peer_public_key, plaintext, payload_size, temp_ephemeral, ciphertext, &cipher_len);
    ecc_sign(test_private_key, plaintext, payload_size, signature);
    memcpy(ephemeral_pub, temp_ephemeral, 64);
    
    for (uint32_t i = 0; i < iterations; i++) {
        int64_t start = esp_timer_get_time();
        
        // Step 1: Decrypt
        bool decrypt_ok = crypto_ecies_decrypt(peer_private_key, ephemeral_pub,
                                              ciphertext, cipher_len,
                                              decrypted, &dec_len);
        
        // Step 2: Verify signature
        bool verify_ok = false;
        if (decrypt_ok) {
            verify_ok = ecc_verify(test_public_key, decrypted, dec_len, signature);
        }
        
        int64_t end = esp_timer_get_time();
        
        times[i] = end - start;
        
        if (!decrypt_ok || !verify_ok) {
            failures++;
        }
        
        if (i % 50 == 0) {
            vTaskDelay(1);
        }
    }
    
    calculate_stats(times, iterations, stats);
    stats->failures = failures;
    
    free(times);
    free(plaintext);
    
    ESP_LOGI(TAG, "Full RX cycle: avg=%lld µs, min=%lld µs, max=%lld µs, failures=%u",
             stats->avg_us, stats->min_us, stats->max_us, stats->failures);
    
    return true;
}

/**
 * @brief Run complete crypto benchmark suite
 */
bool benchmark_crypto_suite(uint32_t iterations, size_t payload_size,
                           crypto_benchmark_results_t *results) {
    ESP_LOGI(TAG, "\n");
    ESP_LOGI(TAG, "========================================");
    ESP_LOGI(TAG, "  CRYPTO BENCHMARK SUITE");
    ESP_LOGI(TAG, "========================================");
    ESP_LOGI(TAG, "Iterations: %u", iterations);
    ESP_LOGI(TAG, "Payload size: %u bytes", payload_size);
    ESP_LOGI(TAG, "========================================\n");
    
    memset(results, 0, sizeof(crypto_benchmark_results_t));
    results->payload_size = payload_size;
    
    // Capture initial memory
    results->heap_before = esp_get_free_heap_size();
    
    // Run all benchmarks
    if (!benchmark_key_generation(iterations, &results->key_generation)) {
        return false;
    }
    
    if (!benchmark_signature_generation(iterations, payload_size, 
                                       &results->signature_generation)) {
        return false;
    }
    
    if (!benchmark_signature_verification(iterations, payload_size,
                                         &results->signature_verification)) {
        return false;
    }
    
    if (!benchmark_encryption(iterations, payload_size, &results->encryption)) {
        return false;
    }
    
    if (!benchmark_decryption(iterations, payload_size, &results->decryption)) {
        return false;
    }
    
    if (!benchmark_ecdh(iterations, &results->ecdh_shared_secret)) {
        return false;
    }
    
    if (!benchmark_full_tx_cycle(iterations, payload_size, &results->full_tx_cycle)) {
        return false;
    }
    
    if (!benchmark_full_rx_cycle(iterations, payload_size, &results->full_rx_cycle)) {
        return false;
    }
    
    // Capture final memory
    results->heap_after = esp_get_free_heap_size();
    results->heap_used = results->heap_before - results->heap_after;
    results->stack_hwm = uxTaskGetStackHighWaterMark(NULL);
    
    ESP_LOGI(TAG, "\n========================================");
    ESP_LOGI(TAG, "  BENCHMARK COMPLETE");
    ESP_LOGI(TAG, "========================================\n");
    
    benchmark_print_results(results);
    
    return true;
}

/**
 * @brief Print benchmark statistics
 */
void benchmark_print_stats(const char *name, const benchmark_stats_t *stats) {
    printf("%-25s | Avg: %6lld µs | Min: %6lld µs | Max: %6lld µs | Fail: %lu\n",
           name, stats->avg_us, stats->min_us, stats->max_us, (unsigned long)stats->failures);
}

/**
 * @brief Print complete benchmark results
 */
void benchmark_print_results(const crypto_benchmark_results_t *results) {
    ESP_LOGI(TAG, "┌─────────────────────────────────────────────────────────────────────────┐");
    ESP_LOGI(TAG, "│                     CRYPTO BENCHMARK RESULTS                            │");
    ESP_LOGI(TAG, "├─────────────────────────────────────────────────────────────────────────┤");
    ESP_LOGI(TAG, "│ Payload Size: %3u bytes                                                 │", 
             results->payload_size);
    ESP_LOGI(TAG, "├─────────────────────────────────────────────────────────────────────────┤");
    
    benchmark_print_stats("Key Generation", &results->key_generation);
    benchmark_print_stats("Signature Gen", &results->signature_generation);
    benchmark_print_stats("Signature Verify", &results->signature_verification);
    benchmark_print_stats("Encryption (ECIES)", &results->encryption);
    benchmark_print_stats("Decryption (ECIES)", &results->decryption);
    benchmark_print_stats("ECDH", &results->ecdh_shared_secret);
    benchmark_print_stats("Full TX Cycle", &results->full_tx_cycle);
    benchmark_print_stats("Full RX Cycle", &results->full_rx_cycle);
    
    ESP_LOGI(TAG, "├─────────────────────────────────────────────────────────────────────────┤");
    ESP_LOGI(TAG, "│ MEMORY USAGE                                                            │");
    ESP_LOGI(TAG, "├─────────────────────────────────────────────────────────────────────────┤");
    ESP_LOGI(TAG, "│ Heap before:  %6lu bytes                                              │",
             results->heap_before);
    ESP_LOGI(TAG, "│ Heap after:   %6lu bytes                                              │",
             results->heap_after);
    ESP_LOGI(TAG, "│ Heap used:    %6lu bytes                                              │",
             results->heap_used);
    ESP_LOGI(TAG, "│ Stack HWM:    %6lu bytes                                              │",
             results->stack_hwm);
    ESP_LOGI(TAG, "└─────────────────────────────────────────────────────────────────────────┘");
    
    // Calculate throughput metrics
    if (results->full_tx_cycle.avg_us > 0) {
        float tx_per_sec = 1000000.0 / results->full_tx_cycle.avg_us;
        float bytes_per_sec = tx_per_sec * results->payload_size;
        ESP_LOGI(TAG, "\n┌─────────────────────────────────────────────────────────────────────────┐");
        ESP_LOGI(TAG, "│ THROUGHPUT METRICS                                                      │");
        ESP_LOGI(TAG, "├─────────────────────────────────────────────────────────────────────────┤");
        ESP_LOGI(TAG, "│ Max TX rate:    %.2f messages/sec                                    │", tx_per_sec);
        ESP_LOGI(TAG, "│ Max throughput: %.2f bytes/sec (%.2f KB/sec)                        │",
                 bytes_per_sec, bytes_per_sec / 1024.0);
        ESP_LOGI(TAG, "└─────────────────────────────────────────────────────────────────────────┘");
    }
}

/**
 * @brief Export benchmark results as JSON string
 */
int benchmark_export_json(const crypto_benchmark_results_t *results,
                         char *buffer, size_t buffer_size) {
    return snprintf(buffer, buffer_size,
        "{\n"
        "  \"payload_size\": %u,\n"
        "  \"key_generation\": {\"avg_us\": %lld, \"min_us\": %lld, \"max_us\": %lld, \"failures\": %lu},\n"
        "  \"signature_generation\": {\"avg_us\": %lld, \"min_us\": %lld, \"max_us\": %lld, \"failures\": %lu},\n"
        "  \"signature_verification\": {\"avg_us\": %lld, \"min_us\": %lld, \"max_us\": %lld, \"failures\": %lu},\n"
        "  \"encryption\": {\"avg_us\": %lld, \"min_us\": %lld, \"max_us\": %lld, \"failures\": %lu},\n"
        "  \"decryption\": {\"avg_us\": %lld, \"min_us\": %lld, \"max_us\": %lld, \"failures\": %lu},\n"
        "  \"ecdh\": {\"avg_us\": %lld, \"min_us\": %lld, \"max_us\": %lld, \"failures\": %lu},\n"
        "  \"full_tx_cycle\": {\"avg_us\": %lld, \"min_us\": %lld, \"max_us\": %lld, \"failures\": %lu},\n"
        "  \"full_rx_cycle\": {\"avg_us\": %lld, \"min_us\": %lld, \"max_us\": %lld, \"failures\": %lu},\n"
        "  \"memory\": {\"heap_before\": %lu, \"heap_after\": %lu, \"heap_used\": %lu, \"stack_hwm\": %lu}\n"
        "}",
        results->payload_size,
        results->key_generation.avg_us, results->key_generation.min_us, results->key_generation.max_us, (unsigned long)results->key_generation.failures,
        results->signature_generation.avg_us, results->signature_generation.min_us, results->signature_generation.max_us, (unsigned long)results->signature_generation.failures,
        results->signature_verification.avg_us, results->signature_verification.min_us, results->signature_verification.max_us, (unsigned long)results->signature_verification.failures,
        results->encryption.avg_us, results->encryption.min_us, results->encryption.max_us, (unsigned long)results->encryption.failures,
        results->decryption.avg_us, results->decryption.min_us, results->decryption.max_us, (unsigned long)results->decryption.failures,
        results->ecdh_shared_secret.avg_us, results->ecdh_shared_secret.min_us, results->ecdh_shared_secret.max_us, (unsigned long)results->ecdh_shared_secret.failures,
        results->full_tx_cycle.avg_us, results->full_tx_cycle.min_us, results->full_tx_cycle.max_us, (unsigned long)results->full_tx_cycle.failures,
        results->full_rx_cycle.avg_us, results->full_rx_cycle.min_us, results->full_rx_cycle.max_us, (unsigned long)results->full_rx_cycle.failures,
        results->heap_before, results->heap_after, results->heap_used, results->stack_hwm
    );
}
