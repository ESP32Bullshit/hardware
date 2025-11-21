#ifndef BENCHMARK_H
#define BENCHMARK_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

/**
 * @brief Crypto operation benchmark statistics
 */
typedef struct {
    int64_t min_us;        // Minimum time in microseconds
    int64_t max_us;        // Maximum time in microseconds
    int64_t avg_us;        // Average time in microseconds
    int64_t total_us;      // Total time
    uint32_t iterations;   // Number of iterations
    uint32_t failures;     // Number of failed operations
} benchmark_stats_t;

/**
 * @brief Complete benchmark results for all crypto operations
 */
typedef struct {
    benchmark_stats_t key_generation;
    benchmark_stats_t signature_generation;
    benchmark_stats_t signature_verification;
    benchmark_stats_t encryption;
    benchmark_stats_t decryption;
    benchmark_stats_t ecdh_shared_secret;
    benchmark_stats_t full_tx_cycle;      // Encrypt + Sign
    benchmark_stats_t full_rx_cycle;      // Decrypt + Verify
    
    // Memory metrics
    uint32_t heap_before;
    uint32_t heap_after;
    uint32_t heap_used;
    uint32_t stack_hwm;                   // High water mark
    
    // Payload size tested
    size_t payload_size;
} crypto_benchmark_results_t;

/**
 * @brief Initialize benchmarking system
 */
void benchmark_init(void);

/**
 * @brief Run complete crypto benchmark suite
 * 
 * @param iterations Number of iterations for each test
 * @param payload_size Size of test payload (e.g., 64 bytes)
 * @param results Output results structure
 * @return true if successful, false otherwise
 */
bool benchmark_crypto_suite(uint32_t iterations, size_t payload_size, 
                           crypto_benchmark_results_t *results);

/**
 * @brief Benchmark ECC key pair generation
 * 
 * @param iterations Number of key pairs to generate
 * @param stats Output statistics
 * @return true if successful
 */
bool benchmark_key_generation(uint32_t iterations, benchmark_stats_t *stats);

/**
 * @brief Benchmark ECDSA signature generation
 * 
 * @param iterations Number of signatures to generate
 * @param payload_size Size of message to sign
 * @param stats Output statistics
 * @return true if successful
 */
bool benchmark_signature_generation(uint32_t iterations, size_t payload_size,
                                   benchmark_stats_t *stats);

/**
 * @brief Benchmark ECDSA signature verification
 * 
 * @param iterations Number of verifications
 * @param payload_size Size of message to verify
 * @param stats Output statistics
 * @return true if successful
 */
bool benchmark_signature_verification(uint32_t iterations, size_t payload_size,
                                     benchmark_stats_t *stats);

/**
 * @brief Benchmark ECIES encryption
 * 
 * @param iterations Number of encryptions
 * @param payload_size Size of plaintext
 * @param stats Output statistics
 * @return true if successful
 */
bool benchmark_encryption(uint32_t iterations, size_t payload_size,
                         benchmark_stats_t *stats);

/**
 * @brief Benchmark ECIES decryption
 * 
 * @param iterations Number of decryptions
 * @param payload_size Size of plaintext
 * @param stats Output statistics
 * @return true if successful
 */
bool benchmark_decryption(uint32_t iterations, size_t payload_size,
                         benchmark_stats_t *stats);

/**
 * @brief Benchmark ECDH shared secret computation
 * 
 * @param iterations Number of ECDH operations
 * @param stats Output statistics
 * @return true if successful
 */
bool benchmark_ecdh(uint32_t iterations, benchmark_stats_t *stats);

/**
 * @brief Benchmark full TX cycle (encrypt + sign)
 * 
 * @param iterations Number of TX cycles
 * @param payload_size Size of data to transmit
 * @param stats Output statistics
 * @return true if successful
 */
bool benchmark_full_tx_cycle(uint32_t iterations, size_t payload_size,
                            benchmark_stats_t *stats);

/**
 * @brief Benchmark full RX cycle (decrypt + verify)
 * 
 * @param iterations Number of RX cycles
 * @param payload_size Size of data to receive
 * @param stats Output statistics
 * @return true if successful
 */
bool benchmark_full_rx_cycle(uint32_t iterations, size_t payload_size,
                            benchmark_stats_t *stats);

/**
 * @brief Print benchmark statistics
 * 
 * @param name Operation name
 * @param stats Statistics to print
 */
void benchmark_print_stats(const char *name, const benchmark_stats_t *stats);

/**
 * @brief Print complete benchmark results
 * 
 * @param results Complete results structure
 */
void benchmark_print_results(const crypto_benchmark_results_t *results);

/**
 * @brief Export benchmark results as JSON string
 * 
 * @param results Results to export
 * @param buffer Output buffer
 * @param buffer_size Size of output buffer
 * @return Number of bytes written, or -1 on error
 */
int benchmark_export_json(const crypto_benchmark_results_t *results,
                         char *buffer, size_t buffer_size);

#endif // BENCHMARK_H
