#include <stdio.h>
#include <string.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "driver/gpio.h"
#include "driver/spi_master.h"
#include "esp_log.h"
#include "../include/lora_handler.h"

static const char *TAG = "LoRa";

// SX1278 Registers
#define REG_FIFO                0x00
#define REG_OP_MODE             0x01
#define REG_FRF_MSB             0x06
#define REG_FRF_MID             0x07
#define REG_FRF_LSB             0x08
#define REG_PA_CONFIG           0x09
#define REG_LNA                 0x0C
#define REG_FIFO_ADDR_PTR       0x0D
#define REG_FIFO_TX_BASE_ADDR   0x0E
#define REG_FIFO_RX_BASE_ADDR   0x0F
#define REG_IRQ_FLAGS           0x12
#define REG_RX_NB_BYTES         0x13
#define REG_PKT_RSSI_VALUE      0x1A
#define REG_MODEM_CONFIG_1      0x1D
#define REG_MODEM_CONFIG_2      0x1E
#define REG_PAYLOAD_LENGTH      0x22
#define REG_MODEM_CONFIG_3      0x26

#define MODE_LONG_RANGE_MODE    0x80
#define MODE_SLEEP              0x00
#define MODE_STDBY              0x01
#define MODE_TX                 0x03

#define IRQ_TX_DONE_MASK        0x08

// ESP32-S2 Pin Mapping (shared SS pin with button)
#define SS_PIN    GPIO_NUM_9
#define RST_PIN   GPIO_NUM_14
#define DIO0_PIN  GPIO_NUM_33
#define SCK_PIN   GPIO_NUM_36
#define MISO_PIN  GPIO_NUM_37
#define MOSI_PIN  GPIO_NUM_35

static spi_device_handle_t spi;

// -------------------------------
// SPI READ / WRITE LOW LEVEL
// -------------------------------
static uint8_t lora_read_reg(uint8_t reg) {
    uint8_t tx[2] = { reg & 0x7F, 0 };
    uint8_t rx[2];
    spi_transaction_t t = {
        .length = 16,
        .tx_buffer = tx,
        .rx_buffer = rx,
    };
    spi_device_transmit(spi, &t);
    return rx[1];
}

static void lora_write_reg(uint8_t reg, uint8_t val) {
    uint8_t tx[2] = { reg | 0x80, val };
    spi_transaction_t t = {
        .length = 16,
        .tx_buffer = tx,
    };
    spi_device_transmit(spi, &t);
}

// -------------------------------
// SX1278 FUNCTIONS
// -------------------------------
static void lora_set_frequency(long freq) {
    uint64_t frf = ((uint64_t)freq << 19) / 32000000;
    lora_write_reg(REG_FRF_MSB, (uint8_t)(frf >> 16));
    lora_write_reg(REG_FRF_MID, (uint8_t)(frf >> 8));
    lora_write_reg(REG_FRF_LSB, (uint8_t)(frf >> 0));
}

static void lora_configure_modem() {
    // Configure modem for matching RX settings
    // BW=125kHz, CR=4/5, Implicit Header OFF (explicit)
    lora_write_reg(REG_MODEM_CONFIG_1, 0x72); // BW=125kHz, CR=4/5, explicit header
    
    // SF=7, TxContinuousMode=0, RxPayloadCrcOn=1 (enable CRC)
    lora_write_reg(REG_MODEM_CONFIG_2, 0x74); // SF=7, CRC ON
    
    // LowDataRateOptimize=0, AGC=1
    lora_write_reg(REG_MODEM_CONFIG_3, 0x04); // AGC ON
    
    // Set preamble length to 8 symbols
    lora_write_reg(0x20, 0x00); // Preamble MSB
    lora_write_reg(0x21, 0x08); // Preamble LSB = 8
    
    ESP_LOGI(TAG, "Modem configured: BW=125kHz, CR=4/5, SF=7, CRC=ON, Preamble=8");
}

static void lora_sleep() {
    lora_write_reg(REG_OP_MODE, MODE_LONG_RANGE_MODE | MODE_SLEEP);
}

static void lora_idle() {
    lora_write_reg(REG_OP_MODE, MODE_LONG_RANGE_MODE | MODE_STDBY);
}

static void lora_reset() {
    gpio_set_direction(RST_PIN, GPIO_MODE_OUTPUT);
    gpio_set_level(RST_PIN, 0);
    vTaskDelay(pdMS_TO_TICKS(10));
    gpio_set_level(RST_PIN, 1);
    vTaskDelay(pdMS_TO_TICKS(10));
}

void lora_send(uint8_t *data, uint8_t len) {
    ESP_LOGI(TAG, "Sending %d bytes...", len);

    lora_idle();
    
    // Reset FIFO address pointer
    lora_write_reg(REG_FIFO_ADDR_PTR, 0);
    
    // Write data to FIFO
    for (int i = 0; i < len; i++) {
        lora_write_reg(REG_FIFO, data[i]);
    }
    
    // Set payload length
    lora_write_reg(REG_PAYLOAD_LENGTH, len);
    
    // Start transmission
    lora_write_reg(REG_OP_MODE, MODE_LONG_RANGE_MODE | MODE_TX);

    // Wait for TX done
    while ((lora_read_reg(REG_IRQ_FLAGS) & IRQ_TX_DONE_MASK) == 0) {
        vTaskDelay(pdMS_TO_TICKS(10));
    }

    // Clear IRQ flags
    lora_write_reg(REG_IRQ_FLAGS, 0xFF);
    
    // Back to standby
    lora_idle();
    
    ESP_LOGI(TAG, "✓ TX complete");
}

// -------------------------------
// SPI INIT
// -------------------------------
static void lora_init_spi() {
    spi_bus_config_t buscfg = {
        .miso_io_num = MISO_PIN,
        .mosi_io_num = MOSI_PIN,
        .sclk_io_num = SCK_PIN,
        .max_transfer_sz = 32,
    };

    spi_device_interface_config_t devcfg = {
        .clock_speed_hz = 1 * 1000 * 1000,
        .mode = 0,
        .spics_io_num = SS_PIN,
        .queue_size = 1,
    };

    spi_bus_initialize(SPI2_HOST, &buscfg, SPI_DMA_CH_AUTO);
    spi_bus_add_device(SPI2_HOST, &devcfg, &spi);
}

// -------------------------------
// LORA INIT
// -------------------------------
void lora_init(void) {
    ESP_LOGI(TAG, "Initializing LoRa module...");

    lora_reset();
    lora_init_spi();

    // Check chip version to verify SPI communication
    lora_sleep();
    uint8_t version = lora_read_reg(0x42); // REG_VERSION
    ESP_LOGI(TAG, "SX127x chip version: 0x%02X (expected 0x12)", version);
    
    if (version != 0x12) {
        ESP_LOGE(TAG, "ERROR: Invalid chip version! Check SPI wiring.");
        ESP_LOGE(TAG, "Expected 0x12, got 0x%02X", version);
        return;
    }

    lora_write_reg(REG_OP_MODE, MODE_LONG_RANGE_MODE);   // LoRa Mode ON

    lora_set_frequency(433000000);   // 433 MHz
    
    // Configure TX Power: PA_BOOST pin, max power (0x8F = 17dBm)
    lora_write_reg(REG_PA_CONFIG, 0x8F);
    ESP_LOGI(TAG, "TX Power configured: 17dBm (PA_BOOST)");
    
    // Configure modem settings
    lora_configure_modem();

    lora_write_reg(REG_FIFO_TX_BASE_ADDR, 0);
    lora_write_reg(REG_FIFO_RX_BASE_ADDR, 0);
    lora_idle();

    ESP_LOGI(TAG, "LoRa initialized successfully, ready to transmit");
}
