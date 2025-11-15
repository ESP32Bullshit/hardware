#include <stdio.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "driver/gpio.h"
#include "esp_timer.h"
#include "esp_log.h"
#include "../include/button_handler.h"
#include "../include/webserver.h"

static const char *TAG = "button_handler";

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

void button_init(void)
{
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
