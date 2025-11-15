#ifndef BUTTON_HANDLER_H
#define BUTTON_HANDLER_H

#include "driver/gpio.h"

#define BUTTON_PIN GPIO_NUM_10  // Changed from GPIO_NUM_9 (now used by LoRa SS)

void button_task(void *arg);
void button_init(void);

#endif // BUTTON_HANDLER_H
