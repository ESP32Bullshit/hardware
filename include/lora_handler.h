#ifndef LORA_HANDLER_H
#define LORA_HANDLER_H

#include <stdint.h>
#include <stddef.h>

void lora_init(void);
void lora_send(uint8_t *data, uint8_t len);

#endif // LORA_HANDLER_H
