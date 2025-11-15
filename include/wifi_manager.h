#ifndef WIFI_MANAGER_H
#define WIFI_MANAGER_H

#include "esp_wifi.h"
#include "esp_event.h"

void wifi_init_apsta(void);
bool is_wifi_connected(void);

#endif // WIFI_MANAGER_H
