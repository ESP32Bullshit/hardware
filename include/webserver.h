#ifndef WEBSERVER_H
#define WEBSERVER_H

#include "esp_http_server.h"

httpd_handle_t start_webserver(void);
esp_err_t websocket_send_event(const char *msg);

#endif // WEBSERVER_H
