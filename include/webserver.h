#ifndef WEBSERVER_H
#define WEBSERVER_H

#include "esp_http_server.h"

httpd_handle_t start_webserver(void);
esp_err_t websocket_send_event(const char *msg);
esp_err_t public_key_get_handler(httpd_req_t *req);
esp_err_t store_peer_post_handler(httpd_req_t *req);
esp_err_t set_uid_post_handler(httpd_req_t *req);
esp_err_t send_location_get_handler(httpd_req_t *req);

#endif // WEBSERVER_H
