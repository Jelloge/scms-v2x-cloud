#ifndef HTTP_H
#define HTTP_H

typedef struct {
    char *body;
    long status_code;
} http_response_t;

int http_post_json(const char *url, const char *json_payload, http_response_t *response);
void http_response_free(http_response_t *response);

#endif
