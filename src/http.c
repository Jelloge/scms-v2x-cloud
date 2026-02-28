#include "http.h"

#include <curl/curl.h>
#include <stdlib.h>
#include <string.h>

typedef struct {
    char *data;
    size_t len;
} buffer_t;

static size_t write_cb(void *contents, size_t size, size_t nmemb, void *userp) {
    size_t realsize = size * nmemb;
    buffer_t *buf = (buffer_t *) userp;
    char *new_mem = realloc(buf->data, buf->len + realsize + 1);
    if (!new_mem) return 0;
    buf->data = new_mem;
    memcpy(&(buf->data[buf->len]), contents, realsize);
    buf->len += realsize;
    buf->data[buf->len] = '\0';
    return realsize;
}

static int mock_post_json(const char *url, http_response_t *response) {
    response->status_code = 200;
    if (strstr(url, "pseudonym")) {
        response->body = strdup("{\"certificates\":[\"pseudo-cert-1\",\"pseudo-cert-2\"]}");
    } else {
        response->body = strdup("{\"certificate\":\"enrollment-cert\",\"ca\":\"MockCA\"}");
    }
    return response->body ? 0 : -1;
}

int http_post_json(const char *url, const char *json_payload, http_response_t *response) {
    if (strncmp(url, "mock://", 7) == 0) {
        (void) json_payload;
        return mock_post_json(url, response);
    }

    CURL *curl = curl_easy_init();
    if (!curl) return -1;

    buffer_t buffer = {.data = calloc(1, 1), .len = 0};
    struct curl_slist *headers = NULL;
    headers = curl_slist_append(headers, "Content-Type: application/json");

    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, json_payload);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_cb);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &buffer);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);

    CURLcode rc = curl_easy_perform(curl);
    if (rc != CURLE_OK) {
        curl_slist_free_all(headers);
        curl_easy_cleanup(curl);
        free(buffer.data);
        return -1;
    }

    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &response->status_code);
    response->body = buffer.data;

    curl_slist_free_all(headers);
    curl_easy_cleanup(curl);
    return 0;
}

void http_response_free(http_response_t *response) {
    free(response->body);
    response->body = NULL;
}
