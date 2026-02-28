#include "pki.h"

#include "config.h"
#include "http.h"
#include "metrics.h"
#include "storage.h"

#include <openssl/core_names.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static char *json_escape_string(const char *in) {
    size_t extra = 0;
    for (const char *p = in; *p; ++p) {
        if (*p == '\\' || *p == '"' || *p == '\n' || *p == '\r') extra++;
    }

    size_t len = strlen(in);
    char *out = calloc(len + extra + 1, 1);
    if (!out) return NULL;

    char *w = out;
    for (const char *p = in; *p; ++p) {
        if (*p == '\\' || *p == '"') {
            *w++ = '\\';
            *w++ = *p;
        } else if (*p == '\n') {
            *w++ = '\\';
            *w++ = 'n';
        } else if (*p == '\r') {
            *w++ = '\\';
            *w++ = 'r';
        } else {
            *w++ = *p;
        }
    }
    *w = '\0';
    return out;
}

int generate_enrollment_key_and_csr(const char *common_name) {
    EVP_PKEY_CTX *kctx = NULL;
    EVP_PKEY *pkey = NULL;
    X509_REQ *req = NULL;
    X509_NAME *name = NULL;
    FILE *kf = NULL, *cf = NULL;

    kctx = EVP_PKEY_CTX_new_from_name(NULL, "EC", NULL);
    if (!kctx) goto err;
    if (EVP_PKEY_keygen_init(kctx) <= 0) goto err;
    if (EVP_PKEY_CTX_set_group_name(kctx, "prime256v1") <= 0) goto err;
    if (EVP_PKEY_keygen(kctx, &pkey) <= 0) goto err;

    req = X509_REQ_new();
    if (!req) goto err;
    X509_REQ_set_version(req, 1L);

    name = X509_NAME_new();
    if (!name) goto err;
    X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC,
                               (const unsigned char *) common_name, -1, -1, 0);
    X509_REQ_set_subject_name(req, name);
    X509_REQ_set_pubkey(req, pkey);
    if (!X509_REQ_sign(req, pkey, EVP_sha256())) goto err;

    kf = fopen(PRIVATE_KEY_PATH, "w");
    cf = fopen(CSR_PATH, "w");
    if (!kf || !cf) goto err;

    if (!PEM_write_PrivateKey(kf, pkey, NULL, NULL, 0, NULL, NULL)) goto err;
    if (!PEM_write_X509_REQ(cf, req)) goto err;

    fclose(kf);
    fclose(cf);
    X509_NAME_free(name);
    X509_REQ_free(req);
    EVP_PKEY_free(pkey);
    EVP_PKEY_CTX_free(kctx);
    return 0;

err:
    if (kf) fclose(kf);
    if (cf) fclose(cf);
    X509_NAME_free(name);
    X509_REQ_free(req);
    EVP_PKEY_free(pkey);
    EVP_PKEY_CTX_free(kctx);
    return -1;
}

int submit_enrollment_request(const char *url) {
    char *csr = read_text_file(CSR_PATH);
    if (!csr) return -1;

    char *escaped = json_escape_string(csr);
    free(csr);
    if (!escaped) return -1;

    size_t payload_len = strlen(escaped) + 128;
    char *payload = calloc(payload_len, 1);
    if (!payload) {
        free(escaped);
        return -1;
    }
    snprintf(payload, payload_len, "{\"csrPem\":\"%s\"}", escaped);

    http_response_t resp = {0};
    int rc = http_post_json(url, payload, &resp);
    if (rc == 0 && resp.status_code >= 200 && resp.status_code < 300) {
        rc = write_text_file(ENROLLMENT_CERT_PATH, resp.body ? resp.body : "");
    } else {
        rc = -1;
    }

    free(escaped);
    free(payload);
    http_response_free(&resp);
    return rc;
}

int request_pseudonym_batch(const char *url, int batch_size) {
    char payload[128];
    snprintf(payload, sizeof(payload), "{\"batchSize\":%d}", batch_size);

    http_response_t resp = {0};
    int rc = http_post_json(url, payload, &resp);
    if (rc == 0 && resp.status_code >= 200 && resp.status_code < 300) {
        rc = write_text_file(PSEUDONYM_BUNDLE_PATH, resp.body ? resp.body : "");
    } else {
        rc = -1;
    }

    http_response_free(&resp);
    return rc;
}

int run_provisioning_cycle(const char *enroll_url, const char *pseudo_url,
                           pki_cycle_metrics_t *metrics_out) {
    timer_sample_t t = {0};

    timer_start(&t);
    if (generate_enrollment_key_and_csr("qnx-vehicle-client") != 0) return -1;
    timer_stop(&t);
    metrics_out->keygen_ms = timer_elapsed_ms(&t);

    timer_start(&t);
    if (submit_enrollment_request(enroll_url) != 0) return -1;
    timer_stop(&t);
    metrics_out->enroll_ms = timer_elapsed_ms(&t);

    timer_start(&t);
    if (request_pseudonym_batch(pseudo_url, CERT_BATCH_SIZE) != 0) return -1;
    timer_stop(&t);
    metrics_out->pseudonym_ms = timer_elapsed_ms(&t);

    return 0;
}
