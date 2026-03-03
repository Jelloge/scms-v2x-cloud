#include "pki.h"

#include "config.h"
#include "http.h"
#include "metrics.h"
#include "storage.h"

#include <openssl/bio.h>
#include <openssl/bn.h>
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

/* helper to pull a json string value out of a response body.
   super basic just looks for "key":"value" and returns a copy
   of the value. good enough for ejbca responses where we only
   need the certificate field */
static char *json_get_string(const char *json, const char *key) {
    if (!json || !key) return NULL;

    /* build the search pattern like "certificate":" */
    char pattern[128];
    snprintf(pattern, sizeof(pattern), "\"%s\":\"", key);

    const char *start = strstr(json, pattern);
    if (!start) {
        /* try with a space after the colon: "certificate": " */
        snprintf(pattern, sizeof(pattern), "\"%s\": \"", key);
        start = strstr(json, pattern);
        if (!start) return NULL;
    }

    start = strchr(start, ':');
    if (!start) return NULL;
    start++; // skip
    while (*start == ' ') start++; // skip spaces
    if (*start != '"') return NULL;
    start++; // skip opening quote 

    // find the closing quote (handle escaped quotes) 
    const char *end = start;
    while (*end && !(*end == '"' && *(end - 1) != '\\')) end++;
    if (!*end) return NULL;

    size_t len = end - start;
    char *val = calloc(len + 1, 1);
    if (!val) return NULL;
    memcpy(val, start, len);
    return val;
}

/* base64 decode helper ejbca returns the certificate as base64-encoded
   DER, so we need to decode it and convert to PEM for storage.
   openssl has built-in base64 decoding which makes this pretty easy */
static int base64_decode_to_pem(const char *b64, const char *out_path) {
    if (!b64 || !out_path) return -1;

    /* use openssl's BIO chain */
    BIO *b64_bio = BIO_new(BIO_f_base64());
    BIO *mem_bio = BIO_new_mem_buf(b64, -1);
    if (!b64_bio || !mem_bio) {
        BIO_free(b64_bio);
        BIO_free(mem_bio);
        return -1;
    }
    BIO_set_flags(b64_bio, BIO_FLAGS_BASE64_NO_NL);
    mem_bio = BIO_push(b64_bio, mem_bio);

    /* read the decoded DER bytes */
    unsigned char der_buf[4096];
    int der_len = BIO_read(mem_bio, der_buf, sizeof(der_buf));
    BIO_free_all(mem_bio);

    if (der_len <= 0) return -1;

    /* parse DER into an X509 struct and write out as PEM */
    const unsigned char *p = der_buf;
    X509 *cert = d2i_X509(NULL, &p, der_len);
    if (!cert) return -1;

    FILE *f = fopen(out_path, "w");
    if (!f) { X509_free(cert); return -1; }
    int ok = PEM_write_X509(f, cert);
    fclose(f);
    X509_free(cert);
    return ok ? 0 : -1;
}

int submit_enrollment_request(const char *url) {
    char *csr = read_text_file(CSR_PATH);
    if (!csr) return -1;

    char *escaped = json_escape_string(csr);
    free(csr);
    if (!escaped) return -1;

    /* build the json payload. for mock urls we keep the old simple format,
       for real ejbca we need to include all the profile info so ejbca
       knows which CA and profiles to use for issuing the cert */
    size_t payload_len = strlen(escaped) + 512;
    char *payload = calloc(payload_len, 1);
    if (!payload) {
        free(escaped);
        return -1;
    }

    if (strncmp(url, "mock://", 7) == 0) {
        snprintf(payload, payload_len, "{\"csrPem\":\"%s\"}", escaped);
    } else {
        // ejbca pkcs10enroll format, the field names have to match exactly
        // what the rest api expects or you get a 400 back 
        // this was painful
        snprintf(payload, payload_len,
            "{"
            "\"certificate_request\":\"%s\","
            "\"certificate_profile_name\":\"%s\","
            "\"end_entity_profile_name\":\"%s\","
            "\"certificate_authority_name\":\"%s\","
            "\"username\":\"%s\","
            "\"password\":\"%s\","
            "\"include_chain\":true"
            "}",
            escaped,
            EJBCA_CERT_PROFILE,
            EJBCA_EE_PROFILE,
            EJBCA_CA_NAME,
            EJBCA_USERNAME,
            EJBCA_PASSWORD);
    }

    http_response_t resp = {0};
    int rc = http_post_json(url, payload, &resp);

    if (rc == 0 && resp.status_code >= 200 && resp.status_code < 300) {
        if (strncmp(url, "mock://", 7) == 0) {
            /* mock mode, just save the raw json like before */
            rc = write_text_file(ENROLLMENT_CERT_PATH, resp.body ? resp.body : "");
        } else {
            /* real ejbca, response has the cert as base64 DER in a json field.
               we need to pull it out and decode it to PEM */
            char *cert_b64 = json_get_string(resp.body, "certificate");
            if (cert_b64) {
                rc = base64_decode_to_pem(cert_b64, ENROLLMENT_CERT_PATH);
                free(cert_b64);
            } else {
                /* maybe ejbca returned the cert directly or an error */
                fprintf(stderr, "[enroll] could not parse certificate from response\n");
                if (resp.body) fprintf(stderr, "[enroll] response: %s\n", resp.body);
                rc = -1;
            }
        }
    } else {
        if (resp.body) fprintf(stderr, "[enroll] server error %ld: %s\n",
                                resp.status_code, resp.body);
        rc = -1;
    }

    free(escaped);
    free(payload);
    http_response_free(&resp);
    return rc;
}

/* for pseudonym certs we reuse the same pkcs10 enrollment endpoint.
   in a real scms (like the brecht paper describes) there would be a
   separate pseudonym CA that issues batches of short lived anonymous certs.
   after looking at the documentation for 10 years, i learned that
   ejbca community edition doesn't have that concept natively, so we can 
   simulate it by enrolling once and saving the result as our "pseudonym".
   for the project this is fine,  the important part is measuring the
   round-trip latency to the cloud CA, which is the same either way (hopefully) */
int request_pseudonym_batch(const char *url, int batch_size) {
    (void)batch_size; /* not used for real ejbca */

    if (strncmp(url, "mock://", 7) == 0) {
        /* keep the old simple behavior */
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

    char *csr = read_text_file(CSR_PATH);
    if (!csr) return -1;

    char *escaped = json_escape_string(csr);
    free(csr);
    if (!escaped) return -1;

    size_t payload_len = strlen(escaped) + 512;
    char *payload = calloc(payload_len, 1);
    if (!payload) {
        free(escaped);
        return -1;
    }

    snprintf(payload, payload_len,
        "{"
        "\"certificate_request\":\"%s\","
        "\"certificate_profile_name\":\"%s\","
        "\"end_entity_profile_name\":\"%s\","
        "\"certificate_authority_name\":\"%s\","
        "\"username\":\"%s\","
        "\"password\":\"%s\","
        "\"include_chain\":true"
        "}",
        escaped,
        EJBCA_CERT_PROFILE,
        EJBCA_EE_PROFILE,
        EJBCA_CA_NAME,
        EJBCA_USERNAME,
        EJBCA_PASSWORD);

    http_response_t resp = {0};
    int rc = http_post_json(url, payload, &resp);

    if (rc == 0 && resp.status_code >= 200 && resp.status_code < 300) {
        char *cert_b64 = json_get_string(resp.body, "certificate");
        if (cert_b64) {
            rc = base64_decode_to_pem(cert_b64, PSEUDONYM_BUNDLE_PATH);
            free(cert_b64);
        } else {
            fprintf(stderr, "[pseudonym] could not parse cert from response\n");
            if (resp.body) fprintf(stderr, "[pseudonym] response: %s\n", resp.body);
            rc = -1;
        }
    } else {
        if (resp.body) fprintf(stderr, "[pseudonym] server error %ld: %s\n",
                                resp.status_code, resp.body);
        rc = -1;
    }

    free(escaped);
    free(payload);
    http_response_free(&resp);
    return rc;
}

/* read the private key back from disk after enrollment so we can
   hand it to thread 0 for bsm signing. thread 1 calls this after
   each successful provisioning */
EVP_PKEY *load_signing_key(const char *key_path) {
    FILE *f = fopen(key_path, "r");
    if (!f) return NULL;
    EVP_PKEY *pkey = PEM_read_PrivateKey(f, NULL, NULL, NULL);
    fclose(f);
    return pkey;
}

/* signs a bsm payload with ecdsa p-256 + sha256 using the EVP_DigestSign api
   this is what thread 0 calls every 100ms to simulate a vehicle broadcasting
   a signed basic safety message (the brecht paper section V-B)
   we call DigestSignFinal twice: first to get the required sigmatuire buffer size,
   then again to actually produce the signature */
int sign_bsm_payload(EVP_PKEY *key, const unsigned char *payload,
                     size_t payload_len, unsigned char *sig_out,
                     size_t *sig_len_out) {
    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
    if (!mdctx) return -1;

    if (EVP_DigestSignInit(mdctx, NULL, EVP_sha256(), NULL, key) <= 0) {
        EVP_MD_CTX_free(mdctx);
        return -1;
    }
    if (EVP_DigestSignUpdate(mdctx, payload, payload_len) <= 0) {
        EVP_MD_CTX_free(mdctx);
        return -1;
    }

    // first call with NULL gets us the required buffer length
    size_t siglen = 0;
    if (EVP_DigestSignFinal(mdctx, NULL, &siglen) <= 0) {
        EVP_MD_CTX_free(mdctx);
        return -1;
    }
    if (siglen > *sig_len_out) {
        EVP_MD_CTX_free(mdctx);
        return -1;  /* caller's buffer is too small */
    }
    /* second call actually writes the signature bytes */
    if (EVP_DigestSignFinal(mdctx, sig_out, &siglen) <= 0) {
        EVP_MD_CTX_free(mdctx);
        return -1;
    }

    *sig_len_out = siglen;
    EVP_MD_CTX_free(mdctx);
    return 0;
}

int run_provisioning_cycle(const char *enroll_url, const char *pseudo_url,
                           pki_cycle_metrics_t *metrics_out) {
    timer_sample_t t = {0};

    if (!enroll_url || !pseudo_url || !metrics_out) {
        fprintf(stderr, "[provision] invalid input: enroll_url=%p pseudo_url=%p metrics_out=%p\n",
                (void *)enroll_url, (void *)pseudo_url, (void *)metrics_out);
        return -1;
    }

    timer_start(&t);
    if (generate_enrollment_key_and_csr("qnx-vehicle-client") != 0) {
        fprintf(stderr, "[provision] key/CSR generation failed\n");
        return -1;
    }
    timer_stop(&t);
    metrics_out->keygen_ms = timer_elapsed_ms(&t);

    timer_start(&t);
    if (submit_enrollment_request(enroll_url) != 0) {
        fprintf(stderr, "[provision] enrollment request failed url=%s\n", enroll_url);
        return -1;
    }
    timer_stop(&t);
    metrics_out->enroll_ms = timer_elapsed_ms(&t);

    timer_start(&t);
    if (request_pseudonym_batch(pseudo_url, CERT_BATCH_SIZE) != 0) {
        fprintf(stderr, "[provision] pseudonym request failed url=%s\n", pseudo_url);
        return -1;
    }
    timer_stop(&t);
    metrics_out->pseudonym_ms = timer_elapsed_ms(&t);

    return 0;
}

/*
 * Loads certificate identifiers needed by runtime metrics and revoke/CRL flows.
 *
 * cert_path          -> path to PEM certificate file
 * serial_out         -> destination buffer for certificate serial (hex string)
 * serial_out_len     -> size of serial_out buffer
 * issuer_dn_out      -> destination buffer for issuer distinguished name
 * issuer_dn_out_len  -> size of issuer_dn_out buffer
 *
 * Returns:
 *   0  -> success
 *  -1  -> invalid input, file/cert parse failure, or extraction failure
 */
int load_cert_identifiers(const char *cert_path, char *serial_out, size_t serial_out_len, char *issuer_dn_out, size_t issuer_dn_out_len) {
    if (!cert_path || !serial_out || !issuer_dn_out || serial_out_len == 0 || issuer_dn_out_len == 0) {
        return -1;
    }

    FILE *f = fopen(cert_path, "rb");
    if (!f){
        return -1;
    }

    X509 *cert = PEM_read_X509(f, NULL, NULL, NULL);
    fclose(f);
    if (!cert){
        return -1;
    }

    // extract serial number and convert to hex string
    const ASN1_INTEGER *serial = X509_get0_serialNumber(cert);
    BIGNUM *serial_bn = ASN1_INTEGER_to_BN(serial, NULL);
    if (!serial_bn) {
        X509_free(cert);
        return -1;
    }

    char *serial_hex = BN_bn2hex(serial_bn);
    BN_free(serial_bn);
    if (!serial_hex) {
        X509_free(cert);
        return -1;
    }

    snprintf(serial_out, serial_out_len, "%s", serial_hex);
    OPENSSL_free(serial_hex);
    
    X509_NAME *issuer = X509_get_issuer_name(cert);
    if (!issuer) {
        X509_free(cert);
        return -1;
    }

    char issuer_tmp[1024] = {0};
    if (!X509_NAME_oneline(issuer, issuer_tmp, sizeof(issuer_tmp))) {
        X509_free(cert);
        return -1;
    }

    snprintf(issuer_dn_out, issuer_dn_out_len, "%s", issuer_tmp);
    X509_free(cert);
    return 0;
}
