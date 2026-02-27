#ifndef PKI_H
#define PKI_H

#include <openssl/evp.h>
#include <stddef.h>

typedef struct {
    double keygen_ms;
    double enroll_ms;
    double pseudonym_ms;
} pki_cycle_metrics_t;

int generate_enrollment_key_and_csr(const char *common_name);
int submit_enrollment_request(const char *url);
int request_pseudonym_batch(const char *url, int batch_size);
int run_provisioning_cycle(const char *enroll_url, const char *pseudo_url,
                           pki_cycle_metrics_t *metrics_out);

/* loads the enrollment private key from a pem file so thread 0 can
   use it for bsm signing. caller needs to free with EVP_PKEY_free() */
EVP_PKEY *load_signing_key(const char *key_path);

/* signs a bsm payload using ecdsa p-256 with sha-256 digest.
   we use the openssl EVP_DigestSign api for this (same pattern as the csr signing).
   returns 0 on success, -1 on any failure */
int sign_bsm_payload(EVP_PKEY *key, const unsigned char *payload,
                     size_t payload_len, unsigned char *sig_out,
                     size_t *sig_len_out);

#endif
