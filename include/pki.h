#ifndef PKI_H
#define PKI_H

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

#endif
