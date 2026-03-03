#ifndef METRICS_H
#define METRICS_H

#include <stdint.h>

#define CERT_SERIAL_MAX_LEN 128
#define CERT_ISSUER_DN_MAX_LEN 512

typedef struct {
    uint64_t start_ns;
    uint64_t end_ns;
} timer_sample_t;

typedef struct {
    uint64_t bsm_cycles;
    uint64_t bsm_deadline_miss;
    uint64_t provision_ok;
    uint64_t provision_fail;
    double last_keygen_ms;
    double last_enroll_ms;
    double last_pseudonym_ms;
    // tracks how long each ecdsa sign operation takes in thread 0
    double last_bsm_sign_ms;
    double max_bsm_sign_ms;
    // how long thread 0 blocks waiting on the mutex when thread 1 holds it
    //  during cert swap - this shows mutex contention (lecture 5)
    double last_mutex_wait_ms;
    double max_mutex_wait_ms;
    char active_cert_serial[CERT_SERIAL_MAX_LEN];
    char active_cert_issuer_dn[CERT_ISSUER_DN_MAX_LEN];
} runtime_metrics_t;

uint64_t monotonic_time_ns(void);
void timer_start(timer_sample_t *sample);
void timer_stop(timer_sample_t *sample);
double timer_elapsed_ms(const timer_sample_t *sample);

int metrics_csv_init(const char *path);
int metrics_csv_append(const char *path, const runtime_metrics_t *m);

#endif
