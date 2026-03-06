#include "metrics.h"

#include <stdio.h>
#include <time.h>

uint64_t monotonic_time_ns(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t) ts.tv_sec * 1000000000ull + (uint64_t) ts.tv_nsec;
}

void timer_start(timer_sample_t *sample) { sample->start_ns = monotonic_time_ns(); }

void timer_stop(timer_sample_t *sample) { sample->end_ns = monotonic_time_ns(); }

double timer_elapsed_ms(const timer_sample_t *sample) {
    return (double) (sample->end_ns - sample->start_ns) / 1000000.0;
}

int metrics_csv_init(const char *path) {
    FILE *f = fopen(path, "w");
    if (!f) return -1;
fprintf(f,
"timestamp_ns,bsm_cycles,bsm_deadline_miss,provision_ok,provision_fail,"
"last_keygen_ms,last_enroll_ms,last_pseudonym_ms,"
"last_bsm_sign_ms,max_bsm_sign_ms,"
"last_mutex_wait_ms,max_mutex_wait_ms,"
"last_crl_check_ms,max_crl_check_ms,revoke_request_ms\n");
    fclose(f);
    return 0;
}

int metrics_csv_append(const char *path, const runtime_metrics_t *m) {
    FILE *f = fopen(path, "a");
    if (!f) return -1;
    fprintf(f, "%llu,%llu,%llu,%llu,%llu,%.3f,%.3f,%.3f,%.3f,%.3f,%.3f,%.3f,%.3f,%.3f,%.3f\n",
            (unsigned long long) monotonic_time_ns(),
            (unsigned long long) m->bsm_cycles,
            (unsigned long long) m->bsm_deadline_miss,
            (unsigned long long) m->provision_ok,
            (unsigned long long) m->provision_fail,
            m->last_keygen_ms,
            m->last_enroll_ms,
            m->last_pseudonym_ms,
            m->last_bsm_sign_ms,
            m->max_bsm_sign_ms,
            m->last_mutex_wait_ms,
            m->max_mutex_wait_ms,
              m->last_crl_check_ms,
              m->max_crl_check_ms,
              m->revoke_request_ms
            );
    fclose(f);
    return 0;
}
