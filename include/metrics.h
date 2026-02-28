#ifndef METRICS_H
#define METRICS_H

#include <stdint.h>

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
} runtime_metrics_t;

uint64_t monotonic_time_ns(void);
void timer_start(timer_sample_t *sample);
void timer_stop(timer_sample_t *sample);
double timer_elapsed_ms(const timer_sample_t *sample);

int metrics_csv_init(const char *path);
int metrics_csv_append(const char *path, const runtime_metrics_t *m);

#endif
