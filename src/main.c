#include "config.h"
#include "metrics.h"
#include "pki.h"
#include "storage.h"

#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>

typedef struct {
    pthread_mutex_t lock;
    runtime_metrics_t metrics;
    int cert_ready;
    int stop;
    char enrollment_cert[256];
    char pseudonym_bundle[256];
    const char *enroll_url;
    const char *pseudo_url;
} app_state_t;

static app_state_t g_state;

static void nanosleep_ms(int ms) {
    struct timespec ts = {.tv_sec = ms / 1000, .tv_nsec = (long) (ms % 1000) * 1000000L};
    nanosleep(&ts, NULL);
}

static void on_sigint(int sig) {
    (void) sig;
    pthread_mutex_lock(&g_state.lock);
    g_state.stop = 1;
    pthread_mutex_unlock(&g_state.lock);
}

static void *signer_thread(void *arg) {
    app_state_t *s = (app_state_t *) arg;
    for (;;) {
        uint64_t start = monotonic_time_ns();

        pthread_mutex_lock(&s->lock);
        int stop = s->stop;
        int cert_ready = s->cert_ready;
        if (!stop) s->metrics.bsm_cycles++;
        pthread_mutex_unlock(&s->lock);

        if (stop) break;

        if (cert_ready) {
            nanosleep_ms(5);
        }

        uint64_t elapsed_ns = monotonic_time_ns() - start;
        if (elapsed_ns > (uint64_t) BSM_PERIOD_MS * 1000000ull) {
            pthread_mutex_lock(&s->lock);
            s->metrics.bsm_deadline_miss++;
            pthread_mutex_unlock(&s->lock);
        }

        if (elapsed_ns < (uint64_t) BSM_PERIOD_MS * 1000000ull) {
            uint64_t remain_ns = (uint64_t) BSM_PERIOD_MS * 1000000ull - elapsed_ns;
            nanosleep_ms((int) (remain_ns / 1000000ull));
        }
    }
    return NULL;
}

static void *provision_thread(void *arg) {
    app_state_t *s = (app_state_t *) arg;
    for (;;) {
        pthread_mutex_lock(&s->lock);
        int stop = s->stop;
        pthread_mutex_unlock(&s->lock);
        if (stop) break;

        pki_cycle_metrics_t cycle = {0};
        int rc = run_provisioning_cycle(s->enroll_url, s->pseudo_url, &cycle);

        pthread_mutex_lock(&s->lock);
        if (rc == 0) {
            s->metrics.provision_ok++;
            s->metrics.last_keygen_ms = cycle.keygen_ms;
            s->metrics.last_enroll_ms = cycle.enroll_ms;
            s->metrics.last_pseudonym_ms = cycle.pseudonym_ms;

            char *enroll = read_text_file(ENROLLMENT_CERT_PATH);
            char *pseudo = read_text_file(PSEUDONYM_BUNDLE_PATH);
            if (enroll) {
                snprintf(s->enrollment_cert, sizeof(s->enrollment_cert), "%s", enroll);
                free(enroll);
            }
            if (pseudo) {
                snprintf(s->pseudonym_bundle, sizeof(s->pseudonym_bundle), "%s", pseudo);
                free(pseudo);
            }
            s->cert_ready = 1;
        } else {
            s->metrics.provision_fail++;
        }
        pthread_mutex_unlock(&s->lock);

        sleep(PROVISION_PERIOD_SEC);
    }
    return NULL;
}

static void *monitor_thread(void *arg) {
    app_state_t *s = (app_state_t *) arg;
    while (1) {
        pthread_mutex_lock(&s->lock);
        int stop = s->stop;
        runtime_metrics_t snapshot = s->metrics;
        pthread_mutex_unlock(&s->lock);

        metrics_csv_append(METRICS_CSV_PATH, &snapshot);
        printf("[METRICS] bsm=%llu miss=%llu ok=%llu fail=%llu key=%.2fms enroll=%.2fms pseudo=%.2fms\n",
               (unsigned long long) snapshot.bsm_cycles,
               (unsigned long long) snapshot.bsm_deadline_miss,
               (unsigned long long) snapshot.provision_ok,
               (unsigned long long) snapshot.provision_fail,
               snapshot.last_keygen_ms,
               snapshot.last_enroll_ms,
               snapshot.last_pseudonym_ms);

        if (stop) break;
        sleep(1);
    }
    return NULL;
}

int main(int argc, char **argv) {
    const char *enroll_url = argc > 1 ? argv[1] : DEFAULT_ENROLLMENT_URL;
    const char *pseudo_url = argc > 2 ? argv[2] : DEFAULT_PSEUDONYM_URL;

    if (ensure_cert_store() != 0) {
        fprintf(stderr, "failed to initialize certificate storage\n");
        return 1;
    }
    if (metrics_csv_init(METRICS_CSV_PATH) != 0) {
        fprintf(stderr, "failed to initialize metrics csv\n");
        return 1;
    }

    pthread_mutex_init(&g_state.lock, NULL);
    g_state.enroll_url = enroll_url;
    g_state.pseudo_url = pseudo_url;

    signal(SIGINT, on_sigint);

    pthread_t signer_tid, prov_tid, mon_tid;
    pthread_create(&signer_tid, NULL, signer_thread, &g_state);
    pthread_create(&prov_tid, NULL, provision_thread, &g_state);
    pthread_create(&mon_tid, NULL, monitor_thread, &g_state);

    printf("RTOS client started. enroll=%s pseudo=%s\n", enroll_url, pseudo_url);
    printf("Press Ctrl+C to stop. Metrics: %s\n", METRICS_CSV_PATH);

    pthread_join(signer_tid, NULL);
    pthread_join(prov_tid, NULL);
    pthread_join(mon_tid, NULL);

    pthread_mutex_destroy(&g_state.lock);
    return 0;
}
