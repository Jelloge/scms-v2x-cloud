/*
 * main.c - multi-threaded QNX RTOS vehicle client for SCMS performance evaluation
 *
 * runs 3 threads at different priorities to simulate a V2X vehicle module:
 *   thread 0 (highest): signs BSMs every 100ms using ecdsa p-256
 *   thread 1 (medium):  handles certificate enrollment with the cloud CA
 *   thread 2 (lowest):  logs performance metrics to csv
 *
 * demonstrates mutexes, condition variables, and preemptive priority scheduling
 * as covered in lectures 5 and 18.
 *
 * based on the SCMS architecture from brecht et al. [1] and the
 * performance scenarios from chen et al. [3]
 */

#include "config.h"
#include "metrics.h"
#include "pki.h"
#include "storage.h"

#include <openssl/evp.h>
#include <pthread.h>
#include <sched.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

/* shared state between all three threads. everything in here is
   protected by the mutex except enroll_url/pseudo_url which are
   read-only after main() sets them */
typedef struct {
    pthread_mutex_t lock;
    pthread_cond_t  cert_available;       /* used to wake up thread 0 after first enrollment */
    runtime_metrics_t metrics;
    int             cert_ready;           /* set to 1 once we have a valid cert */
    int             stop;                 /* set to 1 on ctrl+c */
    EVP_PKEY       *signing_key;          /* the current ecdsa key for bsm signing */
    char            enrollment_cert_path[256];
    char            pseudonym_bundle_path[256];
    const char     *enroll_url;
    const char     *pseudo_url;
} app_state_t;

static app_state_t g_state;

/* helper to sleep for a given number of milliseconds using nanosleep.
   we use this instead of usleep because nanosleep is more portable
   and works properly on QNX */
static void nanosleep_ms(int ms) {
    struct timespec ts = {.tv_sec = ms / 1000, .tv_nsec = (long)(ms % 1000) * 1000000L};
    nanosleep(&ts, NULL);
}

/* ctrl+c handler. sets the stop flag and broadcasts the condition variable
   so thread 0 wakes up if its still waiting for the first cert */
static void on_sigint(int sig) {
    (void)sig;
    pthread_mutex_lock(&g_state.lock);
    g_state.stop = 1;
    pthread_cond_broadcast(&g_state.cert_available);
    pthread_mutex_unlock(&g_state.lock);
}

/*
 * thread 0 - BSM signer (highest priority)
 *
 * this thread simulates a vehicle signing and broadcasting basic safety
 * messages 10 times per second (every 100ms). in a real V2X system this
 * would be the most time-critical task since late BSMs could cause
 * collisions (amjad et al. report 10-100ms latency requirements).
 *
 * it starts by waiting on a condition variable until thread 1 finishes
 * the first enrollment and we have a valid signing key. then it loops
 * every 100ms, grabs the key from shared state, signs a payload, and
 * checks if it met the deadline.
 *
 * we also time how long the mutex acquisition takes each cycle to
 * measure contention when thread 1 is swapping certificates.
 */
static void *signer_thread(void *arg) {
    app_state_t *s = (app_state_t *)arg;

    /* block here until thread 1 signals that enrollment is done.
       using the while loop to guard against spurious wakeups
       (learned this pattern from the pthreads docs) */
    pthread_mutex_lock(&s->lock);
    while (!s->cert_ready && !s->stop) {
        pthread_cond_wait(&s->cert_available, &s->lock);
    }
    pthread_mutex_unlock(&s->lock);

    /* fill bsm payload with dummy data. in a real vehicle this would
       contain gps position, speed, heading, brake status etc */
    unsigned char bsm_payload[BSM_PAYLOAD_SIZE];
    memset(bsm_payload, 0xAA, sizeof(bsm_payload));

    unsigned char signature[256];
    timer_sample_t mutex_timer, sign_timer;

    for (;;) {
        uint64_t cycle_start = monotonic_time_ns();

        /* time how long we block waiting for the mutex. if thread 1 is
           in the middle of swapping the signing key, we'll see contention here */
        timer_start(&mutex_timer);
        pthread_mutex_lock(&s->lock);
        timer_stop(&mutex_timer);

        int stop = s->stop;
        EVP_PKEY *key = s->signing_key;
        /* increment the refcount so thread 1 can safely free the old key
           while we're still using it for signing. EVP_PKEY_up_ref is
           openssl's built-in reference counting mechanism */
        if (key) EVP_PKEY_up_ref(key);
        s->metrics.bsm_cycles++;

        double wait_ms = timer_elapsed_ms(&mutex_timer);
        s->metrics.last_mutex_wait_ms = wait_ms;
        if (wait_ms > s->metrics.max_mutex_wait_ms)
            s->metrics.max_mutex_wait_ms = wait_ms;

        pthread_mutex_unlock(&s->lock);

        if (stop) {
            if (key) EVP_PKEY_free(key);
            break;
        }

        /* do the actual ecdsa signature outside the critical section
           so we don't hold the mutex longer than necessary */
        if (key) {
            timer_start(&sign_timer);
            size_t sig_len = sizeof(signature);
            int rc = sign_bsm_payload(key, bsm_payload, sizeof(bsm_payload),
                                      signature, &sig_len);
            timer_stop(&sign_timer);

            if (rc == 0) {
                double sign_ms = timer_elapsed_ms(&sign_timer);
                pthread_mutex_lock(&s->lock);
                s->metrics.last_bsm_sign_ms = sign_ms;
                if (sign_ms > s->metrics.max_bsm_sign_ms)
                    s->metrics.max_bsm_sign_ms = sign_ms;
                pthread_mutex_unlock(&s->lock);
            }

            EVP_PKEY_free(key);  /* decrements refcount */
        }

        /* check if we exceeded the 100ms deadline (lecture 18).
           if sign + mutex wait + overhead > 100ms, thats a deadline miss */
        uint64_t elapsed_ns = monotonic_time_ns() - cycle_start;
        if (elapsed_ns > (uint64_t)BSM_PERIOD_MS * 1000000ull) {
            pthread_mutex_lock(&s->lock);
            s->metrics.bsm_deadline_miss++;
            pthread_mutex_unlock(&s->lock);
        }

        /* sleep for whatever time is left in the 100ms period */
        if (elapsed_ns < (uint64_t)BSM_PERIOD_MS * 1000000ull) {
            uint64_t remain_ns = (uint64_t)BSM_PERIOD_MS * 1000000ull - elapsed_ns;
            nanosleep_ms((int)(remain_ns / 1000000ull));
        }
    }
    return NULL;
}

/*
 thread 1 - certificate provisioning (medium priority)
 
 handles the enrollment workflow from brecht et al. [1, figure 5]:
    1)generate ecdsa p-256 keypair and x.509 csr
   2)send csr to the enrollment endpoint (EJBCA REST api)
   3)request a batch of 20 pseudonym certs
   4)load the new signing key and swwaps it into shared state
   5)signal the condition variable so thread 0 knows theres a new cert

  runs every PROVISION_PERIOD_SEC seconds. the actual http requests go
 through libcurl (or mock mode for offline testing)
 */
static void *provision_thread(void *arg) {
    app_state_t *s = (app_state_t *)arg;
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
            s->metrics.last_keygen_ms    = cycle.keygen_ms;
            s->metrics.last_enroll_ms    = cycle.enroll_ms;
            s->metrics.last_pseudonym_ms = cycle.pseudonym_ms;

            /* load the newly generated private key from disk and swap it
               into the shared state. thread 0 uses EVP_PKEY_up_ref so its
               safe to free the old key here even if thread 0 grabbed a
               reference to it already */
            // at least i think it's safe? i'll check it again in a bit
            EVP_PKEY *new_key = load_signing_key(PRIVATE_KEY_PATH);
            if (new_key) {
                EVP_PKEY *old_key = s->signing_key;
                s->signing_key = new_key;
                if (old_key) EVP_PKEY_free(old_key);
            }

            snprintf(s->enrollment_cert_path, sizeof(s->enrollment_cert_path),
                     "%s", ENROLLMENT_CERT_PATH);
            snprintf(s->pseudonym_bundle_path, sizeof(s->pseudonym_bundle_path),
                     "%s", PSEUDONYM_BUNDLE_PATH);

            // signal thread 0 that a cert is ready. this matters for the
            //  very first enrollment 
            s->cert_ready = 1;
            pthread_cond_signal(&s->cert_available);
        } else {
            s->metrics.provision_fail++;
        }
        pthread_mutex_unlock(&s->lock);

        sleep(PROVISION_PERIOD_SEC);
    }
    return NULL;
}

/*
  thread 2 performance monitor (lowest prio)
 
takes a snapshot of the metrics struct every second and writes it
 to the csv file + prints to stdout
 */
static void *monitor_thread(void *arg) {
    app_state_t *s = (app_state_t *)arg;
    while (1) {
        pthread_mutex_lock(&s->lock);
        int stop = s->stop;
        runtime_metrics_t snapshot = s->metrics;
        pthread_mutex_unlock(&s->lock);

        metrics_csv_append(METRICS_CSV_PATH, &snapshot);
        printf("[METRICS] bsm=%llu miss=%llu ok=%llu fail=%llu "
               "key=%.2fms enroll=%.2fms pseudo=%.2fms "
               "sign=%.2fms(max %.2f) mutex=%.3fms(max %.3f)\n",
               (unsigned long long)snapshot.bsm_cycles,
               (unsigned long long)snapshot.bsm_deadline_miss,
               (unsigned long long)snapshot.provision_ok,
               (unsigned long long)snapshot.provision_fail,
               snapshot.last_keygen_ms,
               snapshot.last_enroll_ms,
               snapshot.last_pseudonym_ms,
               snapshot.last_bsm_sign_ms,
               snapshot.max_bsm_sign_ms,
               snapshot.last_mutex_wait_ms,
               snapshot.max_mutex_wait_ms);

        if (stop) break;
        sleep(1);
    }
    return NULL;
}

/*
  sets up SCHED_RR priority for a thread (lecture 5 preemptive scheduling).
  on QNX this enforces priority preemption i think. on linux/windows dev
  machines it usually fails silently because you need root, so we just
  fall back to the default scheduler and print out a warning
 */
static int set_thread_priority(pthread_attr_t *attr, int priority) {
    struct sched_param param;
    param.sched_priority = priority;

    if (pthread_attr_setinheritsched(attr, PTHREAD_EXPLICIT_SCHED) != 0)
        return -1;

#ifdef __QNX__
    // on QNX, SCHED_RR is the real-time scheduler 
    if (pthread_attr_setschedpolicy(attr, SCHED_RR) != 0)
        return -1;
#else
    /* on linux/windows try but fall back to SCHED_OTHER if
       we dont have permissions  */
    if (pthread_attr_setschedpolicy(attr, SCHED_RR) != 0) {
        pthread_attr_setschedpolicy(attr, SCHED_OTHER);
        param.sched_priority = 0;
    }
#endif

    if (pthread_attr_setschedparam(attr, &param) != 0)
        return -1;

    return 0;
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

    /* init shared state */
    pthread_mutex_init(&g_state.lock, NULL);
    pthread_cond_init(&g_state.cert_available, NULL);
    g_state.signing_key = NULL;
    g_state.enroll_url  = enroll_url;
    g_state.pseudo_url  = pseudo_url;

    signal(SIGINT, on_sigint);

    /* set up thread attributes with priorities. on QNX these will
       cause preemptive scheduling. on our machines they'll probably fail
       and fall back to defaults which is fine for testing */
    pthread_attr_t attr_signer, attr_prov, attr_mon;
    pthread_attr_init(&attr_signer);
    pthread_attr_init(&attr_prov);
    pthread_attr_init(&attr_mon);

    set_thread_priority(&attr_signer, PRIO_SIGNER);
    set_thread_priority(&attr_prov,   PRIO_PROVISION);
    set_thread_priority(&attr_mon,    PRIO_MONITOR);

    pthread_t signer_tid, prov_tid, mon_tid;
    int rc;

    /* create each thread with its priority. if the priority setup failed
       (eg no root on linux), fall back */
    rc = pthread_create(&signer_tid, &attr_signer, signer_thread, &g_state);
    if (rc != 0) {
        fprintf(stderr, "WARN: signer thread priority failed (%d), using default\n", rc);
        pthread_create(&signer_tid, NULL, signer_thread, &g_state);
    }

    rc = pthread_create(&prov_tid, &attr_prov, provision_thread, &g_state);
    if (rc != 0) {
        fprintf(stderr, "WARN: provision thread priority failed (%d), using default\n", rc);
        pthread_create(&prov_tid, NULL, provision_thread, &g_state);
    }

    rc = pthread_create(&mon_tid, &attr_mon, monitor_thread, &g_state);
    if (rc != 0) {
        fprintf(stderr, "WARN: monitor thread priority failed (%d), using default\n", rc);
        pthread_create(&mon_tid, NULL, monitor_thread, &g_state);
    }

    pthread_attr_destroy(&attr_signer);
    pthread_attr_destroy(&attr_prov);
    pthread_attr_destroy(&attr_mon);

    printf("RTOS client started. enroll=%s pseudo=%s\n", enroll_url, pseudo_url);
    printf("Thread priorities: signer=%d provision=%d monitor=%d\n",
           PRIO_SIGNER, PRIO_PROVISION, PRIO_MONITOR);
    printf("Press Ctrl+C to stop. Metrics: %s\n", METRICS_CSV_PATH);

    pthread_join(signer_tid, NULL);
    pthread_join(prov_tid, NULL);
    pthread_join(mon_tid, NULL);

    /* cleanup */
    if (g_state.signing_key) EVP_PKEY_free(g_state.signing_key);
    pthread_cond_destroy(&g_state.cert_available);
    pthread_mutex_destroy(&g_state.lock);
    return 0;
}
