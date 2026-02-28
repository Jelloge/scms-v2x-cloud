#ifndef CONFIG_H
#define CONFIG_H

#define CERT_BATCH_SIZE 20
#define CERT_STORE_DIR "./cert_store"
#define PRIVATE_KEY_PATH CERT_STORE_DIR "/enrollment_key.pem"
#define CSR_PATH CERT_STORE_DIR "/enrollment.csr.pem"
#define ENROLLMENT_CERT_PATH CERT_STORE_DIR "/enrollment_cert.pem"
#define PSEUDONYM_BUNDLE_PATH CERT_STORE_DIR "/pseudonym_bundle.pem"
#define METRICS_CSV_PATH CERT_STORE_DIR "/metrics.csv"

#define DEFAULT_ENROLLMENT_URL "mock://enroll"
#define DEFAULT_PSEUDONYM_URL "mock://pseudonym"

#define BSM_PERIOD_MS 100
#define PROVISION_PERIOD_SEC 5

#endif
