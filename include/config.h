#ifndef CONFIG_H
#define CONFIG_H

#define CERT_BATCH_SIZE 20
#define CERT_STORE_DIR "./cert_store"
#define PRIVATE_KEY_PATH CERT_STORE_DIR "/enrollment_key.pem"
#define CSR_PATH CERT_STORE_DIR "/enrollment.csr.pem"
#define ENROLLMENT_CERT_PATH CERT_STORE_DIR "/enrollment_cert.pem"
#define PSEUDONYM_BUNDLE_PATH CERT_STORE_DIR "/pseudonym_bundle.pem"
#define METRICS_CSV_PATH CERT_STORE_DIR "/metrics.csv"
#define CRL_PATH CERT_STORE_DIR "/ca.crl.pem"
#define TRUSTED_CA_CERT_PATH CERT_STORE_DIR "/SCMSRootCA.pem"
#define CRL_SIGNER_CERT_PATH TRUSTED_CA_CERT_PATH

#define DEFAULT_ENROLLMENT_URL "mock://enroll"
#define DEFAULT_PSEUDONYM_URL "mock://pseudonym"
#define DEFAULT_CRL_URL "mock://crl"
#define DEFAULT_REVOKE_URL "mock://revoke"

/* ejbca rest api config - these need to match whatever you set up
   in the ejbca admin ui (certificate profile, end entity profile, etc).
   change these if your ejbca setup uses different names */
#define EJBCA_CERT_PROFILE   "V2X-Enrollment"
#define EJBCA_EE_PROFILE     "V2X-EndEntity"
#define EJBCA_CA_NAME        "V2X-RootCA"
#define EJBCA_USERNAME       "qnx-vehicle-client"
#define EJBCA_PASSWORD       "steed"

/* client certificate for ejbca rest api authentication (mutual TLS).
   ejbca requires a superadmin client cert to access the rest api.
   extract these from the docker container with:
     docker cp ejbca:/opt/keyfactor/p12/superadmin.p12 .
     openssl pkcs12 -in superadmin.p12 -clcerts -nokeys -out superadmin_cert.pem
     openssl pkcs12 -in superadmin.p12 -nocerts -nodes -out superadmin_key.pem
   then place them in cert_store/ */
#define EJBCA_CLIENT_CERT  CERT_STORE_DIR "/superadmin_cert.pem"
#define EJBCA_CLIENT_KEY   CERT_STORE_DIR "/superadmin_key.pem"

#define BSM_PERIOD_MS 100
#define PROVISION_PERIOD_SEC 5

/* thread priorities for QNX SCHED_RR (lecture 5). higher number = higher prio */
#define PRIO_SIGNER    20   /* thread 0-bsm signer (highest) */
#define PRIO_PROVISION 15   /* thread 1-cert provisioning (medium) */
#define PRIO_MONITOR   10   /* thread 2-metrics logger (lowest) */

/* size of the simulated BSM payload in bytes. real V2X BSMs are
   typically around 200-400 bytes containing position, speed, heading etc */
#define BSM_PAYLOAD_SIZE 300

#define ENROLLMENT_URL_ENDPOINT "/ejbca/ejbca-rest-api/v1/certificate/pkcs10enroll"
#define PSEUDONYM_URL_ENDPOINT "/ejbca/ejbca-rest-api/v1/certificate/pkcs10enroll"
#define CRL_URL_ENDPOINT "/ejbca/publicweb/webdist/certdist?cmd=crl"
#define REVOKE_URL_ENDPOINT "/ejbca/ejbcaws/ejbcaws"

// @TODO: Revoke request might break with it on needs to be tested
// enable to skip TLS verification in the http client for testing with self-signed certs
// Needs Root CA certs to be in place for the client to work properly
// this is SSL_VERIFYPEER + SSL_VERIFYHOST = who EJBCA is to YOU (server authentication).
#define EJBCA_TLS 0

// how often the client refreshes the CRL to check for revocation (in seconds)
#define CRL_REFRESH_SEC 30

// probability of simulating a revocation for the active cert on each provisioning cycle (for testing CRL refresh and signer behavior on revocation)
#define SIM_REVOCATION_PROBABILITY_PERCENT 25

#endif
