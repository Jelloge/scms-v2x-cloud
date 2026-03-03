#ifndef CERT_REVOCATION_H
#define CERT_REVOCATION_H

#include <stddef.h>

typedef struct X509_crl_st X509_CRL;

int crl_download_to_file(const char *url, const char *out_path);
int crl_refresh_and_check(const char *crl_url, const char *crl_path, const char *cert_path, int *is_revoked);
int crl_print_bad_certs(const char *crl_path);

#define DEBUG_CRL 0
#define VERIFY_CRL_SIGNATURE 1

#endif

