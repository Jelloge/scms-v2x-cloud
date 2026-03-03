#ifndef SIM_CERT_REVOCATION_H
#define SIM_CERT_REVOCATION_H

#include <stddef.h>

int sim_maybe_revoke_active_cert(const char *revoke_url, const char *cert_serial, const char *issuer_dn);


#define SOAP_DEBUG 0

#endif
