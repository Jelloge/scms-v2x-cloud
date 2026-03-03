#include "simCertRevocation.h"

#include "certRevocation.h"
#include "config.h"
#include "http.h"
#include "metrics.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/*
 * Revocation simulation module
 *
 * Current behavior:
 *   - Randomly decides whether to revoke active cert
 *   - derives issuer DN from active enrollment cert metadata (runtime)
 *   - submits SOAP revokeCert request to EJBCA over mTLS 
 * ( I couldnt get the API endpoint to work for some reason using SOAP worked)
 *   - returns immediately (non-blocking) 
 */

/*
 * Randomly decides whether to revoke the active certificate based on a configured probability.
 * This simulates the occurrence of revocation events in the system.
 */
static int should_attempt_revoke(void) {
    int roll = rand() % 100;
    return roll < SIM_REVOCATION_PROBABILITY_PERCENT;
}

/*
 * Normalizes issuer DN string formatting for EJBCA request usage.
 *
 * If input is already RFC2253-like (comma-separated), it is copied as-is.
 * If input is slash-separated (e.g. /CN=Root/O=Org), leading slash is removed
 * and remaining slashes are converted to commas.
 *
 * input       -> raw issuer DN string
 * output      -> destination buffer for normalized issuer DN
 * output_len  -> size of destination buffer
 */
static void normalize_issuer_dn(const char *input, char *output, size_t output_len) {
    if (!output || output_len == 0){
        return;
    }

    output[0] = '\0';
    
    if (!input || !*input){
        return;
    }

    if (input[0] != '/') {
        snprintf(output, output_len, "%s", input);
        return;
    }

    size_t write_idx = 0;
    for (size_t i = 1; input[i] != '\0' && write_idx + 1 < output_len; ++i) {
        char ch = input[i];
        if (ch == '/') ch = ',';
        output[write_idx++] = ch;
    }
    
    output[write_idx] = '\0';
}

/*
 * Maybe revokes the currently active enrollment certificate.
 *
 * Flow:
 *   1) Validate required inputs.
 *   2) Decide probabilistically whether this cycle triggers a revoke event.
 *   3) Normalize issuer DN into EJBCA-compatible format.
 *   4) Build SOAP revokeCert payload: (issuerDn, serialNumber, reasonCode=1).
 *   5) Submit SOAP request via mTLS and detect both HTTP errors and SOAP Faults.
 *
 * Behavior notes:
 *   - Non-blocking model: success means request submission accepted now;
 *     CRL propagation is observed later by periodic CRL refresh/check logic.
 *
 * Parameters:
 *   revoke_url   -> EJBCA SOAP revoke endpoint URL.
 *   cert_serial  -> serial number of active cert to revoke.
 *   issuer_dn    -> issuer DN associated with active cert (input may be slash-format).
 *
 * Returns:
 *   0 on success path (including "no revoke this cycle"),
 *  -1 on invalid input or SOAP submission failure.
 */
int sim_maybe_revoke_active_cert(const char *revoke_url, const char *cert_serial, const char *issuer_dn) {
    if (!revoke_url || !cert_serial || !issuer_dn) {
        return -1;
    }

    if (!should_attempt_revoke()) {
        if(SOAP_DEBUG){
            fprintf(stderr, "PASSED: enrollment cert serial=%s issuer=%s behaved\n", cert_serial, issuer_dn);
        }
        return 0;
    }

    fprintf(stderr, "CERT MISBEHAVIOR REVOKE: enrollment cert serial=%s issuer=%s\n", cert_serial, issuer_dn);

    char normalized_issuer[512] = {0};
    normalize_issuer_dn(issuer_dn, normalized_issuer, sizeof(normalized_issuer));

    // If normalization results in an empty issuer DN, treat as failure since EJBCA requires issuer DN for revocation requests and we have no fallback option.
    if (!normalized_issuer[0]) {
        if(SOAP_DEBUG){
            fprintf(
                stderr,
                "REVOKE_REQUEST_FAILED: missing issuer from enrollment cert for serial=%s\n",
                cert_serial
            );
        }
        return -1;
    }

    /* issuer used in SOAP request: always certificate-derived (no config fallback) */
    const char *request_issuer_dn = normalized_issuer;

    // SOAP revokeCert(issuerDn, serialNumber, reasonCode) reasonCode=1 maps to keyCompromise in X.509 reason codes.
    char soap_xml[4096];
    snprintf(soap_xml, sizeof(soap_xml),
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
        "<soapenv:Envelope xmlns:soapenv=\"http://schemas.xmlsoap.org/soap/envelope/\" "
            "xmlns:ws=\"http://ws.protocol.core.ejbca.org/\">"
        "<soapenv:Header/>"
        "<soapenv:Body>"
        "<ws:revokeCert>"
        "<arg0>%s</arg0>"
        "<arg1>%s</arg1>"
        "<arg2>%d</arg2>"
        "</ws:revokeCert>"
        "</soapenv:Body>"
        "</soapenv:Envelope>",
        request_issuer_dn,
        cert_serial,
        1
    );

    if(SOAP_DEBUG){
        fprintf(stderr, "SOAP_REVOKE_URL: %s\n", revoke_url);
        fprintf(stderr, "SOAP_REVOKE_ISSUER: %s\n", request_issuer_dn);
        fprintf(stderr, "SOAP_REVOKE_SERIAL: %s\n", cert_serial);
    }
    
    // Submit SOAP request via mTLS and detect both HTTP errors and SOAP Faults in the response body.
    http_response_t resp = {0};
    int rc = http_post_xml(revoke_url, soap_xml, &resp);
    int is_fault = (resp.body && strstr(resp.body, "Fault") != NULL);

    // Consider the request failed if there was an HTTP error, an unexpected HTTP status code, or a SOAP Fault in the response body.
    if (rc != 0 || resp.status_code < 200 || resp.status_code >= 300 || is_fault) {
        if(SOAP_DEBUG){
            fprintf(stderr, "SOAP_REVOKE_FAILED: serial=%s issuer=%s http=%ld fault=%d\n",
                    cert_serial, request_issuer_dn, resp.status_code, is_fault);
            if (resp.body) {
                fprintf(stderr, "SOAP_REVOKE_RESPONSE: %.500s\n", resp.body);
            }
        }
        http_response_free(&resp);
        return -1;
    }

    // Success: request accepted and no SOAP Fault detected. CRL propagation will be observed later by periodic CRL refresh/check logic.
    if(SOAP_DEBUG){
        fprintf(stderr, "SOAP_REVOKED_OK: serial=%s issuer=%s http=%ld\n", cert_serial, request_issuer_dn, resp.status_code);
    }

    http_response_free(&resp);

    return 0;
}
