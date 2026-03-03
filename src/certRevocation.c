#include "certRevocation.h"
#include "config.h"

// libcurl = used to download the CRL file from a URL
#include <curl/curl.h>

// OpenSSL = used to parse certificates and CRLs parsing, signature verification, and time validation.
#include <openssl/evp.h>
#include <openssl/bn.h>
#include <openssl/pem.h>
#include <openssl/x509.h>

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/*
 * CRL validation module
 *
 * Current behavior summary:
 *   - downloads CRL over HTTP/HTTPS (with TLS settings from config)
 *   - supports PEM first, DER fallback parsing
 *   - verifies CRL signature against trusted signer cert
 *   - verifies CRL freshness (thisUpdate/nextUpdate checks)
 *   - maintains last-known-good CRL cache on disk
 *   - prints current revoked serial list for observability
 *
 * This module is invoked from signer thread periodically to enforce
 * revocation before BSM signing continues.
 */

/*
 * Struct used to pass a FILE pointer into the libcurl write callback.
 * It allows curl to write downloaded bytes directly into a FILE.
 */
typedef struct {
	FILE *file;
} file_writer_t;


/* ============================================================
   CRL SIGNATURE VERIFICATION
   ============================================================ */

/*
 * Verifies that the CRL was signed by the expected signer and was not tampered with.
 * for our use case, this is the trusted root CA
 * 
 * crl                -> Parsed CRL object
 * signer_cert_path   -> Path to trusted CA certificate
 *
 * Returns:
 *   0  -> signature valid
 *  -1  -> invalid or error
 *  
 */
static int crl_signature_is_valid(X509_CRL *crl, const char *signer_cert_path) {
	if (!crl || !signer_cert_path){
		if (DEBUG_CRL) {
			fprintf(stderr, "[crl] signature check: invalid input\n");
		}
		return -1;
	}

	// Load the trusted signer certificate from disk (PEM)
	FILE *signer_file = fopen(signer_cert_path, "rb");
	if (!signer_file){
		if (DEBUG_CRL) {
			fprintf(stderr, "[crl] signature check: cannot open signer cert at %s\n", signer_cert_path);
		}
		return -1;
	}

    // Parse the signer cert into an X509 object
	X509 *signer_cert = PEM_read_X509(signer_file, NULL, NULL, NULL);
	fclose(signer_file);
	if (!signer_cert){
		if (DEBUG_CRL) {
			fprintf(stderr, "[crl] signature check: failed to parse signer cert (PEM)\n");
		}
		return -1;
	}

    // Extract the public key from the signer cert (needed to verify CRL signature)
	EVP_PKEY *signer_pubkey = X509_get_pubkey(signer_cert);
	if (!signer_pubkey) {
		if (DEBUG_CRL) {
			fprintf(stderr, "[crl] signature check: signer cert has no public key\n");
		}
		X509_free(signer_cert);
		return -1;
	}

	// Verify CRL signature using signer public key
    int ok = 1;
    if(VERIFY_CRL_SIGNATURE){
        ok = X509_CRL_verify(crl, signer_pubkey);
    }

    // Free crypto objects
	EVP_PKEY_free(signer_pubkey);
	X509_free(signer_cert);

	if (ok != 1) {
		if (DEBUG_CRL) {
			fprintf(stderr, "[crl] signature check: CRL signature verification failed\n");
		}
	}

	// X509_CRL_verify returns 1 if valid
	return (ok == 1) ? 0 : -1;
}


/* ============================================================
   CRL TIME VALIDATION
   ============================================================ */

/*
 * Ensures CRL validity period is sane and current.
 *
 * thisUpdate: when this CRL was issued
 * nextUpdate: when you should expect the next one
 * 
 * Checks:
 *  - thisUpdate is not in the future
 *  - nextUpdate has not expired
 *  - nextUpdate is after thisUpdate
 *
 * Returns:
 *   0  -> valid timing
 *  -1  -> invalid or expired
 */
static int crl_time_is_sane(X509_CRL *crl) {
	if (!crl){
		if (DEBUG_CRL) {
			fprintf(stderr, " [crl] time check: CRL handle is null\n");
		}
		return -1;
	}

    // Pull CRL timestamps out of OpenSSL object
	const ASN1_TIME *this_update = X509_CRL_get0_lastUpdate(crl);
	const ASN1_TIME *next_update = X509_CRL_get0_nextUpdate(crl);

	if (!this_update || !next_update){
		if (DEBUG_CRL) {
			fprintf(stderr, "[crl] time check: missing thisUpdate/nextUpdate\n");
		}
		return -1;
	}

	// CRL must not be from the future
	if (X509_cmp_current_time(this_update) > 0){
		if (DEBUG_CRL) {
			fprintf(stderr, "[crl] time check: thisUpdate is in the future\n");
		}
		return -1;
	}

	// CRL must not be expired
	if (X509_cmp_current_time(next_update) <= 0) {
		if (DEBUG_CRL) {
			fprintf(stderr, "[crl] time check: CRL has expired (nextUpdate reached)\n");
		}
		return -1;
	}

	// Ensure nextUpdate > thisUpdate
	int day = 0;
	int sec = 0;
	if (ASN1_TIME_diff(&day, &sec, this_update, next_update) != 1) {
        if(DEBUG_CRL){
            fprintf(stderr, "[crl] time check: failed to compare thisUpdate/nextUpdate\n");
        }
		return -1;
	}

	if (day < 0 || (day == 0 && sec <= 0)){
        if(DEBUG_CRL){
            fprintf(stderr, "[crl] time check: nextUpdate is not after thisUpdate\n");
        }
		return -1;
	}

	return 0;
}


/* ============================================================
   CURL WRITE CALLBACK
   ============================================================ */

/*
 * Called by libcurl when data is received.
 * Writes downloaded bytes directly to file.
 */
static size_t write_file_cb(void *contents, size_t size, size_t nmemb, void *userp) {
	file_writer_t *writer = (file_writer_t *) userp;
	return fwrite(contents, size, nmemb, writer->file);
}

// Checks if this character is safe to use in a URL without encoding it
static int is_unreserved_url_char(unsigned char ch) {
	if ((ch >= 'A' && ch <= 'Z') || (ch >= 'a' && ch <= 'z') || (ch >= '0' && ch <= '9')) {
		return 1;
	}
	return (ch == '-' || ch == '_' || ch == '.' || ch == '~');
}

// Percent-encodes a string for safe inclusion in a URL query parameter
static char *percent_encode_query_value(const char *in) {
	if (!in) return NULL;

	size_t in_len = strlen(in);
	char *out = calloc(in_len * 3 + 1, 1);
	if (!out) return NULL;

	char *w = out;
	for (const unsigned char *p = (const unsigned char *)in; *p; ++p) {
		if (is_unreserved_url_char(*p)) {
			*w++ = (char)*p;
		} else {
			w += sprintf(w, "%%%02X", *p);
		}
	}

	*w = '\0';
	return out;
}

/* ============================================================
   URL BUILDING HELPERS
   ============================================================ */

/*
 * Builds a retry URL by percent-encoding the existing issuer query value.
 *
 * Why this exists:
 *   Some CRL endpoints reject unencoded issuer DNs (for example values containing
 *   commas, spaces, or '=' characters). This helper rewrites only the issuer
 *   value and keeps the rest of the URL unchanged.
 *
 * url -> original URL that must already contain "issuer="
 *
 * Returns:
 *   newly allocated URL string with encoded issuer value, or NULL on failure.
 *   Caller owns the returned buffer and must free it.
 */
static char *build_encoded_issuer_retry_url(const char *url) {
	if (!url){
        return NULL;
	}

	const char *issuer_key = strstr(url, "issuer=");
	if (!issuer_key){
        return NULL;
	}

	const char *issuer_value = issuer_key + strlen("issuer=");
	const char *issuer_end   = strchr(issuer_value, '&');
	if (!issuer_end){
        issuer_end = url + strlen(url);
    } 
        

	if (issuer_end <= issuer_value){
        return NULL;
    }

	size_t issuer_len  = (size_t)(issuer_end - issuer_value);
	char *raw_issuer   = calloc(issuer_len + 1, 1);
	if (!raw_issuer){
        return NULL;
    } 
	memcpy(raw_issuer, issuer_value, issuer_len);

	char *encoded_issuer = percent_encode_query_value(raw_issuer);
	free(raw_issuer);
	if (!encoded_issuer){
        return NULL;
    }
	size_t prefix_len = (size_t)(issuer_value - url);
	size_t suffix_len = strlen(issuer_end);
	size_t encoded_len = strlen(encoded_issuer);

	char *retry_url = calloc(prefix_len + encoded_len + suffix_len + 1, 1);
	if (!retry_url) {
		free(encoded_issuer);
		return NULL;
	}

	memcpy(retry_url, url, prefix_len);
	memcpy(retry_url + prefix_len, encoded_issuer, encoded_len);
	memcpy(retry_url + prefix_len + encoded_len, issuer_end, suffix_len);

	free(encoded_issuer);
	return retry_url;
}


/*
 * Builds a URL that includes an issuer query parameter.
 *
 * Why this exists:
 *   Some CRL endpoints require issuer DN as a query parameter. When the
 *   original URL does not include "issuer=", this helper appends it using
 *   proper percent-encoding for safe transport.
 *
 * url        -> base URL (must not already contain "issuer=")
 * issuer_dn  -> issuer DN to append (will be percent-encoded)
 *
 * Returns:
 *   newly allocated URL string on success, or NULL on failure.
 *   Caller owns the returned buffer and must free it.
 */
static char *build_url_with_issuer(const char *url, const char *issuer_dn) {
	if (!url || !issuer_dn || !*issuer_dn){
        return NULL;
	}
	
    if (strstr(url, "issuer=")){
        return NULL;
    }

	char *encoded_issuer = percent_encode_query_value(issuer_dn);
	if (!encoded_issuer){
        return NULL;
	}

	const char *separator = strchr(url, '?') ? "&" : "?";
	size_t out_len = strlen(url) + strlen(separator) + strlen("issuer=") + strlen(encoded_issuer) + 1;
	char *out = calloc(out_len, 1);
	if (!out) {
		free(encoded_issuer);
		return NULL;
	}

	snprintf(out, out_len, "%s%sissuer=%s", url, separator, encoded_issuer);
	free(encoded_issuer);
	return out;
}


/* ============================================================
    CRL URL VARIANTS (encoded issuer retry and issuer-appended)
   ============================================================ */


/*
 * Loads a certificate from disk and extracts its issuer DN in RFC2253 format.
 *
 * cert_path       -> path to certificate file (PEM)
 * issuer_out      -> destination buffer for issuer DN text
 * issuer_out_len  -> destination buffer size
 *
 * Returns:
 *   0  -> success
 *  -1  -> failure (invalid input, read/parse failure, or buffer/write failure)
 */
static int load_cert_issuer_rfc2253(const char *cert_path, char *issuer_out, size_t issuer_out_len) {
	if (!cert_path || !issuer_out || issuer_out_len == 0){
        return -1;
    }

	FILE *cert_file = fopen(cert_path, "rb");
	if (!cert_file){
        return -1;
    }

	X509 *cert = PEM_read_X509(cert_file, NULL, NULL, NULL);
	fclose(cert_file);
	if (!cert){
        return -1;
    }

	X509_NAME *issuer = X509_get_issuer_name(cert);
	if (!issuer) {
		X509_free(cert);
		return -1;
	}

	BIO *bio = BIO_new(BIO_s_mem());
	if (!bio) {
		X509_free(cert);
		return -1;
	}

	if (X509_NAME_print_ex(bio, issuer, 0, XN_FLAG_RFC2253) < 0) {
		BIO_free(bio);
		X509_free(cert);
		return -1;
	}

	char *data = NULL;
	long len = BIO_get_mem_data(bio, &data);
	if (len <= 0 || !data) {
		BIO_free(bio);
		X509_free(cert);
		return -1;
	}

	size_t copy_len = (size_t)len;
	if (copy_len >= issuer_out_len){
        copy_len = issuer_out_len - 1;
	}

	memcpy(issuer_out, data, copy_len);
	issuer_out[copy_len] = '\0';

	BIO_free(bio);
	X509_free(cert);
	return 0;
}

/*
 * Builds a new URL by adding the "cmd=crl" query parameter to an existing URL.
 *
 * const char *url - the original URL
 *
 * returns:
 *   A newly allocated string with the updated URL, or NULL on failure
 */
static char *build_url_with_cmd_crl(const char *url) {
	if (!url){
        return NULL;
	}

	if (strstr(url, "cmd=crl")){
        return NULL;
	}

	const char *separator = strchr(url, '?') ? "&" : "?";
	size_t out_len = strlen(url) + strlen(separator) + strlen("cmd=crl") + 1;
	char *out = calloc(out_len, 1);
	if (!out){
        return NULL;
	}

	snprintf(out, out_len, "%s%scmd=crl", url, separator);
	return out;
}


/* ============================================================
   CRL LOADING + FORMAT FALLBACK (PEM first, then DER)
   ============================================================ */

/*
 * Load a CRL from disk.
 *
 * First attempt: PEM format (human-readable, -----BEGIN X509 CRL-----)
 * Fallback: DER format (binary)
 *
 * Returns:
 *   X509_CRL* on success (caller must free with X509_CRL_free)
 *   NULL on failure
 */
static X509_CRL *load_crl_with_der_fallback(const char *crl_path) {
	if (!crl_path){
        return NULL;
    }

	FILE *crl_file = fopen(crl_path, "rb");
	if (!crl_file) {
        if(DEBUG_CRL){
            fprintf(stderr, "[crl] parse: cannot open CRL file at %s\n", crl_path);
        }
		return NULL;
	}

    // Try PEM first
	X509_CRL *crl = PEM_read_X509_CRL(crl_file, NULL, NULL, NULL);
	if (crl) {
		fclose(crl_file);
		return crl;
	}

    // PEM failed → rewind and try DER
	rewind(crl_file);
	crl = d2i_X509_CRL_fp(crl_file, NULL);
	fclose(crl_file);

	if (!crl) {
		if (DEBUG_CRL) {
			fprintf(stderr, "[crl] parse: failed to parse CRL as PEM or DER\n");
		}
		return NULL;
	}

    if (DEBUG_CRL) {
        fprintf(stderr, "[crl] parse: PEM parse failed, DER fallback succeeded\n");
    }
	return crl;
}

/*
 * Validate a CRL file on disk:
 *   1) parse it (PEM/DER)
 *   2) verify signature (authenticity)
 *   3) verify timing (freshness)
 *
 * Returns:
 *   0  = valid
 *  -1  = invalid
 */
static int crl_file_is_valid(const char *crl_path) {
	X509_CRL *crl = load_crl_with_der_fallback(crl_path);
	if (!crl) return -1;

	if (crl_signature_is_valid(crl, CRL_SIGNER_CERT_PATH) != 0) {
		X509_CRL_free(crl);
		return -1;
	}

	if (crl_time_is_sane(crl) != 0) {
		X509_CRL_free(crl);
		return -1;
	}

	X509_CRL_free(crl);
	return 0;
}


/* ============================================================
   CRL DOWNLOAD
   ============================================================ */

/*
 * Downloads CRL from URL and saves to out_path.
 *
 * const char *url - the URL to download the CRL from
 * const char *out_path - the path to save the downloaded CRL
 *
 * Returns:
 *   0  -> success
 *  -1  -> failure
 */
int crl_download_to_file(const char *url, const char *out_path) {
	if (!url || !out_path){
        if (DEBUG_CRL){
            fprintf(stderr, "[crl] download: invalid input parameters\n");
        }
		return -1;
	}

    // Initialize libcurl
	CURL *curl = curl_easy_init();
	if (!curl) {
		if (DEBUG_CRL) {
			fprintf(stderr, "[crl] download: curl init failed\n");
		}
		return -1;
	}

    // Open output file in binary write mode
	FILE *file = fopen(out_path, "wb");
	if (!file) {
		if (DEBUG_CRL) {
			fprintf(stderr, "[crl] download: cannot open output path %s\n", out_path);
		}
		curl_easy_cleanup(curl);
		return -1;
	}
    
	file_writer_t writer = {.file = file};

    // Set curl options
	curl_easy_setopt(curl, CURLOPT_URL, url);

    // Tell curl to use our write callback
	curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_file_cb);

    // Pass our file writer struct to the callback
	curl_easy_setopt(curl, CURLOPT_WRITEDATA, &writer);

    // Follow HTTP redirects (301/302)
	curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
    

	FILE *ca_check = fopen(TRUSTED_CA_CERT_PATH, "r");
	if (ca_check) {
		fclose(ca_check);
		curl_easy_setopt(curl, CURLOPT_CAINFO, TRUSTED_CA_CERT_PATH);
		curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 1L);
		curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 2L);
	} else {
		if (DEBUG_CRL) {
			fprintf(stderr, "[crl] trusted CA not found at %s, falling back to insecure TLS\n",
					TRUSTED_CA_CERT_PATH);
		}
		curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
		curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);
	}

    // Perform the HTTP request
	CURLcode rc = curl_easy_perform(curl);

    // Get HTTP status code (200, 404, etc.)
	long http_status = 0;
	curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_status);

    // Clean up
	fclose(file);
	curl_easy_cleanup(curl);

	/*
	 * Retry strategy for endpoint-format mismatches seen during integration:
	 *   1) if cmd=crl missing, retry with cmd=crl
	 *   2) if issuer present but not encoded, retry with encoded issuer
	 *   3) if issuer missing and fallback enabled, derive issuer from active
	 *      enrollment cert and retry with issuer query parameter
	 */
	// Check for download errors or bad HTTP response
	if (rc != CURLE_OK || http_status < 200 || http_status >= 300) {
		if (rc == CURLE_OK && (http_status == 400 || http_status == 404)) {
			char *retry_url = NULL;

			if (!strstr(url, "cmd=crl")) {
				retry_url = build_url_with_cmd_crl(url);
				if (retry_url) {
					if (DEBUG_CRL) {
						fprintf(stderr, "[crl] download: got %ld, retrying with cmd=crl\n", http_status);
					}
				}
			} else if (strstr(url, "issuer=")) {
				retry_url = build_encoded_issuer_retry_url(url);
				if (retry_url && strcmp(retry_url, url) != 0) {
					if (DEBUG_CRL) {
						fprintf(stderr, "[crl] download: got %ld, retrying with encoded issuer URL\n", http_status);
					}
				}
			}

			if (retry_url) {
				if (strcmp(retry_url, url) != 0) {
					int retry_rc = crl_download_to_file(retry_url, out_path);
					free(retry_url);
					retry_url = NULL;
					if (retry_rc == 0) {
						return 0;
					}
				} else {
					free(retry_url);
					retry_url = NULL;
				}
			}

			if (!strstr(url, "issuer=")) {
				char cert_issuer[512] = {0};
				if (load_cert_issuer_rfc2253(ENROLLMENT_CERT_PATH, cert_issuer, sizeof(cert_issuer)) == 0) {
					char *cert_retry_url = build_url_with_issuer(url, cert_issuer);
					if (cert_retry_url && strcmp(cert_retry_url, url) != 0) {
						if (DEBUG_CRL) {
							fprintf(stderr, "[crl] download: retrying with issuer from enrolled cert (%s)\n", cert_issuer);
						}
						int cert_retry_rc = crl_download_to_file(cert_retry_url, out_path);
						free(cert_retry_url);
						if (cert_retry_rc == 0) {
							return 0;
						}
					} else {
						free(cert_retry_url);
					}
				}
			}
		}

        if(DEBUG_CRL){
            if (rc != CURLE_OK) {
                fprintf(stderr, "[crl] download: curl request failed (%s)\n", curl_easy_strerror(rc));
            } else {
                fprintf(stderr, "[crl] download: unexpected HTTP status %ld\n", http_status);
            }
        }

		remove(out_path);
		return -1;
	}

	return 0;
}


/* ============================================================
   CERTIFICATE REVOCATION CHECK
   ============================================================ */

/*
 * Internal certificate-vs-CRL revocation check.
 *
 * validate_crl = 1 -> perform signature + freshness validation on the CRL.
 * validate_crl = 0 -> assume CRL was already validated by caller.
 */
static int cert_is_revoked_by_crl_internal(const char *cert_path, const char *crl_path, int *is_revoked, int validate_crl) {
	if (!cert_path || !crl_path || !is_revoked) {
        if(DEBUG_CRL){
            fprintf(stderr, "[crl] check: invalid input parameters\n");
        }
		return -1;
	}

	FILE *cert_file = fopen(cert_path, "rb");
	if (!cert_file) {
		if (DEBUG_CRL) {
			fprintf(stderr, "[crl] check: cannot open cert file at %s\n", cert_path);
		}
		return -1;
	}

	X509 *cert = PEM_read_X509(cert_file, NULL, NULL, NULL);
	fclose(cert_file);
	if (!cert) {
		if (DEBUG_CRL) {
			fprintf(stderr, "[crl] check: failed to parse certificate (PEM)\n");
		}
		return -1;
	}

	X509_CRL *crl = load_crl_with_der_fallback(crl_path);
	if (!crl) {
		if (DEBUG_CRL) {
			fprintf(stderr, "[crl] check: CRL parse failed\n");
		}
		X509_free(cert);
		return -1;
	}

    // Optional CRL validation step. If validate_crl=0, we assume the caller has already verified the CRL's signature and freshness (for example, during a prior refresh step). This allows us to skip redundant checks if we trust the CRL file on disk.
	if (validate_crl) {
		if (crl_signature_is_valid(crl, CRL_SIGNER_CERT_PATH) != 0) {
			if (DEBUG_CRL) {
				fprintf(stderr, "[crl] check: CRL signature validation failed\n");
			}
			X509_CRL_free(crl);
			X509_free(cert);
			return -1;
		}

		if (crl_time_is_sane(crl) != 0) {
			if (DEBUG_CRL) {
				fprintf(stderr, "[crl] check: CRL freshness validation failed\n");
			}
			X509_CRL_free(crl);
			X509_free(cert);
			return -1;
		}
	}

    // Extract the certificate's serial number and check if it's listed in the CRL
	const ASN1_INTEGER *serial = X509_get0_serialNumber(cert);
	X509_REVOKED *revoked = NULL;
	int found = X509_CRL_get0_by_serial(crl, &revoked, serial);
	*is_revoked = (found == 1) ? 1 : 0;

	X509_CRL_free(crl);
	X509_free(cert);
	return 0;
}

/* ============================================================
   HIGH-LEVEL WRAPPER
   ============================================================ */

/*
 * Refresh the CRL and then check a certificate against it.
 *
 *   Maintain "last-known-good" CRL on disk.
 *   - Download into a temporary file
 *   - Validate temp file (parse + signature + time)
 *   - Only replace the existing CRL if the new one is valid
 *   - If download fails, keep using cached CRL
 *
 * crl_url     -> URL to fetch CRL from
 * crl_path    -> local path to CRL file (used for caching last-known-good
 * cert_path   -> path to certificate to check
 * is_revoked  -> output flag (1 = revoked, 0 = not revoked) 
 * 
 * Returns:
 *  0  on success
 * -1  on failure
 */
int crl_refresh_and_check(const char *crl_url, const char *crl_path, const char *cert_path, int *is_revoked) {

    fprintf(stderr, "[crl] CRL refresh and check\n");

	if (!crl_url || !crl_path || !cert_path || !is_revoked){
		if (DEBUG_CRL) {
			fprintf(stderr, "[crl] refresh/check: invalid input parameters\n");
		}
		return -1;
	}

    // TODO: DELETE Maybe 
	// Special case: mock mode (for testing). Keep signing fail-open behavior,
	// report local cache status if available, and do not attempt network download.
	if (strncmp(crl_url, "mock://", 7) == 0) {
		FILE *cached = fopen(crl_path, "rb");
		if (cached) {
			fclose(cached);
			if (crl_print_bad_certs(crl_path) != 0) {
				if (DEBUG_CRL) {
					fprintf(stderr, "[crl] mock mode: local CRL exists but could not be parsed: %s\n", crl_path);
				}
			}
		} else {
			if (DEBUG_CRL) {
				fprintf(stderr, "[crl] mock mode: no cached CRL yet at %s\n", crl_path);
			}
		}
		*is_revoked = 0;
		return 0;
	}

    // Build a temporary path like "<crl_path>.tmp" for atomic-like update
	char tmp_path[512];
	int n = snprintf(tmp_path, sizeof(tmp_path), "%s.tmp", crl_path);
	if (n <= 0 || (size_t) n >= sizeof(tmp_path)) {
		if (DEBUG_CRL) {
			fprintf(stderr, "[crl] refresh/check: temp path too long\n");
		}
		return -1;
	}

    // Download new CRL to temp path.
	// If download succeeds, validate it, and only then replace the active CRL.
	if (crl_download_to_file(crl_url, tmp_path) == 0) {

		if (crl_file_is_valid(tmp_path) == 0) {
			if (remove(crl_path) != 0 && errno != ENOENT) {
				if (DEBUG_CRL) {
					fprintf(stderr, "[crl] refresh/check: failed to remove old CRL at %s\n", crl_path);
				}   
			}
			if (rename(tmp_path, crl_path) != 0) {
				if (DEBUG_CRL) {
					fprintf(stderr, "[crl] refresh/check: failed to promote temp CRL, keeping existing CRL\n");
				}
				remove(tmp_path);
			} else {
				if (DEBUG_CRL) {
					fprintf(stderr, "[crl] refresh/check: installed new validated CRL\n");
				}
			}
		} else {
			if (DEBUG_CRL) {
				fprintf(stderr, "[crl] refresh/check: downloaded CRL invalid, keeping last-known-good\n");
			}
			remove(tmp_path);
		}
	} else {
		if (DEBUG_CRL) {
			fprintf(stderr, "[crl] refresh/check: download failed, trying last-known-good CRL\n");
		}
	}

	if (crl_file_is_valid(crl_path) != 0) {
		if (DEBUG_CRL) {
			fprintf(stderr, "[crl] refresh/check: no valid CRL available (new or cached)\n");
		}
		return -1;
	}
    
	if (crl_print_bad_certs(crl_path) != 0) {
		if (DEBUG_CRL) {
			fprintf(stderr, "[crl] failed to print current bad-cert list from %s\n", crl_path);
		}
	}

	// Final revocation decision used by signer thread for current active cert.
	return cert_is_revoked_by_crl_internal(cert_path, crl_path, is_revoked, 0);
}



int crl_print_bad_certs(const char *crl_path) {
	if (!crl_path){ 
        return -1;
    }

    // Load CRL (PEM/DER)
	X509_CRL *crl = load_crl_with_der_fallback(crl_path);
	if (!crl){
        return -1;
    }

    // Validate CRL before trusting its contents
	if (crl_time_is_sane(crl) != 0) {
		X509_CRL_free(crl);
		return -1;
	}

    // Print the count of revoked certificates and their serial numbers for observability
    STACK_OF(X509_REVOKED) *revoked_list = X509_CRL_get_REVOKED(crl);
	int count = revoked_list ? sk_X509_REVOKED_num(revoked_list) : 0;
	fprintf(stderr, "BAD_CERT_LIST: count=%d\n", count);

    // Iterate through revoked certs and print their serial numbers in hex
	for (int i = 0; i < count; ++i) {
		X509_REVOKED *rev = sk_X509_REVOKED_value(revoked_list, i);
		if (!rev) continue;

		const ASN1_INTEGER *serial = X509_REVOKED_get0_serialNumber(rev);
		BIGNUM *bn = ASN1_INTEGER_to_BN(serial, NULL);
		if (!bn) continue;

		char *serial_hex = BN_bn2hex(bn);
		BN_free(bn);
		if (!serial_hex) continue;

		fprintf(stderr, "BAD_CERT: serial=%s\n", serial_hex);
		OPENSSL_free(serial_hex);
	}
    
	X509_CRL_free(crl);
	return 0;
}