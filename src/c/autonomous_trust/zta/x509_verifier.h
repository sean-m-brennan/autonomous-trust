/********************
 *  Copyright 2025 Sean M. Brennan and contributors
 *
 *   Licensed under the Apache License, Version 2.0 (the "License");
 *   you may not use this file except in compliance with the License.
 *   You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 *   Unless required by applicable law or agreed to in writing, software
 *   distributed under the License is distributed on an "AS IS" BASIS,
 *   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *   See the License for the specific language governing permissions and
 *   limitations under the License.
 *******************/

#ifndef X509_VERIFIER_H
#define X509_VERIFIER_H

#include "zta_verifier.h"

#ifdef __cplusplus
extern "C" {
#endif

#define X509_PATH_LEN 256

/**
 * @brief Configuration for the X.509 verifier
 */
typedef struct {
    char ca_bundle_path[X509_PATH_LEN];   /* Path to CA bundle (PEM); required */
    char ocsp_url[X509_PATH_LEN];         /* OCSP responder URL; empty = disabled */
    char crl_path[X509_PATH_LEN];         /* Path to CRL file (PEM/DER); empty = disabled */
    int connect_timeout_ms;               /* Network timeout for OCSP queries; default 2000 */
} x509_verifier_config_t;

/**
 * @brief Create an X.509 certificate verifier using OpenSSL
 *
 * Validates certificates against the configured CA bundle.
 * Optionally checks revocation via OCSP and/or CRL.
 *
 * @param cfg   Verifier configuration
 * @param out   Output: newly allocated verifier (caller must destroy)
 * @return 0 on success, error code on failure
 */
/*@
  requires \valid(cfg);
  requires \valid(out);
  allocates *out;
  behavior success:
    ensures \result == 0;
    ensures *out != \null;
  behavior failure:
    ensures \result != 0;
  disjoint behaviors;
*/
int x509_verifier_create(const x509_verifier_config_t *cfg,
                         zta_verifier_t **out);

/* Error codes */
#define EX509_CALOAD  290
DECLARE_ERROR(EX509_CALOAD, "Failed to load CA bundle");

#define EX509_PARSE   291
DECLARE_ERROR(EX509_PARSE, "Failed to parse X.509 certificate");

#define EX509_VERIFY  292
DECLARE_ERROR(EX509_VERIFY, "X.509 certificate verification failed");

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* X509_VERIFIER_H */
