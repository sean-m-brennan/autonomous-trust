/********************
 *  Copyright 2026 TekFive, Inc., Sean M. Brennan, and contributors
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

/** @addtogroup internal_zta
 *  @{
 */

#include "zta_verifier.h"

#ifdef __cplusplus
extern "C" {
#endif

#define X509_PATH_LEN 256

/**
 * @brief Configuration for the X.509 verifier
 */
typedef struct {
    char ca_bundle_path[X509_PATH_LEN];   /* CA bundle: concatenated PEM, a single
                                             DER cert, or PKCS#7 .p7b (DER or
                                             PEM-wrapped); required */
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

/**
 * @brief Verify a detached signature over @p data under @p cert_der's public key.
 *
 * Needs no verifier instance and no CA store: this answers only "did the holder of
 * this certificate's private key sign these bytes". Whether the certificate itself
 * is trustworthy — and operator-class — is a separate question its caller must
 * already have answered against the anchors.
 *
 * SHA-256 with the algorithm the key implies: PKCS#1 v1.5 for RSA, ECDSA for EC,
 * matching Python `PivVerifier._verify_signature` (which is what signs these on the
 * other side, via `PivToken.sign`). Any other key type is refused rather than
 * guessed at.
 *
 * Written for the operator-key binding (@ref operator_binding_preimage); nothing
 * about it is specific to that use.
 *
 * @param[in] cert_der  Certificate, DER (or PEM — the same parser as the chain path).
 * @param[in] cert_len  Length of @p cert_der.
 * @param[in] data      Signed bytes.
 * @param[in] data_len  Length of @p data.
 * @param[in] sig       Detached signature.
 * @param[in] sig_len   Length of @p sig.
 * @return true only when the signature verifies. False on any bad argument,
 *         unparseable certificate, unsupported key type, or verification failure —
 *         a caller cannot act differently on those and must not be tempted to.
 */
/*@
  requires cert_der == \null || \valid_read(cert_der + (0 .. cert_len - 1));
  requires data == \null || \valid_read(data + (0 .. data_len - 1));
  requires sig == \null || \valid_read(sig + (0 .. sig_len - 1));
  assigns \nothing;
*/
bool x509_verify_data_signature(const uint8_t *cert_der, size_t cert_len,
                                const uint8_t *data, size_t data_len,
                                const uint8_t *sig, size_t sig_len);

/* Error codes */
#define EX509_CALOAD  290
DECLARE_ERROR(EX509_CALOAD, "Failed to load CA bundle");

#define EX509_PARSE   291
DECLARE_ERROR(EX509_PARSE, "Failed to parse X.509 certificate");

#define EX509_VERIFY  292
DECLARE_ERROR(EX509_VERIFY, "X.509 certificate verification failed");

/* The bundle path held an identifiable non-certificate object (CRL, CSR, or
 * private key) rather than being merely unreadable -- a configuration mix-up,
 * distinguished so it is not diagnosed as a missing/corrupt bundle. The Python
 * mirror names it in the reject reason; see doc/architecture/zta-python-parity.md
 * §2.1. */
/* NB: no commas in the description -- preprocess.py splits DECLARE_ERROR args on
 * commas when building the error table. */
#define EX509_CAKIND  293
DECLARE_ERROR(EX509_CAKIND, "CA bundle is not certificates (CRL / CSR / key?)");

#ifdef __cplusplus
} /* extern "C" */
#endif


/** @} */ /* end of internal_zta */

#endif /* X509_VERIFIER_H */
