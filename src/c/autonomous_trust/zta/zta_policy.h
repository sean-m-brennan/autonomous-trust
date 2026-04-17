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

#ifndef ZTA_POLICY_H
#define ZTA_POLICY_H

/** @addtogroup internal_zta
 *  @{
 */

#include <stdbool.h>
#include <jansson.h>

#include "utilities/allocation.h"
#include "config/configuration.h"
#include "zta_verifier.h"

#ifdef __cplusplus
extern "C" {
#endif

#define ZTA_VERIFIER_TYPE_LEN 32
#define ZTA_PATH_LEN 256

/**
 * @brief ZTA policy configuration
 *
 * Controls runtime behavior of ZTA credential verification.
 * When enabled is false, all ZTA code paths are no-ops.
 */
typedef struct {
    smrt_ptr_t;
    bool enabled;                                  /**< Master switch; when @c false all other fields are ignored and ZTA code paths become no-ops. */
    bool require_at_admission;                     /**< Require a valid credential before admitting a peer. Mutually informative with @c allow_ddil_fallback. */
    int reverify_interval_sec;                     /**< Periodic re-verification cadence; 0 disables periodic re-checks. */
    double revocation_reputation_penalty;          /**< Reputation delta (0.0–1.0) applied on credential revocation. */
    bool allow_ddil_fallback;                      /**< Permit admission when the PKI/OIDC backend is unreachable (Disconnected/Degraded/Intermittent/Limited). */
    double ddil_fallback_reputation_cap;           /**< Maximum reputation a peer admitted via fallback can earn until verified. */
    bool audit_deferred_verifications;             /**< Emit an audit log entry for every deferred verification. */
    char verifier_type[ZTA_VERIFIER_TYPE_LEN];     /**< "x509", "oidc", or "null"; selects the verifier constructed by zta_policy_create_verifier(). */
    /* Fields below are used only when @c verifier_type == "x509". */
    double delegated_verification_min_reputation;  /**< Min peer reputation whose delegated verification this node trusts. */
    int delegated_verification_quorum;             /**< Count of independent delegated verifications that lifts @c ddil_fallback_reputation_cap. */
    char ca_bundle_path[ZTA_PATH_LEN];             /**< X.509: path to the trusted CA bundle (PEM). */
    char ocsp_url[ZTA_PATH_LEN];                   /**< X.509: OCSP responder URL; empty disables OCSP. */
    char crl_path[ZTA_PATH_LEN];                   /**< X.509: path to the CRL; empty disables CRL checks. */
} zta_policy_t;

/**
 * @brief Initialize a zta_policy_t with default values (disabled)
 */
/*@
  requires \valid(policy);
  assigns *policy;
  ensures policy->enabled == \false;
*/
void zta_policy_defaults(zta_policy_t *policy);

/**
 * @brief Serialize a zta_policy_t to JSON
 */
int zta_policy_to_json(const void *data_struct, json_t **obj_ptr);

/**
 * @brief Deserialize a zta_policy_t from JSON
 */
int zta_policy_from_json(const json_t *obj, void *data_struct);

/**
 * @brief Create the appropriate verifier based on policy configuration
 *
 * When enabled is false, returns a null verifier.
 * When verifier_type is "x509", creates an X.509 verifier.
 * When verifier_type is "oidc", creates an OIDC stub verifier.
 * Otherwise, returns a null verifier.
 *
 * @param policy ZTA policy configuration
 * @param out    Output: newly allocated verifier (caller must destroy)
 * @return 0 on success, error code on failure
 */
/*@
  requires \valid(policy);
  requires \valid(out);
  allocates *out;
  behavior success:
    ensures \result == 0;
    ensures *out != \null;
  behavior failure:
    ensures \result != 0;
  disjoint behaviors;
*/
int zta_policy_create_verifier(const zta_policy_t *policy, zta_verifier_t **out);

#ifdef __cplusplus
} /* extern "C" */
#endif


/** @} */ /* end of internal_zta */

#endif /* ZTA_POLICY_H */
