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
    bool enabled;                       /* Master switch: must be true for ZTA to activate */
    bool require_at_admission;          /* Require valid ZTA credential at admission */
    int reverify_interval_sec;          /* Periodic re-verification interval; 0 = disable */
    double revocation_reputation_penalty; /* Reputation penalty on revocation (0.0-1.0) */
    bool allow_ddil_fallback;           /* Allow admission when ZTA infrastructure unreachable */
    double ddil_fallback_reputation_cap;  /* Max reputation for peers admitted without ZTA */
    bool audit_deferred_verifications;  /* Log deferred checks for compliance */
    char verifier_type[ZTA_VERIFIER_TYPE_LEN]; /* "x509", "oidc", "null" */
    /* Verifier-specific config (X.509 fields) */
    double delegated_verification_min_reputation; /* Min reputation to accept delegated verification */
    int delegated_verification_quorum;    /* Number of independent verifications needed to lift cap */
    char ca_bundle_path[ZTA_PATH_LEN];
    char ocsp_url[ZTA_PATH_LEN];
    char crl_path[ZTA_PATH_LEN];
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

#endif /* ZTA_POLICY_H */
