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

/* How hard the admission gate insists on a credential->identity binding
 * (@ref zta_binding.h). REQUIRE is the default because without a binding the gate
 * falls back on first-use-wins, and TOFU is the whole of
 * doc/architecture/zta-integration.md. The cost is
 * a flag day: a credential provisioned before bindings existed is refused until
 * re-provisioned, so a fleet mid-migration wants PREFER for one hop.
 *
 * Keep the wire spellings identical to Python's BINDING_MODE_* — a policy file is
 * read by both runtimes. */
typedef enum {
    ZTA_BINDING_MODE_REQUIRE = 0,  /**< unbound credential -> unusable */
    ZTA_BINDING_MODE_PREFER,       /**< unbound -> admit, DDIL-capped, TOFU stands */
    ZTA_BINDING_MODE_OFF,          /**< verify a binding if offered, never require */
} zta_binding_mode_t;

/**
 * @brief Parse a binding_mode string.
 *
 * An unrecognized value resolves to REQUIRE, deliberately: a typo must tighten the
 * gate, never open it. Same rule as Python.
 */
zta_binding_mode_t zta_binding_mode_parse(const char *s);

/** @brief The wire spelling of a binding mode ("require"/"prefer"/"off"). */
const char *zta_binding_mode_str(zta_binding_mode_t mode);

#define ZTA_ANCHOR_NAME_MAX 64
#define ZTA_POLICY_MAX_ANCHORS 8

/**
 * @brief One named trust anchor: an agency, and the CA bundle that speaks for it.
 *
 * Multiple anchors arise because a network gateway bridges agencies. Nothing here
 * makes two CAs recognize each other — cross-certification is not needed and was
 * never the obstacle; what is needed is for THIS node to recognize both, which is
 * a local list.
 */
typedef struct {
    char name[ZTA_ANCHOR_NAME_MAX];      /**< label a peer earns authority for */
    char ca_bundle_path[ZTA_PATH_LEN];   /**< PEM bundle; an anchor with none is dropped */
    bool is_operator;                    /**< credentials here mark a human guardian */
} zta_anchor_t;

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
    char operator_ca_bundle_path[ZTA_PATH_LEN];    /**< DISTINCT operator trust anchor (ethne D8/Q9):
                                                        a credential is operator-class (has a human
                                                        guardian) iff it chain-verifies against THIS
                                                        bundle, separate from ca_bundle_path. Empty =>
                                                        the node cannot confirm any peer is human
                                                        (operator_bound stays false, fail-safe).
                                                        Parity with Python ZtaPolicy. */
    /* Named trust anchors, one per agency (doc/architecture/zta-integration.md). EMPTY IS
     * THE COMMON CASE
       AND NOT A DEGENERATE ONE: zta_policy_resolved_anchors() synthesizes the
       historical pair from ca_bundle_path / operator_ca_bundle_path, so every
       pre-existing config resolves to exactly the two anchors it already had, in
       the same roles. That is what makes multi-anchor additive rather than a
       config flag day (unlike binding_mode, which is a credential one). */
    zta_anchor_t anchors[ZTA_POLICY_MAX_ANCHORS];
    size_t num_anchors;
    zta_binding_mode_t binding_mode;               /**< default REQUIRE; see the enum. */
    char san_uri_template[ZTA_PATH_LEN];           /**< e.g. "at://{uuid}"; the `{uuid}`
                                                        placeholder is Python's spelling
                                                        because the policy file is shared.
                                                        Empty disables the CA-asserted path,
                                                        leaving holder-asserted signatures as
                                                        the only accepted proof. */
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

/**
 * @brief Construct the OPERATOR-anchor verifier (chain-only X.509 over
 *        operator_ca_bundle_path), used by the admission gate to classify an
 *        already-verified credential as operator-class (ethne D8/Q9). Returns
 *        EZTA_INTERNAL / non-zero and leaves *out NULL when disabled or no
 *        operator anchor is configured. Distinct from zta_policy_create_verifier
 *        (the peer anchor); parity with Python ZtaPolicy.create_operator_verifier.
 */
int zta_policy_create_operator_verifier(const zta_policy_t *policy, zta_verifier_t **out);

/**
 * @brief The trust anchors to evaluate a peer's credentials against, normalized.
 *
 * When @c anchors is empty this SYNTHESIZES the historical pair — a "peer" anchor
 * from @c ca_bundle_path and, if configured, a distinct "operator" anchor from
 * @c operator_ca_bundle_path. An existing single-CA deployment therefore resolves
 * to exactly the two anchors it already had, which is what keeps the multi-anchor
 * work additive.
 *
 * Anchors with no bundle path are dropped (one that trusts nothing can verify
 * nothing, and keeping it would only produce confusing per-anchor failures).
 * Names are deduplicated by first occurrence, so a config that repeats one cannot
 * make a credential count twice toward gateway authority.
 *
 * Mirrors Python `ZtaPolicy.resolved_anchors`.
 *
 * @param[out] out    Caller-provided array.
 * @param[in]  max    Capacity of @p out.
 * @return the number written (0 when nothing is configured).
 */
size_t zta_policy_resolved_anchors(const zta_policy_t *policy,
                                   zta_anchor_t *out, size_t max);

/**
 * @brief Construct a chain-walking verifier for one resolved anchor.
 *
 * An anchor IS a CA bundle, so this is always X.509 regardless of
 * @c verifier_type — mirroring Python `create_anchor_verifiers`, which does the
 * same and for the same reason.
 *
 * @return 0 on success, EZTA_INTERNAL on a bad argument.
 */
int zta_policy_create_anchor_verifier(const zta_policy_t *policy,
                                      const zta_anchor_t *anchor,
                                      zta_verifier_t **out);

/**
 * @brief Render a SAN URI template by substituting @c {uuid}.
 *
 * Textual substitution of Python's placeholder rather than printf: see
 * @ref ZTA_SAN_URI_TEMPLATE for why the shared policy file forces this. A template
 * with no placeholder is copied through unchanged (it names a fixed URI, which is
 * strange but not an error). Only the FIRST occurrence is substituted, matching
 * nothing in particular — a second one would name two nodes at once.
 *
 * @return 0 on success, EINVAL on a bad argument or a result that would not fit.
 */
int zta_render_san_uri(const char *template_str, const char *uuid_str,
                       char *out, size_t out_len);

#ifdef __cplusplus
} /* extern "C" */
#endif


/** @} */ /* end of internal_zta */

#endif /* ZTA_POLICY_H */
