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

#include <string.h>

#include "zta_policy.h"
#include "x509_verifier.h"
#include "oidc_verifier.h"

/* Register this configuration so load_all_configs() auto-discovers it. */
DECLARE_CONFIGURATION(zta_policy, sizeof(zta_policy_t), zta_policy_to_json, zta_policy_from_json);

/* ---------- defaults ---------- */

void zta_policy_defaults(zta_policy_t *policy)
{
    if (!policy)
        return;
    memset(policy, 0, sizeof(*policy));
    policy->enabled = false;
    policy->require_at_admission = true;
    policy->reverify_interval_sec = 3600;
    policy->revocation_reputation_penalty = 0.8;
    policy->allow_ddil_fallback = true;
    policy->ddil_fallback_reputation_cap = 0.5;
    policy->audit_deferred_verifications = true;
    policy->delegated_verification_min_reputation = 0.7;
    policy->delegated_verification_quorum = 1;
    strncpy(policy->verifier_type, "x509", ZTA_VERIFIER_TYPE_LEN - 1);
    /* ca_bundle_path, ocsp_url, crl_path left empty (zeroed) */
}

/* ---------- JSON serialization ---------- */

int zta_policy_to_json(const void *data_struct, json_t **obj_ptr)
{
    const zta_policy_t *p = (const zta_policy_t *)data_struct;
    if (!p || !obj_ptr)
        return ECFG_BADFMT;

    json_t *obj = json_object();
    if (!obj)
        return ECFG_BADFMT;

    json_object_set_new(obj, "enabled", json_boolean(p->enabled));
    json_object_set_new(obj, "require_at_admission", json_boolean(p->require_at_admission));
    json_object_set_new(obj, "reverify_interval_sec", json_integer(p->reverify_interval_sec));
    json_object_set_new(obj, "revocation_reputation_penalty", json_real(p->revocation_reputation_penalty));
    json_object_set_new(obj, "allow_ddil_fallback", json_boolean(p->allow_ddil_fallback));
    json_object_set_new(obj, "ddil_fallback_reputation_cap", json_real(p->ddil_fallback_reputation_cap));
    json_object_set_new(obj, "audit_deferred_verifications", json_boolean(p->audit_deferred_verifications));
    json_object_set_new(obj, "delegated_verification_min_reputation",
                        json_real(p->delegated_verification_min_reputation));
    json_object_set_new(obj, "delegated_verification_quorum",
                        json_integer(p->delegated_verification_quorum));
    json_object_set_new(obj, "verifier_type", json_string(p->verifier_type));
    json_object_set_new(obj, "ca_bundle_path", json_string(p->ca_bundle_path));
    json_object_set_new(obj, "ocsp_url", json_string(p->ocsp_url));
    json_object_set_new(obj, "crl_path", json_string(p->crl_path));

    *obj_ptr = obj;
    return 0;
}

int zta_policy_from_json(const json_t *obj, void *data_struct)
{
    zta_policy_t *p = (zta_policy_t *)data_struct;
    if (!obj || !p)
        return ECFG_BADFMT;

    /* Start with defaults so missing fields get sane values */
    zta_policy_defaults(p);

    json_t *val;

    val = json_object_get(obj, "enabled");
    if (json_is_boolean(val))
        p->enabled = json_boolean_value(val);

    val = json_object_get(obj, "require_at_admission");
    if (json_is_boolean(val))
        p->require_at_admission = json_boolean_value(val);

    val = json_object_get(obj, "reverify_interval_sec");
    if (json_is_integer(val))
        p->reverify_interval_sec = (int)json_integer_value(val);

    val = json_object_get(obj, "revocation_reputation_penalty");
    if (json_is_real(val) || json_is_integer(val))
        p->revocation_reputation_penalty = json_number_value(val);

    val = json_object_get(obj, "allow_ddil_fallback");
    if (json_is_boolean(val))
        p->allow_ddil_fallback = json_boolean_value(val);

    val = json_object_get(obj, "ddil_fallback_reputation_cap");
    if (json_is_real(val) || json_is_integer(val))
        p->ddil_fallback_reputation_cap = json_number_value(val);

    val = json_object_get(obj, "audit_deferred_verifications");
    if (json_is_boolean(val))
        p->audit_deferred_verifications = json_boolean_value(val);

    val = json_object_get(obj, "delegated_verification_min_reputation");
    if (json_is_real(val) || json_is_integer(val))
        p->delegated_verification_min_reputation = json_number_value(val);

    val = json_object_get(obj, "delegated_verification_quorum");
    if (json_is_integer(val))
        p->delegated_verification_quorum = (int)json_integer_value(val);

    val = json_object_get(obj, "verifier_type");
    if (json_is_string(val))
        snprintf(p->verifier_type, ZTA_VERIFIER_TYPE_LEN, "%s", json_string_value(val));

    val = json_object_get(obj, "ca_bundle_path");
    if (json_is_string(val))
        snprintf(p->ca_bundle_path, ZTA_PATH_LEN, "%s", json_string_value(val));

    val = json_object_get(obj, "ocsp_url");
    if (json_is_string(val))
        snprintf(p->ocsp_url, ZTA_PATH_LEN, "%s", json_string_value(val));

    val = json_object_get(obj, "crl_path");
    if (json_is_string(val))
        snprintf(p->crl_path, ZTA_PATH_LEN, "%s", json_string_value(val));

    return 0;
}

/* ---------- verifier factory ---------- */

/* Frama-C: skipped — [solver-timeout] error-path postcondition */
int zta_policy_create_verifier(const zta_policy_t *policy, zta_verifier_t **out)
{
    if (!policy || !out)
        return EZTA_INTERNAL;

    if (!policy->enabled)
        return zta_null_verifier_create(out);

    if (strcmp(policy->verifier_type, "x509") == 0) {
        x509_verifier_config_t cfg;
        memset(&cfg, 0, sizeof(cfg));
        /* snprintf (not strncpy) for guaranteed NUL-termination — satisfies
         * -Wstringop-truncation and is safe when src is full-length. */
        snprintf(cfg.ca_bundle_path, sizeof(cfg.ca_bundle_path), "%s",
                 policy->ca_bundle_path);
        snprintf(cfg.ocsp_url, sizeof(cfg.ocsp_url), "%s", policy->ocsp_url);
        snprintf(cfg.crl_path, sizeof(cfg.crl_path), "%s", policy->crl_path);
        cfg.connect_timeout_ms = 2000;
        return x509_verifier_create(&cfg, out);
    }

    if (strcmp(policy->verifier_type, "oidc") == 0)
        return oidc_verifier_create(out);

    /* Unknown type: fall back to null */
    return zta_null_verifier_create(out);
}
