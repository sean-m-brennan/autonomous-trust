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

#include <string.h>

#include "utilities/util.h"          /* at_strlcpy */
#include "identity/identity.h"       /* ZTA_SAN_URI_TEMPLATE / _PLACEHOLDER */
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
    /* REQUIRE by default: an unbound credential leaves the gate on first-use-wins,
       which is the hole §1.5 is about. Matches Python's default. */
    policy->binding_mode = ZTA_BINDING_MODE_REQUIRE;
    snprintf(policy->san_uri_template, ZTA_PATH_LEN, "%s", ZTA_SAN_URI_TEMPLATE);
    /* anchors left empty; resolved_anchors() synthesizes the historical pair. */
}

/* ---------- binding mode ---------- */

zta_binding_mode_t zta_binding_mode_parse(const char *s)
{
    if (s == NULL)
        return ZTA_BINDING_MODE_REQUIRE;
    if (strcmp(s, "prefer") == 0)
        return ZTA_BINDING_MODE_PREFER;
    if (strcmp(s, "off") == 0)
        return ZTA_BINDING_MODE_OFF;
    /* Including an unrecognized value: a typo must tighten the gate, not open it. */
    return ZTA_BINDING_MODE_REQUIRE;
}

const char *zta_binding_mode_str(zta_binding_mode_t mode)
{
    switch (mode) {
        case ZTA_BINDING_MODE_PREFER: return "prefer";
        case ZTA_BINDING_MODE_OFF:    return "off";
        case ZTA_BINDING_MODE_REQUIRE:
        default:                      return "require";
    }
}

int zta_render_san_uri(const char *template_str, const char *uuid_str,
                       char *out, size_t out_len)
{
    if (template_str == NULL || uuid_str == NULL || out == NULL || out_len == 0)
        return EINVAL;
    const char *hit = strstr(template_str, ZTA_SAN_URI_PLACEHOLDER);
    if (hit == NULL) {
        if (strlen(template_str) >= out_len)
            return EINVAL;
        at_strlcpy(out, template_str, out_len);
        return 0;
    }
    size_t head = (size_t)(hit - template_str);
    const char *tail = hit + strlen(ZTA_SAN_URI_PLACEHOLDER);
    if (head + strlen(uuid_str) + strlen(tail) >= out_len)
        return EINVAL;
    memcpy(out, template_str, head);
    /* Bounded by the check above; built piecewise rather than with snprintf("%s%s%s")
       so a template containing a stray '%' cannot reach a format string. */
    out[head] = '\0';
    at_strlcpy(out + head, uuid_str, out_len - head);
    at_strlcpy(out + strlen(out), tail, out_len - strlen(out));
    return 0;
}

/* ---------- anchors ---------- */

size_t zta_policy_resolved_anchors(const zta_policy_t *policy,
                                   zta_anchor_t *out, size_t max)
{
    if (policy == NULL || out == NULL || max == 0)
        return 0;
    /* The synthesized pair, when no explicit anchors are configured. Built on the
       stack rather than branching twice below, so the dedup/drop rules below apply
       identically to both sources. */
    zta_anchor_t synth[2];
    const zta_anchor_t *raw = policy->anchors;
    size_t n_raw = policy->num_anchors;
    if (n_raw == 0) {
        size_t k = 0;
        memset(synth, 0, sizeof(synth));
        if (policy->ca_bundle_path[0] != '\0') {
            at_strlcpy(synth[k].name, "peer", ZTA_ANCHOR_NAME_MAX);
            at_strlcpy(synth[k].ca_bundle_path, policy->ca_bundle_path, ZTA_PATH_LEN);
            synth[k].is_operator = false;
            k++;
        }
        if (policy->operator_ca_bundle_path[0] != '\0') {
            at_strlcpy(synth[k].name, "operator", ZTA_ANCHOR_NAME_MAX);
            at_strlcpy(synth[k].ca_bundle_path, policy->operator_ca_bundle_path,
                       ZTA_PATH_LEN);
            synth[k].is_operator = true;
            k++;
        }
        raw = synth;
        n_raw = k;
    }
    size_t n_out = 0;
    for (size_t i = 0; i < n_raw && n_out < max; i++) {
        if (raw[i].ca_bundle_path[0] == '\0')
            continue;  /* an anchor that trusts nothing verifies nothing */
        bool dup = false;
        for (size_t j = 0; j < n_out; j++)
            if (strcmp(out[j].name, raw[i].name) == 0) { dup = true; break; }
        if (dup)
            continue;
        out[n_out] = raw[i];
        if (out[n_out].name[0] == '\0')
            snprintf(out[n_out].name, ZTA_ANCHOR_NAME_MAX, "anchor%zu", i);
        n_out++;
    }
    return n_out;
}

int zta_policy_create_anchor_verifier(const zta_policy_t *policy,
                                      const zta_anchor_t *anchor,
                                      zta_verifier_t **out)
{
    if (policy == NULL || anchor == NULL || out == NULL)
        return EZTA_INTERNAL;
    *out = NULL;
    if (anchor->ca_bundle_path[0] == '\0')
        return EZTA_INTERNAL;
    x509_verifier_config_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    snprintf(cfg.ca_bundle_path, sizeof(cfg.ca_bundle_path), "%s",
             anchor->ca_bundle_path);
    /* Revocation sources are policy-wide, not per-anchor: a CRL/OCSP endpoint
       answers about certificates, and which anchor we happened to walk to reach
       one does not change whether it was revoked. */
    snprintf(cfg.ocsp_url, sizeof(cfg.ocsp_url), "%s", policy->ocsp_url);
    snprintf(cfg.crl_path, sizeof(cfg.crl_path), "%s", policy->crl_path);
    cfg.connect_timeout_ms = 2000;
    return x509_verifier_create(&cfg, out);
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
    json_object_set_new(obj, "operator_ca_bundle_path",
                        json_string(p->operator_ca_bundle_path));
    json_object_set_new(obj, "binding_mode",
                        json_string(zta_binding_mode_str(p->binding_mode)));
    json_object_set_new(obj, "san_uri_template", json_string(p->san_uri_template));
    /* Emitted only when explicitly configured. An empty list round-trips as an
       absent key, which is what keeps a pre-anchors config byte-identical after a
       load/store cycle — resolved_anchors() synthesizes the pair on demand rather
       than materializing it into the file. */
    if (p->num_anchors > 0) {
        json_t *arr = json_array();
        for (size_t i = 0; i < p->num_anchors; i++) {
            json_t *a = json_object();
            json_object_set_new(a, "name", json_string(p->anchors[i].name));
            json_object_set_new(a, "ca_bundle_path",
                                json_string(p->anchors[i].ca_bundle_path));
            json_object_set_new(a, "operator",
                                json_boolean(p->anchors[i].is_operator));
            json_array_append_new(arr, a);
        }
        json_object_set_new(obj, "anchors", arr);
    }

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

    /* Optional (additive) operator trust anchor; older configs / the Python
     * side omitting it leave the zeroed default (no operator classification). */
    val = json_object_get(obj, "operator_ca_bundle_path");
    if (json_is_string(val))
        snprintf(p->operator_ca_bundle_path, ZTA_PATH_LEN, "%s", json_string_value(val));

    /* Absent key => the REQUIRE default set above. That is deliberate and it is
       the flag day: a config written before bindings existed now demands them.
       `prefer` is the one-hop migration setting. */
    val = json_object_get(obj, "binding_mode");
    if (json_is_string(val))
        p->binding_mode = zta_binding_mode_parse(json_string_value(val));

    val = json_object_get(obj, "san_uri_template");
    if (json_is_string(val))
        snprintf(p->san_uri_template, ZTA_PATH_LEN, "%s", json_string_value(val));

    /* Optional/additive: absent leaves num_anchors 0, and resolved_anchors()
       then synthesizes exactly the two anchors this config always had. Entries
       past ZTA_POLICY_MAX_ANCHORS are dropped rather than failing the load — a
       config listing more agencies than we will evaluate is a deployment to
       correct, not a reason to refuse to start. */
    val = json_object_get(obj, "anchors");
    if (json_is_array(val)) {
        size_t idx;
        json_t *entry;
        json_array_foreach(val, idx, entry) {
            if (p->num_anchors >= ZTA_POLICY_MAX_ANCHORS)
                break;
            if (!json_is_object(entry))
                continue;
            const char *path = json_string_value(
                json_object_get(entry, "ca_bundle_path"));
            if (path == NULL || path[0] == '\0')
                continue;
            zta_anchor_t *a = &p->anchors[p->num_anchors];
            memset(a, 0, sizeof(*a));
            const char *name = json_string_value(json_object_get(entry, "name"));
            if (name != NULL && name[0] != '\0')
                snprintf(a->name, ZTA_ANCHOR_NAME_MAX, "%s", name);
            else
                snprintf(a->name, ZTA_ANCHOR_NAME_MAX, "anchor%zu", idx);
            snprintf(a->ca_bundle_path, ZTA_PATH_LEN, "%s", path);
            json_t *op = json_object_get(entry, "operator");
            a->is_operator = json_is_boolean(op) ? json_boolean_value(op) : false;
            p->num_anchors++;
        }
    }

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

int zta_policy_create_operator_verifier(const zta_policy_t *policy, zta_verifier_t **out)
{
    if (!policy || !out)
        return EZTA_INTERNAL;
    *out = NULL;
    /* No operator anchor configured (or ZTA disabled) => cannot classify a
     * credential as operator-class; caller treats a NULL verifier as
     * "operator_bound stays false" (fail-safe). Mirrors Python
     * ZtaPolicy.create_operator_verifier returning None. */
    if (!policy->enabled || policy->operator_ca_bundle_path[0] == '\0')
        return EZTA_INTERNAL;

    x509_verifier_config_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    snprintf(cfg.ca_bundle_path, sizeof(cfg.ca_bundle_path), "%s",
             policy->operator_ca_bundle_path);
    snprintf(cfg.ocsp_url, sizeof(cfg.ocsp_url), "%s", policy->ocsp_url);
    snprintf(cfg.crl_path, sizeof(cfg.crl_path), "%s", policy->crl_path);
    cfg.connect_timeout_ms = 2000;
    return x509_verifier_create(&cfg, out);
}
