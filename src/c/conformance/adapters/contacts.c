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

/** @file Contacts / first-contact adapter (kind: scenario, protocol: contacts).
 *
 *  Twin of the Python ContactsAdapter. Reads fixtures.contacts.op, runs the
 *  production first-contact call (contacts/contacts.h), and asserts the pinned
 *  observables in expected_state.host. Both adapters must assert the same
 *  values -- the harnesses are diffed by case_id status.
 */

#include "contacts.h"

#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <jansson.h>
#include <uuid/uuid.h>

#include "contacts/contacts.h"
#include "identity/identity_priv.h"   /* public_identity_from_json */

#define FAILF(...)                                                        \
    do {                                                                  \
        char _d[256];                                                     \
        snprintf(_d, sizeof(_d), __VA_ARGS__);                            \
        at_case_result_set_fail(out, 0, "AssertionError", _d);            \
        return;                                                           \
    } while (0)

static const char *_sfield(json_t *o, const char *k)
{
    return json_string_value(json_object_get(o, k));
}

static bool _bfield(json_t *o, const char *k, bool dflt)
{
    json_t *v = json_object_get(o, k);
    if (json_is_true(v))
        return true;
    if (json_is_false(v))
        return false;
    return dflt;
}

static double _dfield(json_t *o, const char *k, double dflt)
{
    json_t *v = json_object_get(o, k);
    if (json_is_real(v))
        return json_real_value(v);
    if (json_is_integer(v))
        return (double)json_integer_value(v);
    return dflt;
}

static const char *_redeem_status_str(int rc)
{
    switch (rc) {
    case AT_INVITE_OK:
        return "ok";
    case AT_INVITE_BAD_SIG:
        return "bad_sig";
    case AT_INVITE_EXPIRED:
        return "expired";
    default:
        return "malformed";
    }
}

/* --- ops ----------------------------------------------------------------- */

static void _op_redeem(json_t *fx, json_t *exp, at_case_result_t *out)
{
    const char *blob = _sfield(fx, "blob");
    if (blob == NULL)
        FAILF("redeem: missing blob");
    bool in_person = _bfield(fx, "in_person", false);

    contact_t c;
    int rc = at_redeem_invitation(blob, in_person, (double)time(NULL), &c);

    const char *want_status = _sfield(exp, "redeem_status");
    if (want_status != NULL) {
        const char *got = _redeem_status_str(rc);
        if (rc == AT_INVITE_OK)
            contact_free(&c);
        if (strcmp(got, want_status) != 0)
            FAILF("redeem_status: got %s want %s", got, want_status);
        at_case_result_set_pass(out, 0);
        return;
    }

    if (rc != AT_INVITE_OK)
        FAILF("redeem failed rc=%d (%s)", rc, _redeem_status_str(rc));

    bool want_verified = _bfield(exp, "verified", false);
    if (c.verified != want_verified) {
        contact_free(&c);
        FAILF("verified: got %d want %d", (int)c.verified, (int)want_verified);
    }
    const char *want_prov = _sfield(exp, "provenance");
    if (want_prov != NULL && strcmp(at_provenance_str(c.provenance), want_prov) != 0) {
        contact_free(&c);
        FAILF("provenance: got %s want %s", at_provenance_str(c.provenance), want_prov);
    }
    double want_seed = _dfield(exp, "trust_seed", 0.0);
    if (fabs(c.trust_seed - want_seed) >= 1e-9) {
        contact_free(&c);
        FAILF("trust_seed: got %g want %g", c.trust_seed, want_seed);
    }
    const char *want_uuid = _sfield(exp, "uuid");
    if (want_uuid != NULL) {
        char uuid_s[UUID_STRING_LEN + 1];
        uuid_unparse(c.identity.uuid, uuid_s);
        if (strcmp(uuid_s, want_uuid) != 0) {
            contact_free(&c);
            FAILF("uuid: got %s want %s", uuid_s, want_uuid);
        }
    }
    const char *want_nick = _sfield(exp, "nickname");
    if (want_nick != NULL && strcmp(c.identity.nickname, want_nick) != 0) {
        contact_free(&c);
        FAILF("nickname: got %s want %s", c.identity.nickname, want_nick);
    }
    contact_free(&c);
    at_case_result_set_pass(out, 0);
}

static void _op_safety_number(json_t *fx, json_t *exp, at_case_result_t *out)
{
    json_t *ja = json_object_get(fx, "identity_a");
    json_t *jb = json_object_get(fx, "identity_b");
    public_identity_t a, b;
    if (public_identity_from_json(ja, &a) != 0)
        FAILF("safety_number: identity_a did not parse");
    if (public_identity_from_json(jb, &b) != 0) {
        if (a.operator_key_binding != NULL)
            free(a.operator_key_binding);
        FAILF("safety_number: identity_b did not parse");
    }
    char sn[AT_SAFETY_NUMBER_LEN];
    int rc = at_safety_number(&a, &b, sn, sizeof(sn));
    if (a.operator_key_binding != NULL)
        free(a.operator_key_binding);
    if (b.operator_key_binding != NULL)
        free(b.operator_key_binding);
    if (rc != 0)
        FAILF("safety_number: computation failed");
    const char *want = _sfield(exp, "safety_number");
    if (want == NULL || strcmp(sn, want) != 0)
        FAILF("safety_number: got %s want %s", sn, want ? want : "(none)");
    at_case_result_set_pass(out, 0);
}

static void _op_verify_contact(json_t *fx, json_t *exp, at_case_result_t *out)
{
    const char *blob = _sfield(fx, "blob");
    const char *presented = _sfield(fx, "presented");
    json_t *jb = json_object_get(fx, "identity_b");
    if (blob == NULL || presented == NULL)
        FAILF("verify_contact: missing blob/presented");

    contact_t c;
    int rc = at_redeem_invitation(blob, false, (double)time(NULL), &c);
    if (rc != AT_INVITE_OK)
        FAILF("verify_contact: redeem failed rc=%d", rc);

    public_identity_t me;
    if (public_identity_from_json(jb, &me) != 0) {
        contact_free(&c);
        FAILF("verify_contact: identity_b did not parse");
    }
    int vr = at_verify_contact(&c, presented, &me);
    if (me.operator_key_binding != NULL)
        free(me.operator_key_binding);

    const char *status = (vr == AT_INVITE_OK) ? "ok" : "mismatch";
    const char *want_status = _sfield(exp, "verify_status");
    if (want_status != NULL && strcmp(status, want_status) != 0) {
        contact_free(&c);
        FAILF("verify_status: got %s want %s", status, want_status);
    }
    bool want_verified = _bfield(exp, "verified", false);
    if (c.verified != want_verified) {
        contact_free(&c);
        FAILF("verified: got %d want %d", (int)c.verified, (int)want_verified);
    }
    double want_seed = _dfield(exp, "trust_seed", 0.0);
    if (fabs(c.trust_seed - want_seed) >= 1e-9) {
        contact_free(&c);
        FAILF("trust_seed: got %g want %g", c.trust_seed, want_seed);
    }
    contact_free(&c);
    at_case_result_set_pass(out, 0);
}

static void _op_store_roundtrip(json_t *fx, json_t *exp, at_case_result_t *out)
{
    json_t *store_j = json_object_get(fx, "store");
    contacts_t store;
    if (contacts_from_json(store_j, &store) != 0) {
        contacts_free(&store);
        FAILF("store_roundtrip: store did not parse");
    }
    long want_count = (long)_dfield(exp, "count", -1);
    if ((long)contacts_count(&store) != want_count) {
        long got = (long)contacts_count(&store);
        contacts_free(&store);
        FAILF("count: got %ld want %ld", got, want_count);
    }

    contact_t *a = contacts_get(&store, _sfield(exp, "a_uuid"));
    if (a == NULL) {
        contacts_free(&store);
        FAILF("store_roundtrip: contact a missing");
    }
    const char *ap = _sfield(exp, "a_petname");
    if (ap != NULL && strcmp(a->petname, ap) != 0) {
        contacts_free(&store);
        FAILF("a.petname: got %s want %s", a->petname, ap);
    }
    if (a->verified != _bfield(exp, "a_verified", false)) {
        contacts_free(&store);
        FAILF("a.verified: got %d", (int)a->verified);
    }
    const char *aprov = _sfield(exp, "a_provenance");
    if (aprov != NULL && strcmp(at_provenance_str(a->provenance), aprov) != 0) {
        contacts_free(&store);
        FAILF("a.provenance: got %s want %s", at_provenance_str(a->provenance), aprov);
    }
    if (fabs(a->trust_seed - _dfield(exp, "a_trust_seed", 0.0)) >= 1e-9) {
        contacts_free(&store);
        FAILF("a.trust_seed: got %g", a->trust_seed);
    }

    contact_t *b = contacts_get(&store, _sfield(exp, "b_uuid"));
    if (b == NULL) {
        contacts_free(&store);
        FAILF("store_roundtrip: contact b missing");
    }
    if (b->verified != _bfield(exp, "b_verified", false)) {
        contacts_free(&store);
        FAILF("b.verified: got %d", (int)b->verified);
    }
    if (fabs(b->trust_seed - _dfield(exp, "b_trust_seed", 0.0)) >= 1e-9) {
        contacts_free(&store);
        FAILF("b.trust_seed: got %g", b->trust_seed);
    }

    /* internal round-trip stability: to_json -> from_json preserves count */
    json_t *re = NULL;
    if (contacts_to_json(&store, &re) != 0) {
        contacts_free(&store);
        FAILF("store_roundtrip: re-serialize failed");
    }
    contacts_t store2;
    int rc = contacts_from_json(re, &store2);
    json_decref(re);
    size_t n2 = contacts_count(&store2);
    contacts_free(&store2);
    size_t n1 = contacts_count(&store);
    contacts_free(&store);
    if (rc != 0 || n2 != n1)
        FAILF("store_roundtrip: unstable re-parse (%zu vs %zu)", n2, n1);
    at_case_result_set_pass(out, 0);
}

void at_contacts_run(const at_case_t *c, at_case_result_t *out)
{
    if (strcmp(c->kind, "scenario") != 0) {
        char detail[160];
        snprintf(detail, sizeof(detail),
                 "C contacts adapter only handles kind:scenario (got %s)",
                 c->kind);
        at_case_result_set_skip(out, detail);
        return;
    }

    json_t *data = c->data;
    json_t *fixtures = json_object_get(data, "fixtures");
    json_t *fx = json_is_object(fixtures)
                     ? json_object_get(fixtures, "contacts") : NULL;
    if (!json_is_object(fx)) {
        at_case_result_set_fail(out, 0, "AssertionError",
                                "missing fixtures.contacts");
        return;
    }
    json_t *state = json_object_get(data, "expected_state");
    json_t *exp = json_is_object(state)
                      ? json_object_get(state, "host") : NULL;
    if (!json_is_object(exp))
        exp = json_object();   /* empty; asserts on absent keys are skipped */

    const char *op = _sfield(fx, "op");
    if (op == NULL) {
        at_case_result_set_fail(out, 0, "AssertionError",
                                "missing fixtures.contacts.op");
        return;
    }
    if (strcmp(op, "redeem") == 0)
        _op_redeem(fx, exp, out);
    else if (strcmp(op, "safety_number") == 0)
        _op_safety_number(fx, exp, out);
    else if (strcmp(op, "verify_contact") == 0)
        _op_verify_contact(fx, exp, out);
    else if (strcmp(op, "store_roundtrip") == 0)
        _op_store_roundtrip(fx, exp, out);
    else {
        char detail[160];
        snprintf(detail, sizeof(detail), "unknown contacts op %s", op);
        at_case_result_set_fail(out, 0, "AssertionError", detail);
    }
}
