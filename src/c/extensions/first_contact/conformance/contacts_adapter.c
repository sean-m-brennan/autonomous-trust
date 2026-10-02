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

#include "contacts_adapter.h"

#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <time.h>

#include <jansson.h>
#include <sodium.h>
#include <uuid/uuid.h>

#include "first_contact/backup.h"
#include "first_contact/contacts.h"
#include "first_contact/device.h"
#include "first_contact/siblings.h"
#include "first_contact/sync.h"
#include "first_contact/directory.h"
#include "identity/identity_priv.h"   /* public_identity_from_json */
#include "first_contact/net_registry.h"
#include "first_contact/net_hub.h"
#include "first_contact/area_card.h"

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


/* -- several devices, one human (FIRST_CONTACT_PLAN Phase 4) --------------- */
static const char *_device_status(int rc)
{
    return rc == AT_DEVICE_OK ? "ok" : at_device_reason(rc);
}

/* devices_of {contact uuid: [device uuids]} and resolves {uuid: contact uuid
 * | null} against @p store; a failure message into @p err, else "". */
static void _device_state(contacts_t *store, json_t *exp, char *err, size_t n)
{
    err[0] = '\0';
    const char *key;
    json_t *want;
    json_object_foreach(json_object_get(exp, "devices_of"), key, want) {
        contact_t *c = contacts_get(store, key);
        if (c == NULL) {
            snprintf(err, n, "no contact %s", key);
            return;
        }
        if (json_array_size(want) != c->devices_count) {
            snprintf(err, n, "%s: %zu devices, want %zu", key, c->devices_count,
                     json_array_size(want));
            return;
        }
        for (size_t i = 0; i < c->devices_count; i++)
            if (strcasecmp(c->devices[i].uuid, json_string_value(json_array_get(want, i))) != 0) {
                snprintf(err, n, "%s: device #%zu is %s", key, i, c->devices[i].uuid);
                return;
            }
    }
    json_object_foreach(json_object_get(exp, "resolves"), key, want) {
        contact_t *c = contacts_get(store, key);
        char got[UUID_STRING_LEN + 1] = "";
        if (c != NULL)
            uuid_unparse_lower(c->identity.uuid, got);
        bool ok = json_is_null(want) ? c == NULL
                                     : c != NULL && strcasecmp(got, json_string_value(want)) == 0;
        if (!ok) {
            snprintf(err, n, "%s resolves to %s", key, c != NULL ? got : "nothing");
            return;
        }
    }
}

/* Mirrors Python ContactsAdapter._device. */
static void _op_device(json_t *fx, json_t *exp, at_case_result_t *out)
{
    const char *mode = _sfield(fx, "mode");
    if (mode == NULL)
        FAILF("device: no mode");
    char err[256] = "";
    const char *status = "ok";
    contacts_t store;
    contacts_init(&store);
    bool have_store = false;
    at_dir_signed_t cert;
    memset(&cert, 0, sizeof(cert));
    json_t *cw = json_object_get(fx, "cert");
    int crc = cw != NULL ? at_dir_from_wire(cw, &cert) : AT_DIR_MALFORMED;
    public_identity_t ident;
    memset(&ident, 0, sizeof(ident));
    json_t *ij = json_object_get(fx, "identity");
    bool have_ident = ij != NULL && public_identity_from_json(ij, &ident) == 0;

    if (strcmp(mode, "verify") == 0) {
        int rc = crc == AT_DIR_OK ? at_device_cert_verify(&cert) : AT_DEVICE_MALFORMED;
        status = _device_status(rc);
        const char *op = _sfield(exp, "operator");
        if (rc == AT_DEVICE_OK && op != NULL && strcmp(at_device_cert_operator(&cert), op) != 0)
            snprintf(err, sizeof(err), "operator %s", at_device_cert_operator(&cert));
        json_t *names = json_object_get(exp, "names");
        if (rc == AT_DEVICE_OK && names != NULL
            && (!have_ident || at_device_cert_names(&cert, &ident) != json_is_true(names)))
            snprintf(err, sizeof(err), "names");
    } else if (strcmp(mode, "adopt") == 0) {
        contact_t c;
        if (contact_from_json(json_object_get(fx, "contact"), &c) != 0) {
            snprintf(err, sizeof(err), "contact did not parse");
        } else {
            if (json_object_get(fx, "store") != NULL)
                have_store = contacts_from_json(json_object_get(fx, "store"), &store) == 0;
            int rc = crc == AT_DIR_OK ? at_adopt_operator(&c, &cert, have_store ? &store : NULL)
                                      : AT_DEVICE_MALFORMED;
            status = _device_status(rc);
            const char *want = _sfield(exp, "operator_key");
            if (want != NULL && strcmp(c.operator_key, want) != 0)
                snprintf(err, sizeof(err), "operator_key %s", c.operator_key);
            contact_free(&c);
        }
    } else if (strcmp(mode, "link") == 0 || strcmp(mode, "load") == 0) {
        have_store = contacts_from_json(json_object_get(fx, "store"), &store) == 0;
        if (!have_store)
            snprintf(err, sizeof(err), "store did not parse");
        else if (mode[1] == 'i') {
            int rc = !have_ident ? AT_DEVICE_MALFORMED
                   : crc == AT_DIR_OK ? at_link_device(&store, &ident, &cert, NULL)
                                      : AT_DEVICE_MALFORMED;
            status = _device_status(rc);
        }
    } else {
        snprintf(err, sizeof(err), "unknown device mode %s", mode);
    }
    const char *want = _sfield(exp, "device_status");
    if (err[0] == '\0' && want != NULL && strcmp(status, want) != 0)
        snprintf(err, sizeof(err), "device_status: got %s want %s", status, want);
    if (err[0] == '\0' && have_store)
        _device_state(&store, exp, err, sizeof(err));
    if (err[0] == '\0' && have_store && mode[0] == 'l') {
        /* The file form survives a round trip unchanged. */
        json_t *a = NULL, *b = NULL;
        contacts_t again;
        contacts_init(&again);
        if (contacts_to_json(&store, &a) != 0 || contacts_from_json(a, &again) != 0
            || contacts_to_json(&again, &b) != 0 || !json_equal(a, b))
            snprintf(err, sizeof(err), "store round trip");
        json_decref(a);
        json_decref(b);
        contacts_free(&again);
    }
    at_dir_free(&cert);
    free(ident.operator_key_binding);
    contacts_free(&store);
    if (err[0] != '\0')
        FAILF("device: %s", err);
    at_case_result_set_pass(out, 0);
}

/* -- live pairing: one address book across devices (Phase 4) -------------- */

/* Numbers equal by value (1 == 1.0, as in Python), arrays element-wise,
 * anything else by json_equal. */
static bool _same(json_t *a, json_t *b)
{
    if (json_is_number(a) && json_is_number(b))
        return fabs(json_number_value(a) - json_number_value(b)) < 1e-9;
    if (json_is_array(a) && json_is_array(b)) {
        if (json_array_size(a) != json_array_size(b))
            return false;
        for (size_t i = 0; i < json_array_size(a); i++)
            if (!_same(json_array_get(a, i), json_array_get(b, i)))
                return false;
        return true;
    }
    return json_equal(a, b);
}

static const char *const _SYNC_FIELDS[] = {
    "petname", "verified", "verified_at", "provenance", "trust_seed",
    "reach_seq", "rendezvous", "updated_at", "operator_key", NULL};

static bool _sync_field(const char *k)
{
    for (int i = 0; _SYNC_FIELDS[i] != NULL; i++)
        if (strcmp(_SYNC_FIELDS[i], k) == 0)
            return true;
    return false;
}

/* The book pins a sync or a restore shares (Python _check_book): changes,
 * contacts, devices_of, tombstones, and a clean round trip. Leaves @p err
 * alone when it already says something. */
static void _check_book(contacts_t *store, json_t *exp, json_t *changes, char *err,
                        size_t n_err)
{
    json_t *wc = json_object_get(exp, "changes");
    if (err[0] == '\0' && wc != NULL && !json_equal(wc, changes)) {
        char *got = json_dumps(changes, JSON_COMPACT);
        snprintf(err, n_err, "changes %s", got != NULL ? got : "?");
        free(got);
    }
    const char *key;
    json_t *w;
    json_object_foreach(json_object_get(exp, "contacts"), key, w) {
        if (err[0] != '\0')
            break;
        contact_t *c = contacts_get_first(store, key);
        if (json_is_null(w)) {
            if (c != NULL)
                snprintf(err, n_err, "contact %s still here", key);
            continue;
        }
        if (c == NULL) {
            snprintf(err, n_err, "no contact %s", key);
            continue;
        }
        json_t *got = NULL;
        contact_to_json(c, &got);
        if (json_object_get(got, "updated_at") == NULL)
            json_object_set_new(got, "updated_at", json_real(0.0));
        if (json_object_get(got, "reach_seq") == NULL)
            json_object_set_new(got, "reach_seq", json_integer(0));
        if (json_object_get(got, "operator_key") == NULL)
            json_object_set_new(got, "operator_key", json_string(""));
        const char *k;
        json_t *v;
        json_object_foreach(w, k, v) {
            if (!_sync_field(k)) {
                snprintf(err, n_err, "unknown field %s", k);
                break;
            }
            if (!_same(json_object_get(got, k), v)) {
                snprintf(err, n_err, "%s.%s differs", key, k);
                break;
            }
        }
        json_decref(got);
    }
    if (err[0] == '\0')
        _device_state(store, exp, err, n_err);
    json_t *wt = json_object_get(exp, "tombstones");
    if (err[0] == '\0' && wt != NULL) {
        bool ok = json_object_size(wt) == store->tombstones_count;
        for (size_t i = 0; ok && i < store->tombstones_count; i++) {
            json_t *at = json_object_get(wt, store->tombstones[i].uuid);
            ok = at != NULL && json_is_number(at)
                 && fabs(json_number_value(at) - store->tombstones[i].at) < 1e-9;
        }
        if (!ok)
            snprintf(err, n_err, "tombstones differ (%zu here)", store->tombstones_count);
    }
    if (err[0] == '\0') {
        json_t *a = NULL, *b = NULL;
        contacts_t again;
        contacts_init(&again);
        if (contacts_to_json(store, &a) != 0 || contacts_from_json(a, &again) != 0
            || contacts_to_json(&again, &b) != 0 || !json_equal(a, b))
            snprintf(err, n_err, "store round trip");
        json_decref(a);
        json_decref(b);
        contacts_free(&again);
    }
}

/* Mirrors Python ContactsAdapter._sync. */
static void _op_sync(json_t *fx, json_t *exp, at_case_result_t *out)
{
    char err[256] = "";
    contacts_t store;
    json_t *sj = json_object_get(fx, "store");
    if (sj != NULL)
        contacts_from_json(sj, &store);
    else
        contacts_init(&store);
    double now = _dfield(fx, "now", 0.0);
    json_t *exj = json_object_get(fx, "exclude");
    size_t n_ex = json_array_size(exj);
    const char **ex = calloc(n_ex ? n_ex : 1, sizeof(char *));
    for (size_t i = 0; i < n_ex; i++)
        ex[i] = json_string_value(json_array_get(exj, i));
    json_t *payloads = json_object_get(fx, "payloads");
    json_t *one = NULL;
    if (payloads == NULL) {
        one = json_array();
        json_array_append(one, json_object_get(fx, "payload"));
        payloads = one;
    }
    const char *status = "ok";
    json_t *changes = json_array();
    for (size_t p = 0; p < json_array_size(payloads); p++) {
        at_sync_change_t *ch = NULL;
        size_t n = 0;
        if (at_sync_merge(&store, json_array_get(payloads, p), now, ex, n_ex, &ch, &n) != 0) {
            status = "invalid";
            break;
        }
        for (size_t i = 0; i < n; i++)
            json_array_append_new(changes, json_pack("[s, s]", ch[i].uuid,
                                                     at_sync_action_str(ch[i].action)));
        free(ch);
    }
    json_decref(one);
    free(ex);

    const char *want = _sfield(exp, "sync_status");
    if (want != NULL && strcmp(status, want) != 0)
        snprintf(err, sizeof(err), "sync_status: got %s want %s", status, want);
    _check_book(&store, exp, changes, err, sizeof(err));
    json_decref(changes);
    contacts_free(&store);
    if (err[0] != '\0')
        FAILF("sync: %s", err);
    at_case_result_set_pass(out, 0);
}

static const char *_backup_status(int rc)
{
    return rc == AT_BACKUP_OK ? "ok" : at_backup_reason_str(rc);
}

static bool _status_is(json_t *exp, const char *key, const char *got, char *err, size_t n)
{
    const char *want = _sfield(exp, key);
    if (want == NULL)
        want = "ok";
    if (strcmp(got, want) != 0) {
        snprintf(err, n, "%s: got %s want %s", key, got, want);
        return false;
    }
    return true;
}

/* Mirrors Python ContactsAdapter._backup. */
static void _op_backup(json_t *fx, json_t *exp, at_case_result_t *out)
{
    char err[256] = "";
    const char *mode = _sfield(fx, "mode");
    if (mode == NULL)
        FAILF("backup: no mode");
    if (strcmp(mode, "seal") == 0) {
        uint8_t salt[AT_BACKUP_SALT_BYTES], nonce[AT_BACKUP_NONCE_BYTES];
        size_t got = 0;
        const char *sh = _sfield(fx, "salt"), *nh = _sfield(fx, "nonce");
        if (sh == NULL || nh == NULL ||
            sodium_hex2bin(salt, sizeof(salt), sh, strlen(sh), NULL, &got, NULL) != 0 ||
            got != sizeof(salt) ||
            sodium_hex2bin(nonce, sizeof(nonce), nh, strlen(nh), NULL, &got, NULL) != 0 ||
            got != sizeof(nonce))
            FAILF("backup seal: bad salt or nonce fixture");
        const char *pt = _sfield(fx, "plaintext");
        json_t *blob = NULL;
        int rc = at_backup_seal_bytes((const uint8_t *)pt, pt != NULL ? strlen(pt) : 0,
                                      _sfield(fx, "passphrase"),
                                      (unsigned long long)_dfield(fx, "ops", 0),
                                      (size_t)_dfield(fx, "mem", 0), salt, nonce, &blob);
        if (_status_is(exp, "backup_status", _backup_status(rc), err, sizeof(err))) {
            const char *ct = _sfield(exp, "ct");
            if (ct != NULL && strcmp(ct, json_string_value(json_object_get(blob, "ct"))) != 0)
                snprintf(err, sizeof(err), "ct differs");
            const char *want_ad = _sfield(exp, "ad");
            char ad[256];
            if (err[0] == '\0' && want_ad != NULL &&
                (at_backup_header_ad(
                     (unsigned long long)json_integer_value(json_object_get(blob, "ops")),
                     (size_t)json_integer_value(json_object_get(blob, "mem")),
                     json_string_value(json_object_get(blob, "salt")),
                     json_string_value(json_object_get(blob, "nonce")), ad, sizeof(ad)) < 0 ||
                 strcmp(ad, want_ad) != 0))
                snprintf(err, sizeof(err), "ad differs");
        }
        json_decref(blob);
    } else if (strcmp(mode, "open") == 0) {
        uint8_t *pt = NULL;
        size_t n = 0;
        const char *pass = _sfield(fx, "passphrase");
        const char *text = _sfield(fx, "text");
        int rc = text != NULL ? at_backup_open_text(text, pass != NULL ? pass : "", &pt, &n)
                              : at_backup_open_bytes(json_object_get(fx, "blob"),
                                                     pass != NULL ? pass : "", &pt, &n);
        if (_status_is(exp, "backup_status", _backup_status(rc), err, sizeof(err))) {
            const char *want = _sfield(exp, "plaintext");
            if (want != NULL && (pt == NULL || strlen(want) != n || memcmp(pt, want, n) != 0))
                snprintf(err, sizeof(err), "plaintext differs");
        }
        free(pt);
    } else if (strcmp(mode, "passphrase") == 0) {
        const char *pass = _sfield(fx, "passphrase");
        if (_status_is(exp, "passphrase_status",
                       _backup_status(at_backup_check_passphrase(pass)), err, sizeof(err))) {
            const char *want = _sfield(exp, "normalized");
            char norm[512];
            at_backup_normalize_passphrase(pass, norm, sizeof(norm));
            if (want != NULL && strcmp(norm, want) != 0)
                snprintf(err, sizeof(err), "normalized: got %.200s", norm);
        }
    } else if (strcmp(mode, "restore") == 0) {
        contacts_t store;
        json_t *sj = json_object_get(fx, "store");
        if (sj != NULL)
            contacts_from_json(sj, &store);
        else
            contacts_init(&store);
        at_sync_change_t *ch = NULL;
        size_t n = 0;
        const char *own = _sfield(fx, "own_uuid");
        int rc = at_backup_restore(&store, NULL, json_object_get(fx, "contents"), NULL,
                                   own != NULL ? own : "", _dfield(fx, "now", 0.0), &ch, &n,
                                   NULL, NULL);
        json_t *changes = json_array();
        for (size_t i = 0; i < n; i++)
            json_array_append_new(changes, json_pack("[s, s]", ch[i].uuid,
                                                     at_sync_action_str(ch[i].action)));
        free(ch);
        if (_status_is(exp, "backup_status", _backup_status(rc), err, sizeof(err)))
            _check_book(&store, exp, changes, err, sizeof(err));
        json_decref(changes);
        contacts_free(&store);
    } else {
        FAILF("unknown backup mode %s", mode);
    }
    if (err[0] != '\0')
        FAILF("backup: %s", err);
    at_case_result_set_pass(out, 0);
}

/* Mirrors Python ContactsAdapter._siblings. */
static void _op_siblings(json_t *fx, json_t *exp, at_case_result_t *out)
{
    char err[256] = "";
    const char *mode = _sfield(fx, "mode");
    at_siblings_t sib;
    at_siblings_from_json(json_object_get(fx, "siblings"), &sib);
    const char *status = "ok";
    if (mode != NULL && strcmp(mode, "add") == 0) {
        public_identity_t ident;
        memset(&ident, 0, sizeof(ident));
        if (public_identity_from_json(json_object_get(fx, "identity"), &ident) != 0) {
            snprintf(err, sizeof(err), "identity did not parse");
        } else {
            at_dir_signed_t cert, own;
            memset(&cert, 0, sizeof(cert));
            memset(&own, 0, sizeof(own));
            json_t *ow = json_object_get(fx, "own_cert");
            bool have_own = ow != NULL && at_dir_from_wire(ow, &own) == AT_DIR_OK;
            int rc = at_dir_from_wire(json_object_get(fx, "cert"), &cert) != AT_DIR_OK
                         ? (have_own && at_device_cert_verify(&own) == AT_DEVICE_OK
                                ? AT_DEVICE_MALFORMED : AT_DEVICE_UNKNOWN_OPERATOR)
                         : at_siblings_add(&sib, &ident, &cert, have_own ? &own : NULL);
            status = _device_status(rc);
            at_dir_free(&cert);
            at_dir_free(&own);
        }
        free(ident.operator_key_binding);
    } else if (mode == NULL || strcmp(mode, "load") != 0) {
        snprintf(err, sizeof(err), "unknown siblings mode %s", mode != NULL ? mode : "?");
    }
    const char *want = _sfield(exp, "sibling_status");
    if (err[0] == '\0' && want != NULL && strcmp(status, want) != 0)
        snprintf(err, sizeof(err), "sibling_status: got %s want %s", status, want);
    json_t *ws = json_object_get(exp, "siblings");
    if (err[0] == '\0' && ws != NULL) {
        bool ok = json_array_size(ws) == sib.count;
        for (size_t i = 0; ok && i < sib.count; i++)
            ok = strcmp(sib.devices[i].uuid, json_string_value(json_array_get(ws, i))) == 0;
        if (!ok)
            snprintf(err, sizeof(err), "siblings differ (%zu here)", sib.count);
    }
    const char *wo = _sfield(exp, "operator");
    if (err[0] == '\0' && wo != NULL && strcmp(sib.operator_key, wo) != 0)
        snprintf(err, sizeof(err), "operator %s", sib.operator_key);
    if (err[0] == '\0') {
        json_t *a = at_siblings_to_json(&sib), *b = NULL;
        at_siblings_t again;
        at_siblings_from_json(a, &again);
        b = at_siblings_to_json(&again);
        if (!json_equal(a, b))
            snprintf(err, sizeof(err), "siblings round trip");
        json_decref(a);
        json_decref(b);
        at_siblings_free(&again);
    }
    at_siblings_free(&sib);
    if (err[0] != '\0')
        FAILF("siblings: %s", err);
    at_case_result_set_pass(out, 0);
}

/* -- the directory (FIRST_CONTACT_PLAN Phase 3) ---------------------------- */
static const char *const _DIR_REASONS[] = {"ok", "malformed", "bad_signature", "expired",
                                           "untrusted", "mismatch"};

/* Mirrors Python ContactsAdapter._dir_verify. */
static void _op_dir_verify(json_t *fx, json_t *exp, at_case_result_t *out)
{
    const char *what = _sfield(fx, "what");
    double now = _dfield(fx, "now", 0.0);
    json_t *tr = json_object_get(fx, "trusted");
    const char *trusted[16];
    size_t n_trusted = 0;
    for (size_t i = 0; json_is_array(tr) && i < json_array_size(tr) && i < 16; i++)
        trusted[n_trusted++] = json_string_value(json_array_get(tr, i));
    const char *const *tp = json_is_array(tr) ? trusted : NULL;
    if (what == NULL)
        FAILF("dir_verify: no what");
    at_dir_signed_t obj;
    int rc = at_dir_from_wire(json_object_get(fx, "wire"), &obj);
    if (rc == AT_DIR_OK) {
        if (strcmp(what, "entry") == 0)
            rc = at_dir_entry_verify(&obj, tp, n_trusted, now);
        else if (strcmp(what, "attestation") == 0)
            rc = at_dir_attest_verify(&obj, tp, n_trusted, now);
        else if (strcmp(what, "request") == 0)
            rc = at_dir_request_verify(&obj, now);
        else if (strcmp(what, "area_card") == 0)
            rc = at_area_card_verify(&obj, now);
        else {
            at_dir_free(&obj);
            FAILF("dir_verify: unknown what %s", what);
        }
    }
    const char *status = rc <= 0 && rc >= AT_DIR_MISMATCH ? _DIR_REASONS[-rc] : "?";
    const char *want = _sfield(exp, "dir_status");
    if (want == NULL || strcmp(status, want) != 0) {
        at_dir_free(&obj);
        FAILF("dir_verify: got %s want %s", status, want ? want : "(none)");
    }
    if (rc == AT_DIR_OK) {
        const char *h = _sfield(exp, "handle");
        if (h != NULL && (at_dir_handle(&obj) == NULL || strcmp(at_dir_handle(&obj), h) != 0)) {
            at_dir_free(&obj);
            FAILF("dir_verify: handle mismatch");
        }
        json_t *seq = json_object_get(exp, "seq");
        if (json_is_integer(seq) && at_dir_seq(&obj) != (int64_t)json_integer_value(seq)) {
            at_dir_free(&obj);
            FAILF("dir_verify: seq %lld want %lld", (long long)at_dir_seq(&obj),
                  (long long)json_integer_value(seq));
        }
        const char *u = _sfield(exp, "uuid");
        const char *got_u = strcmp(what, "request") == 0 ? at_dir_request_from(&obj)
                                                         : at_dir_uuid(&obj);
        if (u != NULL && (got_u == NULL || strcasecmp(got_u, u) != 0)) {
            at_dir_free(&obj);
            FAILF("dir_verify: uuid mismatch");
        }
        const char *fields[] = {"area", "bucket"};
        for (size_t f = 0; f < 2; f++) {
            const char *w = _sfield(exp, fields[f]);
            const char *g = json_string_value(json_object_get(obj.body, fields[f]));
            if (w != NULL && (g == NULL || strcmp(g, w) != 0)) {
                at_dir_free(&obj);
                FAILF("dir_verify: %s mismatch", fields[f]);
            }
        }
    }
    at_dir_free(&obj);
    at_case_result_set_pass(out, 0);
}

/* Mirrors Python ContactsAdapter._dir_normalize. */
static void _op_dir_normalize(json_t *fx, json_t *exp, at_case_result_t *out)
{
    json_t *in = json_object_get(fx, "handles");
    json_t *want = json_object_get(exp, "folded");
    if (!json_is_array(in) || !json_is_array(want) || json_array_size(in) != json_array_size(want))
        FAILF("dir_normalize: handles/folded missing or of different lengths");
    for (size_t i = 0; i < json_array_size(in); i++) {
        char folded[AT_DIR_HANDLE_MAX + 1];
        const char *h = json_string_value(json_array_get(in, i));
        bool ok = h != NULL && at_dir_normalize_handle(h, folded, sizeof(folded)) == 0;
        json_t *w = json_array_get(want, i);
        if (json_is_null(w) ? ok : (!ok || strcmp(folded, json_string_value(w)) != 0))
            FAILF("dir_normalize: #%zu got %s", i, ok ? folded : "null");
    }
    at_case_result_set_pass(out, 0);
}

static double g_reg_mono, g_reg_now;
static double _reg_mono(void) { return g_reg_mono; }
static double _reg_now(void) { return g_reg_now; }

static json_t *g_reg_distrusted;
static bool _reg_distrust(void *arg, const char *uuid, const char *key)
{
    (void)arg;
    (void)key;
    for (size_t i = 0; json_is_array(g_reg_distrusted) && i < json_array_size(g_reg_distrusted); i++) {
        const char *d = json_string_value(json_array_get(g_reg_distrusted, i));
        if (d != NULL && strcasecmp(d, uuid) == 0)
            return true;
    }
    return false;
}

/* Mirrors Python ContactsAdapter._registry. */
static void _op_registry(json_t *fx, json_t *exp, at_case_result_t *out)
{
    json_t *iss = json_object_get(fx, "issuers");
    const char *issuers[16];
    size_t n = 0;
    for (size_t i = 0; json_is_array(iss) && i < json_array_size(iss) && i < 16; i++)
        issuers[n++] = json_string_value(json_array_get(iss, i));
    json_t *rate = json_object_get(fx, "rate");
    net_registry_t *reg = net_registry_new(issuers, n,
                                           json_is_integer(rate) ? (int)json_integer_value(rate) : 10);
    if (reg == NULL)
        FAILF("registry: could not create");
    g_reg_mono = 0.0;
    g_reg_now = _dfield(fx, "now", 0.0);
    g_reg_distrusted = json_object_get(fx, "distrusted");
    net_registry_set_clocks(reg, _reg_mono, _reg_now);
    net_registry_set_distrust(reg, _reg_distrust, NULL);
    json_t *clients = json_object_get(fx, "clients");
    json_t *calls = json_object_get(fx, "calls");
    json_t *replies = json_array();
    size_t i;
    json_t *call;
    json_array_foreach(calls, i, call) {
        g_reg_mono += _dfield(call, "advance", 0.0);
        json_t *who = json_object_get(clients, _sfield(call, "as"));
        const char *uu = _sfield(who, "uuid"), *key = _sfield(who, "key");
        const char *kind = _sfield(call, "call");
        json_t *r = NULL;
        if (uu == NULL || key == NULL || kind == NULL)
            r = json_pack("{s:s}", "op", "bad_call");
        else if (strcmp(kind, "publish") == 0)
            r = net_registry_publish(reg, uu, key, json_object_get(call, "entry"));
        else if (strcmp(kind, "withdraw") == 0)
            r = net_registry_withdraw(reg, uu, key, _sfield(call, "handle"));
        else
            r = net_registry_lookup(reg, uu, _sfield(call, "handle"));
        json_t *got = json_object();
        json_object_set(got, "op", json_object_get(r, "op"));
        json_object_set_new(got, "handle", json_string(_sfield(r, "handle") ? _sfield(r, "handle") : ""));
        if (json_object_get(r, "reason") != NULL)
            json_object_set(got, "reason", json_object_get(r, "reason"));
        if (json_object_get(r, "seq") != NULL)
            json_object_set(got, "seq", json_object_get(r, "seq"));
        const char *op = _sfield(r, "op");
        if (op != NULL && strcmp(op, "dir_entry") == 0)
            json_object_set_new(got, "found", json_boolean(json_is_object(json_object_get(r, "entry"))));
        json_array_append_new(replies, got);
        json_decref(r);
    }
    net_registry_free(reg);
    json_t *want = json_object_get(exp, "replies");
    bool same = json_equal(replies, want);
    if (!same) {
        char *g = json_dumps(replies, JSON_COMPACT);
        char detail[256];
        snprintf(detail, sizeof(detail), "registry: replies %.200s", g ? g : "?");
        free(g);
        json_decref(replies);
        at_case_result_set_fail(out, 0, "AssertionError", detail);
        return;
    }
    json_decref(replies);
    at_case_result_set_pass(out, 0);
}

/* Mirrors Python ContactsAdapter._hub. */
static void _op_hub(json_t *fx, json_t *exp, at_case_result_t *out)
{
    json_t *ja = json_object_get(fx, "areas");
    const char *areas[AT_HUB_MAX_AREAS];
    size_t n = 0;
    for (size_t i = 0; json_is_array(ja) && i < json_array_size(ja) && n < AT_HUB_MAX_AREAS; i++)
        areas[n++] = json_string_value(json_array_get(ja, i));
    json_t *rate = json_object_get(fx, "rate");
    net_hub_t *hub = net_hub_new(areas, n, json_is_integer(rate) ? (int)json_integer_value(rate) : 10);
    if (hub == NULL)
        FAILF("hub: could not create");
    g_reg_mono = 0.0;
    g_reg_now = _dfield(fx, "now", 0.0);
    g_reg_distrusted = json_object_get(fx, "distrusted");
    net_hub_set_clocks(hub, _reg_mono, _reg_now);
    net_hub_set_distrust(hub, _reg_distrust, NULL);
    json_t *clients = json_object_get(fx, "clients");
    json_t *calls = json_object_get(fx, "calls");
    json_t *replies = json_array();
    size_t i;
    json_t *call;
    json_array_foreach(calls, i, call) {
        g_reg_mono += _dfield(call, "advance", 0.0);
        json_t *who = json_object_get(clients, _sfield(call, "as"));
        const char *uu = _sfield(who, "uuid"), *key = _sfield(who, "key");
        const char *kind = _sfield(call, "call");
        json_t *r = NULL;
        if (uu == NULL || key == NULL || kind == NULL)
            r = json_pack("{s:s}", "op", "bad_call");
        else if (strcmp(kind, "publish") == 0)
            r = net_hub_publish(hub, uu, key, json_object_get(call, "card"));
        else if (strcmp(kind, "withdraw") == 0)
            r = net_hub_withdraw(hub, uu, key, _sfield(call, "area"));
        else
            r = net_hub_lookup(hub, uu, _sfield(call, "area"));
        json_t *got = json_object();
        json_object_set(got, "op", json_object_get(r, "op"));
        json_object_set_new(got, "area", json_string(_sfield(r, "area") ? _sfield(r, "area") : ""));
        if (json_object_get(r, "reason") != NULL)
            json_object_set(got, "reason", json_object_get(r, "reason"));
        if (json_object_get(r, "seq") != NULL)
            json_object_set(got, "seq", json_object_get(r, "seq"));
        const char *op = _sfield(r, "op");
        if (op != NULL && strcmp(op, "hub_cards") == 0) {
            json_t *uuids = json_array();
            size_t k;
            json_t *c;
            json_array_foreach(json_object_get(r, "cards"), k, c) {
                at_dir_signed_t card;
                if (at_dir_from_wire(c, &card) == AT_DIR_OK) {
                    char low[UUID_STR_LEN + 1];
                    snprintf(low, sizeof(low), "%s", at_dir_uuid(&card) ? at_dir_uuid(&card) : "");
                    for (char *ch = low; *ch != '\0'; ch++)
                        if (*ch >= 'A' && *ch <= 'Z')
                            *ch = (char)(*ch + 32);
                    json_array_append_new(uuids, json_string(low));
                    at_dir_free(&card);
                }
            }
            json_object_set_new(got, "cards", uuids);
        }
        json_array_append_new(replies, got);
        json_decref(r);
    }
    net_hub_free(hub);
    json_t *want = json_object_get(exp, "replies");
    bool same = json_equal(replies, want);
    if (!same) {
        char *g = json_dumps(replies, JSON_COMPACT);
        char detail[256];
        snprintf(detail, sizeof(detail), "hub: replies %.200s", g ? g : "?");
        free(g);
        json_decref(replies);
        at_case_result_set_fail(out, 0, "AssertionError", detail);
        return;
    }
    json_decref(replies);
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
    else if (strcmp(op, "dir_verify") == 0)
        _op_dir_verify(fx, exp, out);
    else if (strcmp(op, "dir_normalize") == 0)
        _op_dir_normalize(fx, exp, out);
    else if (strcmp(op, "registry") == 0)
        _op_registry(fx, exp, out);
    else if (strcmp(op, "hub") == 0)
        _op_hub(fx, exp, out);
    else if (strcmp(op, "device") == 0)
        _op_device(fx, exp, out);
    else if (strcmp(op, "sync") == 0)
        _op_sync(fx, exp, out);
    else if (strcmp(op, "siblings") == 0)
        _op_siblings(fx, exp, out);
    else if (strcmp(op, "backup") == 0)
        _op_backup(fx, exp, out);
    else {
        char detail[160];
        snprintf(detail, sizeof(detail), "unknown contacts op %s", op);
        at_case_result_set_fail(out, 0, "AssertionError", detail);
    }
}
