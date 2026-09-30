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

/* One address book across a user's devices (contacts/sync) and the file of
 * those devices (contacts/siblings), FIRST_CONTACT_PLAN Phase 4 live pairing.
 * Mirrors Python tests/a_unit/test_contacts_sync.py. */

#define _GNU_SOURCE
#define DEBUG_TESTS 1
#include "test_setup.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <sodium.h>

#include "contacts/contacts.h"
#include "contacts/device.h"
#include "contacts/siblings.h"
#include "contacts/sync.h"
#include "identity/identity_priv.h"
#include "utilities/util.h"

#define NOW 1800000000.0
#define PUB(id) ((const public_identity_t *)(id))

static identity_t *_mk(const char *name)
{
    uuid_t u;
    uuid_generate(u);
    identity_t *id = NULL;
    ck_assert_ret_ok(identity_create(&u, "127.0.0.1", name, name, &id));
    return id;
}

static void _uuid(const identity_t *id, char out[UUID_STRING_LEN + 1])
{
    uuid_unparse_lower(id->uuid, out);
}

static void _operator(unsigned char seed_byte, unsigned char sk[crypto_sign_SECRETKEYBYTES])
{
    unsigned char seed[32], pk[crypto_sign_PUBLICKEYBYTES];
    memset(seed, seed_byte, sizeof(seed));
    crypto_sign_seed_keypair(pk, sk, seed);
}

static void _cert(const unsigned char *sk, const identity_t *id, at_dir_signed_t *out)
{
    ck_assert_int_eq(at_device_cert_create(sk, PUB(id), 1000, out), AT_DEVICE_OK);
}

/* A contact for @p id added at @p at (shallow: add it to a store, which
 * copies, and do not free it). */
static contact_t _contact(const identity_t *id, double at)
{
    contact_t c;
    memset(&c, 0, sizeof(c));
    c.identity = *PUB(id);
    c.identity.operator_key_binding = NULL;
    c.identity.operator_key_binding_len = 0;
    snprintf(c.petname, sizeof(c.petname), "%.100s-pet", id->nickname);
    c.provenance = AT_PROV_TOKEN;
    c.added_at = at;
    return c;
}

static contact_t *_get(contacts_t *s, const identity_t *id)
{
    char u[UUID_STRING_LEN + 1];
    _uuid(id, u);
    return contacts_get(s, u);
}

/* Merge @p from's full payload into @p into; the number of changes. */
static size_t _merge(contacts_t *into, const contacts_t *from, double now,
                     at_sync_change_t **changes)
{
    json_t *p = at_sync_build(from, NULL, 0);
    ck_assert_ptr_nonnull(p);
    size_t n = 0;
    at_sync_change_t *ch = NULL;
    ck_assert_ret_ok(at_sync_merge(into, p, now, NULL, 0, &ch, &n));
    json_decref(p);
    if (changes != NULL)
        *changes = ch;
    else
        free(ch);
    return n;
}

/* What should agree between siblings: everything but provenance and
 * reachability, as canonical text. malloc'd. */
static char *_book(const contacts_t *s)
{
    json_t *root = NULL;
    ck_assert_ret_ok(contacts_to_json(s, &root));
    const char *k;
    json_t *v;
    json_object_foreach(json_object_get(root, "contacts"), k, v) {
        json_object_del(v, "provenance");
        json_object_del(v, "reach_seq");
        json_object_del(v, "rendezvous");
    }
    char *out = json_dumps(root, JSON_SORT_KEYS | JSON_COMPACT);
    json_decref(root);
    return out;
}

/* -- the stored form ------------------------------------------------------- */

DEFINE_TEST(test_the_stored_form)
{
    identity_t *bob = _mk("bob");
    char bu[UUID_STRING_LEN + 1];
    _uuid(bob, bu);
    contacts_t s;
    contacts_init(&s);
    contact_t c = _contact(bob, NOW - 1000);
    contact_mark_verified(&c, 0.3);
    ck_assert_ret_ok(contacts_add(&s, &c));

    /* Never edited: neither key written. */
    json_t *root = NULL;
    ck_assert_ret_ok(contacts_to_json(&s, &root));
    ck_assert_ptr_null(json_object_get(root, "tombstones"));
    ck_assert_ptr_null(json_object_get(json_object_get(json_object_get(root, "contacts"), bu),
                                       "updated_at"));
    json_decref(root);

    /* A rename dates it, and touch never goes back. */
    contact_t *got = contacts_get(&s, bu);
    contact_touch(got, NOW);
    ck_assert(contact_version(got) >= NOW && contact_version(got) <= NOW);
    contact_touch(got, NOW - 50);
    ck_assert(got->updated_at >= NOW);
    ck_assert_ret_ok(contacts_to_json(&s, &root));
    contacts_t back;
    ck_assert_ret_ok(contacts_from_json(root, &back));
    ck_assert(contacts_get(&back, bu)->updated_at >= NOW);
    contacts_free(&back);
    json_decref(root);

    /* Removal leaves a tombstone never older than what it removed; it
     * survives the file; adding again lifts it. */
    ck_assert(contacts_remove_at(&s, bu, NOW - 500));
    ck_assert(contacts_tombstone(&s, bu) >= NOW);
    ck_assert_ret_ok(contacts_to_json(&s, &root));
    ck_assert_ret_ok(contacts_from_json(root, &back));
    ck_assert(contacts_tombstone(&back, bu) >= NOW);
    contacts_free(&back);
    json_decref(root);
    contact_t again = _contact(bob, NOW + 1);
    ck_assert_ret_ok(contacts_add(&s, &again));
    ck_assert(contacts_tombstone(&s, bu) < 0.0);

    /* Malformed tombstones, or one for a live contact, do not load. */
    root = json_pack("{s:s, s:i, s:{}, s:{s:i, s:s, s:b, s:f}}", "typename", "contacts",
                     "version", 1, "contacts", "tombstones",
                     "00000000-0000-4000-8000-000000000001", -1,
                     "00000000-0000-4000-8000-000000000002", "x",
                     "00000000-0000-4000-8000-000000000003", 1,
                     "00000000-0000-4000-8000-00000000000A", NOW);
    ck_assert_ret_ok(contacts_from_json(root, &back));
    ck_assert_uint_eq(back.tombstones_count, 0);
    contacts_free(&back);
    json_decref(root);
    ck_assert_ret_ok(contacts_to_json(&s, &root));
    json_object_set_new(root, "tombstones", json_pack("{s:f}", bu, NOW));
    ck_assert_ret_ok(contacts_from_json(root, &back));
    ck_assert_uint_eq(back.tombstones_count, 0);
    contacts_free(&back);
    json_decref(root);

    contacts_free(&s);
    identity_free(bob);
}
END_TEST_DEFINITION()

/* -- merge ----------------------------------------------------------------- */

DEFINE_TEST(test_new_newer_older_and_ties)
{
    identity_t *bob = _mk("bob");
    char bu[UUID_STRING_LEN + 1];
    _uuid(bob, bu);

    /* New here: a sibling contact, verification and all. */
    contacts_t there, here;
    contacts_init(&there);
    contacts_init(&here);
    contact_t c = _contact(bob, NOW - 1000);
    contact_mark_verified(&c, 0.3);
    c.verified_at = NOW - 10;
    contacts_add(&there, &c);
    at_sync_change_t *ch = NULL;
    ck_assert_uint_eq(_merge(&here, &there, NOW, &ch), 1);
    ck_assert_str_eq(ch[0].uuid, bu);
    ck_assert_int_eq(ch[0].action, AT_SYNC_ADDED);
    free(ch);
    contact_t *got = _get(&here, bob);
    ck_assert_int_eq(got->provenance, AT_PROV_SIBLING);
    ck_assert(got->verified && got->verified_at >= NOW - 10 && got->verified_at <= NOW - 10);
    ck_assert_str_eq(got->petname, "bob-pet");
    contacts_free(&here);
    contacts_free(&there);

    /* The newer edit wins and keeps our provenance; reachability merges. */
    contacts_init(&here);
    contacts_init(&there);
    contact_t mine = _contact(bob, NOW - 1000);
    mine.provenance = AT_PROV_IN_PERSON;
    mine.reach_seq = 9;
    char ra[] = "relay:a";
    char *ha[] = {ra};
    mine.rendezvous = ha;
    mine.rendezvous_count = 1;
    contacts_add(&here, &mine);
    contact_t theirs = _contact(bob, NOW - 1000);
    at_strlcpy(theirs.petname, "Bobby", sizeof(theirs.petname));
    theirs.reach_seq = 3;
    char rb[] = "relay:b";
    char *hb[] = {rb};
    theirs.rendezvous = hb;
    theirs.rendezvous_count = 1;
    contact_touch(&theirs, NOW);
    contacts_add(&there, &theirs);
    ck_assert_uint_eq(_merge(&here, &there, NOW, &ch), 1);
    ck_assert_int_eq(ch[0].action, AT_SYNC_UPDATED);
    free(ch);
    got = _get(&here, bob);
    ck_assert_str_eq(got->petname, "Bobby");
    ck_assert_int_eq(got->provenance, AT_PROV_IN_PERSON);
    ck_assert_int_eq(got->reach_seq, 9);
    ck_assert_uint_eq(got->rendezvous_count, 2);
    ck_assert_str_eq(got->rendezvous[0], "relay:a");
    ck_assert_str_eq(got->rendezvous[1], "relay:b");

    /* An older edit loses. */
    contact_t old = _contact(bob, NOW - 1000);
    at_strlcpy(old.petname, "Robert", sizeof(old.petname));
    contact_touch(&old, NOW - 5);
    contacts_t older;
    contacts_init(&older);
    contacts_add(&older, &old);
    ck_assert_uint_eq(_merge(&here, &older, NOW, NULL), 0);
    ck_assert_str_eq(_get(&here, bob)->petname, "Bobby");
    contacts_free(&older);
    contacts_free(&here);
    contacts_free(&there);

    /* A tie goes the same way on both sides. */
    contacts_t sa, sb;
    contacts_init(&sa);
    contacts_init(&sb);
    contact_t a = _contact(bob, NOW - 1000), b = _contact(bob, NOW - 1000);
    at_strlcpy(a.petname, "Aaa", sizeof(a.petname));
    at_strlcpy(b.petname, "Zzz", sizeof(b.petname));
    contact_touch(&a, NOW);
    contact_touch(&b, NOW);
    contacts_add(&sa, &a);
    contacts_add(&sb, &b);
    json_t *pa = at_sync_build(&sa, NULL, 0), *pb = at_sync_build(&sb, NULL, 0);
    ck_assert_ret_ok(at_sync_merge(&sa, pb, NOW, NULL, 0, NULL, NULL));
    ck_assert_ret_ok(at_sync_merge(&sb, pa, NOW, NULL, 0, NULL, NULL));
    ck_assert_str_eq(_get(&sa, bob)->petname, "Zzz");
    ck_assert_str_eq(_get(&sb, bob)->petname, "Zzz");
    json_decref(pa);
    json_decref(pb);
    contacts_free(&sa);
    contacts_free(&sb);
    identity_free(bob);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_what_only_grows_is_never_lost)
{
    identity_t *bob = _mk("bob");
    /* The older copy verified; the newer one only renamed. */
    contacts_t here, there;
    contacts_init(&here);
    contacts_init(&there);
    contact_t mine = _contact(bob, NOW - 1000);
    contact_mark_verified(&mine, 0.3);
    mine.verified_at = NOW - 20;
    contacts_add(&here, &mine);
    contact_t theirs = _contact(bob, NOW - 1000);
    at_strlcpy(theirs.petname, "Bobby", sizeof(theirs.petname));
    contact_touch(&theirs, NOW - 10);
    contacts_add(&there, &theirs);
    json_t *ph = at_sync_build(&here, NULL, 0), *pt = at_sync_build(&there, NULL, 0);
    ck_assert_ret_ok(at_sync_merge(&here, pt, NOW, NULL, 0, NULL, NULL));
    ck_assert_ret_ok(at_sync_merge(&there, ph, NOW, NULL, 0, NULL, NULL));
    json_decref(ph);
    json_decref(pt);
    contacts_t *both[] = {&here, &there};
    for (int i = 0; i < 2; i++) {
        contact_t *got = _get(both[i], bob);
        ck_assert(got->verified);
        ck_assert(got->verified_at >= NOW - 20 && got->verified_at <= NOW - 20);
        ck_assert_str_eq(got->petname, "Bobby");
    }
    char *bh = _book(&here), *bt = _book(&there);
    ck_assert_str_eq(bh, bt);
    free(bh);
    free(bt);
    contacts_free(&here);
    contacts_free(&there);

    /* Devices linked on either side both survive. */
    unsigned char sk[crypto_sign_SECRETKEYBYTES];
    _operator(0x44, sk);
    identity_t *carol = _mk("carol"), *dave = _mk("dave"), *erin = _mk("erin");
    contacts_init(&here);
    contacts_init(&there);
    contact_t base = _contact(carol, NOW - 1000);
    contact_mark_verified(&base, 0.3);
    at_dir_signed_t cert;
    _cert(sk, carol, &cert);
    ck_assert_int_eq(at_adopt_operator(&base, &cert, NULL), AT_DEVICE_OK);
    at_dir_free(&cert);
    contacts_add(&here, &base);
    contacts_add(&there, &base);
    _cert(sk, dave, &cert);
    ck_assert_int_eq(at_link_device(&here, PUB(dave), &cert, NULL), AT_DEVICE_OK);
    at_dir_free(&cert);
    _cert(sk, erin, &cert);
    ck_assert_int_eq(at_link_device(&there, PUB(erin), &cert, NULL), AT_DEVICE_OK);
    at_dir_free(&cert);
    ph = at_sync_build(&here, NULL, 0);
    pt = at_sync_build(&there, NULL, 0);
    /* Far enough ahead that the link times (the wall clock) are not "future". */
    double later = 4.0e9;
    ck_assert_ret_ok(at_sync_merge(&here, pt, later, NULL, 0, NULL, NULL));
    ck_assert_ret_ok(at_sync_merge(&there, ph, later, NULL, 0, NULL, NULL));
    json_decref(ph);
    json_decref(pt);
    for (int i = 0; i < 2; i++) {
        ck_assert_uint_eq(_get(both[i], carol)->devices_count, 2);
        ck_assert_ptr_eq(_get(both[i], erin), _get(both[i], carol));
        ck_assert_ptr_eq(_get(both[i], dave), _get(both[i], carol));
    }
    contacts_free(&here);
    contacts_free(&there);
    identity_free(carol);
    identity_free(dave);
    identity_free(erin);
    identity_free(bob);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_removals)
{
    identity_t *bob = _mk("bob");
    char bu[UUID_STRING_LEN + 1];
    _uuid(bob, bu);
    contacts_t here, there, third;

    /* A removal wins over an equal record. */
    contacts_init(&here);
    contacts_init(&there);
    contact_t c = _contact(bob, NOW - 100);
    contacts_add(&here, &c);
    contacts_add(&there, &c);
    contacts_remove_at(&there, bu, NOW - 100);
    at_sync_change_t *ch = NULL;
    ck_assert_uint_eq(_merge(&here, &there, NOW, &ch), 1);
    ck_assert_int_eq(ch[0].action, AT_SYNC_REMOVED);
    free(ch);
    ck_assert_ptr_null(_get(&here, bob));
    ck_assert(contacts_tombstone(&here, bu) >= NOW - 100);
    contacts_free(&here);
    contacts_free(&there);

    /* A later re-add beats it, and then lifts it over there. */
    contacts_init(&here);
    contacts_init(&there);
    contacts_add(&there, &c);
    contacts_remove_at(&there, bu, NOW - 50);
    contact_t readd = _contact(bob, NOW - 10);
    contacts_add(&here, &readd);
    ck_assert_uint_eq(_merge(&here, &there, NOW, NULL), 0);
    ck_assert_ptr_nonnull(_get(&here, bob));
    ck_assert_uint_eq(_merge(&there, &here, NOW, &ch), 1);
    ck_assert_int_eq(ch[0].action, AT_SYNC_ADDED);
    free(ch);
    ck_assert(contacts_tombstone(&there, bu) < 0.0);
    contacts_free(&here);
    contacts_free(&there);

    /* A removed contact does not come back from a stale payload. */
    contacts_init(&here);
    contacts_add(&here, &c);
    json_t *stale = at_sync_build(&here, NULL, 0);
    contacts_remove_at(&here, bu, NOW - 50);
    size_t n = 9;
    ck_assert_ret_ok(at_sync_merge(&here, stale, NOW, NULL, 0, NULL, &n));
    ck_assert_uint_eq(n, 0);
    ck_assert_ptr_null(_get(&here, bob));
    json_decref(stale);
    contacts_free(&here);

    /* A tombstone is kept to pass on. */
    contacts_init(&here);
    contacts_init(&there);
    contacts_init(&third);
    contacts_add(&there, &c);
    contacts_remove_at(&there, bu, NOW);
    ck_assert_uint_eq(_merge(&here, &there, NOW, &ch), 1);
    ck_assert_int_eq(ch[0].action, AT_SYNC_TOMBSTONE);
    free(ch);
    contacts_add(&third, &c);
    ck_assert_uint_eq(_merge(&third, &here, NOW, &ch), 1);
    ck_assert_int_eq(ch[0].action, AT_SYNC_REMOVED);
    free(ch);
    contacts_free(&here);
    contacts_free(&there);
    contacts_free(&third);
    identity_free(bob);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_clock_skew_exclusion_and_conflicts)
{
    identity_t *bob = _mk("bob");
    char bu[UUID_STRING_LEN + 1];
    _uuid(bob, bu);
    contacts_t here, there;

    /* A time from the future is taken as now; within the skew it is kept. */
    contacts_init(&here);
    contacts_init(&there);
    contact_t c = _contact(bob, NOW - 1000);
    contacts_add(&here, &c);
    contact_t t = _contact(bob, NOW - 1000);
    at_strlcpy(t.petname, "Bobby", sizeof(t.petname));
    contact_touch(&t, NOW + 86400);
    contacts_add(&there, &t);
    _merge(&here, &there, NOW, NULL);
    contact_t *got = _get(&here, bob);
    ck_assert_str_eq(got->petname, "Bobby");
    ck_assert(contact_version(got) <= NOW);
    contacts_free(&here);
    contacts_init(&here);
    contacts_get(&there, bu)->updated_at = NOW + AT_SYNC_CLOCK_SKEW;
    _merge(&here, &there, NOW, NULL);
    ck_assert(_get(&here, bob)->updated_at >= NOW + AT_SYNC_CLOCK_SKEW);
    contacts_free(&here);
    contacts_free(&there);

    /* A future tombstone is taken as now. */
    contacts_init(&here);
    contacts_init(&there);
    contacts_add(&there, &c);
    contacts_remove_at(&there, bu, NOW + 86400);
    _merge(&here, &there, NOW, NULL);
    ck_assert(contacts_tombstone(&here, bu) <= NOW);
    contacts_free(&here);
    contacts_free(&there);

    /* Our own devices are never contacts. */
    contacts_init(&here);
    contacts_init(&there);
    contacts_add(&there, &c);
    json_t *p = at_sync_build(&there, NULL, 0);
    const char *ex[] = {bu};
    size_t n = 9;
    ck_assert_ret_ok(at_sync_merge(&here, p, NOW, ex, 1, NULL, &n));
    ck_assert_uint_eq(n, 0);
    ck_assert_uint_eq(contacts_count(&here), 0);
    json_decref(p);
    contacts_free(&here);
    contacts_free(&there);

    /* A device filed under another contact, or a second holder of one
     * operator key, is refused. */
    unsigned char sk[crypto_sign_SECRETKEYBYTES];
    _operator(0x45, sk);
    identity_t *carol = _mk("carol"), *dave = _mk("dave");
    contacts_init(&here);
    contact_t base = _contact(carol, NOW - 1000);
    contact_mark_verified(&base, 0.3);
    at_dir_signed_t cert;
    _cert(sk, carol, &cert);
    at_adopt_operator(&base, &cert, NULL);
    at_dir_free(&cert);
    contacts_add(&here, &base);
    _cert(sk, dave, &cert);
    ck_assert_int_eq(at_link_device(&here, PUB(dave), &cert, NULL), AT_DEVICE_OK);
    at_dir_free(&cert);
    contacts_init(&there);
    contact_t alone = _contact(dave, NOW - 1000);
    contacts_add(&there, &alone);
    ck_assert_uint_eq(_merge(&here, &there, NOW, NULL), 0);
    ck_assert_ptr_eq(_get(&here, dave), _get(&here, carol));
    contacts_free(&there);
    contacts_init(&there);
    contact_t second = _contact(dave, NOW - 1000);
    contact_mark_verified(&second, 0.3);
    at_strlcpy(second.operator_key, base.operator_key, sizeof(second.operator_key));
    contacts_add(&there, &second);
    contacts_free(&here);
    contacts_init(&here);
    contact_t base2 = _contact(carol, NOW - 1000);
    at_strlcpy(base2.operator_key, base.operator_key, sizeof(base2.operator_key));
    contacts_add(&here, &base2);
    ck_assert_uint_eq(_merge(&here, &there, NOW, NULL), 0);
    contacts_free(&here);
    contacts_free(&there);
    identity_free(carol);
    identity_free(dave);
    identity_free(bob);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_payloads)
{
    identity_t *bob = _mk("bob"), *carol = _mk("carol");
    char bu[UUID_STRING_LEN + 1], cu[UUID_STRING_LEN + 1];
    _uuid(bob, bu);
    _uuid(carol, cu);
    contacts_t s;
    contacts_init(&s);
    contact_t b = _contact(bob, NOW - 1000), c = _contact(carol, NOW - 1000);
    contacts_add(&s, &b);
    contacts_add(&s, &c);
    contacts_remove_at(&s, cu, NOW);

    /* A delta carries only what changed. */
    const char *only[] = {cu};
    json_t *d = at_sync_build(&s, only, 1);
    ck_assert_uint_eq(json_object_size(json_object_get(d, "contacts")), 0);
    ck_assert_ptr_nonnull(json_object_get(json_object_get(d, "tombstones"), cu));
    json_decref(d);

    /* Not a sync payload: refused, the store untouched. */
    const char *bad[] = {
        "null", "[]", "{}", "{\"v\":1}",
        "{\"v\":2,\"typename\":\"at-contacts-sync\"}",
        "{\"v\":true,\"typename\":\"at-contacts-sync\"}",
        "{\"v\":1.0,\"typename\":\"at-contacts-sync\"}",
        "{\"v\":1,\"typename\":\"at-contacts-sync\",\"contacts\":[]}",
        "{\"v\":1,\"typename\":\"at-contacts-sync\",\"tombstones\":\"x\"}",
    };
    for (size_t i = 0; i < sizeof(bad) / sizeof(bad[0]); i++) {
        json_t *p = json_loads(bad[i], JSON_DECODE_ANY, NULL);
        ck_assert_int_eq(at_sync_merge(&s, p, NOW, NULL, 0, NULL, NULL), -1);
        json_decref(p);
    }

    /* Malformed records inside are skipped. */
    contacts_t one, here;
    contacts_init(&one);
    contacts_init(&here);
    contacts_add(&one, &b);
    json_t *p = at_sync_build(&one, NULL, 0);
    json_t *cs = json_object_get(p, "contacts");
    json_object_set_new(cs, "junk", json_pack("{s:s}", "identity", "nope"));
    json_object_set(cs, cu, json_object_get(cs, bu));   /* wrong key */
    json_object_set_new(json_object_get(p, "tombstones"), "NOT-A-UUID", json_real(NOW));
    at_sync_change_t *ch = NULL;
    size_t n = 0;
    ck_assert_ret_ok(at_sync_merge(&here, p, NOW, NULL, 0, &ch, &n));
    ck_assert_uint_eq(n, 1);
    ck_assert_str_eq(ch[0].uuid, bu);
    ck_assert_int_eq(ch[0].action, AT_SYNC_ADDED);
    free(ch);
    json_decref(p);
    contacts_free(&one);
    contacts_free(&here);
    contacts_free(&s);
    identity_free(bob);
    identity_free(carol);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_siblings_converge_whatever_order_edits_arrive)
{
    identity_t *who[4] = {_mk("bob"), _mk("carol"), _mk("dave"), _mk("erin")};
    contacts_t dev[3];
    for (int i = 0; i < 3; i++)
        contacts_init(&dev[i]);
    srand(4);
    double t = NOW - 10000;
    const int steps[] = {0, 1, 5};
    for (int k = 0; k < 60; k++) {
        t += steps[rand() % 3];
        contacts_t *s = &dev[rand() % 3];
        identity_t *id = who[rand() % 4];
        char u[UUID_STRING_LEN + 1];
        _uuid(id, u);
        contact_t *c = contacts_get_first(s, u);
        double op = (double)rand() / RAND_MAX;
        if (c == NULL && op < 0.6) {
            contact_t n = _contact(id, t);
            contacts_add(s, &n);
        } else if (c != NULL && op < 0.4) {
            snprintf(c->petname, sizeof(c->petname), "p%d", rand() % 10);
            contact_touch(c, t);
        } else if (c != NULL && op < 0.6) {
            contact_mark_verified(c, 0.3);
            c->verified_at = t;
        } else if (c != NULL) {
            contacts_remove_at(s, u, t);
        }
    }
    for (int r = 0; r < 2; r++)
        for (int a = 0; a < 3; a++)
            for (int b = 0; b < 3; b++)
                if (a != b)
                    _merge(&dev[b], &dev[a], NOW, NULL);
    char *b0 = _book(&dev[0]), *b1 = _book(&dev[1]), *b2 = _book(&dev[2]);
    /* Tombstones are part of the book too. */
    ck_assert_str_eq(b0, b1);
    ck_assert_str_eq(b1, b2);
    free(b0);
    free(b1);
    free(b2);
    for (int i = 0; i < 3; i++)
        contacts_free(&dev[i]);
    for (int i = 0; i < 4; i++)
        identity_free(who[i]);
}
END_TEST_DEFINITION()

/* -- siblings ---------------------------------------------------------------- */

DEFINE_TEST(test_siblings)
{
    unsigned char sk[crypto_sign_SECRETKEYBYTES], sk2[crypto_sign_SECRETKEYBYTES];
    _operator(0x46, sk);
    _operator(0x47, sk2);
    identity_t *me = _mk("me"), *other = _mk("other"), *third = _mk("third");
    char ou[UUID_STRING_LEN + 1], tu[UUID_STRING_LEN + 1];
    _uuid(other, ou);
    _uuid(third, tu);
    at_dir_signed_t own, oc, tc, foreign;
    _cert(sk, me, &own);
    _cert(sk, other, &oc);
    _cert(sk, third, &tc);
    _cert(sk2, other, &foreign);

    at_siblings_t s;
    at_siblings_init(&s);
    ck_assert_int_eq(at_siblings_add(&s, PUB(other), &oc, NULL), AT_DEVICE_UNKNOWN_OPERATOR);
    ck_assert_int_eq(at_siblings_add(&s, PUB(other), &foreign, &own), AT_DEVICE_MISMATCH);
    ck_assert_int_eq(at_siblings_add(&s, PUB(other), &tc, &own), AT_DEVICE_MISMATCH);
    ck_assert_int_eq(at_siblings_add(&s, PUB(me), &own, &own), AT_DEVICE_KNOWN);
    at_dir_signed_t forged;
    json_t *w = at_dir_to_wire(&oc);
    json_object_set_new(w, "sig", json_string("0000000000000000000000000000000000000000000000000000000000000000"
                                              "0000000000000000000000000000000000000000000000000000000000000000"));
    ck_assert_int_eq(at_dir_from_wire(w, &forged), AT_DIR_OK);
    ck_assert_int_eq(at_siblings_add(&s, PUB(other), &forged, &own), AT_DEVICE_BAD_SIGNATURE);
    at_dir_free(&forged);
    json_decref(w);
    ck_assert_uint_eq(s.count, 0);

    ck_assert_int_eq(at_siblings_add(&s, PUB(other), &oc, &own), AT_DEVICE_OK);
    ck_assert_int_eq(at_siblings_add(&s, PUB(other), &oc, &own), AT_DEVICE_OK);
    ck_assert_uint_eq(s.count, 1);
    ck_assert(at_siblings_contains(&s, ou));
    ck_assert_str_eq(s.operator_key, at_device_cert_operator(&own));

    /* The file round-trips; hand-added devices and a missing operator do not
     * load. */
    char dir[] = "/tmp/at_siblings_testXXXXXX";
    ck_assert_ptr_nonnull(mkdtemp(dir));
    ck_assert_ret_ok(at_siblings_save(&s, dir));
    at_siblings_t back;
    at_siblings_load(dir, &back);
    ck_assert_uint_eq(back.count, 1);
    ck_assert(at_siblings_contains(&back, ou));
    at_siblings_free(&back);

    json_t *doc = at_siblings_to_json(&s);
    json_t *devs = json_object_get(doc, "devices");
    json_t *ij = json_object_get(json_array_get(devs, 0), "identity");
    json_array_append_new(devs, json_pack("{s:O, s:o, s:f}", "identity", ij,
                                          "cert", at_dir_to_wire(&foreign), "added_at", 1.0));
    json_t *tj = NULL;
    ck_assert_ret_ok(public_identity_to_json(PUB(me), &tj));
    json_array_append_new(devs, json_pack("{s:o, s:o, s:f}", "identity", tj,
                                          "cert", at_dir_to_wire(&tc), "added_at", 1.0));
    at_siblings_from_json(doc, &back);
    ck_assert_uint_eq(back.count, 1);
    at_siblings_free(&back);
    json_object_set_new(doc, "operator", json_string(""));
    at_siblings_from_json(doc, &back);
    ck_assert_uint_eq(back.count, 0);
    at_siblings_free(&back);
    json_decref(doc);

    char path[128];
    snprintf(path, sizeof(path), "%s/%s", dir, AT_SIBLINGS_FILENAME);
    FILE *f = fopen(path, "w");
    fputs("{not json", f);
    fclose(f);
    at_siblings_load(dir, &back);
    ck_assert_uint_eq(back.count, 0);
    at_siblings_free(&back);
    unlink(path);
    rmdir(dir);

    /* A new operator starts the list over. */
    at_dir_signed_t own2, tc2;
    _cert(sk2, me, &own2);
    _cert(sk2, third, &tc2);
    ck_assert_int_eq(at_siblings_add(&s, PUB(third), &tc2, &own2), AT_DEVICE_OK);
    ck_assert_uint_eq(s.count, 1);
    ck_assert(at_siblings_contains(&s, tu));

    /* At most AT_CONTACT_DEVICES_MAX. */
    for (int i = 1; i < AT_CONTACT_DEVICES_MAX; i++) {
        identity_t *d = _mk("dev");
        at_dir_signed_t dc;
        _cert(sk2, d, &dc);
        ck_assert_int_eq(at_siblings_add(&s, PUB(d), &dc, &own2), AT_DEVICE_OK);
        at_dir_free(&dc);
        identity_free(d);
    }
    identity_t *extra = _mk("extra");
    at_dir_signed_t ec;
    _cert(sk2, extra, &ec);
    ck_assert_int_eq(at_siblings_add(&s, PUB(extra), &ec, &own2), AT_DEVICE_FULL);
    at_dir_free(&ec);
    identity_free(extra);
    ck_assert(at_siblings_remove(&s, tu));
    ck_assert(!at_siblings_contains(&s, tu));

    at_siblings_free(&s);
    at_dir_free(&own);
    at_dir_free(&oc);
    at_dir_free(&tc);
    at_dir_free(&foreign);
    at_dir_free(&own2);
    at_dir_free(&tc2);
    identity_free(me);
    identity_free(other);
    identity_free(third);
}
END_TEST_DEFINITION()

RUN_TESTS(ContactsSync,
          test_the_stored_form,
          test_new_newer_older_and_ties,
          test_what_only_grows_is_never_lost,
          test_removals,
          test_clock_skew_exclusion_and_conflicts,
          test_payloads,
          test_siblings_converge_whatever_order_edits_arrive,
          test_siblings)
