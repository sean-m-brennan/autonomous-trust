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

/* The directory registry on a relay (network/net_registry), FIRST_CONTACT_PLAN
 * Phase 3. Mirrors Python tests/a_unit/test_registry.py. */

#define _GNU_SOURCE
#define DEBUG_TESTS 1
#include "test_setup.h"

#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include <sodium.h>

#include "contacts/directory.h"
#include "identity/identity_priv.h"
#include "network/net_registry.h"
#include "network/net_relay.h"
#include "network/net_proc_priv.h"
#include "network/network.h"
#include "utilities/message.h"
#include "utilities/msg_types_priv.h"

static unsigned char g_issuer_sk[crypto_sign_SECRETKEYBYTES];
static char g_issuer_hex[65];
static double g_now = 1000.0;

static double _clock(void) { return g_now; }

static void _issuer(void)
{
    unsigned char seed[32], pk[crypto_sign_PUBLICKEYBYTES];
    memset(seed, 0x44, sizeof(seed));
    crypto_sign_seed_keypair(pk, g_issuer_sk, seed);
    sodium_bin2hex(g_issuer_hex, sizeof(g_issuer_hex), pk, sizeof(pk));
}

static identity_t *_mk(const char *name)
{
    uuid_t u;
    uuid_generate(u);
    identity_t *id = NULL;
    ck_assert_ret_ok(identity_create(&u, "127.0.0.1", name, name, &id));
    return id;
}

static void _ids(const identity_t *who, char *uu, const char **key)
{
    uuid_unparse_lower(who->uuid, uu);
    *key = (const char *)who->signature.public_hex;
}

/* A wire entry (new reference). */
static json_t *_entry(const identity_t *who, const char *handle, int64_t seq,
                      const char *vis, const unsigned char *issuer_sk, long ttl)
{
    at_dir_signed_t att, e;
    ck_assert_int_eq(at_dir_attest(issuer_sk, handle, (const char *)who->signature.public_hex,
                                   (long)time(NULL) + ttl, &att), AT_DIR_OK);
    ck_assert_int_eq(at_dir_create_entry(who, &att, seq, vis, 0, (double)time(NULL), &e),
                     AT_DIR_OK);
    json_t *w = at_dir_to_wire(&e);
    at_dir_free(&att);
    at_dir_free(&e);
    return w;
}

static net_registry_t *_registry(int rate)
{
    _issuer();
    const char *issuers[] = {g_issuer_hex};
    net_registry_t *r = net_registry_new(issuers, 1, rate);
    g_now = 1000.0;
    net_registry_set_clocks(r, _clock, NULL);
    return r;
}

static const char *_op(const json_t *reply)
{
    return json_string_value(json_object_get(reply, "op"));
}

static const char *_reason(const json_t *reply)
{
    const char *r = json_string_value(json_object_get(reply, "reason"));
    return r != NULL ? r : "";
}

/* publish + check op/reason, consuming both. */
static void _publish_is(net_registry_t *r, const identity_t *as, json_t *wire,
                        const char *op, const char *reason)
{
    char uu[UUID_STR_LEN + 1];
    const char *key;
    _ids(as, uu, &key);
    json_t *rep = net_registry_publish(r, uu, key, wire);
    ck_assert_str_eq(_op(rep), op);
    if (reason != NULL)
        ck_assert_str_eq(_reason(rep), reason);
    json_decref(rep);
    json_decref(wire);
}

static bool _found(net_registry_t *r, const identity_t *as, const char *handle)
{
    char uu[UUID_STR_LEN + 1];
    const char *key;
    _ids(as, uu, &key);
    json_t *rep = net_registry_lookup(r, uu, handle);
    ck_assert_str_eq(_op(rep), "dir_entry");
    bool found = json_is_object(json_object_get(rep, "entry"));
    json_decref(rep);
    return found;
}

DEFINE_TEST(test_publish_then_lookup)
{
    net_registry_t *r = _registry(10);
    identity_t *alice = _mk("alice"), *bob = _mk("bob");
    _publish_is(r, alice, _entry(alice, "Alice@Example.org", 1, "anyone", g_issuer_sk, 3600),
                "dir_published", NULL);
    char uu[UUID_STR_LEN + 1];
    const char *key;
    _ids(bob, uu, &key);
    json_t *rep = net_registry_lookup(r, uu, "ALICE@example.org");
    ck_assert_str_eq(json_string_value(json_object_get(rep, "handle")), "alice@example.org");
    at_dir_signed_t e;
    ck_assert_int_eq(at_dir_from_wire(json_object_get(rep, "entry"), &e), AT_DIR_OK);
    ck_assert_int_eq(at_dir_entry_verify(&e, NULL, 0, (double)time(NULL)), AT_DIR_OK);
    at_dir_free(&e);
    json_decref(rep);
    ck_assert(!_found(r, bob, "nobody@example.org"));
    identity_free(alice);
    identity_free(bob);
    net_registry_free(r);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_an_entry_that_fails_its_check_is_refused_with_the_reason)
{
    net_registry_t *r = _registry(10);
    identity_t *alice = _mk("alice");
    unsigned char seed[32], pk[32], other_sk[64];
    memset(seed, 0x66, sizeof(seed));
    crypto_sign_seed_keypair(pk, other_sk, seed);
    _publish_is(r, alice, _entry(alice, "a@x", 1, "anyone", other_sk, 3600),
                "dir_refused", "untrusted");
    _publish_is(r, alice, _entry(alice, "a@x", 1, "anyone", g_issuer_sk, -1),
                "dir_refused", "expired");
    identity_free(alice);
    net_registry_free(r);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_only_the_holder_files_its_entry)
{
    net_registry_t *r = _registry(10);
    identity_t *alice = _mk("alice"), *mallory = _mk("mallory");
    _publish_is(r, mallory, _entry(alice, "a@x", 1, "anyone", g_issuer_sk, 3600),
                "dir_refused", "not_holder");
    identity_free(alice);
    identity_free(mallory);
    net_registry_free(r);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_a_newer_seq_replaces_and_an_older_is_refused)
{
    net_registry_t *r = _registry(10);
    identity_t *alice = _mk("alice");
    json_t *two = _entry(alice, "a@x", 2, "anyone", g_issuer_sk, 3600);
    json_incref(two);
    _publish_is(r, alice, two, "dir_published", NULL);
    _publish_is(r, alice, _entry(alice, "a@x", 1, "anyone", g_issuer_sk, 3600),
                "dir_refused", "stale");
    _publish_is(r, alice, _entry(alice, "a@x", 2, "published", g_issuer_sk, 3600),
                "dir_refused", "stale");
    _publish_is(r, alice, two, "dir_published", NULL);   /* the same one refiles */
    _publish_is(r, alice, _entry(alice, "a@x", 3, "anyone", g_issuer_sk, 3600),
                "dir_published", NULL);
    identity_free(alice);
    net_registry_free(r);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_a_handle_held_by_another_key_is_taken)
{
    net_registry_t *r = _registry(10);
    identity_t *alice = _mk("alice"), *eve = _mk("eve");
    _publish_is(r, alice, _entry(alice, "a@x", 1, "anyone", g_issuer_sk, 3600),
                "dir_published", NULL);
    _publish_is(r, eve, _entry(eve, "a@x", 1, "anyone", g_issuer_sk, 3600),
                "dir_refused", "taken");
    identity_free(alice);
    identity_free(eve);
    net_registry_free(r);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_withdraw_is_holder_only)
{
    net_registry_t *r = _registry(10);
    identity_t *alice = _mk("alice"), *eve = _mk("eve");
    _publish_is(r, alice, _entry(alice, "a@x", 1, "anyone", g_issuer_sk, 3600),
                "dir_published", NULL);
    char uu[UUID_STR_LEN + 1];
    const char *key;
    _ids(eve, uu, &key);
    json_decref(net_registry_withdraw(r, uu, key, "a@x"));
    ck_assert(_found(r, eve, "a@x"));
    _ids(alice, uu, &key);
    json_t *rep = net_registry_withdraw(r, uu, key, "A@X");
    ck_assert_str_eq(_op(rep), "dir_withdrawn");
    ck_assert_str_eq(json_string_value(json_object_get(rep, "handle")), "a@x");
    json_decref(rep);
    ck_assert(!_found(r, eve, "a@x"));
    identity_free(alice);
    identity_free(eve);
    net_registry_free(r);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_published_visibility_needs_the_asker_to_be_published)
{
    net_registry_t *r = _registry(10);
    identity_t *alice = _mk("alice"), *bob = _mk("bob");
    _publish_is(r, alice, _entry(alice, "a@x", 1, "published", g_issuer_sk, 3600),
                "dir_published", NULL);
    ck_assert(!_found(r, bob, "a@x"));
    _publish_is(r, bob, _entry(bob, "b@x", 1, "anyone", g_issuer_sk, 3600),
                "dir_published", NULL);
    ck_assert(_found(r, bob, "a@x"));
    identity_free(alice);
    identity_free(bob);
    net_registry_free(r);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_lookups_are_rate_limited_per_client)
{
    net_registry_t *r = _registry(3);
    identity_t *alice = _mk("alice"), *bob = _mk("bob"), *carol = _mk("carol");
    _publish_is(r, alice, _entry(alice, "a@x", 1, "anyone", g_issuer_sk, 3600),
                "dir_published", NULL);
    char bu[UUID_STR_LEN + 1], cu[UUID_STR_LEN + 1];
    const char *key;
    _ids(bob, bu, &key);
    _ids(carol, cu, &key);
    const char *want[] = {"dir_entry", "dir_entry", "dir_entry", "dir_limited"};
    for (int i = 0; i < 4; i++) {
        json_t *rep = net_registry_lookup(r, bu, "a@x");
        ck_assert_str_eq(_op(rep), want[i]);
        json_decref(rep);
    }
    json_t *rep = net_registry_lookup(r, cu, "a@x");
    ck_assert_str_eq(_op(rep), "dir_entry");
    json_decref(rep);
    g_now += 20.0;                  /* a third of a minute: one token at 3/min */
    rep = net_registry_lookup(r, bu, "a@x");
    ck_assert_str_eq(_op(rep), "dir_entry");
    json_decref(rep);
    rep = net_registry_lookup(r, bu, "a@x");
    ck_assert_str_eq(_op(rep), "dir_limited");
    json_decref(rep);
    identity_free(alice);
    identity_free(bob);
    identity_free(carol);
    net_registry_free(r);
}
END_TEST_DEFINITION()

static char g_bad_uuid[UUID_STR_LEN + 1];
static bool _distrust(void *arg, const char *uuid, const char *key)
{
    (void)arg;
    (void)key;
    return strcmp(uuid, g_bad_uuid) == 0;
}

DEFINE_TEST(test_a_distrusted_holder_is_not_served)
{
    net_registry_t *r = _registry(10);
    identity_t *alice = _mk("alice"), *bob = _mk("bob");
    net_registry_set_distrust(r, _distrust, NULL);
    g_bad_uuid[0] = '\0';
    _publish_is(r, alice, _entry(alice, "a@x", 1, "anyone", g_issuer_sk, 3600),
                "dir_published", NULL);
    ck_assert(_found(r, bob, "a@x"));
    uuid_unparse_lower(alice->uuid, g_bad_uuid);
    ck_assert(!_found(r, bob, "a@x"));
    identity_free(alice);
    identity_free(bob);
    net_registry_free(r);
}
END_TEST_DEFINITION()

/* -- over the relay's own link --------------------------------------------- */
static struct {
    pthread_mutex_t lock;
    int n;
    json_t *last;
} g_dir = { .lock = PTHREAD_MUTEX_INITIALIZER };

static void _on_dir(void *arg, const json_t *msg, const char *host, int port)
{
    (void)arg;
    (void)host;
    (void)port;
    pthread_mutex_lock(&g_dir.lock);
    json_decref(g_dir.last);
    g_dir.last = json_deep_copy(msg);
    g_dir.n++;
    pthread_mutex_unlock(&g_dir.lock);
}

static bool _wait_dir(int n)
{
    for (int i = 0; i < 500; i++) {
        pthread_mutex_lock(&g_dir.lock);
        bool ok = g_dir.n >= n;
        pthread_mutex_unlock(&g_dir.lock);
        if (ok)
            return true;
        usleep(10 * 1000);
    }
    return false;
}

static void _nodeliver(void *arg, const char *from, const uint8_t *frame, size_t len,
                       const char *host, int port)
{
    (void)arg; (void)from; (void)frame; (void)len; (void)host; (void)port;
}

DEFINE_TEST(test_the_ops_run_over_the_relay_link)
{
    net_registry_t *r = _registry(10);
    net_registry_set_clocks(r, NULL, NULL);
    net_relay_server_t *srv = net_relay_server_start("127.0.0.1", 0, NULL);
    ck_assert(srv != NULL);
    net_relay_server_set_registry(srv, r);
    identity_t *alice = _mk("alice"), *bob = _mk("bob");
    int port = net_relay_server_port(srv);
    net_relay_client_t *a = net_relay_client_new("127.0.0.1", port, alice, _nodeliver, NULL, NULL);
    net_relay_client_t *b = net_relay_client_new("127.0.0.1", port, bob, _nodeliver, NULL, NULL);
    net_relay_client_on_dir(a, _on_dir, NULL);
    net_relay_client_on_dir(b, _on_dir, NULL);
    g_dir.n = 0;
    json_t *e = _entry(alice, "alice@example.org", 1, "anyone", g_issuer_sk, 3600);
    ck_assert_int_eq(net_relay_client_dir_publish(a, e), 0);
    json_decref(e);
    ck_assert(_wait_dir(1));
    ck_assert_str_eq(_op(g_dir.last), "dir_published");
    ck_assert_int_eq(net_relay_client_dir_lookup(b, "Alice@Example.org"), 0);
    ck_assert(_wait_dir(2));
    ck_assert_str_eq(_op(g_dir.last), "dir_entry");
    ck_assert(json_is_object(json_object_get(g_dir.last, "entry")));
    /* A plain relay (no registry) refuses. */
    net_relay_server_set_registry(srv, NULL);
    ck_assert_int_eq(net_relay_client_dir_lookup(b, "a@x"), 0);
    ck_assert(_wait_dir(3));
    ck_assert_str_eq(_op(g_dir.last), "dir_refused");
    ck_assert_str_eq(_reason(g_dir.last), "not_registry");
    net_relay_client_free(a);
    net_relay_client_free(b);
    net_relay_server_stop(srv);
    identity_free(alice);
    identity_free(bob);
    net_registry_free(r);
    json_decref(g_dir.last);
    g_dir.last = NULL;
}
END_TEST_DEFINITION()

/* -- the network process between identity and the registries --------------- */
static struct {
    int n_asks;
    char asks[16][96];              /* "host:port op arg" */
    int n_out;
    char fn[16][32];
    json_t *body[16];
} g_net;

static int _test_dir(const char *host, int port, const char *op, const char *handle,
                     const json_t *entry)
{
    (void)entry;
    if (g_net.n_asks < 16)
        snprintf(g_net.asks[g_net.n_asks++], sizeof(g_net.asks[0]), "%s:%d %s %s",
                 host, port, op, handle != NULL ? handle : "-");
    return 0;
}

static int _net_hook(const char *key, const message_type_t type, generic_msg_t *msg,
                     bool blocking)
{
    (void)key; (void)blocking;
    if (type == NET_MESSAGE && msg->info.net_msg.function != NULL && g_net.n_out < 16) {
        at_strlcpy(g_net.fn[g_net.n_out], msg->info.net_msg.function, sizeof(g_net.fn[0]));
        json_t *b = NULL;
        (void)net_msg_unpack_json(&msg->info.net_msg, &b);
        g_net.body[g_net.n_out++] = b;
    }
    return 0;
}

static void _net_begin(void)
{
    for (int i = 0; i < g_net.n_out; i++)
        json_decref(g_net.body[i]);
    memset(&g_net, 0, sizeof(g_net));
    setenv("AT_USE_RELAY", "198.51.100.1:27790,198.51.100.2:27790", 1);
    net_relay_reset_routes();
    net_relay_set_test_dir(_test_dir);
    messaging_set_test_hook(_net_hook);
}

static void _net_end(void)
{
    messaging_set_test_hook(NULL);
    net_relay_set_test_dir(NULL);
    unsetenv("AT_USE_RELAY");
    for (int i = 0; i < g_net.n_out; i++)
        json_decref(g_net.body[i]);
    memset(&g_net, 0, sizeof(g_net));
}

static void _ipc(int (*h)(net_msg_t *, logger_t *), const char *fn, json_t *body,
                 const identity_t *from)
{
    generic_msg_t msg = {0};
    msg.type = NET_MESSAGE;
    msg.info.net_msg.function = (char *)fn;
    if (from != NULL)
        uuid_copy(msg.info.net_msg.from_whom.uuid, from->uuid);
    ck_assert_ret_ok(net_msg_pack_json(&msg.info.net_msg, body));
    json_decref(body);
    (void)h(&msg.info.net_msg, NULL);
}

static void _answer(const char *host, const char *frame_text)
{
    json_t *f = json_loads(frame_text, 0, NULL);
    net_relay_dir_answer(NULL, f, host, 27790);
    json_decref(f);
}

DEFINE_TEST(test_a_lookup_asks_every_relay_and_answers_once)
{
    _net_begin();
    _registry(10);
    identity_t *alice = _mk("alice");
    _ipc(net_handle_dir_lookup, NET_FN_DIR_LOOKUP, json_pack("{s:s}", "handle", "A@X"), NULL);
    ck_assert_int_eq(g_net.n_asks, 2);
    ck_assert_str_eq(g_net.asks[0], "198.51.100.1:27790 dir_lookup a@x");
    ck_assert_str_eq(g_net.asks[1], "198.51.100.2:27790 dir_lookup a@x");
    _answer("198.51.100.1", "{\"op\":\"dir_entry\",\"handle\":\"a@x\",\"entry\":null}");
    net_relay_drain_dir();
    ck_assert_int_eq(g_net.n_out, 0);           /* the second has not answered */
    json_t *wire = _entry(alice, "a@x", 1, "anyone", g_issuer_sk, 3600);
    json_t *f = json_pack("{s:s, s:s, s:O}", "op", "dir_entry", "handle", "a@x", "entry", wire);
    net_relay_dir_answer(NULL, f, "198.51.100.2", 27790);
    json_decref(f);
    net_relay_drain_dir();
    ck_assert_int_eq(g_net.n_out, 1);
    ck_assert_str_eq(g_net.fn[0], "dir_result");
    ck_assert(json_equal(json_object_get(g_net.body[0], "entry"), wire));
    ck_assert_str_eq(json_string_value(json_object_get(g_net.body[0], "relay")),
                     "198.51.100.2:27790");
    json_decref(wire);
    identity_free(alice);
    _net_end();
}
END_TEST_DEFINITION()

DEFINE_TEST(test_a_lookup_nobody_can_answer_is_not_found_and_limited_is_passed_on)
{
    _net_begin();
    _ipc(net_handle_dir_lookup, NET_FN_DIR_LOOKUP, json_pack("{s:s}", "handle", "a@x"), NULL);
    _answer("198.51.100.1", "{\"op\":\"dir_limited\",\"handle\":\"a@x\"}");
    _answer("198.51.100.2", "{\"op\":\"dir_refused\",\"handle\":\"a@x\",\"reason\":\"not_registry\"}");
    net_relay_drain_dir();
    ck_assert_int_eq(g_net.n_out, 1);
    json_t *want = json_pack("{s:s, s:n, s:b, s:s}", "handle", "a@x", "entry",
                             "limited", 1, "relay", "");
    ck_assert(json_equal(g_net.body[0], want));
    json_decref(want);
    _net_end();
}
END_TEST_DEFINITION()

DEFINE_TEST(test_an_answer_from_a_relay_not_asked_is_ignored)
{
    _net_begin();
    _registry(10);
    identity_t *alice = _mk("alice");
    _ipc(net_handle_dir_lookup, NET_FN_DIR_LOOKUP, json_pack("{s:s}", "handle", "a@x"), NULL);
    json_t *wire = _entry(alice, "a@x", 1, "anyone", g_issuer_sk, 3600);
    json_t *f = json_pack("{s:s, s:s, s:o}", "op", "dir_entry", "handle", "a@x", "entry", wire);
    net_relay_dir_answer(NULL, f, "203.0.113.66", 1);
    json_decref(f);
    net_relay_drain_dir();
    ck_assert_int_eq(g_net.n_out, 0);
    identity_free(alice);
    _net_end();
}
END_TEST_DEFINITION()

DEFINE_TEST(test_a_lookup_times_out)
{
    _net_begin();
    _ipc(net_handle_dir_lookup, NET_FN_DIR_LOOKUP, json_pack("{s:s}", "handle", "a@x"), NULL);
    net_relay_dir_age_lookups(NET_DIR_LOOKUP_TIMEOUT_SEC + 1);
    net_relay_drain_dir();
    ck_assert_int_eq(g_net.n_out, 1);
    ck_assert(json_is_null(json_object_get(g_net.body[0], "entry")));
    _net_end();
}
END_TEST_DEFINITION()

DEFINE_TEST(test_the_directory_ipc_is_refused_from_the_wire)
{
    _net_begin();
    identity_t *m = _mk("m");
    _ipc(net_handle_dir_lookup, NET_FN_DIR_LOOKUP, json_pack("{s:s}", "handle", "a@x"), m);
    _ipc(net_handle_dir_withdraw, NET_FN_DIR_WITHDRAW, json_pack("{s:s}", "handle", "a@x"), m);
    ck_assert_int_eq(g_net.n_asks, 0);
    identity_free(m);
    _net_end();
}
END_TEST_DEFINITION()

DEFINE_TEST(test_our_entry_is_filed_at_our_relays_and_withdrawn)
{
    _net_begin();
    _registry(10);
    identity_t *alice = _mk("alice");
    json_t *wire = _entry(alice, "a@x", 1, "anyone", g_issuer_sk, 3600);
    _ipc(net_handle_dir_publish, NET_FN_DIR_PUBLISH, json_pack("{s:O}", "entry", wire), NULL);
    ck_assert_int_eq(g_net.n_asks, 2);
    ck_assert_str_eq(g_net.asks[0], "198.51.100.1:27790 dir_publish -");
    ck_assert_str_eq(g_net.asks[1], "198.51.100.2:27790 dir_publish -");
    _ipc(net_handle_dir_withdraw, NET_FN_DIR_WITHDRAW, json_pack("{s:s}", "handle", "a@x"), NULL);
    ck_assert_int_eq(g_net.n_asks, 4);
    ck_assert_str_eq(g_net.asks[3], "198.51.100.2:27790 dir_withdraw a@x");
    _answer("198.51.100.1", "{\"op\":\"dir_published\",\"handle\":\"a@x\",\"seq\":1}");
    net_relay_drain_dir();
    ck_assert_int_eq(g_net.n_out, 1);
    ck_assert_str_eq(g_net.fn[0], "dir_status");
    ck_assert_str_eq(json_string_value(json_object_get(g_net.body[0], "op")), "dir_published");
    ck_assert_int_eq(json_integer_value(json_object_get(g_net.body[0], "seq")), 1);
    json_decref(wire);
    identity_free(alice);
    _net_end();
}
END_TEST_DEFINITION()

RUN_TESTS(NetRegistry,
          test_publish_then_lookup,
          test_an_entry_that_fails_its_check_is_refused_with_the_reason,
          test_only_the_holder_files_its_entry,
          test_a_newer_seq_replaces_and_an_older_is_refused,
          test_a_handle_held_by_another_key_is_taken,
          test_withdraw_is_holder_only,
          test_published_visibility_needs_the_asker_to_be_published,
          test_lookups_are_rate_limited_per_client,
          test_a_distrusted_holder_is_not_served,
          test_the_ops_run_over_the_relay_link,
          test_a_lookup_asks_every_relay_and_answers_once,
          test_a_lookup_nobody_can_answer_is_not_found_and_limited_is_passed_on,
          test_an_answer_from_a_relay_not_asked_is_ignored,
          test_a_lookup_times_out,
          test_the_directory_ipc_is_refused_from_the_wire,
          test_our_entry_is_filed_at_our_relays_and_withdrawn)
