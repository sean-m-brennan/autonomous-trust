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

/* The signed relay seed list (network/net_relay_seeds), FIRST_CONTACT_PLAN
 * §10.1. Mirrors Python tests/a_unit/test_relay_seeds.py. */

#define _GNU_SOURCE
#define DEBUG_TESTS 1
#include "test_setup.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include <jansson.h>
#include <sodium.h>

#include "rendezvous/net_relay.h"
#include "rendezvous/net_relay_seeds.h"

/* Python relay_seeds.sign_seeds("11"*32, 7, ["relay://203.0.113.9:27790"]). */
#define PY_SIGNED_LIST "{\"body\":\"{\\\"v\\\":1,\\\"typename\\\":\\\"at-seeds\\\",\\\"seq\\\":7,\\\"relays\\\":[\\\"relay://203.0.113.9:27790\\\"]}\",\"sig\":\"a03e84878d9170627a0a3efc39398f7237521e0ac67b17aa6c778ca12b7e15f5b2d3609ee0a89114bc0b82d7ed17664f602ee55cf8c960e496d5bb8a8dea7c0f\"}"

#define PINNED "relay://00000000-0000-4000-8000-000000000001:" \
    "abababababababababababababababab@198.51.100.1:27790"

static unsigned char g_release_seed[32], g_node_seed[32];
static char g_release_key[65], g_root[256];

static void _key_of(const unsigned char *seed, char *hex)
{
    unsigned char pk[crypto_sign_PUBLICKEYBYTES], sk[crypto_sign_SECRETKEYBYTES];
    crypto_sign_seed_keypair(pk, sk, seed);
    sodium_bin2hex(hex, 65, pk, sizeof(pk));
}

/* {"body": body, "sig": seed over domain+body}, as Python's _sign writes it. */
static char *_signed(const unsigned char *seed, const char *domain, const char *body)
{
    unsigned char pk[crypto_sign_PUBLICKEYBYTES], sk[crypto_sign_SECRETKEYBYTES],
                  sig[crypto_sign_BYTES];
    crypto_sign_seed_keypair(pk, sk, seed);
    size_t dl = strlen(domain), bl = strlen(body);
    unsigned char *msg = malloc(dl + bl);
    memcpy(msg, domain, dl);
    memcpy(msg + dl, body, bl);
    crypto_sign_detached(sig, NULL, msg, dl + bl, sk);
    free(msg);
    char sig_hex[2 * crypto_sign_BYTES + 1];
    sodium_bin2hex(sig_hex, sizeof(sig_hex), sig, sizeof(sig));
    json_t *w = json_pack("{s:s, s:s}", "body", body, "sig", sig_hex);
    char *out = json_dumps(w, JSON_COMPACT);
    json_decref(w);
    return out;
}

static char *_list(const unsigned char *seed, int seq, const char *relays_json)
{
    char body[2048];
    snprintf(body, sizeof(body),
             "{\"v\":1,\"typename\":\"at-seeds\",\"seq\":%d,\"relays\":%s}", seq, relays_json);
    return _signed(seed, AT_RELAY_SEEDS_DOMAIN, body);
}

static char *_edits(const unsigned char *seed, const char *add, const char *remove)
{
    char body[2048];
    snprintf(body, sizeof(body),
             "{\"v\":1,\"typename\":\"at-seeds-local\",\"add\":%s,\"remove\":%s}", add, remove);
    return _signed(seed, AT_RELAY_SEEDS_LOCAL_DOMAIN, body);
}

static void _write(const char *dir, const char *name, const char *text)
{
    char path[512];
    snprintf(path, sizeof(path), "%s/%s/%s", g_root, dir, name);
    FILE *f = fopen(path, "w");
    ck_assert(f != NULL);
    fputs(text, f);
    fclose(f);
}

static void _ship(int seq, const char *relays_json)
{
    char *t = _list(g_release_seed, seq, relays_json);
    _write("etc/at", AT_RELAY_SEEDS_FILE, t);
    free(t);
}

static void _local(const unsigned char *seed, const char *add, const char *remove)
{
    char *t = _edits(seed, add, remove);
    _write("var/at", AT_RELAY_SEEDS_LOCAL_FILE, t);
    free(t);
}

/* A fresh root with a node identity, first contact on, AT_USE_RELAY unset. */
static void _fresh_root(void)
{
    snprintf(g_root, sizeof(g_root), "/tmp/at-seeds-XXXXXX");
    ck_assert(mkdtemp(g_root) != NULL);
    char p[512];
    snprintf(p, sizeof(p), "%s/etc", g_root);
    mkdir(p, 0755);
    snprintf(p, sizeof(p), "%s/etc/at", g_root);
    mkdir(p, 0755);
    snprintf(p, sizeof(p), "%s/var", g_root);
    mkdir(p, 0755);
    snprintf(p, sizeof(p), "%s/var/at", g_root);
    mkdir(p, 0755);
    setenv("AUTONOMOUS_TRUST_ROOT", g_root, 1);
    unsetenv("AT_USE_RELAY");
    unsetenv(AT_RELAY_SEEDS_ENV);
    setenv("AT_RELAY_SEED_FALLBACK", "1", 1);
    memset(g_release_seed, 0x11, sizeof(g_release_seed));
    memset(g_node_seed, 0x22, sizeof(g_node_seed));
    _key_of(g_release_seed, g_release_key);
    net_relay_seeds_set_release_key(g_release_key);
    char seed_hex[65], ident[256];
    sodium_bin2hex(seed_hex, sizeof(seed_hex), g_node_seed, sizeof(g_node_seed));
    snprintf(ident, sizeof(ident),
             "{\"typename\":\"identity\",\"signature\":{\"hex_seed\":\"%s\"}}", seed_hex);
    _write("etc/at", "identity.cfg.json", ident);
}

static size_t _own(net_relay_ep_t *eps)
{
    return net_relay_own_list(eps, AT_RELAY_MAX);
}

DEFINE_TEST(test_a_signed_list_round_trips)
{
    _fresh_root();
    char *t = _list(g_release_seed, 3, "[\"" PINNED "\",\"relay://203.0.113.9:1\"]");
    long long seq = 0;
    net_relay_seed_list_t l;
    ck_assert_int_eq(net_relay_seeds_verify(t, g_release_key, &seq, &l), 0);
    ck_assert_int_eq(seq, 3);
    ck_assert_uint_eq(l.n, 2);
    ck_assert_str_eq(l.eps[0].host, "198.51.100.1");
    ck_assert(l.pins[0].set);
    ck_assert_str_eq(l.pins[0].uuid, "00000000-0000-4000-8000-000000000001");
    ck_assert(!l.pins[1].set);
    ck_assert_int_eq(l.eps[1].port, 1);
    free(t);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_the_signature_covers_the_exact_body)
{
    _fresh_root();
    char *t = _list(g_release_seed, 1, "[\"relay://a:1\"]");
    char *at = strstr(t, "a:1");
    ck_assert(at != NULL);
    *at = 'b';
    net_relay_seed_list_t l;
    ck_assert_int_eq(net_relay_seeds_verify(t, g_release_key, NULL, &l), -1);
    free(t);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_another_key_or_no_key_is_refused)
{
    _fresh_root();
    unsigned char other[32];
    memset(other, 0x33, sizeof(other));
    char *t = _list(other, 1, "[\"relay://a:1\"]");
    net_relay_seed_list_t l;
    ck_assert_int_eq(net_relay_seeds_verify(t, g_release_key, NULL, &l), -1);
    free(t);
    t = _list(g_release_seed, 1, "[\"relay://a:1\"]");
    ck_assert_int_eq(net_relay_seeds_verify(t, "", NULL, &l), -1);
    free(t);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_a_local_edit_signature_does_not_verify_as_a_list)
{
    _fresh_root();
    char *t = _edits(g_release_seed, "[\"relay://a:1\"]", "[]");
    net_relay_seed_list_t l;
    ck_assert_int_eq(net_relay_seeds_verify(t, g_release_key, NULL, &l), -1);
    free(t);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_one_bad_entry_refuses_the_whole_list)
{
    _fresh_root();
    char *t = _list(g_release_seed, 1, "[\"relay://a:1\",\"nonsense\"]");
    net_relay_seed_list_t l;
    ck_assert_int_eq(net_relay_seeds_verify(t, g_release_key, NULL, &l), -1);
    ck_assert_uint_eq(l.n, 0);
    free(t);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_a_version_must_be_the_integer_one)
{
    _fresh_root();
    net_relay_seed_list_t l;
    const char *bad[] = {
        "{\"v\":1.0,\"typename\":\"at-seeds\",\"seq\":1,\"relays\":[]}",
        "{\"v\":true,\"typename\":\"at-seeds\",\"seq\":1,\"relays\":[]}",
        "{\"v\":1,\"typename\":\"at-seeds\",\"seq\":0,\"relays\":[]}",
        "{\"v\":1,\"typename\":\"at-seeds\",\"seq\":true,\"relays\":[]}",
    };
    for (size_t i = 0; i < sizeof(bad) / sizeof(bad[0]); i++) {
        char *t = _signed(g_release_seed, AT_RELAY_SEEDS_DOMAIN, bad[i]);
        ck_assert_int_eq(net_relay_seeds_verify(t, g_release_key, NULL, &l), -1);
        free(t);
    }
}
END_TEST_DEFINITION()

DEFINE_TEST(test_seed_list_stands_in_only_without_an_explicit_relay)
{
    _fresh_root();
    net_relay_ep_t eps[AT_RELAY_MAX];
    _ship(1, "[\"relay://203.0.113.9:1\"]");
    ck_assert_uint_eq(_own(eps), 1);
    ck_assert_str_eq(eps[0].host, "203.0.113.9");
    setenv("AT_USE_RELAY", "198.51.100.5:2", 1);
    ck_assert_uint_eq(_own(eps), 1);
    ck_assert_str_eq(eps[0].host, "198.51.100.5");
    unsetenv("AT_USE_RELAY");
}
END_TEST_DEFINITION()

DEFINE_TEST(test_off_means_off)
{
    _fresh_root();
    net_relay_ep_t eps[AT_RELAY_MAX];
    _ship(1, "[\"relay://203.0.113.9:1\"]");
    unsetenv("AT_RELAY_SEED_FALLBACK");
    ck_assert_uint_eq(_own(eps), 0);
    /* The fallback is rendezvous's own switch: first contact on does not
     * turn it on (FEATURE_SPLIT_PLAN D9). */
    setenv("AT_FIRST_CONTACT", "1", 1);
    ck_assert_uint_eq(_own(eps), 0);
    unsetenv("AT_FIRST_CONTACT");
}
END_TEST_DEFINITION()

DEFINE_TEST(test_no_release_key_trusts_no_shipped_list)
{
    _fresh_root();
    net_relay_ep_t eps[AT_RELAY_MAX];
    net_relay_seeds_set_release_key(NULL);   /* the shipped default: empty */
    _ship(1, "[\"relay://203.0.113.9:1\"]");
    _local(g_node_seed, "[\"relay://198.51.100.7:3\"]", "[]");
    ck_assert_uint_eq(_own(eps), 1);
    ck_assert_str_eq(eps[0].host, "198.51.100.7");
}
END_TEST_DEFINITION()

DEFINE_TEST(test_an_older_list_is_refused_once_a_newer_was_seen)
{
    _fresh_root();
    net_relay_ep_t eps[AT_RELAY_MAX];
    _ship(5, "[\"relay://203.0.113.9:1\"]");
    ck_assert_uint_eq(_own(eps), 1);
    /* Same-size rewrite in the same tick would share a stamp; a new size cannot. */
    _ship(4, "[\"relay://203.0.113.10:1\"]");
    ck_assert_uint_eq(_own(eps), 0);
    _ship(5, "[\"relay://203.0.113.11:11\"]");
    ck_assert_uint_eq(_own(eps), 1);
    ck_assert_str_eq(eps[0].host, "203.0.113.11");
}
END_TEST_DEFINITION()

DEFINE_TEST(test_local_adds_come_first_and_removes_drop_by_endpoint)
{
    _fresh_root();
    net_relay_ep_t eps[AT_RELAY_MAX];
    _ship(1, "[\"" PINNED "\",\"relay://203.0.113.9:1\",\"relay://203.0.113.10:1\"]");
    _local(g_node_seed, "[\"relay://198.51.100.7:3\"]", "[\"198.51.100.1:27790\"]");
    ck_assert_uint_eq(_own(eps), 3);
    ck_assert_str_eq(eps[0].host, "198.51.100.7");
    ck_assert_str_eq(eps[1].host, "203.0.113.9");
    ck_assert_str_eq(eps[2].host, "203.0.113.10");
}
END_TEST_DEFINITION()

DEFINE_TEST(test_the_merge_keeps_the_cap)
{
    _fresh_root();
    net_relay_ep_t eps[AT_RELAY_MAX];
    _ship(1, "[\"relay://10.0.0.1:1\",\"relay://10.0.0.2:1\",\"relay://10.0.0.3:1\","
             "\"relay://10.0.0.4:1\",\"relay://10.0.0.5:1\",\"relay://10.0.0.6:1\"]");
    ck_assert_uint_eq(_own(eps), AT_RELAY_MAX);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_local_edits_signed_by_another_key_are_ignored)
{
    _fresh_root();
    net_relay_ep_t eps[AT_RELAY_MAX];
    _ship(1, "[\"relay://203.0.113.9:1\"]");
    _local(g_release_seed, "[\"relay://198.51.100.7:3\"]", "[]");
    ck_assert_uint_eq(_own(eps), 1);
    ck_assert_str_eq(eps[0].host, "203.0.113.9");
}
END_TEST_DEFINITION()

DEFINE_TEST(test_an_explicit_path_overrides_the_cfg_dir)
{
    _fresh_root();
    net_relay_ep_t eps[AT_RELAY_MAX];
    char *t = _list(g_release_seed, 1, "[\"relay://203.0.113.12:1\"]");
    _write("", "elsewhere.json", t);
    free(t);
    char path[512];
    snprintf(path, sizeof(path), "%s//elsewhere.json", g_root);
    setenv(AT_RELAY_SEEDS_ENV, path, 1);
    ck_assert_uint_eq(_own(eps), 1);
    ck_assert_str_eq(eps[0].host, "203.0.113.12");
    unsetenv(AT_RELAY_SEEDS_ENV);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_a_python_signed_list_verifies)
{
    /* Signed by Python relay_seeds.sign_seeds with seed 0x11*32; the exact
     * bytes pin the two runtimes to one format. */
    _fresh_root();
    const char *py = PY_SIGNED_LIST;
    long long seq = 0;
    net_relay_seed_list_t l;
    ck_assert_int_eq(net_relay_seeds_verify(py, g_release_key, &seq, &l), 0);
    ck_assert_int_eq(seq, 7);
    ck_assert_uint_eq(l.n, 1);
    ck_assert_str_eq(l.eps[0].host, "203.0.113.9");
}
END_TEST_DEFINITION()

RUN_TESTS(NetRelaySeeds,
          test_a_signed_list_round_trips,
          test_the_signature_covers_the_exact_body,
          test_another_key_or_no_key_is_refused,
          test_a_local_edit_signature_does_not_verify_as_a_list,
          test_one_bad_entry_refuses_the_whole_list,
          test_a_version_must_be_the_integer_one,
          test_seed_list_stands_in_only_without_an_explicit_relay,
          test_off_means_off,
          test_no_release_key_trusts_no_shipped_list,
          test_an_older_list_is_refused_once_a_newer_was_seen,
          test_local_adds_come_first_and_removes_drop_by_endpoint,
          test_the_merge_keeps_the_cap,
          test_local_edits_signed_by_another_key_are_ignored,
          test_an_explicit_path_overrides_the_cfg_dir,
          test_a_python_signed_list_verifies)
