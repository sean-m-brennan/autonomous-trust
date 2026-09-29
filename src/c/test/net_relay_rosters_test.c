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

/* Community relay rosters (network/net_relay_rosters), FIRST_CONTACT_PLAN §4.2 /
 * §4.5. Mirrors Python tests/a_unit/test_relay_rosters.py. */

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

#include "network/net_relay.h"
#include "network/net_relay_seeds.h"
#include "network/net_relay_rosters.h"

/* What an Ethne polity emits: en_uplift::rendezvous_roster's byte-pinned
 * vector (ethne/src/rust/en-uplift/src/rendezvous.rs PINNED_VECTOR), issuer
 * seed [7; 32]. The producer and this consumer never share code, so this is the
 * test that they agree on the format. */
#define ETHNE_VECTOR "{\"body\":\"{\\\"v\\\":1,\\\"typename\\\":\\\"at-relay-roster\\\",\\\"issuer\\\":\\\"ea4a6c63e29c520abef5507b132ec5f9954776aebebe7b92421eea691446d22c\\\",\\\"seq\\\":5,\\\"relays\\\":[\\\"relay://0f1e2d3c-4b5a-4968-8776-655443322110:7300c0ae1429cd153252736a781b78f4@relay.example.org:27790\\\",\\\"relay://1a2b3c4d-5e6f-4071-8293-a4b5c6d7e8f9:d7e1e084be213b01e506852af8198b99@[2001:db8::7]:27791\\\"]}\",\"sig\":\"491f75ed4f7472d3c07f204df7de22354eb8a2ba23632af27507822fb94790ebe6b20ac55e69de391b274e6ba850ed148970d7a384c2e8ffe63b578416cd620f\"}"
#define ETHNE_ISSUER "ea4a6c63e29c520abef5507b132ec5f9954776aebebe7b92421eea691446d22c"

static unsigned char g_seed_a[32], g_seed_b[32], g_release_seed[32];
static char g_key_a[65], g_key_b[65], g_release_key[65], g_root[256];

static void _key_of(const unsigned char *seed, char *hex)
{
    unsigned char pk[crypto_sign_PUBLICKEYBYTES], sk[crypto_sign_SECRETKEYBYTES];
    crypto_sign_seed_keypair(pk, sk, seed);
    sodium_bin2hex(hex, 65, pk, sizeof(pk));
}

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

/* A roster from the issuer with @p seed (its key is the body's issuer). */
static char *_roster(const unsigned char *seed, int seq, const char *relays_json)
{
    char key[65], body[4096];
    _key_of(seed, key);
    snprintf(body, sizeof(body),
             "{\"v\":1,\"typename\":\"at-relay-roster\",\"issuer\":\"%s\",\"seq\":%d,"
             "\"relays\":%s}", key, seq, relays_json);
    return _signed(seed, AT_RELAY_ROSTER_DOMAIN, body);
}

/* A pinned hint for relay number @p i. */
#define HINT(i) "\"relay://00000000-0000-4000-8000-00000000000" #i \
    ":abababababababababababababababab@198.51.100." #i ":27790\""

static void _write(const char *dir, const char *name, const char *text)
{
    char path[512];
    snprintf(path, sizeof(path), "%s/%s/%s", g_root, dir, name);
    FILE *f = fopen(path, "w");
    ck_assert(f != NULL);
    fputs(text, f);
    fclose(f);
}

static void _publish(const char *name, const unsigned char *seed, int seq, const char *relays)
{
    /* The hint cache re-reads a file when its size or mtime changes. A rewrite
     * of the same size inside one filesystem timestamp tick (a few ms on
     * tmpfs) would look unchanged, which a test rewriting in a tight loop hits
     * and a host publishing a roster does not. */
    usleep(20000);
    char *t = _roster(seed, seq, relays);
    _write("etc/at/relay_rosters", name, t);
    free(t);
}

static void _pin_file(const char *keys_json)
{
    char doc[512];
    snprintf(doc, sizeof(doc), "{\"issuers\":%s}", keys_json);
    _write("etc/at", AT_RELAY_ROSTER_ISSUERS_FILE, doc);
}

/* A fresh root, first contact on, no explicit relay, no pinned issuer. */
static void _fresh_root(void)
{
    snprintf(g_root, sizeof(g_root), "/tmp/at-rosters-XXXXXX");
    ck_assert(mkdtemp(g_root) != NULL);
    const char *dirs[] = {"etc", "etc/at", "etc/at/relay_rosters", "var", "var/at"};
    for (size_t i = 0; i < sizeof(dirs) / sizeof(dirs[0]); i++) {
        char p[512];
        snprintf(p, sizeof(p), "%s/%s", g_root, dirs[i]);
        mkdir(p, 0755);
    }
    setenv("AUTONOMOUS_TRUST_ROOT", g_root, 1);
    unsetenv("AT_USE_RELAY");
    unsetenv(AT_RELAY_SEEDS_ENV);
    unsetenv(AT_RELAY_ROSTERS_ENV);
    unsetenv(AT_RELAY_ROSTER_ISSUERS_ENV);
    setenv("AT_FIRST_CONTACT", "1", 1);
    memset(g_seed_a, 0x31, sizeof(g_seed_a));
    memset(g_seed_b, 0x32, sizeof(g_seed_b));
    memset(g_release_seed, 0x11, sizeof(g_release_seed));
    _key_of(g_seed_a, g_key_a);
    _key_of(g_seed_b, g_key_b);
    _key_of(g_release_seed, g_release_key);
    net_relay_seeds_set_release_key(g_release_key);
}

static size_t _own(net_relay_ep_t *eps)
{
    return net_relay_own_list(eps, AT_RELAY_MAX);
}

static net_relay_roster_issuers_t _issuers(const char *key)
{
    net_relay_roster_issuers_t is = {0};
    snprintf(is.keys[is.n++], sizeof(is.keys[0]), "%s", key);
    return is;
}

DEFINE_TEST(test_an_ethne_emitted_roster_verifies)
{
    net_relay_roster_issuers_t is = _issuers(ETHNE_ISSUER);
    net_relay_seed_list_t l;
    char issuer[65] = {0};
    long long seq = 0;
    ck_assert_int_eq(net_relay_roster_verify(ETHNE_VECTOR, &is, issuer, &seq, &l), 0);
    ck_assert_str_eq(issuer, ETHNE_ISSUER);
    ck_assert_int_eq(seq, 5);
    ck_assert_uint_eq(l.n, 2);
    ck_assert_str_eq(l.eps[0].host, "relay.example.org");
    ck_assert_int_eq(l.eps[0].port, 27790);
    ck_assert(l.pins[0].set);
    ck_assert_str_eq(l.pins[0].fp, "7300c0ae1429cd153252736a781b78f4");
    ck_assert_str_eq(l.eps[1].host, "2001:db8::7");
    ck_assert_str_eq(l.pins[1].uuid, "1a2b3c4d-5e6f-4071-8293-a4b5c6d7e8f9");
}
END_TEST_DEFINITION()

DEFINE_TEST(test_an_issuer_nobody_pinned_is_refused)
{
    _fresh_root();
    net_relay_roster_issuers_t is = _issuers(g_key_b);
    net_relay_seed_list_t l;
    ck_assert_int_eq(net_relay_roster_verify(ETHNE_VECTOR, &is, NULL, NULL, &l), -1);
    ck_assert_uint_eq(l.n, 0);
    ck_assert_int_eq(net_relay_roster_verify(ETHNE_VECTOR, NULL, NULL, NULL, &l), -1);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_the_signature_covers_the_exact_body)
{
    net_relay_roster_issuers_t is = _issuers(ETHNE_ISSUER);
    char *t = strdup(ETHNE_VECTOR);
    char *at = strstr(t, "seq\\\":5");
    ck_assert(at != NULL);
    at[strlen("seq\\\":")] = '6';
    net_relay_seed_list_t l;
    ck_assert_int_eq(net_relay_roster_verify(t, &is, NULL, NULL, &l), -1);
    free(t);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_a_seed_list_signature_does_not_verify_as_a_roster)
{
    _fresh_root();
    char body[1024];
    snprintf(body, sizeof(body),
             "{\"v\":1,\"typename\":\"at-relay-roster\",\"issuer\":\"%s\",\"seq\":1,"
             "\"relays\":[" HINT(1) "]}", g_key_a);
    char *t = _signed(g_seed_a, AT_RELAY_SEEDS_DOMAIN, body);
    net_relay_roster_issuers_t is = _issuers(g_key_a);
    net_relay_seed_list_t l;
    ck_assert_int_eq(net_relay_roster_verify(t, &is, NULL, NULL, &l), -1);
    free(t);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_an_unpinned_entry_refuses_the_whole_roster)
{
    _fresh_root();
    char *t = _roster(g_seed_a, 1, "[" HINT(1) ",\"relay://203.0.113.9:27790\"]");
    net_relay_roster_issuers_t is = _issuers(g_key_a);
    net_relay_seed_list_t l;
    ck_assert_int_eq(net_relay_roster_verify(t, &is, NULL, NULL, &l), -1);
    ck_assert_uint_eq(l.n, 0);
    free(t);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_a_version_or_seq_out_of_range_is_refused)
{
    _fresh_root();
    net_relay_roster_issuers_t is = _issuers(g_key_a);
    net_relay_seed_list_t l;
    char *t = _roster(g_seed_a, 0, "[" HINT(1) "]");
    ck_assert_int_eq(net_relay_roster_verify(t, &is, NULL, NULL, &l), -1);
    free(t);
    char body[1024];
    snprintf(body, sizeof(body),
             "{\"v\":2,\"typename\":\"at-relay-roster\",\"issuer\":\"%s\",\"seq\":1,"
             "\"relays\":[]}", g_key_a);
    t = _signed(g_seed_a, AT_RELAY_ROSTER_DOMAIN, body);
    ck_assert_int_eq(net_relay_roster_verify(t, &is, NULL, NULL, &l), -1);
    free(t);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_rosters_stand_in_ahead_of_the_seed_list)
{
    _fresh_root();
    char *seeds = NULL;
    {
        char body[512];
        snprintf(body, sizeof(body),
                 "{\"v\":1,\"typename\":\"at-seeds\",\"seq\":1,\"relays\":[" HINT(9) "]}");
        seeds = _signed(g_release_seed, AT_RELAY_SEEDS_DOMAIN, body);
    }
    _write("etc/at", AT_RELAY_SEEDS_FILE, seeds);
    free(seeds);
    _publish("community.cfg.json", g_seed_a, 1, "[" HINT(1) "]");
    net_relay_ep_t eps[AT_RELAY_MAX];
    /* Not pinned yet: only the seed list. */
    ck_assert_uint_eq(_own(eps), 1);
    ck_assert_str_eq(eps[0].host, "198.51.100.9");
    char pins[128];
    snprintf(pins, sizeof(pins), "[\"%s\"]", g_key_a);
    _pin_file(pins);
    ck_assert_uint_eq(_own(eps), 2);
    ck_assert_str_eq(eps[0].host, "198.51.100.1");
    ck_assert_str_eq(eps[1].host, "198.51.100.9");
}
END_TEST_DEFINITION()

DEFINE_TEST(test_an_explicit_relay_wins_and_off_means_off)
{
    _fresh_root();
    setenv(AT_RELAY_ROSTER_ISSUERS_ENV, g_key_a, 1);
    _publish("community.cfg.json", g_seed_a, 1, "[" HINT(1) "]");
    net_relay_ep_t eps[AT_RELAY_MAX];
    setenv("AT_USE_RELAY", "203.0.113.5:27790", 1);
    ck_assert_uint_eq(_own(eps), 1);
    ck_assert_str_eq(eps[0].host, "203.0.113.5");
    unsetenv("AT_USE_RELAY");
    unsetenv("AT_FIRST_CONTACT");
    ck_assert_uint_eq(_own(eps), 0);
    setenv("AT_FIRST_CONTACT", "1", 1);
    ck_assert_uint_eq(_own(eps), 1);
    unsetenv(AT_RELAY_ROSTER_ISSUERS_ENV);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_a_higher_seq_replaces_and_a_lower_is_refused)
{
    _fresh_root();
    setenv(AT_RELAY_ROSTER_ISSUERS_ENV, g_key_a, 1);
    net_relay_ep_t eps[AT_RELAY_MAX];
    _publish("community.cfg.json", g_seed_a, 2, "[" HINT(1) "]");
    ck_assert_uint_eq(_own(eps), 1);
    ck_assert_str_eq(eps[0].host, "198.51.100.1");
    /* Replaced whole: relay 1 is gone, not kept alongside. */
    _publish("community.cfg.json", g_seed_a, 3, "[" HINT(2) "]");
    ck_assert_uint_eq(_own(eps), 1);
    ck_assert_str_eq(eps[0].host, "198.51.100.2");
    /* An older roster reinstalled over a newer is refused. */
    _publish("community.cfg.json", g_seed_a, 1, "[" HINT(3) ", " HINT(4) "]");
    ck_assert_uint_eq(_own(eps), 0);
    unsetenv(AT_RELAY_ROSTER_ISSUERS_ENV);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_an_empty_roster_says_the_community_runs_none)
{
    _fresh_root();
    setenv(AT_RELAY_ROSTER_ISSUERS_ENV, g_key_a, 1);
    net_relay_ep_t eps[AT_RELAY_MAX];
    _publish("community.cfg.json", g_seed_a, 1, "[" HINT(1) "]");
    ck_assert_uint_eq(_own(eps), 1);
    _publish("community.cfg.json", g_seed_a, 2, "[]");
    ck_assert_uint_eq(_own(eps), 0);
    unsetenv(AT_RELAY_ROSTER_ISSUERS_ENV);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_of_two_files_from_one_issuer_the_higher_seq_wins)
{
    _fresh_root();
    setenv(AT_RELAY_ROSTER_ISSUERS_ENV, g_key_a, 1);
    _publish("a-new.cfg.json", g_seed_a, 5, "[" HINT(5) "]");
    _publish("b-old.cfg.json", g_seed_a, 4, "[" HINT(4) "]");
    net_relay_ep_t eps[AT_RELAY_MAX];
    ck_assert_uint_eq(_own(eps), 1);
    ck_assert_str_eq(eps[0].host, "198.51.100.5");
    unsetenv(AT_RELAY_ROSTER_ISSUERS_ENV);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_issuers_count_in_pin_order_env_first)
{
    _fresh_root();
    _publish("a.cfg.json", g_seed_a, 1, "[" HINT(1) "]");
    _publish("b.cfg.json", g_seed_b, 1, "[" HINT(2) "]");
    char pins[160];
    snprintf(pins, sizeof(pins), "[\"%s\", \"%s\"]", g_key_a, g_key_b);
    _pin_file(pins);
    setenv(AT_RELAY_ROSTER_ISSUERS_ENV, g_key_b, 1);
    net_relay_ep_t eps[AT_RELAY_MAX];
    ck_assert_uint_eq(_own(eps), 2);
    ck_assert_str_eq(eps[0].host, "198.51.100.2");   /* b, pinned by the env */
    ck_assert_str_eq(eps[1].host, "198.51.100.1");
    net_relay_roster_issuers_t is;
    ck_assert_uint_eq(net_relay_rosters_pinned(&is), 2);  /* b once, not twice */
    unsetenv(AT_RELAY_ROSTER_ISSUERS_ENV);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_a_malformed_issuer_is_skipped)
{
    _fresh_root();
    char env[200];
    snprintf(env, sizeof(env), "not-a-key, %s ,%.63s", g_key_a, g_key_b);
    setenv(AT_RELAY_ROSTER_ISSUERS_ENV, env, 1);
    net_relay_roster_issuers_t is;
    ck_assert_uint_eq(net_relay_rosters_pinned(&is), 1);
    ck_assert_str_eq(is.keys[0], g_key_a);
    /* An uppercase key is the same key. */
    char upper[65];
    for (int i = 0; i < 65; i++)
        upper[i] = (char)(g_key_b[i] >= 'a' && g_key_b[i] <= 'f' ? g_key_b[i] - 32 : g_key_b[i]);
    setenv(AT_RELAY_ROSTER_ISSUERS_ENV, upper, 1);
    ck_assert_uint_eq(net_relay_rosters_pinned(&is), 1);
    ck_assert_str_eq(is.keys[0], g_key_b);
    unsetenv(AT_RELAY_ROSTER_ISSUERS_ENV);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_an_explicit_dir_overrides_the_cfg_dir)
{
    _fresh_root();
    setenv(AT_RELAY_ROSTER_ISSUERS_ENV, g_key_a, 1);
    char dir[512];
    snprintf(dir, sizeof(dir), "%s/elsewhere", g_root);
    mkdir(dir, 0755);
    setenv(AT_RELAY_ROSTERS_ENV, dir, 1);
    char *t = _roster(g_seed_a, 1, "[" HINT(7) "]");
    char path[600];
    snprintf(path, sizeof(path), "%s/r.cfg.json", dir);
    FILE *f = fopen(path, "w");
    fputs(t, f);
    fclose(f);
    free(t);
    net_relay_ep_t eps[AT_RELAY_MAX];
    ck_assert_uint_eq(_own(eps), 1);
    ck_assert_str_eq(eps[0].host, "198.51.100.7");
    unsetenv(AT_RELAY_ROSTERS_ENV);
    unsetenv(AT_RELAY_ROSTER_ISSUERS_ENV);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_the_merge_keeps_the_cap)
{
    _fresh_root();
    setenv(AT_RELAY_ROSTER_ISSUERS_ENV, g_key_a, 1);
    _publish("r.cfg.json", g_seed_a, 1,
             "[" HINT(1) "," HINT(2) "," HINT(3) "," HINT(4) "," HINT(5) "," HINT(6) "]");
    net_relay_ep_t eps[AT_RELAY_MAX];
    ck_assert_uint_eq(_own(eps), AT_RELAY_MAX);
    ck_assert_str_eq(eps[0].host, "198.51.100.1");
    unsetenv(AT_RELAY_ROSTER_ISSUERS_ENV);
}
END_TEST_DEFINITION()

RUN_TESTS(NetRelayRosters,
          test_an_ethne_emitted_roster_verifies,
          test_an_issuer_nobody_pinned_is_refused,
          test_the_signature_covers_the_exact_body,
          test_a_seed_list_signature_does_not_verify_as_a_roster,
          test_an_unpinned_entry_refuses_the_whole_roster,
          test_a_version_or_seq_out_of_range_is_refused,
          test_rosters_stand_in_ahead_of_the_seed_list,
          test_an_explicit_relay_wins_and_off_means_off,
          test_a_higher_seq_replaces_and_a_lower_is_refused,
          test_an_empty_roster_says_the_community_runs_none,
          test_of_two_files_from_one_issuer_the_higher_seq_wins,
          test_issuers_count_in_pin_order_env_first,
          test_a_malformed_issuer_is_skipped,
          test_an_explicit_dir_overrides_the_cfg_dir,
          test_the_merge_keeps_the_cap)
