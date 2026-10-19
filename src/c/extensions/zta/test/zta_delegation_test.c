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

#define DEBUG_TESTS 1
#include "test_setup.h"

#include <stdio.h>
#include <string.h>

#include "zta/zta_delegation.h"

/*
 * Members' ZTA findings (zta_delegation.h, ISSUES §2.20). The verdicts are
 * pinned in both runtimes by the conformance scenarios zta-delegation-vouch
 * and zta-delegation-alert; these cover what a table there cannot reach
 * cheaply: the capacity limits, a quorum configured at 0, the expiry ceiling,
 * and that this node's own answer clears what was counted.
 *
 * Replaces a test that exercised a copy of the old vouch logic rather than
 * the code itself.
 */

static const uint8_t HASH[ZTA_HASH_LEN] = { 1, 2, 3 };
static const char *SUBJECT = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";

static int g_standings;
static peer_standing_t g_last;
static double g_ceiling;
static zta_status_t g_own = ZTA_UNAVAILABLE;

static bool _member(void *u, const char *uuid) { (void)u; (void)uuid; return true; }
static bool _hash(void *u, const char *p, uint8_t out[ZTA_HASH_LEN])
{
    (void)u; (void)p;
    memcpy(out, HASH, ZTA_HASH_LEN);
    return true;
}
static int _rep(void *u, const char *uuid, double *s) { (void)u; (void)uuid; *s = 0.9; return 1; }
static zta_status_t _own(void *u, const char *p) { (void)u; (void)p; return g_own; }
static void _standing(void *u, const char *p, peer_standing_t st, double c, const char *r)
{
    (void)u; (void)p; (void)r;
    g_standings++;
    g_last = st;
    g_ceiling = c;
}

static zta_deleg_ctx_t _ctx(int quorum)
{
    g_standings = 0;
    g_own = ZTA_UNAVAILABLE;
    zta_deleg_ctx_t c = { .is_member = _member, .recorded_hash = _hash, .reputation = _rep,
                          .own_check = _own, .standing = _standing, .min_reputation = 0.7,
                          .quorum = quorum, .ddil_cap = 0.5, .revocation_penalty = 0.8 };
    return c;
}

static void _sender(int i, char out[ZTA_DELEG_UUID_LEN + 1])
{
    snprintf(out, ZTA_DELEG_UUID_LEN + 1, "00000000-0000-4000-8000-%012d", i);
}

DEFINE_TEST(test_quorum_zero_means_one)
{
    static zta_deleg_t d;
    zta_deleg_init(&d);
    zta_deleg_ctx_t c = _ctx(0);
    zta_deleg_own_result(&d, SUBJECT, ZTA_DEFERRED);
    ck_assert_str_eq(zta_deleg_verdict_str(
        zta_deleg_event(&d, &c, ZTA_DELEG_VOUCH, "s", SUBJECT, HASH, ZTA_VERIFIED)), "quorum");
    ck_assert_int_eq(g_standings, 1);
    ck_assert_int_eq(g_last, PEER_STANDING_PROVED);
    ck_assert(g_ceiling < 0.0);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_senders_beyond_capacity_are_full)
{
    static zta_deleg_t d;
    zta_deleg_init(&d);
    zta_deleg_ctx_t c = _ctx(ZTA_DELEG_MAX_SENDERS + 5);
    zta_deleg_own_result(&d, SUBJECT, ZTA_UNAVAILABLE);
    char s[ZTA_DELEG_UUID_LEN + 1];
    for (int i = 0; i < ZTA_DELEG_MAX_SENDERS; i++) {
        _sender(i, s);
        ck_assert_str_eq(zta_deleg_verdict_str(
            zta_deleg_event(&d, &c, ZTA_DELEG_ALERT, s, SUBJECT, HASH, ZTA_REVOKED)), "counted");
    }
    _sender(ZTA_DELEG_MAX_SENDERS, s);
    ck_assert_str_eq(zta_deleg_verdict_str(
        zta_deleg_event(&d, &c, ZTA_DELEG_ALERT, s, SUBJECT, HASH, ZTA_REVOKED)), "full");
    ck_assert_int_eq(g_standings, 0);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_peers_beyond_capacity_are_full)
{
    static zta_deleg_t d;
    zta_deleg_init(&d);
    zta_deleg_ctx_t c = _ctx(2);
    char p[ZTA_DELEG_UUID_LEN + 1];
    for (int i = 0; i < ZTA_DELEG_MAX_PEERS; i++) {
        _sender(i, p);
        zta_deleg_own_result(&d, p, ZTA_DEFERRED);
    }
    ck_assert_int_eq(d.n, ZTA_DELEG_MAX_PEERS);
    /* A new peer an alert would start tracking has no room. */
    ck_assert_str_eq(zta_deleg_verdict_str(
        zta_deleg_event(&d, &c, ZTA_DELEG_ALERT, "s", SUBJECT, HASH, ZTA_REVOKED)), "full");
}
END_TEST_DEFINITION()

DEFINE_TEST(test_own_answer_clears_what_was_counted)
{
    static zta_deleg_t d;
    zta_deleg_init(&d);
    zta_deleg_ctx_t c = _ctx(2);
    zta_deleg_own_result(&d, SUBJECT, ZTA_UNAVAILABLE);
    ck_assert_str_eq(zta_deleg_verdict_str(
        zta_deleg_event(&d, &c, ZTA_DELEG_ALERT, "a", SUBJECT, HASH, ZTA_REVOKED)), "counted");
    zta_deleg_own_result(&d, SUBJECT, ZTA_VERIFIED);
    ck_assert_int_eq(d.peers[0].n_alert, 0);
    ck_assert(!d.peers[0].unverified);
    /* "a" counts afresh, so one more sender does not reach the quorum of 2. */
    ck_assert_str_eq(zta_deleg_verdict_str(
        zta_deleg_event(&d, &c, ZTA_DELEG_ALERT, "a", SUBJECT, HASH, ZTA_REVOKED)), "counted");
    ck_assert_int_eq(g_standings, 0);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_failed_ceiling)
{
    ck_assert_double_eq_tol(zta_deleg_failed_ceiling(ZTA_REVOKED, 0.8), 0.2, 1e-9);
    ck_assert_double_eq_tol(zta_deleg_failed_ceiling(ZTA_REJECTED, 0.8), 0.2, 1e-9);
    ck_assert_double_eq_tol(zta_deleg_failed_ceiling(ZTA_EXPIRED, 0.8), 0.6, 1e-9);
    ck_assert_double_eq_tol(zta_deleg_failed_ceiling(ZTA_REVOKED, 1.5), 0.0, 1e-9);
    ck_assert_double_eq_tol(zta_deleg_failed_ceiling(ZTA_REVOKED, -1.0), 1.0, 1e-9);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_verdict_strings_are_distinct)
{
    for (int a = ZTA_DELEG_NOT_MEMBER; a <= ZTA_DELEG_FULL; a++) {
        ck_assert(strcmp(zta_deleg_verdict_str((zta_deleg_verdict_t)a), "unknown") != 0);
        for (int b = a + 1; b <= ZTA_DELEG_FULL; b++)
            ck_assert(strcmp(zta_deleg_verdict_str((zta_deleg_verdict_t)a),
                             zta_deleg_verdict_str((zta_deleg_verdict_t)b)) != 0);
    }
}
END_TEST_DEFINITION()

RUN_TESTS(ZTA_Delegation,
    test_quorum_zero_means_one,
    test_senders_beyond_capacity_are_full,
    test_peers_beyond_capacity_are_full,
    test_own_answer_clears_what_was_counted,
    test_failed_ceiling,
    test_verdict_strings_are_distinct)
