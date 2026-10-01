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

/**
 * Unit tests for delegated verification reputation gating.
 *
 * Tests the reputation cache and vouch gating logic that controls
 * whether delegated verification vouches are accepted.  The cache
 * logic mirrors zta_process.c exactly — this validates the algorithm
 * independent of IPC plumbing.
 */

#define DEBUG_TESTS 1
#include "test_setup.h"

#include <string.h>
#include <stdbool.h>
#include <uuid/uuid.h>
#include <sys/time.h>

/* --- Standalone cache implementation (mirrors zta_process.c) --- */

#define ZTA_HASH_LEN 32
#define MAX_REP_CACHE 128
#define MAX_PENDING_VOUCHES 32
#define REP_CACHE_TTL_SEC 600

typedef struct {
    uuid_t uuid;
    double score;
    struct timeval fetched_at;
    bool valid;
} rep_cache_entry_t;

typedef struct {
    uuid_t peer_uuid;
    uuid_t voucher_uuid;
    bool active;
} pending_vouch_t;

static rep_cache_entry_t g_cache[MAX_REP_CACHE];
static int g_cache_count = 0;
static pending_vouch_t g_pending[MAX_PENDING_VOUCHES];
static int g_pending_count = 0;

static bool cache_lookup(const uuid_t peer_uuid, double *score_out)
{
    struct timeval now;
    gettimeofday(&now, NULL);
    for (int i = 0; i < g_cache_count; i++) {
        rep_cache_entry_t *e = &g_cache[i];
        if (!e->valid) continue;
        if (uuid_compare(e->uuid, peer_uuid) != 0) continue;
        long age = now.tv_sec - e->fetched_at.tv_sec;
        if (age > REP_CACHE_TTL_SEC) {
            e->valid = false;
            return false;
        }
        *score_out = e->score;
        return true;
    }
    return false;
}

static void cache_update(const uuid_t peer_uuid, double score)
{
    for (int i = 0; i < g_cache_count; i++) {
        if (g_cache[i].valid &&
            uuid_compare(g_cache[i].uuid, peer_uuid) == 0) {
            g_cache[i].score = score;
            gettimeofday(&g_cache[i].fetched_at, NULL);
            return;
        }
    }
    int slot = -1;
    for (int i = 0; i < g_cache_count; i++) {
        if (!g_cache[i].valid) { slot = i; break; }
    }
    if (slot < 0) {
        if (g_cache_count < MAX_REP_CACHE)
            slot = g_cache_count++;
        else {
            slot = 0;
            for (int i = 1; i < MAX_REP_CACHE; i++) {
                if (g_cache[i].fetched_at.tv_sec < g_cache[slot].fetched_at.tv_sec)
                    slot = i;
            }
        }
    }
    rep_cache_entry_t *e = &g_cache[slot];
    memcpy(e->uuid, peer_uuid, sizeof(uuid_t));
    e->score = score;
    gettimeofday(&e->fetched_at, NULL);
    e->valid = true;
}

static void defer_vouch(const uuid_t peer_uuid, const uuid_t voucher_uuid)
{
    if (g_pending_count >= MAX_PENDING_VOUCHES) return;
    pending_vouch_t *pv = &g_pending[g_pending_count++];
    memcpy(pv->peer_uuid, peer_uuid, sizeof(uuid_t));
    memcpy(pv->voucher_uuid, voucher_uuid, sizeof(uuid_t));
    pv->active = true;
}

static int process_pending(double threshold, int *accepted, int *rejected)
{
    *accepted = 0;
    *rejected = 0;
    int resolved = 0;
    for (int i = g_pending_count - 1; i >= 0; i--) {
        pending_vouch_t *pv = &g_pending[i];
        if (!pv->active) continue;
        double score = 0.0;
        if (!cache_lookup(pv->voucher_uuid, &score)) continue;
        pv->active = false;
        resolved++;
        if (score >= threshold)
            (*accepted)++;
        else
            (*rejected)++;
        if (i < g_pending_count - 1)
            memcpy(pv, &g_pending[--g_pending_count], sizeof(pending_vouch_t));
        else
            g_pending_count--;
    }
    return resolved;
}

static void reset_state(void)
{
    memset(g_cache, 0, sizeof(g_cache));
    g_cache_count = 0;
    memset(g_pending, 0, sizeof(g_pending));
    g_pending_count = 0;
}

/* ---------- tests ---------- */

DEFINE_TEST(test_cache_empty_lookup)
{
    reset_state();
    uuid_t peer;
    uuid_generate(peer);
    double score = -1.0;
    ck_assert(!cache_lookup(peer, &score));
}
END_TEST_DEFINITION()

DEFINE_TEST(test_cache_insert_and_lookup)
{
    reset_state();
    uuid_t peer;
    uuid_generate(peer);
    cache_update(peer, 0.85);

    double score = 0.0;
    ck_assert(cache_lookup(peer, &score));
    ck_assert_double_eq_tol(score, 0.85, 0.001);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_cache_update_existing)
{
    reset_state();
    uuid_t peer;
    uuid_generate(peer);
    cache_update(peer, 0.5);
    cache_update(peer, 0.9);

    double score = 0.0;
    ck_assert(cache_lookup(peer, &score));
    ck_assert_double_eq_tol(score, 0.9, 0.001);

    /* Only one entry should exist */
    int count = 0;
    for (int i = 0; i < g_cache_count; i++)
        if (g_cache[i].valid) count++;
    ck_assert_int_eq(count, 1);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_cache_expiry)
{
    reset_state();
    uuid_t peer;
    uuid_generate(peer);
    cache_update(peer, 0.75);

    /* Backdate the entry past TTL */
    for (int i = 0; i < g_cache_count; i++) {
        if (g_cache[i].valid && uuid_compare(g_cache[i].uuid, peer) == 0) {
            g_cache[i].fetched_at.tv_sec -= REP_CACHE_TTL_SEC + 10;
            break;
        }
    }

    double score = -1.0;
    ck_assert(!cache_lookup(peer, &score));
}
END_TEST_DEFINITION()

DEFINE_TEST(test_cache_multiple_peers)
{
    reset_state();
    uuid_t p1, p2, p3;
    uuid_generate(p1);
    uuid_generate(p2);
    uuid_generate(p3);
    cache_update(p1, 0.1);
    cache_update(p2, 0.5);
    cache_update(p3, 0.9);

    double s = 0.0;
    ck_assert(cache_lookup(p1, &s));
    ck_assert_double_eq_tol(s, 0.1, 0.001);
    ck_assert(cache_lookup(p2, &s));
    ck_assert_double_eq_tol(s, 0.5, 0.001);
    ck_assert(cache_lookup(p3, &s));
    ck_assert_double_eq_tol(s, 0.9, 0.001);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_gating_above_threshold)
{
    reset_state();
    double threshold = 0.7;
    uuid_t voucher;
    uuid_generate(voucher);
    cache_update(voucher, 0.85);

    double rep = 0.0;
    ck_assert(cache_lookup(voucher, &rep));
    ck_assert(rep >= threshold);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_gating_below_threshold)
{
    reset_state();
    double threshold = 0.7;
    uuid_t voucher;
    uuid_generate(voucher);
    cache_update(voucher, 0.4);

    double rep = 0.0;
    ck_assert(cache_lookup(voucher, &rep));
    ck_assert(rep < threshold);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_pending_vouch_defer_and_resolve)
{
    reset_state();
    double threshold = 0.7;
    uuid_t peer, voucher_good, voucher_bad;
    uuid_generate(peer);
    uuid_generate(voucher_good);
    uuid_generate(voucher_bad);

    /* Both vouchers not cached — defer both */
    defer_vouch(peer, voucher_good);
    defer_vouch(peer, voucher_bad);
    ck_assert_int_eq(g_pending_count, 2);

    /* Reputation responses arrive */
    cache_update(voucher_good, 0.85); /* above threshold */
    cache_update(voucher_bad, 0.3);   /* below threshold */

    int accepted = 0, rejected = 0;
    int resolved = process_pending(threshold, &accepted, &rejected);
    ck_assert_int_eq(resolved, 2);
    ck_assert_int_eq(accepted, 1);
    ck_assert_int_eq(rejected, 1);
    ck_assert_int_eq(g_pending_count, 0);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_pending_vouch_partial_resolve)
{
    reset_state();
    double threshold = 0.7;
    uuid_t peer, v1, v2;
    uuid_generate(peer);
    uuid_generate(v1);
    uuid_generate(v2);

    defer_vouch(peer, v1);
    defer_vouch(peer, v2);

    /* Only v1's reputation arrives */
    cache_update(v1, 0.9);

    int accepted = 0, rejected = 0;
    int resolved = process_pending(threshold, &accepted, &rejected);
    ck_assert_int_eq(resolved, 1);
    ck_assert_int_eq(accepted, 1);
    ck_assert_int_eq(g_pending_count, 1); /* v2 still pending */
}
END_TEST_DEFINITION()

RUN_TESTS(ZTA_Delegation,
    test_cache_empty_lookup,
    test_cache_insert_and_lookup,
    test_cache_update_existing,
    test_cache_expiry,
    test_cache_multiple_peers,
    test_gating_above_threshold,
    test_gating_below_threshold,
    test_pending_vouch_defer_and_resolve,
    test_pending_vouch_partial_resolve)
