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

#include <string.h>
#include <stdlib.h>
#include <uuid/uuid.h>
#include <jansson.h>

#include "autonomous_trust/reputation/reputation.h"

DEFINE_TEST(test_tx_history_by_task)
{
    tx_history_t hist;
    ck_assert_ret_ok(tx_history_init(&hist));

    uuid_t task1, task2, peer1, cp;
    uuid_generate(task1);
    uuid_generate(task2);
    uuid_generate(peer1);
    uuid_generate(cp);

    /* Each task needs both slots filled to count as committed —
     * matches Python TransactionHistory semantics where __len__
     * == len(_chain) and `_chain.append` runs only on the
     * bilateral transition. */
    ck_assert_ret_ok(tx_history_update(&hist, task1, peer1, 0.9));
    ck_assert_ret_ok(tx_history_update(&hist, task1, cp, 0.7));
    ck_assert_ret_ok(tx_history_update(&hist, task2, peer1, 0.5));
    ck_assert_ret_ok(tx_history_update(&hist, task2, cp, 0.4));
    ck_assert_int_eq(tx_history_len(&hist), 2);

    transaction_t out;
    memset(&out, 0, sizeof(out));
    ck_assert_ret_ok(tx_history_by_task(&hist, task1, &out));
    ck_assert_double_eq_tol(out.p1_score, 0.9, 0.001);

    tx_history_free(&hist);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_tx_history_by_peer)
{
    tx_history_t hist;
    ck_assert_ret_ok(tx_history_init(&hist));

    uuid_t task1, task2, task3, peer1, peer2, cp;
    uuid_generate(task1);
    uuid_generate(task2);
    uuid_generate(task3);
    uuid_generate(peer1);
    uuid_generate(peer2);
    uuid_generate(cp);

    /* peer1 is in two committed transactions (task1, task2);
     * peer2 is in one (task3). After Bug 6 fix the chain only
     * tracks bilateral commits, but peer_map is appended on
     * every update() call so the count of peer1 entries is 2. */
    ck_assert_ret_ok(tx_history_update(&hist, task1, peer1, 0.8));
    ck_assert_ret_ok(tx_history_update(&hist, task1, cp, 0.5));
    ck_assert_ret_ok(tx_history_update(&hist, task2, peer1, 0.6));
    ck_assert_ret_ok(tx_history_update(&hist, task2, cp, 0.4));
    ck_assert_ret_ok(tx_history_update(&hist, task3, peer2, 0.9));
    ck_assert_ret_ok(tx_history_update(&hist, task3, cp, 0.3));

    transaction_t results[10];
    int count = 0;
    ck_assert_ret_ok(tx_history_by_peer(&hist, peer1, results, &count, 10));
    ck_assert_int_eq(count, 2);

    tx_history_free(&hist);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_tx_history_era)
{
    tx_history_t hist;
    ck_assert_ret_ok(tx_history_init(&hist));

    uuid_t tasks[5], peer, cp;
    uuid_generate(peer);
    uuid_generate(cp);
    /* Fill each task bilaterally so all five enter the committed
     * chain. era's start/end are positional within the committed
     * subsequence (mirrors Python's _chain[offset:]). */
    for (int i = 0; i < 5; i++) {
        uuid_generate(tasks[i]);
        ck_assert_ret_ok(tx_history_update(&hist, tasks[i], peer, 0.1 * (i + 1)));
        ck_assert_ret_ok(tx_history_update(&hist, tasks[i], cp, 0.05 * (i + 1)));
    }
    ck_assert_int_eq(tx_history_len(&hist), 5);

    transaction_t results[10];
    int count = 0;
    ck_assert_ret_ok(tx_history_era(&hist, 1, 3, results, &count));
    ck_assert_int_eq(count, 2);

    tx_history_free(&hist);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_reputation_pure)
{
    tx_history_t hist;
    reputations_t reps;
    ck_assert_ret_ok(tx_history_init(&hist));
    ck_assert_ret_ok(reputations_init(&reps));

    uuid_t peer1, task1;
    uuid_generate(peer1);
    uuid_generate(task1);

    /* Set up some history and reputation */
    ck_assert_ret_ok(tx_history_update(&hist, task1, peer1, 0.9));
    ck_assert_ret_ok(reputations_update(&reps, peer1, 0.85));

    double score = reputation_pure(&hist, &reps, peer1, NULL);
    /* Score should be between 0 and 1 */
    ck_assert(score >= 0.0);
    ck_assert(score <= 1.0);

    tx_history_free(&hist);
    reputations_free(&reps);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_reputation_compute)
{
    tx_history_t hist;
    reputations_t reps;
    ck_assert_ret_ok(tx_history_init(&hist));
    ck_assert_ret_ok(reputations_init(&reps));

    uuid_t self_uuid, peer_uuid, task;
    uuid_generate(self_uuid);
    uuid_generate(peer_uuid);
    uuid_generate(task);

    ck_assert_ret_ok(tx_history_update(&hist, task, peer_uuid, 0.7));
    ck_assert_ret_ok(reputations_update(&reps, peer_uuid, 0.8));

    double score = reputation_compute(&hist, &reps, self_uuid, peer_uuid, NULL);
    ck_assert(score >= 0.0);
    ck_assert(score <= 1.0);

    tx_history_free(&hist);
    reputations_free(&reps);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_reputations_create_destroy)
{
    reputations_t *reps = NULL;
    ck_assert_ret_ok(reputations_create(&reps));
    ck_assert_ptr_nonnull(reps);

    uuid_t peer;
    uuid_generate(peer);
    ck_assert(reputations_contains(reps, peer) == false);

    ck_assert_ret_ok(reputations_update(reps, peer, 0.75));
    ck_assert(reputations_contains(reps, peer) == true);

    double score = 0.0;
    ck_assert_ret_ok(reputations_get(reps, peer, &score));
    ck_assert_double_eq_tol(score, 0.75, 0.001);

    reputations_free(reps);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_tx_history_eviction)
{
    /* Pin the bounded-chain behavior: after MAX_CHAIN_LEN bilateral
     * inserts the oldest tx is evicted FIFO, by_task no longer finds
     * the evicted task_uuid, and by_peer drops the oldest reference
     * so the count caps at the chain length (not the number of
     * inserts ever seen). Mirrors the Python pin in
     * tests/a_unit/test_reputation.py — keep this lockstep with
     * TransactionHistory's eviction semantics. */
    tx_history_t hist;
    ck_assert_ret_ok(tx_history_init(&hist));

    const int extra = 5;  /* inserts past the cap */
    const int total = MAX_CHAIN_LEN + extra;
    uuid_t *tasks = malloc(sizeof(uuid_t) * total);
    uuid_t shared_peer;
    uuid_generate(shared_peer);

    for (int i = 0; i < total; i++)
    {
        uuid_generate(tasks[i]);
        uuid_t cp_peer;
        uuid_generate(cp_peer);
        ck_assert_ret_ok(tx_history_update(&hist, tasks[i], shared_peer, 0.7));
        ck_assert_ret_ok(tx_history_update(&hist, tasks[i], cp_peer, 0.3));
    }
    ck_assert_int_eq(tx_history_len(&hist), MAX_CHAIN_LEN);

    /* The first `extra` task_uuids are evicted; by_task returns
     * EREP_NOTX. */
    transaction_t out;
    for (int i = 0; i < extra; i++)
        ck_assert(tx_history_by_task(&hist, tasks[i], &out) != 0);
    /* The most recent inserts are still present. */
    for (int i = total - 1; i >= total - 3; i--)
        ck_assert_ret_ok(tx_history_by_task(&hist, tasks[i], &out));

    /* by_peer is bounded by the residency window: shared_peer is in
     * every retained tx, so we get exactly MAX_CHAIN_LEN back (not
     * `total`). */
    transaction_t *results = malloc(sizeof(transaction_t) * total);
    int count = 0;
    ck_assert_ret_ok(tx_history_by_peer(&hist, shared_peer, results, &count, total));
    ck_assert_int_eq(count, MAX_CHAIN_LEN);

    free(results);
    free(tasks);
    tx_history_free(&hist);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_tx_history_evicted_task_does_not_reanimate)
{
    /* Late `committed` broadcasts arrive at handle_committed and
     * call tx_history_update without knowing whether the task was
     * already rolled out. Once a task_uuid has been evicted,
     * tx_history_update must refuse to re-add it. Mirrors Python's
     * test_evicted_task_does_not_reanimate; keep in lockstep. */
    tx_history_t hist;
    ck_assert_ret_ok(tx_history_init(&hist));

    /* Fill past the cap so the first task is evicted. */
    uuid_t first_task;
    uuid_generate(first_task);
    {
        uuid_t cp;
        uuid_generate(cp);
        ck_assert_ret_ok(tx_history_update(&hist, first_task, cp, 0.7));
        uuid_t cp2;
        uuid_generate(cp2);
        ck_assert_ret_ok(tx_history_update(&hist, first_task, cp2, 0.3));
    }
    for (int i = 0; i < MAX_CHAIN_LEN + 1; i++)
    {
        uuid_t tid, p1, p2;
        uuid_generate(tid);
        uuid_generate(p1);
        uuid_generate(p2);
        ck_assert_ret_ok(tx_history_update(&hist, tid, p1, 0.7));
        ck_assert_ret_ok(tx_history_update(&hist, tid, p2, 0.3));
    }
    ck_assert_int_eq(tx_history_len(&hist), MAX_CHAIN_LEN);
    /* first_task should be gone from task_map. */
    transaction_t probe;
    ck_assert(tx_history_by_task(&hist, first_task, &probe) != 0);

    /* Late `committed` for the evicted task — both sides. The
     * update must be a no-op: no orphan in task_map, no chain
     * regrowth, no displacement of legitimate recent entries. */
    int len_before = tx_history_len(&hist);
    uuid_t late_p1, late_p2;
    uuid_generate(late_p1);
    uuid_generate(late_p2);
    ck_assert_ret_ok(tx_history_update(&hist, first_task, late_p1, 0.7));
    ck_assert_ret_ok(tx_history_update(&hist, first_task, late_p2, 0.3));
    ck_assert_int_eq(tx_history_len(&hist), len_before);
    ck_assert(tx_history_by_task(&hist, first_task, &probe) != 0);

    tx_history_free(&hist);
}
END_TEST_DEFINITION()

/* ----- Phase 1: prev-hash linking (reputation-vs-blockchain-analysis
 * §2.1). Lockstep with the Python twin in tests/a_unit/test_reputation.py
 * (TestTransactionHistory Phase-1 tests). The canonical serialization and
 * blake2b hashing are byte-identical across languages. */

DEFINE_TEST(test_tx_history_hash_links)
{
    tx_history_t hist;
    ck_assert_ret_ok(tx_history_init(&hist));
    for (int i = 0; i < 4; i++)
    {
        uuid_t tid, p1, p2;
        uuid_generate(tid);
        uuid_generate(p1);
        uuid_generate(p2);
        ck_assert_ret_ok(tx_history_update(&hist, tid, p1, 0.7));
        ck_assert_ret_ok(tx_history_update(&hist, tid, p2, 0.5));
    }
    /* Genesis entry chains from the empty digest. */
    ck_assert_int_eq((int)strlen(hist.chain[0].prev_hash), 0);
    /* Each entry's prev_hash equals the previous entry's entry_hash. */
    for (int i = 1; i < hist.chain_len; i++)
    {
        char expect[TX_HASH_HEX_LEN + 1];
        transaction_entry_hash(&hist.chain[i - 1], expect);
        ck_assert_str_eq(hist.chain[i].prev_hash, expect);
    }
    ck_assert(tx_history_verify_links(&hist));
    tx_history_free(&hist);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_tx_history_verify_links_detects_tampering)
{
    tx_history_t hist;
    ck_assert_ret_ok(tx_history_init(&hist));
    for (int i = 0; i < 4; i++)
    {
        uuid_t tid, p1, p2;
        uuid_generate(tid);
        uuid_generate(p1);
        uuid_generate(p2);
        ck_assert_ret_ok(tx_history_update(&hist, tid, p1, 0.7));
        ck_assert_ret_ok(tx_history_update(&hist, tid, p2, 0.5));
    }
    ck_assert(tx_history_verify_links(&hist));
    /* Mutating a committed score changes that entry's hash, breaking the
     * link its successor recorded. */
    hist.chain[1].p1_score = 0.99;
    ck_assert(!tx_history_verify_links(&hist));
    tx_history_free(&hist);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_tx_history_links_survive_eviction)
{
    /* Eviction drops the head and never rewrites the tail's prev_hash, so
     * the resident window stays internally linked. */
    tx_history_t hist;
    ck_assert_ret_ok(tx_history_init(&hist));
    const int total = MAX_CHAIN_LEN + 6;
    for (int i = 0; i < total; i++)
    {
        uuid_t tid, p1, p2;
        uuid_generate(tid);
        uuid_generate(p1);
        uuid_generate(p2);
        ck_assert_ret_ok(tx_history_update(&hist, tid, p1, 0.7));
        ck_assert_ret_ok(tx_history_update(&hist, tid, p2, 0.5));
    }
    ck_assert_int_eq(tx_history_len(&hist), MAX_CHAIN_LEN);
    ck_assert(tx_history_verify_links(&hist));
    tx_history_free(&hist);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_tx_history_catchup_rejects_broken_chain)
{
    /* Serialize a valid committed chain, corrupt a middle entry in the
     * wire JSON, then deserialize into a fresh history: era_from_json must
     * verify the segment's linkage and load nothing. Mirrors Python's
     * test_catchup_rejects_broken_chain. */
    tx_history_t src;
    ck_assert_ret_ok(tx_history_init(&src));
    for (int i = 0; i < 4; i++)
    {
        uuid_t tid, p1, p2;
        uuid_generate(tid);
        uuid_generate(p1);
        uuid_generate(p2);
        ck_assert_ret_ok(tx_history_update(&src, tid, p1, 0.7));
        ck_assert_ret_ok(tx_history_update(&src, tid, p2, 0.5));
    }
    json_t *good = NULL;
    ck_assert_ret_ok(tx_history_era_to_json(&src, 0, tx_history_len(&src), &good));

    /* Clean chain loads fully. */
    tx_history_t dst;
    ck_assert_ret_ok(tx_history_init(&dst));
    ck_assert_ret_ok(tx_history_era_from_json(&dst, good));
    ck_assert_int_eq(tx_history_len(&dst), 4);
    ck_assert(tx_history_verify_links(&dst));

    /* Corrupt entry[1]'s p2_score so its hash no longer matches entry[2]'s
     * recorded prev_hash. */
    json_t *bad = json_deep_copy(good);
    json_t *entry1 = json_array_get(bad, 1);
    json_object_set_new(entry1, "p2_score", json_real(-1.0));
    tx_history_t dst2;
    ck_assert_ret_ok(tx_history_init(&dst2));
    ck_assert_ret_ok(tx_history_era_from_json(&dst2, bad));
    ck_assert_int_eq(tx_history_len(&dst2), 0);  /* rejected wholesale */

    json_decref(good);
    json_decref(bad);
    tx_history_free(&src);
    tx_history_free(&dst);
    tx_history_free(&dst2);
}
END_TEST_DEFINITION()

/* ----- Phase 2: ordered Merkle root over the resident window
 * (reputation-vs-blockchain-analysis.md §2.1). Lockstep with the Python twin
 * in tests/a_unit/test_reputation.py (TestTransactionHistory Phase-2 tests).
 * The RFC 6962 MTH is byte-identical across languages. */

static void fill_committed(tx_history_t *hist, int n)
{
    for (int i = 0; i < n; i++)
    {
        uuid_t tid, p1, p2;
        uuid_generate(tid);
        uuid_generate(p1);
        uuid_generate(p2);
        ck_assert_ret_ok(tx_history_update(hist, tid, p1, 0.7));
        ck_assert_ret_ok(tx_history_update(hist, tid, p2, 0.5));
    }
}

DEFINE_TEST(test_tx_window_root_deterministic_and_content_bound)
{
    tx_history_t hist;
    ck_assert_ret_ok(tx_history_init(&hist));
    fill_committed(&hist, 5);
    char root1[TX_HASH_HEX_LEN + 1], root2[TX_HASH_HEX_LEN + 1];
    transaction_window_root(&hist, root1);
    transaction_window_root(&hist, root2);
    /* Pure function of content: recomputing yields the same root. */
    ck_assert_str_eq(root1, root2);
    ck_assert_int_eq((int)strlen(root1), TX_HASH_HEX_LEN);
    /* Mutating any committed entry moves the root. */
    hist.chain[2].p1_score = 0.123456789;
    char root3[TX_HASH_HEX_LEN + 1];
    transaction_window_root(&hist, root3);
    ck_assert(strcmp(root1, root3) != 0);
    tx_history_free(&hist);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_tx_window_empty_root_is_hash_of_empty)
{
    tx_history_t hist;
    ck_assert_ret_ok(tx_history_init(&hist));
    char root[TX_HASH_HEX_LEN + 1];
    transaction_window_root(&hist, root);
    /* blake2b of the empty string, hex-encoded — matches Python
     * MerkleTree.get_hash(b''). */
    unsigned char digest[32];
    crypto_generichash(digest, sizeof(digest), (const unsigned char *)"", 0, NULL, 0);
    char expect[TX_HASH_HEX_LEN + 1];
    sodium_bin2hex(expect, sizeof(expect), digest, sizeof(digest));
    ck_assert_str_eq(root, expect);
    tx_history_free(&hist);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_tx_window_inclusion_proof_verifies)
{
    /* 7 entries (not a power of two) — every committed entry must produce a
     * proof that folds back to the live window root. */
    tx_history_t hist;
    ck_assert_ret_ok(tx_history_init(&hist));
    fill_committed(&hist, 7);
    char root[TX_HASH_HEX_LEN + 1];
    transaction_window_root(&hist, root);
    for (int i = 0; i < hist.chain_len; i++)
    {
        if (hist.chain[i].index < 0)
            continue;
        tx_merkle_step_t steps[MAX_CHAIN_LEN];
        int n_steps = 0;
        ck_assert_ret_ok(transaction_window_proof(&hist, hist.chain[i].index,
                                                  steps, &n_steps));
        char leaf[TX_HASH_HEX_LEN + 1];
        transaction_entry_hash(&hist.chain[i], leaf);
        ck_assert(tx_merkle_verify(leaf, steps, n_steps, root));
    }
    tx_history_free(&hist);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_tx_window_inclusion_rejects_wrong)
{
    tx_history_t hist;
    ck_assert_ret_ok(tx_history_init(&hist));
    fill_committed(&hist, 4);
    char root[TX_HASH_HEX_LEN + 1];
    transaction_window_root(&hist, root);
    tx_merkle_step_t steps[MAX_CHAIN_LEN];
    int n_steps = 0;
    ck_assert_ret_ok(transaction_window_proof(&hist, hist.chain[1].index,
                                              steps, &n_steps));
    /* Wrong leaf under a valid proof/root -> reject. */
    char other_leaf[TX_HASH_HEX_LEN + 1];
    transaction_entry_hash(&hist.chain[2], other_leaf);
    ck_assert(!tx_merkle_verify(other_leaf, steps, n_steps, root));
    /* Correct leaf/proof but wrong root -> reject. */
    char leaf[TX_HASH_HEX_LEN + 1];
    transaction_entry_hash(&hist.chain[1], leaf);
    char bad_root[TX_HASH_HEX_LEN + 1];
    memcpy(bad_root, root, sizeof(bad_root));
    bad_root[0] = (bad_root[0] == 'a') ? 'b' : 'a';
    ck_assert(!tx_merkle_verify(leaf, steps, n_steps, bad_root));
    /* Absent index -> no proof. */
    int rc = transaction_window_proof(&hist, 9999, steps, &n_steps);
    ck_assert_int_eq(rc, -1);
    ck_assert_int_eq(n_steps, 0);
    tx_history_free(&hist);
}
END_TEST_DEFINITION()

RUN_TESTS(Reputation2, test_tx_history_by_task, test_tx_history_by_peer,
          test_tx_history_era, test_reputation_pure,
          test_reputation_compute, test_reputations_create_destroy,
          test_tx_history_eviction,
          test_tx_history_evicted_task_does_not_reanimate,
          test_tx_history_hash_links,
          test_tx_history_verify_links_detects_tampering,
          test_tx_history_links_survive_eviction,
          test_tx_history_catchup_rejects_broken_chain,
          test_tx_window_root_deterministic_and_content_bound,
          test_tx_window_empty_root_is_hash_of_empty,
          test_tx_window_inclusion_proof_verifies,
          test_tx_window_inclusion_rejects_wrong)
