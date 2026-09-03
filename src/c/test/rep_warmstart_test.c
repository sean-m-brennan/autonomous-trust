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

/* Verifiable warm start (doc/architecture/reputation.md): the persisted evidence document,
 * the checks that gate adopting it, the per-peer ceilings it supports, and the
 * staleness decay it composes with.
 *
 * The document is SHARED with the Python runtime, so the round-trip tests here
 * are also a format pin: the field names and the derived-from-linkage rules
 * have to stay what the Python writer emits. The process-side wiring
 * (_rebuild_from_evidence and friends) is exercised by the conformance
 * scenarios; these cover the pure functions underneath it.
 */

#define DEBUG_TESTS 1
#include "test_setup.h"

#include <string.h>
#include <stdlib.h>
#include <math.h>
#include <uuid/uuid.h>

#include "autonomous_trust/reputation/reputation.h"
#include "autonomous_trust/structures/map.h"
#include "autonomous_trust/structures/data.h"

/* Commit `n` bilateral transactions between two peers, each side scoring
 * `score`. Returns via out-params so a test can name the peers. */
static void _fill_pair(tx_history_t *hist, const uuid_t p1, const uuid_t p2,
                       int n, double score)
{
    for (int i = 0; i < n; i++)
    {
        uuid_t task;
        uuid_generate(task);
        tx_history_update(hist, task, p1, score, NULL);
        tx_history_update(hist, task, p2, score, NULL);
    }
}

/* A checkpoint over the whole resident window of `hist`, unsigned. */
static void _checkpoint_over(const tx_history_t *hist, rep_checkpoint_t *ckpt,
                             const char *proposer)
{
    ckpt->group_uuid[0] = '\0';   /* primary chain */
    strncpy(ckpt->proposer_uuid, proposer, UUID_STRING_LEN);
    ckpt->proposer_uuid[UUID_STRING_LEN] = '\0';
    transaction_window_root(hist, ckpt->root);
    ckpt->epoch = 4;
    ckpt->count = hist->committed_count;
    ckpt->first_index = (ckpt->count > 0) ? hist->first_index
                                          : hist->next_index;
    ckpt->present = true;
}

/* --- document format ------------------------------------------------------ */

DEFINE_TEST(test_evidence_roundtrip_preserves_chain_and_checkpoint)
{
    tx_history_t hist;
    ck_assert_ret_ok(tx_history_init(&hist));
    uuid_t p1, p2;
    uuid_generate(p1);
    uuid_generate(p2);
    _fill_pair(&hist, p1, p2, 3, 0.9);

    char proposer[UUID_STRING_LEN + 1];
    uuid_unparse_lower(p1, proposer);
    rep_checkpoint_t ckpt;
    ck_assert_ret_ok(rep_checkpoint_init(&ckpt));
    _checkpoint_over(&hist, &ckpt, proposer);
    map_set(&ckpt.sigs, (map_key_t)proposer, string_data((string_t)"ab", 2));

    json_t *doc = NULL;
    ck_assert_ret_ok(reputation_evidence_to_json(&hist, &ckpt, &doc));
    ck_assert_ptr_nonnull(doc);
    /* Field names are the shared contract with the Python writer. */
    ck_assert_str_eq(json_string_value(json_object_get(doc, "schema")),
                     REP_EVIDENCE_SCHEMA);
    json_t *chain = json_object_get(doc, "chain");
    ck_assert(json_is_array(chain));
    ck_assert_int_eq((int)json_array_size(chain), 3);
    json_t *first = json_array_get(chain, 0);
    ck_assert_ptr_nonnull(json_object_get(first, "task_id"));
    ck_assert_ptr_nonnull(json_object_get(first, "p1_id"));
    ck_assert_ptr_nonnull(json_object_get(first, "p2_score"));
    ck_assert_ptr_nonnull(json_object_get(first, "prev_hash"));

    tx_history_t back;
    ck_assert_ret_ok(tx_history_init(&back));
    rep_checkpoint_t ckpt_back;
    ck_assert_ret_ok(rep_checkpoint_init(&ckpt_back));
    ck_assert_ret_ok(reputation_evidence_from_json(doc, &back, &ckpt_back));
    ck_assert_int_eq(back.committed_count, 3);
    /* The root reproduces across the round trip — the only reason a restart
     * can check the entries against what was signed. */
    char root_back[TX_HASH_HEX_LEN + 1];
    transaction_window_root(&back, root_back);
    ck_assert_str_eq(root_back, ckpt.root);
    ck_assert_str_eq(ckpt_back.root, ckpt.root);
    ck_assert_str_eq(ckpt_back.proposer_uuid, proposer);
    ck_assert_int_eq((int)ckpt_back.epoch, 4);
    ck_assert_int_eq(ckpt_back.count, 3);
    ck_assert(ckpt_back.present);

    json_decref(doc);
    rep_checkpoint_free(&ckpt);
    rep_checkpoint_free(&ckpt_back);
    tx_history_free(&hist);
    tx_history_free(&back);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_evidence_omits_uncommitted_entries)
{
    /* A tx with no counterparty yet is not evidence of anything, so it stays
     * out of the document rather than arriving un-indexed. */
    tx_history_t hist;
    ck_assert_ret_ok(tx_history_init(&hist));
    uuid_t task, peer;
    uuid_generate(task);
    uuid_generate(peer);
    tx_history_update(&hist, task, peer, 0.8, NULL);   /* one-sided */

    json_t *doc = NULL;
    ck_assert_ret_ok(reputation_evidence_to_json(&hist, NULL, &doc));
    ck_assert_int_eq((int)json_array_size(json_object_get(doc, "chain")), 0);
    ck_assert(json_is_null(json_object_get(doc, "checkpoint")));
    json_decref(doc);
    tx_history_free(&hist);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_evidence_wrong_schema_is_refused)
{
    /* Pinned so a future shape change is a refusal to rebuild — which degrades
     * safely to clamped restoration — rather than a misparse. */
    json_t *doc = json_pack("{s:s, s:[], s:n}", "schema", "99",
                            "chain", "checkpoint");
    ck_assert_ptr_nonnull(doc);
    tx_history_t hist;
    ck_assert_ret_ok(tx_history_init(&hist));
    ck_assert_ret_nonzero(reputation_evidence_from_json(doc, &hist, NULL));
    json_decref(doc);
    tx_history_free(&hist);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_evidence_broken_hash_link_is_refused)
{
    tx_history_t hist;
    ck_assert_ret_ok(tx_history_init(&hist));
    uuid_t p1, p2;
    uuid_generate(p1);
    uuid_generate(p2);
    _fill_pair(&hist, p1, p2, 3, 0.9);
    json_t *doc = NULL;
    ck_assert_ret_ok(reputation_evidence_to_json(&hist, NULL, &doc));

    /* Raise a committed score in the file. That changes the entry's hash, so
     * its successor's prev_hash no longer matches: tamper-evident. */
    json_t *entry = json_array_get(json_object_get(doc, "chain"), 0);
    json_object_set_new(entry, "p2_score", json_real(1.0));

    tx_history_t back;
    ck_assert_ret_ok(tx_history_init(&back));
    ck_assert_ret_nonzero(reputation_evidence_from_json(doc, &back, NULL));
    /* Nothing adopted: an unverified chain must not be able to feed the
     * scoring path back up to where it was. */
    ck_assert_int_eq(back.committed_count, 0);

    json_decref(doc);
    tx_history_free(&hist);
    tx_history_free(&back);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_evidence_entry_without_index_is_refused)
{
    tx_history_t hist;
    ck_assert_ret_ok(tx_history_init(&hist));
    uuid_t p1, p2;
    uuid_generate(p1);
    uuid_generate(p2);
    _fill_pair(&hist, p1, p2, 2, 0.9);
    json_t *doc = NULL;
    ck_assert_ret_ok(reputation_evidence_to_json(&hist, NULL, &doc));
    json_t *entry = json_array_get(json_object_get(doc, "chain"), 0);
    json_object_del(entry, "index");

    tx_history_t back;
    ck_assert_ret_ok(tx_history_init(&back));
    ck_assert_ret_nonzero(reputation_evidence_from_json(doc, &back, NULL));
    json_decref(doc);
    tx_history_free(&hist);
    tx_history_free(&back);
}
END_TEST_DEFINITION()

/* --- the checkpoint window ------------------------------------------------ */

DEFINE_TEST(test_checkpoint_window_root_matches_signed_root)
{
    tx_history_t hist;
    ck_assert_ret_ok(tx_history_init(&hist));
    uuid_t p1, p2;
    uuid_generate(p1);
    uuid_generate(p2);
    _fill_pair(&hist, p1, p2, 5, 0.9);
    char proposer[UUID_STRING_LEN + 1];
    uuid_unparse_lower(p1, proposer);
    rep_checkpoint_t ckpt;
    ck_assert_ret_ok(rep_checkpoint_init(&ckpt));
    _checkpoint_over(&hist, &ckpt, proposer);

    char root[TX_HASH_HEX_LEN + 1];
    ck_assert_ret_ok(reputation_checkpoint_window_root(&hist, &ckpt, root));
    ck_assert_str_eq(root, ckpt.root);
    rep_checkpoint_free(&ckpt);
    tx_history_free(&hist);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_checkpoint_window_root_ignores_later_commits)
{
    /* A persisted chain may legitimately run PAST its checkpoint: commits land
     * after the checkpoint finalizes, and the file is rewritten when the
     * fuller co-signature set arrives. The window is therefore selected by
     * absolute index, not taken as the whole chain. */
    tx_history_t hist;
    ck_assert_ret_ok(tx_history_init(&hist));
    uuid_t p1, p2;
    uuid_generate(p1);
    uuid_generate(p2);
    _fill_pair(&hist, p1, p2, 4, 0.9);
    char proposer[UUID_STRING_LEN + 1];
    uuid_unparse_lower(p1, proposer);
    rep_checkpoint_t ckpt;
    ck_assert_ret_ok(rep_checkpoint_init(&ckpt));
    _checkpoint_over(&hist, &ckpt, proposer);

    _fill_pair(&hist, p1, p2, 2, 0.4);   /* two more commits, post-checkpoint */
    char root[TX_HASH_HEX_LEN + 1];
    ck_assert_ret_ok(reputation_checkpoint_window_root(&hist, &ckpt, root));
    ck_assert_str_eq(root, ckpt.root);
    rep_checkpoint_free(&ckpt);
    tx_history_free(&hist);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_checkpoint_window_short_is_refused)
{
    /* A missing entry makes the root unreproducible, so a partial window is
     * refused rather than partially credited. */
    tx_history_t hist;
    ck_assert_ret_ok(tx_history_init(&hist));
    uuid_t p1, p2;
    uuid_generate(p1);
    uuid_generate(p2);
    _fill_pair(&hist, p1, p2, 3, 0.9);
    char proposer[UUID_STRING_LEN + 1];
    uuid_unparse_lower(p1, proposer);
    rep_checkpoint_t ckpt;
    ck_assert_ret_ok(rep_checkpoint_init(&ckpt));
    _checkpoint_over(&hist, &ckpt, proposer);
    ckpt.count = 4;   /* claims one more entry than the chain holds */

    char root[TX_HASH_HEX_LEN + 1];
    ck_assert_ret_nonzero(reputation_checkpoint_window_root(&hist, &ckpt, root));
    rep_checkpoint_free(&ckpt);
    tx_history_free(&hist);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_checkpoint_designation_is_the_python_form)
{
    /* Byte-identical to Python Checkpoint.designation, nonce excluded on both
     * sides. If this drifts, every cross-runtime co-signature silently stops
     * verifying — there is no other symptom. */
    uint8_t buf[512];
    size_t n = rep_checkpoint_designation(
        "11111111-2222-3333-4444-555555555555",
        "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789",
        7, 2, 5, NULL, buf, sizeof(buf));
    ck_assert(n > 0);
    ck_assert_mem_eq(buf, "AT-CKPT", 8);   /* tag + its NUL separator */
    ck_assert_str_eq((const char *)buf + 8,
                     "11111111-2222-3333-4444-555555555555|"
                     "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"
                     "|7|2|5");

    /* A CHILD-chain designation appends the group, so a co-signature harvested
     * from a child-group round can never read as agreement about the primary
     * chain -- two chains can perfectly well share a root, epoch and bounds
     * (doc/architecture/gateway-reputation-tree.md). The primary form above is unchanged, which is what keeps every
     * pinned scenario and the Python twin verifying. */
    uint8_t child[512];
    size_t cn = rep_checkpoint_designation(
        "11111111-2222-3333-4444-555555555555",
        "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789",
        7, 2, 5, "99999999-8888-7777-6666-555555555555", child, sizeof(child));
    ck_assert(cn > n);
    ck_assert_str_eq((const char *)child + 8,
                     "11111111-2222-3333-4444-555555555555|"
                     "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"
                     "|7|2|5|99999999-8888-7777-6666-555555555555");
}
END_TEST_DEFINITION()

/* --- gateway child chains (doc/architecture/gateway-reputation-tree.md)
 * ------------------------------ */

DEFINE_TEST(test_evidence_document_carries_the_chain)
{
    /* A gateway writes one document per chain, and each has to say WHICH chain
     * it covers: the group is inside the signed designation, so a restart that
     * lost it could not re-derive the bytes the co-signatures were made over. */
    tx_history_t hist;
    ck_assert_ret_ok(tx_history_init(&hist));
    uuid_t p1, p2, child;
    uuid_generate(p1);
    uuid_generate(p2);
    uuid_generate(child);
    _fill_pair(&hist, p1, p2, 3, 0.9);

    char proposer[UUID_STRING_LEN + 1], child_str[UUID_STRING_LEN + 1];
    uuid_unparse_lower(p1, proposer);
    uuid_unparse_lower(child, child_str);
    rep_checkpoint_t ckpt;
    ck_assert_ret_ok(rep_checkpoint_init(&ckpt));
    _checkpoint_over(&hist, &ckpt, proposer);
    snprintf(ckpt.group_uuid, sizeof(ckpt.group_uuid), "%s", child_str);

    json_t *doc = NULL;
    ck_assert_ret_ok(reputation_evidence_to_json(&hist, &ckpt, &doc));
    json_t *ck = json_object_get(doc, "checkpoint");
    ck_assert(json_is_object(ck));
    ck_assert_str_eq(json_string_value(json_object_get(ck, "group_uuid")),
                     child_str);

    rep_checkpoint_t back_ck;
    ck_assert_ret_ok(rep_checkpoint_init(&back_ck));
    tx_history_t back;
    ck_assert_ret_ok(tx_history_init(&back));
    ck_assert_ret_ok(reputation_evidence_from_json(doc, &back, &back_ck));
    ck_assert_str_eq(back_ck.group_uuid, child_str);
    /* ...and the designation rebuilt from the parsed document is the child
     * form, not the primary one. */
    uint8_t d1[512], d2[512];
    size_t n1 = rep_checkpoint_designation(back_ck.proposer_uuid, back_ck.root,
                                           back_ck.epoch, back_ck.first_index,
                                           back_ck.count, back_ck.group_uuid,
                                           d1, sizeof(d1));
    size_t n2 = rep_checkpoint_designation(back_ck.proposer_uuid, back_ck.root,
                                           back_ck.epoch, back_ck.first_index,
                                           back_ck.count, NULL, d2, sizeof(d2));
    ck_assert(n1 > n2);
    ck_assert(memcmp(d1, d2, n2) == 0);   /* the child form EXTENDS the primary */

    json_decref(doc);
    rep_checkpoint_free(&ckpt);
    rep_checkpoint_free(&back_ck);
    tx_history_free(&hist);
    tx_history_free(&back);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_primary_document_omits_no_chain_marker)
{
    /* The primary document's group is the empty string, and its designation is
     * byte-identical to what it was before child chains existed -- which is
     * what keeps every existing co-signature, pinned scenario and the Python
     * twin verifying. */
    tx_history_t hist;
    ck_assert_ret_ok(tx_history_init(&hist));
    uuid_t p1, p2;
    uuid_generate(p1);
    uuid_generate(p2);
    _fill_pair(&hist, p1, p2, 2, 0.9);
    char proposer[UUID_STRING_LEN + 1];
    uuid_unparse_lower(p1, proposer);
    rep_checkpoint_t ckpt;
    ck_assert_ret_ok(rep_checkpoint_init(&ckpt));
    _checkpoint_over(&hist, &ckpt, proposer);

    json_t *doc = NULL;
    ck_assert_ret_ok(reputation_evidence_to_json(&hist, &ckpt, &doc));
    json_t *ck = json_object_get(doc, "checkpoint");
    ck_assert_str_eq(json_string_value(json_object_get(ck, "group_uuid")), "");

    uint8_t with_empty[512], with_null[512];
    size_t ne = rep_checkpoint_designation(proposer, ckpt.root, ckpt.epoch,
                                           ckpt.first_index, ckpt.count, "",
                                           with_empty, sizeof(with_empty));
    size_t nn = rep_checkpoint_designation(proposer, ckpt.root, ckpt.epoch,
                                           ckpt.first_index, ckpt.count, NULL,
                                           with_null, sizeof(with_null));
    ck_assert(ne == nn);
    ck_assert(memcmp(with_empty, with_null, ne) == 0);

    json_decref(doc);
    rep_checkpoint_free(&ckpt);
    tx_history_free(&hist);
}
END_TEST_DEFINITION()

/* --- evidence ceilings --------------------------------------------------- */

DEFINE_TEST(test_evidence_ceilings_shrink_toward_neutral)
{
    tx_history_t hist;
    ck_assert_ret_ok(tx_history_init(&hist));
    uuid_t p1, p2;
    uuid_generate(p1);
    uuid_generate(p2);
    _fill_pair(&hist, p1, p2, 20, 0.9);
    char proposer[UUID_STRING_LEN + 1], other[UUID_STRING_LEN + 1];
    uuid_unparse_lower(p1, proposer);
    uuid_unparse_lower(p2, other);
    rep_checkpoint_t ckpt;
    ck_assert_ret_ok(rep_checkpoint_init(&ckpt));
    _checkpoint_over(&hist, &ckpt, proposer);

    map_t ceilings;
    ck_assert_ret_ok(map_init(&ceilings));
    /* proposer == self here, so it must be excluded: our own score is not a
     * peer judgement. */
    ck_assert_ret_ok(reputation_evidence_ceilings(&hist, &ckpt, proposer,
                                                  &ceilings));
    data_t *d = NULL;
    ck_assert_ret_nonzero(map_get(&ceilings, (map_key_t)proposer, &d));
    ck_assert_ret_ok(map_get(&ceilings, (map_key_t)other, &d));
    double ceiling = 0.0;
    ck_assert_ret_ok(data_floating_pt_dbl(d, &ceiling));
    double expect = (20.0 * 0.9 + REP_RESTORE_SHRINKAGE_K * PREREP_NEUTRAL)
                    / (20.0 + REP_RESTORE_SHRINKAGE_K);
    ck_assert_double_eq_tol(ceiling, expect, 1e-12);
    /* Strictly below the observed mean: shrinkage means same-valued
     * transactions approach their own score only from below, so an honest
     * score is always bounded by slightly less than it. */
    ck_assert_double_lt(ceiling, 0.9);

    map_free(&ceilings);
    rep_checkpoint_free(&ckpt);
    tx_history_free(&hist);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_short_window_supports_little)
{
    /* Two transactions at 0.9 are two data points, not a track record. Without
     * the pseudo-count they would license the same standing as two hundred,
     * and a forger would only need to mint the shortest chain that verifies. */
    tx_history_t hist;
    ck_assert_ret_ok(tx_history_init(&hist));
    uuid_t p1, p2;
    uuid_generate(p1);
    uuid_generate(p2);
    _fill_pair(&hist, p1, p2, 2, 0.9);
    char proposer[UUID_STRING_LEN + 1], other[UUID_STRING_LEN + 1];
    uuid_unparse_lower(p1, proposer);
    uuid_unparse_lower(p2, other);
    rep_checkpoint_t ckpt;
    ck_assert_ret_ok(rep_checkpoint_init(&ckpt));
    _checkpoint_over(&hist, &ckpt, proposer);

    map_t ceilings;
    ck_assert_ret_ok(map_init(&ceilings));
    ck_assert_ret_ok(reputation_evidence_ceilings(&hist, &ckpt, NULL,
                                                  &ceilings));
    data_t *d = NULL;
    ck_assert_ret_ok(map_get(&ceilings, (map_key_t)other, &d));
    double ceiling = 0.0;
    ck_assert_ret_ok(data_floating_pt_dbl(d, &ceiling));
    /* Below the tier-1 floor (0.50): a two-entry window earns no elevation. */
    ck_assert_double_lt(ceiling, 0.5);
    map_free(&ceilings);
    rep_checkpoint_free(&ckpt);
    tx_history_free(&hist);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_evidence_ceilings_ignore_entries_outside_the_window)
{
    /* Only what the checkpoint attests may bound a score. Commits made after
     * the checkpoint are persisted but unattested, so they must not raise (or
     * lower) the ceiling. */
    tx_history_t hist;
    ck_assert_ret_ok(tx_history_init(&hist));
    uuid_t p1, p2;
    uuid_generate(p1);
    uuid_generate(p2);
    _fill_pair(&hist, p1, p2, 10, 0.9);
    char proposer[UUID_STRING_LEN + 1], other[UUID_STRING_LEN + 1];
    uuid_unparse_lower(p1, proposer);
    uuid_unparse_lower(p2, other);
    rep_checkpoint_t ckpt;
    ck_assert_ret_ok(rep_checkpoint_init(&ckpt));
    _checkpoint_over(&hist, &ckpt, proposer);
    _fill_pair(&hist, p1, p2, 10, 0.1);   /* unattested, and much worse */

    map_t ceilings;
    ck_assert_ret_ok(map_init(&ceilings));
    ck_assert_ret_ok(reputation_evidence_ceilings(&hist, &ckpt, NULL,
                                                  &ceilings));
    data_t *d = NULL;
    ck_assert_ret_ok(map_get(&ceilings, (map_key_t)other, &d));
    double ceiling = 0.0;
    ck_assert_ret_ok(data_floating_pt_dbl(d, &ceiling));
    double expect = (10.0 * 0.9 + REP_RESTORE_SHRINKAGE_K * PREREP_NEUTRAL)
                    / (10.0 + REP_RESTORE_SHRINKAGE_K);
    ck_assert_double_eq_tol(ceiling, expect, 1e-12);
    map_free(&ceilings);
    rep_checkpoint_free(&ckpt);
    tx_history_free(&hist);
}
END_TEST_DEFINITION()

/* --- the loader feeds the scoring path ----------------------------------- */

DEFINE_TEST(test_loaded_chain_is_visible_to_scoring)
{
    /* The loaders used to skip peer_map, and every scoring function reaches
     * its transactions through tx_history_by_peer, which reads peer_map ONLY.
     * A restored (or caught-up) chain was therefore resident and invisible:
     * present in the window, worth nothing to any algorithm consuming it. */
    tx_history_t hist;
    ck_assert_ret_ok(tx_history_init(&hist));
    uuid_t p1, p2;
    uuid_generate(p1);
    uuid_generate(p2);
    _fill_pair(&hist, p1, p2, 6, 0.9);
    json_t *doc = NULL;
    ck_assert_ret_ok(reputation_evidence_to_json(&hist, NULL, &doc));

    tx_history_t back;
    ck_assert_ret_ok(tx_history_init(&back));
    ck_assert_ret_ok(reputation_evidence_from_json(doc, &back, NULL));
    ck_assert_int_eq(back.committed_count, 6);

    transaction_t out[MAX_CHAIN_LEN];
    int count = 0;
    ck_assert_ret_ok(tx_history_by_peer(&back, p2, out, &count,
                                        MAX_CHAIN_LEN));
    ck_assert_int_eq(count, 6);
    /* ...and the consensus EMA therefore moves off its seed. */
    double consensus = reputation_consensus(&back, p2, NULL);
    ck_assert_double_lt(0.5, consensus);

    json_decref(doc);
    tx_history_free(&hist);
    tx_history_free(&back);
}
END_TEST_DEFINITION()

/* --- staleness decay ----------------------------------------------------- */

DEFINE_TEST(test_decay_leaves_a_fresh_score_alone)
{
    /* Onset grace period: a brief out-of-range gap costs nothing. */
    ck_assert_double_eq_tol(reputation_decayed_score(0.9, 0.0), 0.9, 1e-12);
    ck_assert_double_eq_tol(reputation_decayed_score(0.9, REP_DECAY_ONSET),
                            0.9, 1e-12);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_decay_halves_the_gap_at_the_half_life)
{
    double start = 0.9;
    double asymptote = REP_DECAY_ASYMPTOTE;
    double got = reputation_decayed_score(
        start, REP_DECAY_ONSET + REP_DECAY_HALF_LIFE);
    ck_assert_double_eq_tol(got, asymptote + (start - asymptote) / 2.0, 1e-12);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_decay_never_overshoots_the_asymptote)
{
    /* A long-known asset stays faintly preferred over a true stranger; its
     * elevated tier lapses, its memory does not vanish. */
    double got = reputation_decayed_score(0.95, REP_DECAY_HALF_LIFE * 1000.0);
    ck_assert_double_lt(REP_DECAY_ASYMPTOTE - 1e-12, got);
    ck_assert_double_lt(got, 0.3);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_decay_is_asymmetric)
{
    /* Mere absence must never rehabilitate a distrusted or corrupt node, so a
     * score at or below the asymptote is returned untouched however long the
     * peer has been gone. */
    double low = 0.05;
    ck_assert_double_eq_tol(
        reputation_decayed_score(low, REP_DECAY_HALF_LIFE * 100.0),
        low, 1e-12);
    double at = REP_DECAY_ASYMPTOTE;
    ck_assert_double_eq_tol(
        reputation_decayed_score(at, REP_DECAY_HALF_LIFE * 100.0), at, 1e-12);
}
END_TEST_DEFINITION()

RUN_TESTS(RepWarmStart,
          test_evidence_roundtrip_preserves_chain_and_checkpoint,
          test_evidence_omits_uncommitted_entries,
          test_evidence_wrong_schema_is_refused,
          test_evidence_broken_hash_link_is_refused,
          test_evidence_entry_without_index_is_refused,
          test_checkpoint_window_root_matches_signed_root,
          test_checkpoint_window_root_ignores_later_commits,
          test_checkpoint_window_short_is_refused,
          test_checkpoint_designation_is_the_python_form,
          test_evidence_document_carries_the_chain,
          test_primary_document_omits_no_chain_marker,
          test_evidence_ceilings_shrink_toward_neutral,
          test_short_window_supports_little,
          test_evidence_ceilings_ignore_entries_outside_the_window,
          test_loaded_chain_is_visible_to_scoring,
          test_decay_leaves_a_fresh_score_alone,
          test_decay_halves_the_gap_at_the_half_life,
          test_decay_never_overshoots_the_asymptote,
          test_decay_is_asymmetric)
