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

/* Deep resolution: one peer, on demand, at any depth (doc/architecture/gateway-reputation-tree.md).
 *
 * A node holds chains only for its own groups, so a peer two levels down is
 * unscoreable locally. Rather than enumerate the subtree -- a cost that grows
 * with the TREE to answer about one PEER -- the query is relayed toward the
 * holder and the answer returns carrying the quorum-signed window that backs
 * it.
 *
 * The load-bearing property, and most of what is asserted below: an answer is
 * checked by RECOMPUTING the root from the entries it carries. That is what
 * makes withheld entries detectable. Inclusion proofs would show the entries
 * present are genuine while saying nothing about the ones left out, and a
 * holder shading its own subtree would omit rather than invent.
 *
 * The evidence document is shared with the Python runtime, so the round-trip
 * here is also a format pin. The relay wiring (handle_resolve / handle_resolved
 * and their pending table) is exercised by the conformance scenarios and by
 * tests/a_unit/test_deep_resolution.py; these cover what is reachable without
 * a live process.
 */

#define DEBUG_TESTS 1
#include "test_setup.h"

#include <string.h>
#include <stdlib.h>
#include <math.h>
#include <uuid/uuid.h>

#include "autonomous_trust/reputation/reputation.h"
#include "autonomous_trust/reputation/rep_proc_priv.h"
#include "autonomous_trust/structures/map.h"
#include "autonomous_trust/structures/data.h"

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

/* An answer document: the evidence for `hist` plus the resolution envelope
 * (query id, peer, holder's score, carried signers). Mirrors Python
 * resolved_to_dict. */
static json_t *_answer_doc(const tx_history_t *hist, const char *peer_str)
{
    rep_checkpoint_t ckpt;
    ck_assert_int_eq(rep_checkpoint_init(&ckpt), 0);
    ckpt.present = true;
    transaction_window_root(hist, ckpt.root);
    snprintf(ckpt.proposer_uuid, sizeof(ckpt.proposer_uuid),
             "11111111-1111-1111-1111-111111111111");
    ckpt.epoch = 4;
    ckpt.first_index = 0;
    ckpt.count = tx_history_len(hist);
    json_t *doc = NULL;
    ck_assert_int_eq(reputation_evidence_to_json(hist, &ckpt, &doc), 0);
    ck_assert_ptr_nonnull(doc);
    rep_checkpoint_free(&ckpt);
    json_object_set_new(doc, "query_id", json_string("q1"));
    json_object_set_new(doc, "peer_uuid", json_string(peer_str));
    json_object_set_new(doc, "score", json_real(0.9));
    json_object_set_new(doc, "signers", json_array());
    return doc;
}

/* Re-parse a document and report whether its entries still reproduce the root
 * its checkpoint claims -- the single check that defeats both fabrication and
 * omission, and the one a verifier applies before looking at a signature. */
static bool _root_reproduces(json_t *doc)
{
    tx_history_t parsed;
    tx_history_init(&parsed);
    rep_checkpoint_t ckpt;
    if (rep_checkpoint_init(&ckpt) != 0)
        return false;
    if (reputation_evidence_from_json(doc, &parsed, &ckpt) != 0)
    {
        tx_history_free(&parsed);
        rep_checkpoint_free(&ckpt);
        return false;
    }
    char recomputed[TX_HASH_HEX_LEN + 1];
    transaction_window_root(&parsed, recomputed);
    bool ok = ckpt.present && strcmp(recomputed, ckpt.root) == 0;
    tx_history_free(&parsed);
    rep_checkpoint_free(&ckpt);
    return ok;
}

DEFINE_TEST(honest_answer_reproduces_its_root)
{
    tx_history_t hist;
    tx_history_init(&hist);
    uuid_t holder, peer;
    uuid_generate(holder);
    uuid_generate(peer);
    _fill_pair(&hist, holder, peer, 4, 0.9);
    char peer_str[UUID_STRING_LEN + 1];
    uuid_unparse_lower(peer, peer_str);

    json_t *doc = _answer_doc(&hist, peer_str);
    ck_assert(_root_reproduces(doc));
    json_decref(doc);
    tx_history_free(&hist);
}
END_TEST_DEFINITION()

DEFINE_TEST(withheld_entry_is_detectable)
{
    /* The property the whole payload shape exists for. */
    tx_history_t hist;
    tx_history_init(&hist);
    uuid_t holder, peer;
    uuid_generate(holder);
    uuid_generate(peer);
    _fill_pair(&hist, holder, peer, 5, 0.9);
    char peer_str[UUID_STRING_LEN + 1];
    uuid_unparse_lower(peer, peer_str);

    json_t *doc = _answer_doc(&hist, peer_str);
    json_t *chain = json_object_get(doc, "chain");
    ck_assert(json_is_array(chain));
    size_t before = json_array_size(chain);
    ck_assert_int_eq(json_array_remove(chain, before - 1), 0);
    ck_assert(!_root_reproduces(doc));
    json_decref(doc);
    tx_history_free(&hist);
}
END_TEST_DEFINITION()

DEFINE_TEST(edited_score_is_detectable)
{
    tx_history_t hist;
    tx_history_init(&hist);
    uuid_t holder, peer;
    uuid_generate(holder);
    uuid_generate(peer);
    _fill_pair(&hist, holder, peer, 3, 0.9);
    char peer_str[UUID_STRING_LEN + 1];
    uuid_unparse_lower(peer, peer_str);

    json_t *doc = _answer_doc(&hist, peer_str);
    json_t *entry = json_array_get(json_object_get(doc, "chain"), 0);
    json_object_set_new(entry, "p2_score", json_real(0.01));
    ck_assert(!_root_reproduces(doc));
    json_decref(doc);
    tx_history_free(&hist);
}
END_TEST_DEFINITION()

DEFINE_TEST(score_over_the_attested_window_matches_the_chain)
{
    /* A verifier recomputes from the window it was handed rather than trusting
     * the number beside it, so the two must agree for an honest answer. */
    tx_history_t hist;
    tx_history_init(&hist);
    uuid_t holder, peer;
    uuid_generate(holder);
    uuid_generate(peer);
    _fill_pair(&hist, holder, peer, 4, 0.8);
    char peer_str[UUID_STRING_LEN + 1];
    uuid_unparse_lower(peer, peer_str);
    double direct = reputation_consensus(&hist, peer, NULL);

    json_t *doc = _answer_doc(&hist, peer_str);
    tx_history_t parsed;
    tx_history_init(&parsed);
    rep_checkpoint_t ckpt;
    ck_assert_int_eq(rep_checkpoint_init(&ckpt), 0);
    ck_assert_int_eq(reputation_evidence_from_json(doc, &parsed, &ckpt), 0);
    double from_evidence = reputation_consensus(&parsed, peer, NULL);
    ck_assert_double_eq_tol(direct, from_evidence, 1e-9);

    rep_checkpoint_free(&ckpt);
    tx_history_free(&parsed);
    json_decref(doc);
    tx_history_free(&hist);
}
END_TEST_DEFINITION()

DEFINE_TEST(a_leaf_has_nowhere_to_forward)
{
    /* No child groups: the query cannot go anywhere, and saying so is what
     * lets a caller distinguish "no answer yet" from "no answer possible". */
    process_t proc = {0};
    uuid_t peer;
    uuid_generate(peer);
    char peer_str[UUID_STRING_LEN + 1];
    uuid_unparse_lower(peer, peer_str);
    ck_assert_uint_eq(reputation_deep_resolve(&proc, "q-leaf", peer_str, 4), 0);
}
END_TEST_DEFINITION()

DEFINE_TEST(unanswered_peer_has_no_recorded_outcome)
{
    uuid_t peer;
    uuid_generate(peer);
    char peer_str[UUID_STRING_LEN + 1];
    uuid_unparse_lower(peer, peer_str);
    double score = -1.0;
    bool have = true, verified = true;
    char reason[64] = "unset";
    ck_assert(!reputation_resolved_get(peer_str, &score, &have, &verified,
                                       reason, sizeof(reason)));
}
END_TEST_DEFINITION()

DEFINE_TEST(originating_a_query_tracks_it_even_with_nowhere_to_send)
{
    /* The outstanding table is what a late answer is matched against, so it is
     * recorded before the forward, not after a successful one. */
    process_t proc = {0};
    uuid_t peer;
    uuid_generate(peer);
    char peer_str[UUID_STRING_LEN + 1];
    uuid_unparse_lower(peer, peer_str);
    size_t before = reputation_resolve_outstanding_count();
    reputation_deep_resolve(&proc, "q-tracked", peer_str, 4);
    ck_assert_uint_eq(reputation_resolve_outstanding_count(), before + 1);
    /* Nothing was relayed on our behalf: a query we originated is ours, not
     * one we are carrying for somebody else. */
    ck_assert_uint_eq(reputation_resolve_pending_count(), 0);
}
END_TEST_DEFINITION()

RUN_TESTS("rep_resolve",
          honest_answer_reproduces_its_root,
          withheld_entry_is_detectable,
          edited_score_is_detectable,
          score_over_the_attested_window_matches_the_chain,
          a_leaf_has_nowhere_to_forward,
          unanswered_peer_has_no_recorded_outcome,
          originating_a_query_tracks_it_even_with_nowhere_to_send)
