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

/* Verifier-attested scores, the chain's half (doc/architecture/reputation.md,
 * "Verifier-attested scores"). The quorum round is pinned by the conformance
 * corpus (scenarios/reputation/attest-*); these cover what travels with the
 * entry -- the catch-up wire, the evidence document, a fork -- which a
 * single-step scenario cannot reach. Mirrors tests/a_unit/test_attested_scores.py. */

#define DEBUG_TESTS 1
#include "test_setup.h"

#include <string.h>
#include <stdlib.h>
#include <uuid/uuid.h>

#include "autonomous_trust/reputation/reputation.h"

static const char DIGEST[] =
    "abababababababababababababababababababababababababababababababab";
static const char CERT[] = "{\"v\":\"sig\"}";

static uuid_t g_v, g_s;

static transaction_t _attested(double score, const char *channel)
{
    transaction_t tx;
    memset(&tx, 0, sizeof(tx));
    tx.attested = true;
    tx.p1_set = true;
    uuid_copy(tx.p1_uuid, g_v);
    uuid_copy(tx.subject_uuid, g_s);
    tx.p1_score = score;
    snprintf(tx.p1_channel, sizeof(tx.p1_channel), "%s", channel);
    snprintf(tx.evidence_digest, sizeof(tx.evidence_digest), "%s", DIGEST);
    tx_attest_task_uuid(g_v, g_s, DIGEST, tx.task_uuid);
    tx.index = -1;
    return tx;
}

static void _bilateral(tx_history_t *h, double a, double b)
{
    uuid_t t;
    uuid_generate(t);
    ck_assert_ret_ok(tx_history_update(h, t, g_v, a, NULL));
    ck_assert_ret_ok(tx_history_update(h, t, g_s, b, NULL));
}

static bool _same_root(const tx_history_t *a, const tx_history_t *b)
{
    char ra[TX_HASH_HEX_LEN + 1], rb[TX_HASH_HEX_LEN + 1];
    transaction_window_root(a, ra);
    transaction_window_root(b, rb);
    return strcmp(ra, rb) == 0;
}

DEFINE_TEST(test_attest_append_rules)
{
    uuid_generate(g_v);
    uuid_generate(g_s);
    tx_history_t h;
    ck_assert_ret_ok(tx_history_init(&h));

    transaction_t bad = _attested(0.3, "first_person");
    ck_assert(tx_history_append_attested(&h, &bad, NULL) != 0);
    bad = _attested(0.3, "probe");
    uuid_generate(bad.task_uuid);              /* not the derived id */
    ck_assert(tx_history_append_attested(&h, &bad, NULL) != 0);
    bad = _attested(1.5, "probe");
    ck_assert(tx_history_append_attested(&h, &bad, NULL) != 0);
    ck_assert_int_eq(tx_history_len(&h), 0);

    transaction_t tx = _attested(0.3, "probe");
    ck_assert_ret_ok(tx_history_append_attested(&h, &tx, CERT));
    ck_assert_int_eq(tx_history_len(&h), 1);
    ck_assert(tx_history_append_attested(&h, &tx, CERT) != 0);   /* duplicate */
    ck_assert_str_eq(tx_history_attest_cert(&h, tx.task_uuid), CERT);

    /* Nothing may fill the half its subject never gave. */
    ck_assert_ret_ok(tx_history_update(&h, tx.task_uuid, g_s, 1.0, NULL));
    transaction_t out;
    ck_assert_ret_ok(tx_history_by_task(&h, tx.task_uuid, &out));
    ck_assert(!out.p2_set);

    /* About its subject only, scored by the verifier. */
    double sc = 0.0;
    uuid_t author;
    ck_assert(transaction_score_about(&out, g_s, &sc, author));
    ck_assert(sc > 0.299 && sc < 0.301);
    ck_assert_int_eq(uuid_compare(author, g_v), 0);
    ck_assert(!transaction_score_about(&out, g_v, &sc, NULL));
    tx_history_free(&h);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_attest_rides_the_catch_up_wire)
{
    uuid_generate(g_v);
    uuid_generate(g_s);
    tx_history_t ours, fresh;
    ck_assert_ret_ok(tx_history_init(&ours));
    ck_assert_ret_ok(tx_history_init(&fresh));
    _bilateral(&ours, 0.9, 0.9);
    transaction_t tx = _attested(0.3, "probe");
    ck_assert_ret_ok(tx_history_append_attested(&ours, &tx, CERT));
    _bilateral(&ours, 0.8, 0.8);

    json_t *wire = NULL;
    ck_assert_ret_ok(tx_history_era_to_json(&ours, 0, tx_history_len(&ours), &wire));
    tx_reconcile_result_t res;
    ck_assert_ret_ok(tx_history_reconcile(&fresh, wire, -1, &res));
    json_decref(wire);
    ck_assert_int_eq(tx_history_len(&fresh), 3);
    ck_assert(tx_history_verify_links(&fresh));
    ck_assert(_same_root(&fresh, &ours));          /* verbatim, attested included */
    ck_assert(tx_history_attest_cert(&fresh, tx.task_uuid) != NULL);
    tx_reconcile_result_free(&res);
    tx_history_free(&ours);
    tx_history_free(&fresh);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_attest_survives_the_evidence_document)
{
    uuid_generate(g_v);
    uuid_generate(g_s);
    tx_history_t h, back;
    ck_assert_ret_ok(tx_history_init(&h));
    ck_assert_ret_ok(tx_history_init(&back));
    _bilateral(&h, 0.9, 0.9);
    transaction_t tx = _attested(0.3, "probe");
    ck_assert_ret_ok(tx_history_append_attested(&h, &tx, CERT));

    json_t *doc = NULL;
    ck_assert_ret_ok(reputation_evidence_to_json(&h, NULL, &doc));
    ck_assert_ret_ok(reputation_evidence_from_json(doc, &back, NULL));
    json_decref(doc);
    ck_assert(_same_root(&h, &back));
    ck_assert(tx_history_attest_cert(&back, tx.task_uuid) != NULL);
    tx_history_free(&h);
    tx_history_free(&back);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_attest_a_fork_hands_it_back)
{
    /* The re-append itself lives in rep_proc (_reappend_attested); what the
     * chain owes it is the dropped entry, whole, and its certificate. */
    uuid_generate(g_v);
    uuid_generate(g_s);
    tx_history_t ours, theirs;
    ck_assert_ret_ok(tx_history_init(&ours));
    ck_assert_ret_ok(tx_history_init(&theirs));
    transaction_t tx = _attested(0.3, "probe");
    ck_assert_ret_ok(tx_history_append_attested(&ours, &tx, CERT));
    _bilateral(&theirs, 0.9, 0.9);
    _bilateral(&theirs, 0.8, 0.8);

    json_t *wire = NULL;
    ck_assert_ret_ok(tx_history_era_to_json(&theirs, 0, tx_history_len(&theirs), &wire));
    tx_reconcile_result_t res;
    ck_assert_ret_ok(tx_history_reconcile(&ours, wire, -1, &res));
    json_decref(wire);
    ck_assert_int_eq(res.status, TX_RECONCILE_ADOPTED);
    ck_assert_int_eq(res.dropped, 1);
    ck_assert(res.dropped_entries[0].attested);
    ck_assert(tx_history_attest_cert(&ours, tx.task_uuid) != NULL);

    /* Re-appended on top of the adopted chain, it links. */
    transaction_t again = res.dropped_entries[0];
    again.index = -1;
    ck_assert_ret_ok(tx_history_append_attested(&ours, &again,
                                                tx_history_attest_cert(&ours, tx.task_uuid)));
    ck_assert_int_eq(tx_history_len(&ours), 3);
    ck_assert(tx_history_verify_links(&ours));
    tx_reconcile_result_free(&res);
    tx_history_free(&ours);
    tx_history_free(&theirs);
}
END_TEST_DEFINITION()

RUN_TESTS(RepAttest, test_attest_append_rules,
          test_attest_rides_the_catch_up_wire,
          test_attest_survives_the_evidence_document,
          test_attest_a_fork_hands_it_back)
