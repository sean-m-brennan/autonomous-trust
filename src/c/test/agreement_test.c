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

#include <string.h>
#include <sodium.h>

#include "autonomous_trust/algorithms/agreement.h"

#define DEBUG_TESTS 1
#include "test_setup.h"

static int _test_blob_hash(const merkle_blob_t *blob, const uint8_t *nonce,
                           size_t nonce_len, uint8_t *hash_out)
{
    size_t uuid_len = strlen(blob->uuid);
    size_t total = uuid_len + nonce_len;
    uint8_t *buf = malloc(total);
    if (buf == NULL)
        return -1;
    memcpy(buf, blob->uuid, uuid_len);
    if (nonce != NULL && nonce_len > 0)
        memcpy(buf + uuid_len, nonce, nonce_len);
    int ret = merkle_hash(buf, total, hash_out);
    free(buf);
    return ret;
}

static merkle_blob_t *_make_blob(const char *uuid, const char *originator)
{
    merkle_blob_t *blob = malloc(sizeof(merkle_blob_t));
    memset(blob, 0, sizeof(merkle_blob_t));
    strncpy(blob->uuid, uuid, MERKLE_UUID_LEN - 1);
    strncpy(blob->originator, originator, MERKLE_UUID_LEN - 1);
    blob->get_hash = _test_blob_hash;
    return blob;
}

DEFINE_TEST(test_proof_create)
{
    if (sodium_init() < 0 && sodium_init() != 1)
        ck_assert(0);

    uint8_t digest[] = {1, 2, 3, 4};
    agreement_proof_t *proof = NULL;
    ck_assert_ret_ok(agreement_proof_create("voter-uuid", digest, 4, true, NULL, 0, &proof));
    ck_assert_ptr_nonnull(proof);
    ck_assert_str_eq(proof->uuid, "voter-uuid");
    ck_assert(proof->approval);
    ck_assert_int_eq(proof->digest_len, 4);
    ck_assert_mem_eq(proof->digest, digest, 4);
    ck_assert_ptr_null(proof->nonce);

    agreement_proof_free(proof);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_authority_voting)
{
    agreement_voter_t leader = {.rank = 5};
    strncpy(leader.uuid, "leader-uuid", AGREEMENT_UUID_LEN - 1);

    agreement_voter_t peer1 = {.rank = 3};
    strncpy(peer1.uuid, "peer1-uuid", AGREEMENT_UUID_LEN - 1);

    agreement_voter_t peer2 = {.rank = 1};
    strncpy(peer2.uuid, "peer2-uuid", AGREEMENT_UUID_LEN - 1);

    agreement_voter_t others[] = {peer1, peer2};

    agreement_protocol_t *proto = NULL;
    ck_assert_ret_ok(agreement_by_authority_create(&leader, others, 2, 4, &proto));
    ck_assert_ptr_nonnull(proto);

    merkle_blob_t *blob = _make_blob("test-blob", "someone");

    /* leader proves and votes yes */
    agreement_proof_t *leader_proof = NULL;
    ck_assert_ret_ok(agreement_prove(proto, blob, &leader_proof));
    ck_assert(agreement_verify(proto, blob, leader_proof, NULL, 0));

    /* peer1 votes no (below threshold, rank 3 < 4) */
    agreement_proof_t *p1_proof = NULL;
    ck_assert_ret_ok(agreement_proof_create("peer1-uuid", leader_proof->digest,
                                            leader_proof->digest_len, false, NULL, 0, &p1_proof));
    ck_assert(agreement_verify(proto, blob, p1_proof, NULL, 0));

    /* finalize: leader's vote should win */
    ck_assert(agreement_finalize(proto, blob));

    agreement_proof_free(leader_proof);
    agreement_proof_free(p1_proof);
    agreement_protocol_free(proto);
    free(blob);
}
END_TEST_DEFINITION()

static double _test_get_stake(agreement_voter_t *voter)
{
    return (double)voter->rank;
}

DEFINE_TEST(test_stake_voting)
{
    agreement_voter_t me = {.rank = 5};
    strncpy(me.uuid, "me-uuid", AGREEMENT_UUID_LEN - 1);

    agreement_voter_t p1 = {.rank = 3};
    strncpy(p1.uuid, "p1-uuid", AGREEMENT_UUID_LEN - 1);

    agreement_voter_t p2 = {.rank = 2};
    strncpy(p2.uuid, "p2-uuid", AGREEMENT_UUID_LEN - 1);

    agreement_voter_t others[] = {p1, p2};

    agreement_protocol_t *proto = NULL;
    ck_assert_ret_ok(agreement_by_stake_create(&me, others, 2, _test_get_stake, &proto));

    merkle_blob_t *blob = _make_blob("stake-blob", "someone");

    /* me votes yes (stake 5) */
    agreement_proof_t *my_proof = NULL;
    ck_assert_ret_ok(agreement_prove(proto, blob, &my_proof));
    ck_assert(agreement_verify(proto, blob, my_proof, NULL, 0));

    /* p1 votes no (stake 3) */
    agreement_proof_t *p1_proof = NULL;
    ck_assert_ret_ok(agreement_proof_create("p1-uuid", my_proof->digest,
                                            my_proof->digest_len, false, NULL, 0, &p1_proof));
    ck_assert(agreement_verify(proto, blob, p1_proof, NULL, 0));

    /* p2 votes no (stake 2) */
    agreement_proof_t *p2_proof = NULL;
    ck_assert_ret_ok(agreement_proof_create("p2-uuid", my_proof->digest,
                                            my_proof->digest_len, false, NULL, 0, &p2_proof));
    ck_assert(agreement_verify(proto, blob, p2_proof, NULL, 0));

    /* yea=5, nay=5 → not approved (need strict >) */
    ck_assert(!agreement_finalize(proto, blob));

    agreement_proof_free(my_proof);
    agreement_proof_free(p1_proof);
    agreement_proof_free(p2_proof);
    agreement_protocol_free(proto);
    free(blob);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_work_voting)
{
    agreement_voter_t me = {.rank = 1};
    strncpy(me.uuid, "worker-uuid", AGREEMENT_UUID_LEN - 1);

    agreement_protocol_t *proto = NULL;
    /* difficulty=1 means first byte of hash must be 0 */
    ck_assert_ret_ok(agreement_by_work_create(&me, NULL, 0, 1, &proto));

    merkle_blob_t *blob = _make_blob("work-blob", "someone");

    /* prove does PoW */
    agreement_proof_t *proof = NULL;
    ck_assert_ret_ok(agreement_prove(proto, blob, &proof));
    ck_assert_ptr_nonnull(proof);
    ck_assert(proof->approval);

    /* first DIFFICULTY raw bytes should be 0x00 — canonical AT v1 POW
     * digest format on both Python (raw blake2b via _raw_hash) and C
     * (crypto_generichash_blake2b). See BUGS.md §P5 closure. */
    ck_assert_int_eq(proof->digest[0], 0);

    /* verify checks PoW */
    ck_assert(agreement_verify(proto, blob, proof, NULL, 0));

    /* finalize should succeed since blob was approved in verify */
    ck_assert(agreement_finalize(proto, blob));

    agreement_proof_free(proof);
    agreement_protocol_free(proto);
    free(blob);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_originator_auto_approve)
{
    agreement_voter_t me = {.rank = 1};
    strncpy(me.uuid, "orig-uuid", AGREEMENT_UUID_LEN - 1);

    agreement_protocol_t *proto = NULL;
    ck_assert_ret_ok(agreement_by_authority_create(&me, NULL, 0, 1, &proto));

    /* blob originated by ourselves */
    merkle_blob_t *blob = _make_blob("my-blob", "orig-uuid");

    /* originator always approves */
    ck_assert(agreement_finalize(proto, blob));

    agreement_protocol_free(proto);
    free(blob);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_voter_effective_rank)
{
    /* Dynamic topology-rank source (deferred.md §2.2): operational rank =
     * signed rank + one-hop-reachability adjustment, floored at 0. Mirror of
     * Python TestAgreementVoterEffectiveRank. */
    agreement_voter_t v = {.rank = 5};
    ck_assert_int_eq(agreement_voter_effective_rank(&v), 5);

    /* unreachable (e.g. gateway loss) -> demote to 0; signed rank untouched */
    ck_assert(agreement_voter_observe_reachability(&v, false));
    ck_assert_int_eq(agreement_voter_effective_rank(&v), 0);
    ck_assert_int_eq(v.rank, 5);

    /* reachable again -> restore the signed rank */
    ck_assert(agreement_voter_observe_reachability(&v, true));
    ck_assert_int_eq(agreement_voter_effective_rank(&v), 5);

    /* idempotent reachable -> no change */
    ck_assert(!agreement_voter_observe_reachability(&v, true));

    /* graded adjustment + floor at 0 */
    v.rank_adjustment = -2;
    ck_assert_int_eq(agreement_voter_effective_rank(&v), 3);
    v.rank_adjustment = -100;
    ck_assert_int_eq(agreement_voter_effective_rank(&v), 0);
}
END_TEST_DEFINITION()

/* Cast one vote per entry of @p voters[i] / @p approve[i] and finalize.
 * @p me is the protocol's own voter; blob originator is someone else so
 * the originator short-circuit does not apply. */
static bool _vote_and_finalize(agreement_protocol_t *proto, const char *blob_uuid,
                               const char **voters, const bool *approve, int n)
{
    static const uint8_t digest[] = {1, 2, 3, 4};
    merkle_blob_t *blob = _make_blob(blob_uuid, "someone-else");
    agreement_proof_t *proofs[8] = {0};
    for (int i = 0; i < n && i < 8; i++)
    {
        ck_assert_ret_ok(agreement_proof_create(voters[i], digest, sizeof(digest),
                                                approve[i], NULL, 0, &proofs[i]));
        ck_assert(agreement_verify(proto, blob, proofs[i], NULL, 0));
    }
    bool result = agreement_finalize(proto, blob);
    for (int i = 0; i < n && i < 8; i++)
        agreement_proof_free(proofs[i]);
    free(blob);
    return result;
}

static agreement_voter_t _voter(const char *uuid, int rank, int tier)
{
    agreement_voter_t v = {.rank = rank, .tier = tier};
    strncpy(v.uuid, uuid, AGREEMENT_UUID_LEN - 1);
    return v;
}

DEFINE_TEST(test_authority_tied_leaders)
{
    /* RD_13.1 D7: voters tied at the leader rank combine by conjunction.
     * Mirror of Python TestAuthorityAccumulateLeaderAbstains tie cases. */
    agreement_voter_t me = _voter("low", 0, 0);
    agreement_voter_t others[] = {_voter("lead-a", 5, 0), _voter("lead-b", 5, 0)};
    agreement_protocol_t *proto = NULL;
    ck_assert_ret_ok(agreement_by_authority_create(&me, others, 2, 0, &proto));

    const char *ab[] = {"lead-a", "lead-b"};
    const char *ba[] = {"lead-b", "lead-a"};
    const bool yes_no[] = {true, false};
    const bool yes_yes[] = {true, true};
    /* split vote rejects whichever arrives first */
    ck_assert(!_vote_and_finalize(proto, "b1", ab, yes_no, 2));
    ck_assert(!_vote_and_finalize(proto, "b2", ba, yes_no, 2));
    ck_assert(_vote_and_finalize(proto, "b3", ab, yes_yes, 2));
    /* one tied leader silent: the other's vote stands */
    ck_assert(_vote_and_finalize(proto, "b4", ab, yes_yes, 1));

    agreement_protocol_free(proto);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_trust_majority)
{
    /* RD_13.1: PoT is a strict majority of eligible voters (tier >= the
     * threshold, default TRUST_DEFAULT_THRESHOLD_TIER), abstention counts
     * against, below-threshold votes are dropped. Mirror of Python
     * TestAgreementByTrust. */
    agreement_voter_t me = _voter("t1b", 0, 1);
    agreement_voter_t others[] = {_voter("t4", 0, 4), _voter("t2a", 0, 2),
                                  _voter("t2b", 0, 2), _voter("t1a", 0, 1)};
    agreement_protocol_t *proto = NULL;
    ck_assert_ret_ok(agreement_by_trust_create(&me, others, 4, TRUST_THRESHOLD_DERIVE, &proto));
    ck_assert_int_eq(proto->state.trust.threshold_tier, TRUST_THRESHOLD_DERIVE);

    /* climbed top tier rejects, 3 of 5 eligible approve -> true */
    const char *climbed[] = {"t4", "t2a", "t2b", "t1a"};
    const bool climbed_v[] = {false, true, true, true};
    ck_assert(_vote_and_finalize(proto, "c1", climbed, climbed_v, 4));

    /* top tier alone cannot approve */
    const char *top[] = {"t4"};
    const bool yes[] = {true};
    ck_assert(!_vote_and_finalize(proto, "c2", top, yes, 1));

    /* 2 of 5 approve, 3 silent: abstention counts against */
    const char *two[] = {"t2a", "t2b"};
    const bool yes_yes[] = {true, true};
    ck_assert(!_vote_and_finalize(proto, "c3", two, yes_yes, 2));

    /* replayed approval counts once: t2a x3 is still 1 of 5 */
    const char *replay[] = {"t2a", "t2a", "t2a"};
    const bool yes3[] = {true, true, true};
    ck_assert(!_vote_and_finalize(proto, "c4", replay, yes3, 3));
    agreement_protocol_free(proto);

    /* explicit threshold 3: only t4 and t3 eligible; tier-1/2 votes dropped */
    agreement_voter_t me3 = _voter("t3", 0, 3);
    ck_assert_ret_ok(agreement_by_trust_create(&me3, others, 4, 3, &proto));
    const char *hi[] = {"t4", "t3", "t2a", "t2b", "t1a"};
    const bool hi_v[] = {true, true, false, false, false};
    ck_assert(_vote_and_finalize(proto, "c5", hi, hi_v, 5));
    /* tie between the two eligible voters rejects */
    const bool tie_v[] = {true, false, true, true, true};
    ck_assert(!_vote_and_finalize(proto, "c6", hi, tie_v, 5));
    agreement_protocol_free(proto);

    /* zero eligible -> false */
    agreement_voter_t me0 = _voter("t1b", 0, 1);
    ck_assert_ret_ok(agreement_by_trust_create(&me0, others + 1, 3, 5, &proto));
    const char *low[] = {"t2a", "t2b", "t1a"};
    ck_assert(!_vote_and_finalize(proto, "c7", low, yes3, 3));
    agreement_protocol_free(proto);
}
END_TEST_DEFINITION()

RUN_TESTS(agreement, test_proof_create, test_authority_voting,
          test_stake_voting, test_work_voting, test_originator_auto_approve,
          test_voter_effective_rank, test_authority_tied_leaders,
          test_trust_majority)
