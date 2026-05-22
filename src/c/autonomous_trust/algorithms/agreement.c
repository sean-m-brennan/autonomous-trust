/********************
 *  Copyright 2025 Sean M. Brennan and contributors
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

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include <sodium.h>

#include "agreement.h"
#include "../utilities/allocation.h"
#include "algorithms/agreement.pb-c.h"

/* Frama-C: skipped — [solver-timeout] smrt_ptr allocation postconditions */
int agreement_proof_create(const char *uuid, const uint8_t *digest, size_t digest_len,
                           bool approval, const uint8_t *nonce, size_t nonce_len,
                           agreement_proof_t **proof)
{
    if (proof == NULL)
        return EINVAL;
    agreement_proof_t *p = calloc(1, sizeof(agreement_proof_t));
    if (p == NULL)
        return ENOMEM;

    if (uuid != NULL)
        strncpy(p->uuid, uuid, AGREEMENT_UUID_LEN - 1);
    p->approval = approval;

    if (digest != NULL && digest_len > 0)
    {
        p->digest = malloc(digest_len);
        if (p->digest == NULL)
        {
            free(p);
            return ENOMEM;
        }
        memcpy(p->digest, digest, digest_len);
        p->digest_len = digest_len;
    }

    /* WHY the cleanup here frees digest conditionally but not separately
     * calloc'd fields: allocations happen in order (struct → digest → nonce);
     * if we fail at the nonce step, digest may or may not have been
     * allocated depending on whether digest_len > 0 above. The `if
     * (p->digest)` guard handles both paths without needing a second
     * control-flow branch. The struct itself came from calloc so all other
     * pointer fields are guaranteed NULL — no risk of freeing uninitialized
     * memory. Do NOT reorder the allocations; each error branch assumes
     * everything earlier in the sequence is the *only* thing that might
     * need freeing. */
    if (nonce != NULL && nonce_len > 0)
    {
        p->nonce = malloc(nonce_len);
        if (p->nonce == NULL)
        {
            if (p->digest) free(p->digest);
            free(p);
            return ENOMEM;
        }
        memcpy(p->nonce, nonce, nonce_len);
        p->nonce_len = nonce_len;
    }

    *proof = p;
    return 0;
}

/*@
  requires proof == \null || \valid(proof);
  assigns \nothing;
*/
void agreement_proof_free(agreement_proof_t *proof)
{
    if (proof == NULL)
        return;
    if (proof->digest != NULL)
        free(proof->digest);
    if (proof->nonce != NULL)
        free(proof->nonce);
    free(proof);
}

/* Frama-C: skipped — [serialization] protobuf serialization */
int agreement_proof_sync_out(agreement_proof_t *proof, void *proto_msg)
{
    AutonomousTrust__Core__Protobuf__Algorithms__AgreementProof *msg = proto_msg;
    if (proof == NULL || msg == NULL)
        return EINVAL;

    msg->uuid.data = (uint8_t *)proof->uuid;
    msg->uuid.len = strlen(proof->uuid);
    msg->digest.data = proof->digest;
    msg->digest.len = proof->digest_len;
    msg->approval = proof->approval;
    msg->nonce.data = proof->nonce;
    msg->nonce.len = proof->nonce_len;
    return 0;
}

/* Frama-C: skipped — [serialization] protobuf deserialization */
int agreement_proof_sync_in(void *proto_msg, agreement_proof_t *proof)
{
    AutonomousTrust__Core__Protobuf__Algorithms__AgreementProof *msg = proto_msg;
    if (proof == NULL || msg == NULL)
        return EINVAL;

    if (msg->uuid.len > 0 && msg->uuid.len < AGREEMENT_UUID_LEN)
    {
        memcpy(proof->uuid, msg->uuid.data, msg->uuid.len);
        proof->uuid[msg->uuid.len] = '\0';
    }

    proof->approval = msg->approval;

    if (msg->digest.len > 0)
    {
        proof->digest = malloc(msg->digest.len);
        if (proof->digest == NULL)
            return ENOMEM;
        memcpy(proof->digest, msg->digest.data, msg->digest.len);
        proof->digest_len = msg->digest.len;
    }

    if (msg->nonce.len > 0)
    {
        proof->nonce = malloc(msg->nonce.len);
        if (proof->nonce == NULL)
            return ENOMEM;
        memcpy(proof->nonce, msg->nonce.data, msg->nonce.len);
        proof->nonce_len = msg->nonce.len;
    }

    return 0;
}

/* Authority implementation */

static bool _authority_pre_verify(agreement_protocol_t *proto, merkle_blob_t *blob,
                                  agreement_proof_t *proof, const uint8_t *sig, size_t sig_len)
{
    (void)proto; (void)blob; (void)proof; (void)sig; (void)sig_len;
    return true;
}

static void _authority_prep_vote(agreement_protocol_t *proto)
{
    (void)proto;
}

/* AUTHORITY_THRESHOLD_DERIVE lives in agreement.h so callers outside
 * this TU can ask for the derived behavior by name rather than passing
 * a magic -1. */

/* qsort comparator for sort-descending of int. */
static int _int_desc_cmp(const void *a, const void *b)
{
    int ia = *(const int *)a;
    int ib = *(const int *)b;
    return (ia < ib) ? 1 : (ia > ib) ? -1 : 0;
}

/* Derive the effective threshold rank. If an explicit non-negative
 * threshold was supplied at create-time, use it verbatim; otherwise
 * compute the top-1/3 cutoff over the current voter set. Mirrors
 * Python's authority.py:31-39 — sort ranks descending, take
 * ranks[max(1, len//3) - 1]. Empty voter set degrades to 0. */
static int _authority_effective_threshold(const agreement_protocol_t *proto)
{
    if (proto->state.authority.threshold_rank >= 0)
        return proto->state.authority.threshold_rank;
    int n = proto->voter_count;
    if (n <= 0)
        return 0;
    /* Stack copy of voter ranks. voter_count is bounded by the size of
     * the peers list, which is small at runtime. */
    int *ranks = (int *)malloc(sizeof(int) * (size_t)n);
    if (ranks == NULL)
        return 0;
    for (int i = 0; i < n; i++)
        ranks[i] = proto->voters[i].rank;
    qsort(ranks, (size_t)n, sizeof(int), _int_desc_cmp);
    int cutoff_idx = (n / 3 > 1) ? (n / 3) : 1;
    int result = ranks[cutoff_idx - 1];
    free(ranks);
    return result;
}

static void _authority_count_vote(agreement_protocol_t *proto, merkle_blob_t *blob,
                                  agreement_proof_t *proof, agreement_voter_t *voter,
                                  int *rank_out, bool *approval_out)
{
    (void)blob;
    *rank_out = voter->rank;
    if (voter->rank >= _authority_effective_threshold(proto))
        *approval_out = proof->approval;
    else
        *approval_out = false;
}

static bool _authority_accumulate(agreement_protocol_t *proto, int *ranks, bool *approvals, int count)
{
    /* Python authority.py:54-55 short-circuits on empty voter set to
     * `return False` via the `if not self.voters` guard above the dict
     * lookup. The audit (divergence.md M15) called out a "Python returns
     * 0 from the threshold property, C returns false" mechanical
     * difference — the OUTCOME is identical (no approval) because no
     * vote has a rank >= 0 when there are no voters. Documented here so
     * a future reader doesn't try to "harmonize" by switching to a
     * sentinel. */
    int leader_rank = -1;
    for (int i = 0; i < proto->voter_count; i++)
    {
        if (proto->voters[i].rank > leader_rank)
            leader_rank = proto->voters[i].rank;
    }
    for (int i = 0; i < count; i++)
    {
        if (ranks[i] == leader_rank)
            return approvals[i];
    }
    /* count == 0 case falls through here — a deliberate "no leader vote
     * yet, so not approved" — approvals[0] is NEVER read unread. */
    return false;
}

/* Trust (PoT) implementation — parallel to authority but reads
 * voter.tier instead of voter.rank. See doc/architecture/trust-tiers.md §10. */

static bool _trust_pre_verify(agreement_protocol_t *proto, merkle_blob_t *blob,
                              agreement_proof_t *proof, const uint8_t *sig, size_t sig_len)
{
    (void)proto; (void)blob; (void)proof; (void)sig; (void)sig_len;
    return true;
}

static void _trust_prep_vote(agreement_protocol_t *proto)
{
    (void)proto;
}

/* Derive the effective threshold tier. Mirrors
 * _authority_effective_threshold exactly but on the tier axis. */
static int _trust_effective_threshold(const agreement_protocol_t *proto)
{
    if (proto->state.trust.threshold_tier >= 0)
        return proto->state.trust.threshold_tier;
    int n = proto->voter_count;
    if (n <= 0)
        return 0;
    int *tiers = (int *)malloc(sizeof(int) * (size_t)n);
    if (tiers == NULL)
        return 0;
    for (int i = 0; i < n; i++)
        tiers[i] = proto->voters[i].tier;
    qsort(tiers, (size_t)n, sizeof(int), _int_desc_cmp);
    int cutoff_idx = (n / 3 > 1) ? (n / 3) : 1;
    int result = tiers[cutoff_idx - 1];
    free(tiers);
    return result;
}

/* PoT _count_vote: emits (tier, approval) into the (ranks[], approvals[])
 * channel — the channel naming is `ranks` for historical reasons but
 * just carries whatever discriminator the impl uses. _trust_accumulate
 * reads voters[*].tier the same way _authority_accumulate reads .rank,
 * so the channel staying named `ranks` is harmless. */
static void _trust_count_vote(agreement_protocol_t *proto, merkle_blob_t *blob,
                              agreement_proof_t *proof, agreement_voter_t *voter,
                              int *rank_out, bool *approval_out)
{
    (void)blob;
    *rank_out = voter->tier;
    if (voter->tier >= _trust_effective_threshold(proto))
        *approval_out = proof->approval;
    else
        *approval_out = false;
}

static bool _trust_accumulate(agreement_protocol_t *proto, int *ranks, bool *approvals, int count)
{
    int leader_tier = -1;
    for (int i = 0; i < proto->voter_count; i++)
    {
        if (proto->voters[i].tier > leader_tier)
            leader_tier = proto->voters[i].tier;
    }
    for (int i = 0; i < count; i++)
    {
        if (ranks[i] == leader_tier)
            return approvals[i];
    }
    return false;
}

/* Stake implementation */

static bool _stake_pre_verify(agreement_protocol_t *proto, merkle_blob_t *blob,
                               agreement_proof_t *proof, const uint8_t *sig, size_t sig_len)
{
    (void)proto; (void)blob; (void)proof; (void)sig; (void)sig_len;
    return true;
}

static void _stake_prep_vote(agreement_protocol_t *proto)
{
    proto->state.stake.yea = 0.0;
    proto->state.stake.nay = 0.0;
}

static void _stake_count_vote(agreement_protocol_t *proto, merkle_blob_t *blob,
                               agreement_proof_t *proof, agreement_voter_t *voter,
                               int *rank_out, bool *approval_out)
{
    (void)blob;
    double stake = 1.0;
    if (proto->state.stake.get_stake != NULL)
        stake = proto->state.stake.get_stake(voter);
    if (proof->approval)
        proto->state.stake.yea += stake;
    else
        proto->state.stake.nay += stake;
    /* Python's _count_vote returns None (stake.py:35-40) because stake
     * decides via yea/nay accumulators rather than the votes list. The
     * C signature uses out-params for uniformity with the authority/
     * work variants; the rank/approval values are written for shape
     * compatibility but never consulted by _stake_accumulate, which
     * decides purely on yea > nay. Audit ref divergence.md M14. */
    *rank_out = voter->rank;
    *approval_out = proof->approval;
}

static bool _stake_accumulate(agreement_protocol_t *proto, int *ranks, bool *approvals, int count)
{
    (void)ranks; (void)approvals; (void)count;
    return proto->state.stake.yea > proto->state.stake.nay;
}

/* Work implementation */

static bool _work_pre_verify(agreement_protocol_t *proto, merkle_blob_t *blob,
                              agreement_proof_t *proof, const uint8_t *sig, size_t sig_len)
{
    (void)proto; (void)blob; (void)proof; (void)sig; (void)sig_len;
    return true;
}

static void _work_prep_vote(agreement_protocol_t *proto)
{
    (void)proto;
}

static void _work_count_vote(agreement_protocol_t *proto, merkle_blob_t *blob,
                              agreement_proof_t *proof, agreement_voter_t *voter,
                              int *rank_out, bool *approval_out)
{
    (void)blob; (void)proof; (void)voter; (void)proto;
    *rank_out = voter->rank;
    *approval_out = proof->approval;
}

static bool _work_accumulate(agreement_protocol_t *proto, int *ranks, bool *approvals, int count)
{
    (void)proto; (void)ranks; (void)approvals; (void)count;
    return false; /* work uses verify/finalize pattern instead */
}

/* Frama-C: skipped — [solver-timeout] smrt_ptr + paxos init */
int agreement_protocol_create(agreement_voter_t *myself,
                              agreement_voter_t *others, int other_count,
                              agreement_type_t type,
                              agreement_protocol_t **proto)
{
    if (myself == NULL || proto == NULL)
        return EINVAL;

    agreement_protocol_t *p = calloc(1, sizeof(agreement_protocol_t));
    if (p == NULL)
        return ENOMEM;

    memcpy(&p->myself, myself, sizeof(agreement_voter_t));
    p->type = type;

    /* voters = others + myself */
    p->voter_count = other_count + 1;
    p->voters = malloc(sizeof(agreement_voter_t) * p->voter_count);
    if (p->voters == NULL)
    {
        free(p);
        return ENOMEM;
    }
    if (others != NULL && other_count > 0)
        memcpy(p->voters, others, sizeof(agreement_voter_t) * other_count);
    memcpy(&p->voters[other_count], myself, sizeof(agreement_voter_t));

    int err = map_create(&p->votes);
    if (err != 0)
    {
        free(p->voters);
        free(p);
        return err;
    }

    *proto = p;
    return 0;
}

int agreement_by_authority_create(agreement_voter_t *myself,
                                  agreement_voter_t *others, int other_count,
                                  int threshold_rank,
                                  agreement_protocol_t **proto)
{
    int err = agreement_protocol_create(myself, others, other_count, AGREEMENT_AUTHORITY, proto);
    if (err != 0)
        return err;
    (*proto)->state.authority.threshold_rank = threshold_rank;
    (*proto)->pre_verify = _authority_pre_verify;
    (*proto)->prep_vote = _authority_prep_vote;
    (*proto)->count_vote = _authority_count_vote;
    (*proto)->accumulate_votes = _authority_accumulate;
    return 0;
}

int agreement_by_trust_create(agreement_voter_t *myself,
                              agreement_voter_t *others, int other_count,
                              int threshold_tier,
                              agreement_protocol_t **proto)
{
    int err = agreement_protocol_create(myself, others, other_count, AGREEMENT_TRUST, proto);
    if (err != 0)
        return err;
    (*proto)->state.trust.threshold_tier = threshold_tier;
    (*proto)->pre_verify = _trust_pre_verify;
    (*proto)->prep_vote = _trust_prep_vote;
    (*proto)->count_vote = _trust_count_vote;
    (*proto)->accumulate_votes = _trust_accumulate;
    return 0;
}

int agreement_by_stake_create(agreement_voter_t *myself,
                              agreement_voter_t *others, int other_count,
                              double (*get_stake)(agreement_voter_t *voter),
                              agreement_protocol_t **proto)
{
    int err = agreement_protocol_create(myself, others, other_count, AGREEMENT_STAKE, proto);
    if (err != 0)
        return err;
    (*proto)->state.stake.get_stake = get_stake;
    (*proto)->state.stake.yea = 0.0;
    (*proto)->state.stake.nay = 0.0;
    (*proto)->pre_verify = _stake_pre_verify;
    (*proto)->prep_vote = _stake_prep_vote;
    (*proto)->count_vote = _stake_count_vote;
    (*proto)->accumulate_votes = _stake_accumulate;
    return 0;
}

int agreement_by_work_create(agreement_voter_t *myself,
                             agreement_voter_t *others, int other_count,
                             int difficulty,
                             agreement_protocol_t **proto)
{
    int err = agreement_protocol_create(myself, others, other_count, AGREEMENT_WORK, proto);
    if (err != 0)
        return err;
    (*proto)->state.work.difficulty = difficulty;
    int aerr = array_create(&(*proto)->state.work.approved);
    if (aerr != 0)
        return aerr;
    (*proto)->pre_verify = _work_pre_verify;
    (*proto)->prep_vote = _work_prep_vote;
    (*proto)->count_vote = _work_count_vote;
    (*proto)->accumulate_votes = _work_accumulate;
    return 0;
}

/* Frama-C: skipped — [solver-timeout] crypto + paxos preconditions */
int agreement_prove(agreement_protocol_t *proto, merkle_blob_t *blob,
                    agreement_proof_t **proof_out)
{
    if (proto == NULL || blob == NULL || proof_out == NULL)
        return EINVAL;

    uint8_t hash[MERKLE_DIGEST_LEN];

    if (proto->type == AGREEMENT_WORK)
    {
        /* proof of work: find nonce such that hash starts with difficulty zeros */
        int difficulty = proto->state.work.difficulty;
        uint32_t nonce = 0;
        char nonce_str[16];
        while (1)
        {
            snprintf(nonce_str, sizeof(nonce_str), "%u", nonce);
            if (blob->get_hash != NULL)
                blob->get_hash(blob, (uint8_t *)nonce_str, strlen(nonce_str), hash);
            else
                break;

            /* check if first DIFFICULTY raw bytes are 0x00 (canonical
             * cross-language POW digest format — see Python work.py's
             * _raw_hash; BUGS.md §P5 historical note). */
            bool valid = true;
            for (unsigned int i = 0; i < (unsigned int)difficulty && i < MERKLE_DIGEST_LEN; i++)
            {
                if (hash[i] != 0)
                {
                    valid = false;
                    break;
                }
            }
            if (valid)
                break;
            nonce++;
            if (nonce > 0x00FFFFFF) /* safety limit */
                break;
        }
        return agreement_proof_create(proto->myself.uuid, hash, MERKLE_DIGEST_LEN,
                                      true, (uint8_t *)nonce_str, strlen(nonce_str),
                                      proof_out);
    }
    else
    {
        if (blob->get_hash != NULL)
            blob->get_hash(blob, NULL, 0, hash);
        else
            memset(hash, 0, MERKLE_DIGEST_LEN);
        return agreement_proof_create(proto->myself.uuid, hash, MERKLE_DIGEST_LEN,
                                      true, NULL, 0, proof_out);
    }
}

/* Frama-C: skipped — [solver-timeout] crypto verification preconditions */
bool agreement_verify(agreement_protocol_t *proto, merkle_blob_t *blob,
                      agreement_proof_t *proof, const uint8_t *sig, size_t sig_len)
{
    if (proto == NULL || blob == NULL || proof == NULL)
        return false;

    if (proto->type == AGREEMENT_WORK)
    {
        /* verify PoW: hash must match and have correct prefix */
        uint8_t computed[MERKLE_DIGEST_LEN];
        if (blob->get_hash != NULL)
            blob->get_hash(blob, proof->nonce, proof->nonce_len, computed);
        else
            return false;

        bool prefix_ok = true;
        for (unsigned int i = 0; i < (unsigned int)proto->state.work.difficulty && i < MERKLE_DIGEST_LEN; i++)
        {
            if (proof->digest[i] != 0)
            {
                prefix_ok = false;
                break;
            }
        }

        if (prefix_ok && memcmp(proof->digest, computed, MERKLE_DIGEST_LEN) == 0)
        {
            data_t *blob_dat = object_ptr_data(blob, sizeof(merkle_blob_t));
            if (blob_dat != NULL)
                array_append(proto->state.work.approved, blob_dat);
            return true;
        }
        return false;
    }

    if (proto->pre_verify != NULL && !proto->pre_verify(proto, blob, proof, sig, sig_len))
        return false;

    /* store vote for finalize */
    data_t *existing = NULL;
    array_t *vote_list = NULL;
    if (map_get(proto->votes, blob->uuid, &existing) == 0)
    {
        ptr_t ptr = NULL;
        data_object_ptr(existing, &ptr);
        vote_list = (array_t *)ptr;
    }
    else
    {
        array_create(&vote_list);
        data_t *list_dat = object_ptr_data(vote_list, sizeof(void *));
        map_set(proto->votes, blob->uuid, list_dat);
    }

    if (vote_list != NULL)
    {
        data_t *proof_dat = object_ptr_data(proof, sizeof(agreement_proof_t));
        if (proof_dat != NULL)
            array_append(vote_list, proof_dat);
    }
    return true;
}

/* Frama-C: skipped — [solver-timeout] paxos/map precondition cascade */
bool agreement_finalize(agreement_protocol_t *proto, merkle_blob_t *blob)
{
    if (proto == NULL || blob == NULL)
        return false;

    /* originator always approves own blob */
    if (strcmp(proto->myself.uuid, blob->originator) == 0)
        return true;

    if (proto->type == AGREEMENT_WORK)
    {
        /* check if blob was approved during verify */
        int sz = (int)array_size(proto->state.work.approved);
        for (int i = 0; i < sz; i++)
        {
            data_t *val = NULL;
            array_get(proto->state.work.approved, i, &val);
            ptr_t ptr = NULL;
            data_object_ptr(val, &ptr);
            if ((merkle_blob_t *)ptr == blob)
            {
                array_remove(proto->state.work.approved, val);
                return true;
            }
        }
        return false;
    }

    if (proto->prep_vote != NULL)
        proto->prep_vote(proto);

    /* collect stored votes */
    data_t *votes_dat = NULL;
    if (map_get(proto->votes, blob->uuid, &votes_dat) != 0)
        return false;

    ptr_t ptr = NULL;
    data_object_ptr(votes_dat, &ptr);
    array_t *vote_list = (array_t *)ptr;
    if (vote_list == NULL)
        return false;

    int vote_count = (int)array_size(vote_list);
    int *ranks = malloc(sizeof(int) * vote_count);
    bool *approvals = malloc(sizeof(bool) * vote_count);
    if (ranks == NULL || approvals == NULL)
    {
        free(ranks);
        free(approvals);
        return false;
    }

    int actual = 0;
    for (int i = 0; i < vote_count; i++)
    {
        data_t *pval = NULL;
        array_get(vote_list, i, &pval);
        ptr_t pptr = NULL;
        data_object_ptr(pval, &pptr);
        agreement_proof_t *proof = (agreement_proof_t *)pptr;
        if (proof == NULL)
            continue;

        /* find the voter */
        agreement_voter_t *voter = NULL;
        for (int j = 0; j < proto->voter_count; j++)
        {
            if (strcmp(proto->voters[j].uuid, proof->uuid) == 0)
            {
                voter = &proto->voters[j];
                break;
            }
        }
        if (voter == NULL)
            continue;

        if (proto->count_vote != NULL)
        {
            proto->count_vote(proto, blob, proof, voter, &ranks[actual], &approvals[actual]);
            actual++;
        }
    }

    bool result = false;
    if (proto->accumulate_votes != NULL)
        result = proto->accumulate_votes(proto, ranks, approvals, actual);

    free(ranks);
    free(approvals);
    map_remove(proto->votes, blob->uuid);
    return result;
}

void agreement_protocol_free(agreement_protocol_t *proto)
{
    if (proto == NULL)
        return;
    if (proto->voters != NULL)
        free(proto->voters);
    if (proto->type == AGREEMENT_WORK && proto->state.work.approved != NULL)
        array_free(proto->state.work.approved);
    if (proto->votes != NULL)
        map_free(proto->votes);
    free(proto);
}
