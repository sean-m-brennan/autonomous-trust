/********************
 *  Copyright 2026 Sean M. Brennan and contributors
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

/** @file Agreement-protocol adapter (kind: agreement_vector).
 *
 *  Mirrors the Python AgreementAdapter. Each vector pins a synchronous,
 *  deterministic vote-tally scenario: build N voters, construct an
 *  AgreementProtocol of a given impl (authority|stake), submit pre-pinned
 *  votes via agreement_verify(), then assert the agreement_finalize()
 *  outcome.
 *
 *  Voter identities here are not full identity_t objects — agreement.h
 *  only requires `agreement_voter_t {uuid[37], rank}`. The vector format
 *  uses short voter ids ("alice", "bob") which we use directly as the
 *  uuid string; equality is by strcmp, so the actual UUID format doesn't
 *  matter so long as both sides of the protocol agree. Same approach for
 *  the blob's uuid + originator strings.
 */

#include "agreement.h"

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <sodium.h>

#include "algorithms/agreement.h"
#include "structures/merkle.h"

#include "../negative_runner.h"

#define HARNESS_MAX_VOTERS  16

/* ------------------------------------------------------------------------- */
/* Stakes registry — POS impl needs a context-free callback.                  */
/* ------------------------------------------------------------------------- */

/* The stake callback signature is `double(*)(agreement_voter_t *)` with no
 * void* context, so per-test stakes have to live in a static map. Reset
 * before every POS run; reads happen serially within agreement_finalize. */
static struct {
    char uuid[AGREEMENT_UUID_LEN];
    double stake;
} g_stakes[HARNESS_MAX_VOTERS];
static size_t g_stakes_count = 0;

static double _harness_get_stake(agreement_voter_t *voter) {
    for (size_t i = 0; i < g_stakes_count; i++) {
        if (strcmp(voter->uuid, g_stakes[i].uuid) == 0) {
            return g_stakes[i].stake;
        }
    }
    return 0.0;
}

/* ------------------------------------------------------------------------- */
/* Blob hashing — ed-style for deterministic test digests.                    */
/* ------------------------------------------------------------------------- */

/* Generic-hash over the blob's uuid, optionally salted with a nonce. Mirrors
 * the test_blob_hash helper used by the existing C agreement_test.c. */
static int _harness_blob_hash(const merkle_blob_t *blob, const uint8_t *nonce,
                              size_t nonce_len, uint8_t *hash_out) {
    crypto_generichash_state st;
    crypto_generichash_init(&st, NULL, 0, MERKLE_DIGEST_LEN);
    crypto_generichash_update(&st, (const uint8_t *)blob->uuid, strlen(blob->uuid));
    if (nonce != NULL && nonce_len > 0) {
        crypto_generichash_update(&st, nonce, nonce_len);
    }
    return crypto_generichash_final(&st, hash_out, MERKLE_DIGEST_LEN);
}

/* ------------------------------------------------------------------------- */
/* Helpers                                                                     */
/* ------------------------------------------------------------------------- */

static int _put_uuid(char dest[AGREEMENT_UUID_LEN], const char *src) {
    if (src == NULL) return -1;
    size_t n = strlen(src);
    if (n >= AGREEMENT_UUID_LEN) return -1;
    memcpy(dest, src, n);
    dest[n] = '\0';
    return 0;
}

/* Look up a voter's id in the case's voter list to find its agreement_voter_t.
 * Returns NULL if not found. */
static agreement_voter_t *_find_voter_by_id(agreement_voter_t *voters, size_t n,
                                            const char *id) {
    for (size_t i = 0; i < n; i++) {
        if (strcmp(voters[i].uuid, id) == 0) return &voters[i];
    }
    return NULL;
}

/* ------------------------------------------------------------------------- */
/* Main entry                                                                  */
/* ------------------------------------------------------------------------- */

static int run_agreement_vector(const at_case_t *c,
                                char *err, size_t err_len) {
    int rc = -1;
    agreement_protocol_t *proto = NULL;
    merkle_blob_t blob = {0};
    blob.get_hash = _harness_blob_hash;
    /* All voter records are stack-allocated as a single array; the protocol
     * copies them into its internal voters[] in agreement_protocol_create
     * (see agreement.c). */
    agreement_voter_t voters[HARNESS_MAX_VOTERS] = {{{0},0}};
    size_t voter_count = 0;
    /* `proofs[]` keeps each in-flight proof alive until finalize is done —
     * agreement_verify stores a pointer into proto->votes and only that
     * pointer's data is read in finalize. */
    agreement_proof_t *proofs[HARNESS_MAX_VOTERS] = {0};
    size_t proof_count = 0;

    /* Parse top-level fields. */
    json_t *impl_j = json_object_get(c->data, "impl");
    json_t *voters_j = json_object_get(c->data, "voters");
    json_t *myself_j = json_object_get(c->data, "myself");
    json_t *blob_j = json_object_get(c->data, "blob");
    json_t *votes_j = json_object_get(c->data, "votes");
    json_t *expected_j = json_object_get(c->data, "expected");
    if (!json_is_string(impl_j) || !json_is_array(voters_j)
        || !json_is_string(myself_j) || !json_is_object(blob_j)
        || !json_is_object(expected_j)) {
        snprintf(err, err_len, "agreement_vector: missing required field");
        return -1;
    }
    json_t *outcome_j = json_object_get(expected_j, "outcome");
    if (!json_is_boolean(outcome_j)) {
        snprintf(err, err_len, "agreement_vector: expected.outcome must be boolean");
        return -1;
    }
    bool expected_outcome = json_is_true(outcome_j);

    /* Build voters. */
    voter_count = json_array_size(voters_j);
    if (voter_count == 0 || voter_count > HARNESS_MAX_VOTERS) {
        snprintf(err, err_len, "agreement_vector: voter_count out of range (%zu)",
                 voter_count);
        return -1;
    }
    for (size_t i = 0; i < voter_count; i++) {
        json_t *v = json_array_get(voters_j, i);
        json_t *id = json_object_get(v, "id");
        if (!json_is_string(id)) {
            snprintf(err, err_len, "agreement_vector: voters[%zu] missing id", i);
            return -1;
        }
        if (_put_uuid(voters[i].uuid, json_string_value(id)) != 0) {
            snprintf(err, err_len, "agreement_vector: voters[%zu] id too long", i);
            return -1;
        }
        json_t *rank_j = json_object_get(v, "rank");
        voters[i].rank = json_is_integer(rank_j) ? (int)json_integer_value(rank_j) : 0;
    }

    /* Stakes (POS only). */
    g_stakes_count = 0;
    if (strcmp(json_string_value(impl_j), "stake") == 0) {
        json_t *stakes_j = json_object_get(c->data, "stakes");
        if (json_is_object(stakes_j)) {
            const char *key;
            json_t *value;
            json_object_foreach(stakes_j, key, value) {
                if (g_stakes_count >= HARNESS_MAX_VOTERS) break;
                /* Resolve key (a voter id) to its uuid. Since we use ids as
                 * uuids directly, the key itself is the uuid. */
                if (_put_uuid(g_stakes[g_stakes_count].uuid, key) != 0) continue;
                g_stakes[g_stakes_count].stake = json_is_number(value)
                    ? json_number_value(value) : 0.0;
                g_stakes_count++;
            }
        }
    }

    /* Find myself + build others array (everyone except myself). */
    const char *myself_id = json_string_value(myself_j);
    agreement_voter_t *me = _find_voter_by_id(voters, voter_count, myself_id);
    if (me == NULL) {
        snprintf(err, err_len, "agreement_vector: myself %s not in voters", myself_id);
        return -1;
    }
    agreement_voter_t others[HARNESS_MAX_VOTERS];
    int other_count = 0;
    for (size_t i = 0; i < voter_count; i++) {
        if (&voters[i] == me) continue;
        others[other_count++] = voters[i];
    }

    /* Construct the protocol. */
    if (strcmp(json_string_value(impl_j), "authority") == 0) {
        json_t *thr_j = json_object_get(c->data, "threshold_rank");
        int threshold = json_is_integer(thr_j) ? (int)json_integer_value(thr_j) : 0;
        if (agreement_by_authority_create(me, others, other_count, threshold, &proto) != 0
            || proto == NULL) {
            snprintf(err, err_len, "agreement_vector: authority_create failed");
            goto cleanup;
        }
    } else if (strcmp(json_string_value(impl_j), "stake") == 0) {
        if (agreement_by_stake_create(me, others, other_count, _harness_get_stake, &proto) != 0
            || proto == NULL) {
            snprintf(err, err_len, "agreement_vector: stake_create failed");
            goto cleanup;
        }
    } else {
        snprintf(err, err_len, "agreement_vector: unsupported impl %s",
                 json_string_value(impl_j));
        goto cleanup;
    }

    /* Build the blob — uuid + originator strings. */
    json_t *blob_uuid_j = json_object_get(blob_j, "uuid");
    json_t *blob_orig_j = json_object_get(blob_j, "originator");
    if (!json_is_string(blob_uuid_j) || !json_is_string(blob_orig_j)) {
        snprintf(err, err_len, "agreement_vector: blob.uuid/originator missing");
        goto cleanup;
    }
    {
        const char *u = json_string_value(blob_uuid_j);
        const char *o = json_string_value(blob_orig_j);
        if (strlen(u) >= MERKLE_UUID_LEN || strlen(o) >= MERKLE_UUID_LEN) {
            snprintf(err, err_len, "agreement_vector: blob.uuid/originator too long");
            goto cleanup;
        }
        strncpy(blob.uuid, u, MERKLE_UUID_LEN - 1);
        strncpy(blob.originator, o, MERKLE_UUID_LEN - 1);
    }

    /* Submit votes. Each entry: {by: <voter_id>, approval: <bool>}.
     * The harness signs nothing — POA/POS pre_verify is a no-op in the C
     * impl (see agreement.c::_authority_pre_verify), and our agreement_verify
     * call passes NULL/0 for sig/sig_len. The Python adapter does sign with
     * a real Identity to exercise the verify-during-finalize path; the C
     * impl's count_vote does not re-verify the signature, so the harness
     * behavior is equivalent. */
    if (json_is_array(votes_j)) {
        size_t n = json_array_size(votes_j);
        for (size_t i = 0; i < n && proof_count < HARNESS_MAX_VOTERS; i++) {
            json_t *vote = json_array_get(votes_j, i);
            json_t *by_j = json_object_get(vote, "by");
            json_t *appr_j = json_object_get(vote, "approval");
            if (!json_is_string(by_j) || !json_is_boolean(appr_j)) {
                snprintf(err, err_len, "agreement_vector: votes[%zu] malformed", i);
                goto cleanup;
            }
            const char *by_id = json_string_value(by_j);
            agreement_voter_t *voter = _find_voter_by_id(voters, voter_count, by_id);
            if (voter == NULL) {
                snprintf(err, err_len, "agreement_vector: votes[%zu] by=%s not a voter",
                         i, by_id);
                goto cleanup;
            }
            /* digest comes from the blob's hash, mirroring AgreementProtocol.prove
             * in the Python impl — the actual bytes don't drive the test,
             * but they keep the proof structurally valid. */
            uint8_t digest[MERKLE_DIGEST_LEN];
            _harness_blob_hash(&blob, NULL, 0, digest);

            agreement_proof_t *p = NULL;
            if (agreement_proof_create(voter->uuid, digest, MERKLE_DIGEST_LEN,
                                       json_is_true(appr_j), NULL, 0, &p) != 0
                || p == NULL) {
                snprintf(err, err_len, "agreement_vector: votes[%zu] proof_create failed", i);
                goto cleanup;
            }
            proofs[proof_count++] = p;

            agreement_verify(proto, &blob, p, NULL, 0);
        }
    }

    bool actual = agreement_finalize(proto, &blob);
    if (actual != expected_outcome) {
        snprintf(err, err_len,
                 "finalize outcome: expected %s, got %s",
                 expected_outcome ? "true" : "false",
                 actual ? "true" : "false");
        goto cleanup;
    }
    rc = 0;

cleanup:
    for (size_t i = 0; i < proof_count; i++) {
        agreement_proof_free(proofs[i]);
    }
    if (proto != NULL) agreement_protocol_free(proto);
    return rc;
}

/* ------------------------------------------------------------------------- */
/* kind:scenario — multi-blob vote accumulation                                */
/* ------------------------------------------------------------------------- */

#define HARNESS_MAX_BLOBS  8

static int _build_voters_from_participants(json_t *parts, json_t *ranks,
                                           agreement_voter_t *out_voters,
                                           size_t *out_count,
                                           char *err, size_t err_len) {
    if (!json_is_array(parts)) {
        snprintf(err, err_len, "scenario: participants array missing");
        return -1;
    }
    size_t n = json_array_size(parts);
    if (n == 0 || n > HARNESS_MAX_VOTERS) {
        snprintf(err, err_len, "scenario: participant count out of range (%zu)", n);
        return -1;
    }
    for (size_t i = 0; i < n; i++) {
        json_t *p = json_array_get(parts, i);
        const char *id = json_string_value(json_object_get(p, "id"));
        if (id == NULL) {
            snprintf(err, err_len, "scenario: participants[%zu] missing id", i);
            return -1;
        }
        if (_put_uuid(out_voters[i].uuid, id) != 0) {
            snprintf(err, err_len, "scenario: participants[%zu] id too long", i);
            return -1;
        }
        int rank = 0;
        if (json_is_object(ranks)) {
            json_t *r = json_object_get(ranks, id);
            if (json_is_integer(r)) rank = (int)json_integer_value(r);
        }
        out_voters[i].rank = rank;
    }
    *out_count = n;
    return 0;
}

static int run_scenario(const at_case_t *c, char *err, size_t err_len) {
    int rc = -1;
    agreement_protocol_t *proto = NULL;
    agreement_voter_t voters[HARNESS_MAX_VOTERS] = {{{0}, 0}};
    size_t voter_count = 0;
    /* Pre-built blobs, keyed by their scenario id. */
    struct blob_entry {
        char id[MERKLE_UUID_LEN];
        merkle_blob_t blob;
    } blobs[HARNESS_MAX_BLOBS] = {{{0}, {{0}}}};
    size_t blob_count = 0;
    agreement_proof_t *proofs[HARNESS_MAX_VOTERS * HARNESS_MAX_BLOBS] = {0};
    size_t proof_count = 0;

    json_t *parts_j = json_object_get(c->data, "participants");
    json_t *steps_j = json_object_get(c->data, "steps");
    json_t *fixtures_j = json_object_get(c->data, "fixtures");
    json_t *expected_state_j = json_object_get(c->data, "expected_state");
    if (!json_is_array(steps_j) || !json_is_object(fixtures_j)) {
        snprintf(err, err_len, "scenario: steps[] or fixtures missing");
        return -1;
    }

    const char *impl = json_string_value(json_object_get(fixtures_j, "impl"));
    const char *myself_id = json_string_value(json_object_get(fixtures_j, "myself"));
    if (impl == NULL || myself_id == NULL) {
        snprintf(err, err_len, "scenario: fixtures.impl/myself missing");
        return -1;
    }
    json_t *ranks_j = json_object_get(fixtures_j, "ranks");

    if (_build_voters_from_participants(parts_j, ranks_j,
                                        voters, &voter_count,
                                        err, err_len) != 0) {
        return -1;
    }

    /* Stakes (POS only) — same scheme as run_agreement_vector but keyed
     * on fixtures.stakes for the scenario form. */
    g_stakes_count = 0;
    if (strcmp(impl, "stake") == 0) {
        json_t *stakes_j = json_object_get(fixtures_j, "stakes");
        if (json_is_object(stakes_j)) {
            const char *key;
            json_t *value;
            json_object_foreach(stakes_j, key, value) {
                if (g_stakes_count >= HARNESS_MAX_VOTERS) break;
                if (_put_uuid(g_stakes[g_stakes_count].uuid, key) != 0) continue;
                g_stakes[g_stakes_count].stake = json_is_number(value)
                    ? json_number_value(value) : 0.0;
                g_stakes_count++;
            }
        }
    }

    agreement_voter_t *me = _find_voter_by_id(voters, voter_count, myself_id);
    if (me == NULL) {
        snprintf(err, err_len, "scenario: myself %s not in participants", myself_id);
        return -1;
    }
    agreement_voter_t others[HARNESS_MAX_VOTERS];
    int other_count = 0;
    for (size_t i = 0; i < voter_count; i++) {
        if (&voters[i] == me) continue;
        others[other_count++] = voters[i];
    }

    if (strcmp(impl, "authority") == 0) {
        json_t *thr_j = json_object_get(fixtures_j, "threshold_rank");
        int threshold = json_is_integer(thr_j) ? (int)json_integer_value(thr_j) : 0;
        if (agreement_by_authority_create(me, others, other_count, threshold, &proto) != 0
            || proto == NULL) {
            snprintf(err, err_len, "scenario: authority_create failed");
            goto cleanup;
        }
    } else if (strcmp(impl, "stake") == 0) {
        if (agreement_by_stake_create(me, others, other_count, _harness_get_stake, &proto) != 0
            || proto == NULL) {
            snprintf(err, err_len, "scenario: stake_create failed");
            goto cleanup;
        }
    } else if (strcmp(impl, "work") == 0) {
        /* Mirror Python's AgreementByWork.DIFFICULTY = 2 so any future
         * "mine + verify" POW scenario produces byte-identical proofs
         * across languages. The fixture may override via
         * `difficulty: N`. */
        json_t *diff_j = json_object_get(fixtures_j, "difficulty");
        int difficulty = json_is_integer(diff_j) ? (int)json_integer_value(diff_j) : 2;
        if (agreement_by_work_create(me, others, other_count, difficulty, &proto) != 0
            || proto == NULL) {
            snprintf(err, err_len, "scenario: work_create failed");
            goto cleanup;
        }
    } else {
        snprintf(err, err_len, "scenario: unsupported impl %s", impl);
        goto cleanup;
    }

    /* Pre-build all blobs declared in fixtures.blobs. */
    json_t *blobs_j = json_object_get(fixtures_j, "blobs");
    if (json_is_object(blobs_j)) {
        const char *key;
        json_t *value;
        json_object_foreach(blobs_j, key, value) {
            if (blob_count >= HARNESS_MAX_BLOBS) {
                snprintf(err, err_len, "scenario: too many blobs (>%d)", HARNESS_MAX_BLOBS);
                goto cleanup;
            }
            if (strlen(key) >= MERKLE_UUID_LEN) {
                snprintf(err, err_len, "scenario: blob id %s too long", key);
                goto cleanup;
            }
            strncpy(blobs[blob_count].id, key, MERKLE_UUID_LEN - 1);
            const char *origin = json_string_value(json_object_get(value, "originator"));
            if (origin == NULL || strlen(origin) >= MERKLE_UUID_LEN) {
                snprintf(err, err_len, "scenario: blob %s: missing/long originator", key);
                goto cleanup;
            }
            strncpy(blobs[blob_count].blob.uuid, key, MERKLE_UUID_LEN - 1);
            strncpy(blobs[blob_count].blob.originator, origin, MERKLE_UUID_LEN - 1);
            blobs[blob_count].blob.get_hash = _harness_blob_hash;
            blob_count++;
        }
    }
    if (blob_count == 0) {
        snprintf(err, err_len, "scenario: fixtures.blobs is empty");
        goto cleanup;
    }

    /* Walk steps. Two step kinds: function=vote (submit a vote) and
     * function=finalize (inline finalize call with payload.expected_outcome
     * asserted before continuing). */
    size_t nsteps = json_array_size(steps_j);
    for (size_t i = 0; i < nsteps; i++) {
        json_t *step = json_array_get(steps_j, i);
        const char *func = json_string_value(json_object_get(step, "function"));
        json_t *payload = json_object_get(step, "payload");
        const char *blob_id = json_string_value(json_object_get(payload, "blob"));
        if (func == NULL || blob_id == NULL) {
            snprintf(err, err_len,
                     "scenario: steps[%zu] missing function or payload.blob", i);
            goto cleanup;
        }
        struct blob_entry *be = NULL;
        for (size_t j = 0; j < blob_count; j++) {
            if (strcmp(blobs[j].id, blob_id) == 0) { be = &blobs[j]; break; }
        }
        if (be == NULL) {
            snprintf(err, err_len, "scenario: steps[%zu] unknown blob %s", i, blob_id);
            goto cleanup;
        }

        if (strcmp(func, "finalize") == 0) {
            json_t *exp_j = json_object_get(payload, "expected_outcome");
            if (!json_is_boolean(exp_j)) {
                snprintf(err, err_len,
                         "scenario: steps[%zu] finalize step must declare "
                         "payload.expected_outcome", i);
                goto cleanup;
            }
            bool want = json_is_true(exp_j);
            bool got = agreement_finalize(proto, &be->blob);
            if (got != want) {
                snprintf(err, err_len,
                         "steps[%zu] finalize(%s) expected %s, got %s",
                         i, blob_id,
                         want ? "true" : "false",
                         got ? "true" : "false");
                goto cleanup;
            }
            continue;
        }

        if (strcmp(func, "prove") == 0) {
            /* POW-flavored step: agreement_prove mines a valid nonce
             * for the blob (per the protocol's own difficulty rule),
             * then agreement_verify admits the proof. Per-language
             * semantics — see BUGS.md P5 for the cross-language
             * digest-format and DIFFICULTY interpretation drift.
             *
             * repeat: N mines once, then verifies N times with the
             * same proof — replay-attack semantics. agreement_verify
             * appends to proto->state.work.approved each time;
             * agreement_finalize removes ONE entry and returns true,
             * so the outcome is idempotent under replay. Mirrors the
             * Python adapter's `for _ in range(repeat)` loop. */
            agreement_proof_t *mined = NULL;
            if (agreement_prove(proto, &be->blob, &mined) != 0 || mined == NULL) {
                snprintf(err, err_len,
                         "scenario: steps[%zu] agreement_prove failed", i);
                goto cleanup;
            }
            if (proof_count >= (sizeof(proofs) / sizeof(proofs[0]))) {
                agreement_proof_free(mined);
                snprintf(err, err_len, "scenario: too many proofs");
                goto cleanup;
            }
            proofs[proof_count++] = mined;
            /* Optional cross-language byte-pin assertion. */
            const char *exp_hex = json_string_value(
                json_object_get(payload, "expected_digest_hex"));
            if (exp_hex != NULL) {
                size_t want_len = strlen(exp_hex);
                if (want_len != mined->digest_len * 2) {
                    snprintf(err, err_len,
                             "scenario: steps[%zu] expected_digest_hex length %zu "
                             "does not match digest %zu hex chars",
                             i, want_len, mined->digest_len * 2);
                    goto cleanup;
                }
                char got_hex[MERKLE_DIGEST_LEN * 2 + 1] = {0};
                for (size_t b = 0; b < mined->digest_len; b++) {
                    snprintf(got_hex + b * 2, 3, "%02x", mined->digest[b]);
                }
                /* Compare lowercase-insensitively to allow YAML authors to
                 * write either case without re-mining. */
                bool match = true;
                for (size_t k = 0; k < want_len; k++) {
                    char a = (char)tolower((unsigned char)got_hex[k]);
                    char b = (char)tolower((unsigned char)exp_hex[k]);
                    if (a != b) { match = false; break; }
                }
                if (!match) {
                    snprintf(err, err_len,
                             "scenario: steps[%zu] prove(%s) digest_hex %s "
                             "does not match expected %s",
                             i, blob_id, got_hex, exp_hex);
                    goto cleanup;
                }
            }
            int repeat = 1;
            json_t *rep_j = json_object_get(step, "repeat");
            if (json_is_integer(rep_j)) {
                int rv = (int)json_integer_value(rep_j);
                if (rv >= 1) repeat = rv;
            }
            for (int rep = 0; rep < repeat; rep++) {
                agreement_verify(proto, &be->blob, mined, NULL, 0);
            }
            continue;
        }

        if (strcmp(func, "vote") != 0) {
            snprintf(err, err_len,
                     "scenario: steps[%zu] function must be vote|finalize|prove (got %s)",
                     i, func);
            goto cleanup;
        }

        const char *from_id = json_string_value(json_object_get(step, "from"));
        json_t *appr_j = json_object_get(payload, "approval");
        if (from_id == NULL || !json_is_boolean(appr_j)) {
            snprintf(err, err_len, "scenario: steps[%zu] vote payload malformed", i);
            goto cleanup;
        }
        agreement_voter_t *voter = _find_voter_by_id(voters, voter_count, from_id);
        if (voter == NULL) {
            snprintf(err, err_len, "scenario: steps[%zu] unknown voter %s", i, from_id);
            goto cleanup;
        }
        uint8_t digest[MERKLE_DIGEST_LEN];
        _harness_blob_hash(&be->blob, NULL, 0, digest);

        agreement_proof_t *p = NULL;
        if (agreement_proof_create(voter->uuid, digest, MERKLE_DIGEST_LEN,
                                   json_is_true(appr_j), NULL, 0, &p) != 0
            || p == NULL) {
            snprintf(err, err_len, "scenario: steps[%zu] proof_create failed", i);
            goto cleanup;
        }
        proofs[proof_count++] = p;
        /* repeat: N replays the same agreement_verify call N times. The
         * proto's votes list ends up with N references to the same
         * proof; for POA accumulate-by-rank (max-rank wins, dict
         * collapses by key) the outcome is identical to a single-vote
         * run. Mirrors Python adapter's `for _ in range(repeat)` loop. */
        int repeat = 1;
        json_t *rep_j = json_object_get(step, "repeat");
        if (json_is_integer(rep_j)) {
            int rv = (int)json_integer_value(rep_j);
            if (rv >= 1) repeat = rv;
        }
        for (int rep = 0; rep < repeat; rep++) {
            agreement_verify(proto, &be->blob, p, NULL, 0);
        }
    }

    /* Walk expected_state.agreement; finalize each blob and assert outcome. */
    json_t *agreement_expected = json_is_object(expected_state_j)
        ? json_object_get(expected_state_j, "agreement") : NULL;
    if (json_is_object(agreement_expected)) {
        const char *key;
        json_t *value;
        json_object_foreach(agreement_expected, key, value) {
            struct blob_entry *be = NULL;
            for (size_t j = 0; j < blob_count; j++) {
                if (strcmp(blobs[j].id, key) == 0) { be = &blobs[j]; break; }
            }
            if (be == NULL) {
                snprintf(err, err_len,
                         "scenario: expected_state.agreement.%s: unknown blob", key);
                goto cleanup;
            }
            json_t *outcome_j = json_object_get(value, "outcome");
            if (!json_is_boolean(outcome_j)) {
                snprintf(err, err_len,
                         "scenario: expected_state.agreement.%s.outcome must be boolean",
                         key);
                goto cleanup;
            }
            bool want = json_is_true(outcome_j);
            bool got = agreement_finalize(proto, &be->blob);
            if (got != want) {
                snprintf(err, err_len,
                         "finalize(%s): expected %s, got %s",
                         key, want ? "true" : "false", got ? "true" : "false");
                goto cleanup;
            }
        }
    }

    rc = 0;
cleanup:
    for (size_t i = 0; i < proof_count; i++) {
        agreement_proof_free(proofs[i]);
    }
    if (proto != NULL) agreement_protocol_free(proto);
    return rc;
}

/* ------------------------------------------------------------------------- */
/* Dispatch                                                                    */
/* ------------------------------------------------------------------------- */

void at_agreement_run(const at_case_t *c, at_case_result_t *out) {
    if (strcmp(c->kind, "negative") == 0) {
        at_neg_run_wire(c, out);
        return;
    }
    if (strcmp(c->kind, "scenario") == 0) {
        char err[256] = {0};
        struct timespec t0, t1;
        clock_gettime(CLOCK_MONOTONIC, &t0);
        int rc = run_scenario(c, err, sizeof(err));
        clock_gettime(CLOCK_MONOTONIC, &t1);
        int duration_ms = (int)((t1.tv_sec - t0.tv_sec) * 1000
                                + (t1.tv_nsec - t0.tv_nsec) / 1000000);
        if (rc == 0) {
            at_case_result_set_pass(out, duration_ms);
        } else {
            at_case_result_set_fail(out, duration_ms, "AssertionError", err);
        }
        return;
    }
    if (strcmp(c->kind, "agreement_vector") != 0) {
        char detail[160];
        snprintf(detail, sizeof(detail),
                 "agreement adapter: unsupported kind %s", c->kind);
        at_case_result_set_skip(out, detail);
        return;
    }

    char err[256] = {0};
    struct timespec t0, t1;
    clock_gettime(CLOCK_MONOTONIC, &t0);
    int rc = run_agreement_vector(c, err, sizeof(err));
    clock_gettime(CLOCK_MONOTONIC, &t1);
    int duration_ms = (int)((t1.tv_sec - t0.tv_sec) * 1000
                            + (t1.tv_nsec - t0.tv_nsec) / 1000000);

    if (rc == 0) {
        at_case_result_set_pass(out, duration_ms);
    } else {
        at_case_result_set_fail(out, duration_ms, "AssertionError", err);
    }
}
