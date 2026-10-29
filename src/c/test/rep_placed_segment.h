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

/** @file A placed chain for a test to serve as catch-up.
 *
 *  Every group places its order (doc/architecture/reputation.md, "Agreeing on
 *  an order"), so a catch-up segment is taken only where a placement
 *  certificate covers it. These build one the way a group would: a genesis
 *  roster at index 0, signed by every member, then each entry placed at the
 *  next index with every member's signature. Include after test_setup.h and
 *  the identity and reputation headers.
 */

#ifndef REP_PLACED_SEGMENT_H
#define REP_PLACED_SEGMENT_H

#include <string.h>
#include <jansson.h>
#include <sodium.h>
#include <uuid/uuid.h>

/* Place @p e at the next index of @p h, certified by all @p n @p signers. */
static inline void rps_place(tx_history_t *h, transaction_t *e,
                             identity_t **signers, int n)
{
    int k = h->next_index;
    char digest[TX_HASH_HEX_LEN + 1];
    place_value_digest(e, 1, k, digest);
    uint8_t desig[PLACE_DESIG_MAX];
    size_t dlen = place_designation(k, h->head_hash, digest, desig, sizeof(desig));
    json_t *sigs = json_object();
    for (int i = 0; i < n; i++)
    {
        unsigned char sig[crypto_sign_BYTES];
        ck_assert(crypto_sign_detached(sig, NULL, desig, dlen,
                                       signers[i]->signature.private) == 0);
        char hex[crypto_sign_BYTES * 2 + 1];
        hexlify(sig, crypto_sign_BYTES, (unsigned char *)hex);
        char u[UUID_STRING_LEN + 1];
        uuid_unparse_lower(signers[i]->uuid, u);
        json_object_set_new(sigs, u, json_string(hex));
    }
    char *text = json_dumps(sigs, JSON_COMPACT | JSON_SORT_KEYS);
    json_decref(sigs);
    ck_assert_int_eq(tx_history_apply_placed(h, k, e, 1, text), TX_PLACE_APPLIED);
    free(text);
}

/* Found @p h: a genesis roster of @p members, placed at index 0 by all. */
static inline void rps_found(tx_history_t *h, identity_t **members, int n)
{
    json_t *list = json_array();
    for (int i = 0; i < n; i++)
    {
        char u[UUID_STRING_LEN + 1], k[2 * crypto_sign_PUBLICKEYBYTES + 1];
        uuid_unparse_lower(members[i]->uuid, u);
        sodium_bin2hex(k, sizeof(k), members[i]->signature.public,
                       crypto_sign_PUBLICKEYBYTES);
        json_array_append_new(list, json_pack("[s, s]", u, k));
    }
    char d[TX_HASH_HEX_LEN + 1];
    ck_assert_int_eq(tx_history_roster_put(h, list, d), 0);
    json_decref(list);
    transaction_t g;
    memset(&g, 0, sizeof(g));
    g.index = -1;
    g.roster = true;
    at_strlcpy(g.roster_digest, d, sizeof(g.roster_digest));
    strcpy(g.roster_op, "genesis");
    tx_roster_task_uuid(NULL, "genesis", NULL, d, g.task_uuid);
    rps_place(h, &g, members, n);
}

/* @p scorer's own signature over its half of @p task naming @p other
 * (R+D.md §14.2), kept on @p h beside the placed entry. */
static inline void rps_sign_half(tx_history_t *h, const uuid_t task,
                                 const identity_t *scorer,
                                 const identity_t *other, double score)
{
    uint8_t desig[HALF_DESIG_MAX];
    size_t dlen = half_designation(task, scorer->uuid, other->uuid, tx_score_to_milli(score), NULL,
                                   desig, sizeof(desig));
    ck_assert(dlen > 0);
    unsigned char sig[crypto_sign_BYTES];
    ck_assert(crypto_sign_detached(sig, NULL, desig, dlen,
                                   scorer->signature.private) == 0);
    char hex[crypto_sign_BYTES * 2 + 1];
    hexlify(sig, crypto_sign_BYTES, (unsigned char *)hex);
    ck_assert_int_eq(tx_history_attach_half_sig(h, task, scorer->uuid, hex), 0);
}

/* Place a bilateral entry for @p task between @p a and @p b on @p h, signed
 * by all @p n @p signers, each half by its scorer. The halves are ordered by
 * uuid, as a placement orders them. */
static inline void rps_pair(tx_history_t *h, const uuid_t task,
                            identity_t *a, double a_score,
                            identity_t *b, double b_score,
                            identity_t **signers, int n)
{
    if (uuid_compare(b->uuid, a->uuid) < 0)
    {
        identity_t *x = a; a = b; b = x;
        double s = a_score; a_score = b_score; b_score = s;
    }
    transaction_t t;
    memset(&t, 0, sizeof(t));
    t.index = -1;
    uuid_copy(t.task_uuid, task);
    uuid_copy(t.p1_uuid, a->uuid);
    uuid_copy(t.p2_uuid, b->uuid);
    t.p1_set = t.p2_set = true;
    t.p1_score_milli = tx_score_to_milli(a_score);
    t.p2_score_milli = tx_score_to_milli(b_score);
    rps_place(h, &t, signers, n);
    rps_sign_half(h, task, a, b, a_score);
    rps_sign_half(h, task, b, a, b_score);
}

#endif /* REP_PLACED_SEGMENT_H */
