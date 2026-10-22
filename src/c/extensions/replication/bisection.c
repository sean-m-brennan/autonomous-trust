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

#include "replication/bisection.h"

#include <stdio.h>
#include <string.h>

#include <sodium.h>

/* blake2b, 64 lowercase hex chars + NUL: the same primitive as the
 * reputation Merkle's merkle_hash_hex, i.e. Python MerkleTree.get_hash.
 * H(prev || state): the previous digest as its 64 hex bytes (none for h_0)
 * and the state's bytes, streamed, so a state of any length hashes as the
 * Python twin's does. It used to be copied into a 576-byte buffer, which
 * silently truncated any state over 512 bytes. */
static void _digest(const char *prev, const char *state,
                    char out[AT_REPL_HASH_HEX_LEN + 1])
{
    crypto_generichash_state st;
    unsigned char digest[32];
    crypto_generichash_init(&st, NULL, 0, sizeof(digest));
    if (prev != NULL)
        crypto_generichash_update(&st, (const unsigned char *)prev,
                                  AT_REPL_HASH_HEX_LEN);
    if (state != NULL)
        crypto_generichash_update(&st, (const unsigned char *)state, strlen(state));
    crypto_generichash_final(&st, digest, sizeof(digest));
    sodium_bin2hex(out, AT_REPL_HASH_HEX_LEN + 1, digest, sizeof(digest));
}

/* h_0 = H(s_0); h_i = H(h_{i-1} || s_i). Fills chain[0..n-1]. The previous
 * digest is prepended as its 64 hex bytes, exactly as the Python twin chains
 * the hex-ASCII digest with the next state's UTF-8 bytes. */
static void _hash_chain(const char *const *states, size_t n,
                        char (*chain)[AT_REPL_HASH_HEX_LEN + 1])
{
    for (size_t i = 0; i < n; i++)
        _digest(i == 0 ? NULL : chain[i - 1], states[i] ? states[i] : "", chain[i]);
}

bool at_replication_commit_root(const char *const *states, size_t n,
                                char out[AT_REPL_HASH_HEX_LEN + 1])
{
    if (n == 0 || states == NULL || n > AT_REPL_MAX_STEPS)
        return false;
    static char chain[AT_REPL_MAX_STEPS][AT_REPL_HASH_HEX_LEN + 1];
    _hash_chain(states, n, chain);
    memcpy(out, chain[n - 1], AT_REPL_HASH_HEX_LEN + 1);
    return true;
}

/* Smallest index where two chains differ, by binary search over the monotonic
 * "differ" predicate. Returns the index and sets *found; when the chains agree
 * over their common length, *found is true only if the lengths differ (one
 * kept computing past the other), and the index is that common length. */
static int _first_divergence(const char (*chain_a)[AT_REPL_HASH_HEX_LEN + 1],
                             size_t na,
                             const char (*chain_b)[AT_REPL_HASH_HEX_LEN + 1],
                             size_t nb, bool *found)
{
    size_t n = na < nb ? na : nb;
    if (n == 0 || strcmp(chain_a[n - 1], chain_b[n - 1]) == 0)
    {
        if (na != nb)
        {
            *found = true;
            return (int)n;
        }
        *found = false;
        return 0;
    }
    size_t lo = 0, hi = n - 1;
    while (lo < hi)
    {
        size_t mid = (lo + hi) / 2;
        if (strcmp(chain_a[mid], chain_b[mid]) != 0)
            hi = mid;
        else
            lo = mid + 1;
    }
    *found = true;
    return (int)lo;
}

/* Python None == None is true, None == x is false: a state past the end of a
 * trace is NULL and matches only another NULL. */
static bool _streq_nullable(const char *a, const char *b)
{
    if (a == NULL || b == NULL)
        return a == b;
    return strcmp(a, b) == 0;
}

bool at_replication_bisect_adjudicate(
    const char *const *states_a, size_t na,
    const char *const *states_b, size_t nb,
    const char *const *reference, size_t nref,
    int *divergence_out, bool *diverged_out,
    at_repl_verdict_t *verdict_a, at_repl_verdict_t *verdict_b)
{
    if (na > AT_REPL_MAX_STEPS || nb > AT_REPL_MAX_STEPS
        || nref > AT_REPL_MAX_STEPS)
        return false;
    static char chain_a[AT_REPL_MAX_STEPS][AT_REPL_HASH_HEX_LEN + 1];
    static char chain_b[AT_REPL_MAX_STEPS][AT_REPL_HASH_HEX_LEN + 1];
    _hash_chain(states_a, na, chain_a);
    _hash_chain(states_b, nb, chain_b);

    bool found = false;
    int k = _first_divergence(chain_a, na, chain_b, nb, &found);
    if (!found)
    {
        if (diverged_out) *diverged_out = false;
        if (divergence_out) *divergence_out = -1;
        if (verdict_a) *verdict_a = AT_REPL_CORROBORATED;
        if (verdict_b) *verdict_b = AT_REPL_CORROBORATED;
        return true;
    }

    const char *ref_k = ((size_t)k < nref) ? reference[k] : NULL;
    const char *a_k = ((size_t)k < na) ? states_a[k] : NULL;
    const char *b_k = ((size_t)k < nb) ? states_b[k] : NULL;
    if (diverged_out) *diverged_out = true;
    if (divergence_out) *divergence_out = k;
    if (verdict_a)
        *verdict_a = _streq_nullable(a_k, ref_k) ? AT_REPL_CORROBORATED
                                                 : AT_REPL_OUTVOTED;
    if (verdict_b)
        *verdict_b = _streq_nullable(b_k, ref_k) ? AT_REPL_CORROBORATED
                                                 : AT_REPL_OUTVOTED;
    return true;
}

/* ---- The live game -------------------------------------------------------- */

bool at_repl_session_init(at_repl_session_t *s, int len_a, const char *root_a,
                          int len_b, const char *root_b)
{
    if (s == NULL || len_a < 0 || len_b < 0 || len_a > AT_REPL_MAX_STEPS
        || len_b > AT_REPL_MAX_STEPS)
        return false;
    memset(s, 0, sizeof(*s));
    s->lens[0] = len_a;
    s->lens[1] = len_b;
    const char *roots[2] = { root_a, root_b };
    for (int side = 0; side < 2; side++)
        if (s->lens[side] > 0 && roots[side] != NULL)
        {
            int at = s->lens[side] - 1;
            snprintf(s->digests[side][at], AT_REPL_HASH_HEX_LEN + 1, "%s", roots[side]);
            s->have[side][at] = true;
        }
    int n = len_a < len_b ? len_a : len_b;
    if (len_a == len_b && _streq_nullable(root_a, root_b))
        s->disputed = false;               /* no dispute to resolve */
    else
    {
        s->disputed = true;
        s->lo = 0;
        /* Equal lengths differ at the roots; otherwise the shorter has no
         * state at n, so the chains differ there. */
        s->hi = n == 0 ? 0 : (len_a == len_b ? n - 1 : n);
    }
    return true;
}

bool at_repl_session_pending(const at_repl_session_t *s, int *index, bool owe[2])
{
    if (s == NULL || !s->disputed)
        return false;
    bool searching = s->lo < s->hi;
    int at = searching ? (s->lo + s->hi) / 2 : s->lo;
    bool any = false;
    for (int side = 0; side < 2; side++)
    {
        owe[side] = !s->have[side][at] && (searching || at < s->lens[side]);
        any = any || owe[side];
    }
    if (!searching && !any)
        return false;
    *index = at;
    return true;
}

bool at_repl_session_answer(at_repl_session_t *s, int index,
                            const char *digest_a, const char *digest_b)
{
    int at = 0;
    bool owe[2];
    if (!at_repl_session_pending(s, &at, owe) || at != index)
        return false;
    const char *given[2] = { digest_a, digest_b };
    for (int side = 0; side < 2; side++)
        if (owe[side] && (given[side] == NULL
                          || strlen(given[side]) != AT_REPL_HASH_HEX_LEN))
            return false;
    for (int side = 0; side < 2; side++)
        if (owe[side])
        {
            snprintf(s->digests[side][at], AT_REPL_HASH_HEX_LEN + 1, "%s", given[side]);
            s->have[side][at] = true;
        }
    if (s->lo == s->hi)
        return true;                       /* the final fetch at k */
    if (strcmp(s->digests[0][at], s->digests[1][at]) != 0)
        s->hi = at;
    else
        s->lo = at + 1;
    return true;
}

int at_repl_session_divergence(const at_repl_session_t *s)
{
    int at = 0;
    bool owe[2];
    if (s == NULL || !s->disputed || at_repl_session_pending(s, &at, owe))
        return -1;
    return s->lo;
}

static const char *_agreed_prev(const at_repl_session_t *s, int k)
{
    return k > 0 ? s->digests[0][k - 1] : NULL;
}

bool at_repl_reveal_consistent(const at_repl_session_t *s, int side,
                               const at_repl_reveal_t *r, size_t max_state_bytes)
{
    int k = at_repl_session_divergence(s);
    if (k < 0 || side < 0 || side > 1 || r == NULL)
        return false;
    if ((r->pre != NULL && strlen(r->pre) > max_state_bytes)
        || (r->state != NULL && strlen(r->state) > max_state_bytes))
        return false;
    char h[AT_REPL_HASH_HEX_LEN + 1];
    if (k > 0)
    {
        if (r->pre == NULL || (r->prev == NULL) != (k == 1))
            return false;
        if (r->prev != NULL && strlen(r->prev) != AT_REPL_HASH_HEX_LEN)
            return false;
        _digest(r->prev, r->pre, h);
        if (strcmp(h, _agreed_prev(s, k)) != 0)
            return false;
    }
    else if (r->pre != NULL)
        return false;
    if (!s->have[side][k])
        return r->state == NULL;          /* its trace ends before k */
    if (r->state == NULL)
        return false;
    _digest(_agreed_prev(s, k), r->state, h);
    return strcmp(h, s->digests[side][k]) == 0;
}

bool at_repl_settle(const at_repl_session_t *s, const at_repl_reveal_t reveals[2],
                    at_repl_truth_fn truth, void *ctx, size_t max_state_bytes,
                    at_repl_verdict_t out[2])
{
    int k = at_repl_session_divergence(s);
    if (k < 0 || reveals == NULL || truth == NULL || out == NULL)
        return false;
    bool ok[2];
    for (int side = 0; side < 2; side++)
        ok[side] = at_repl_reveal_consistent(s, side, &reveals[side], max_state_bytes);
    const char *pre = NULL;
    if (k > 0)
    {
        if (!ok[0] && !ok[1])
        {
            out[0] = out[1] = AT_REPL_OUTVOTED;
            return true;
        }
        pre = reveals[ok[0] ? 0 : 1].pre;
    }
    const char *true_k = truth(pre, ctx);
    for (int side = 0; side < 2; side++)
        out[side] = ok[side] && _streq_nullable(reveals[side].state, true_k)
            ? AT_REPL_CORROBORATED : AT_REPL_OUTVOTED;
    return true;
}
