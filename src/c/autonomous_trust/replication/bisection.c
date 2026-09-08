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

#include <string.h>

#include <sodium.h>

/* blake2b(in) -> 64 lowercase hex chars + NUL, the same primitive as the
 * reputation Merkle's merkle_hash_hex (crypto_generichash 32-byte digest,
 * sodium_bin2hex), i.e. Python MerkleTree.get_hash. */
static void _hash_hex(const unsigned char *in, size_t len,
                      char out[AT_REPL_HASH_HEX_LEN + 1])
{
    unsigned char digest[32];
    crypto_generichash(digest, sizeof(digest), in, len, NULL, 0);
    sodium_bin2hex(out, AT_REPL_HASH_HEX_LEN + 1, digest, sizeof(digest));
}

/* h_0 = H(s_0); h_i = H(h_{i-1} || s_i). Fills chain[0..n-1]. The previous
 * digest is prepended as its 64 hex bytes, exactly as the Python twin chains
 * the hex-ASCII digest with the next state's UTF-8 bytes. */
static void _hash_chain(const char *const *states, size_t n,
                        char (*chain)[AT_REPL_HASH_HEX_LEN + 1])
{
    unsigned char buf[AT_REPL_HASH_HEX_LEN + 512];
    for (size_t i = 0; i < n; i++)
    {
        const char *s = states[i] ? states[i] : "";
        size_t slen = strlen(s);
        size_t prev_len = (i == 0) ? 0 : AT_REPL_HASH_HEX_LEN;
        if (prev_len + slen > sizeof(buf))
            slen = sizeof(buf) - prev_len;   /* defensive; tokens are short */
        if (i != 0)
            memcpy(buf, chain[i - 1], prev_len);
        memcpy(buf + prev_len, s, slen);
        _hash_hex(buf, prev_len + slen, chain[i]);
    }
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
