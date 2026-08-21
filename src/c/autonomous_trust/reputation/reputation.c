/********************
 *  Copyright 2023 TekFive, Inc., Sean M. Brennan, and contributors
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
#include <stdio.h>
#include <stdlib.h>
#include <math.h>
#include <errno.h>
#include <sodium.h>

#include "reputation/reputation.h"
#include "structures/map.h"
#include "utilities/at_jansson.h"
#include "structures/data.h"
#include "identity/identity.h"

DEFINE_ERROR(EREP_NOTX, "Transaction not found");
DEFINE_ERROR(EREP_NOPEER, "Peer not found in reputation map");
DEFINE_ERROR(EREP_CHAIN_FULL, "Transaction chain is full");

/****************************
 * Phase 1 hash-linking
 ****************************/

/* Serialize a UUID field, or the literal "null" when unset, into out.
 * Returns the number of chars written (excluding NUL). */
static int append_uuid_field(char *out, size_t outsz, const uuid_t u, bool set)
{
    if (!set)
        return snprintf(out, outsz, "null");
    char ustr[UUID_STRING_LEN + 1];
    uuid_unparse_lower(u, ustr);
    return snprintf(out, outsz, "%s", ustr);
}

int transaction_canonical_bytes(const transaction_t *tx, char *out, size_t outsz)
{
    /* Deterministic, language-agnostic serialization of everything EXCEPT
     * prev_hash. MUST match Python Transaction._canonical_bytes:
     *   task_id|p1_id|p1_score|p2_id|p2_score|index
     * UUIDs lowercase-hyphenated (or "null"), floats "%.17g" (or "null"),
     * index decimal (or "null" when pending / -1). The task_uuid is always
     * present. p1/p2 follow their *_set flags; a pending (index < 0) tx
     * serializes index as "null" to match Python's None. */
    char buf[UUID_STRING_LEN * 3 + 128];
    int n = 0;
    char tstr[UUID_STRING_LEN + 1];
    uuid_unparse_lower(tx->task_uuid, tstr);
    n += snprintf(buf + n, sizeof(buf) - n, "%s|", tstr);
    n += append_uuid_field(buf + n, sizeof(buf) - n, tx->p1_uuid, tx->p1_set);
    if (tx->p1_set)
        n += snprintf(buf + n, sizeof(buf) - n, "|%.17g|", tx->p1_score);
    else
        n += snprintf(buf + n, sizeof(buf) - n, "|null|");
    n += append_uuid_field(buf + n, sizeof(buf) - n, tx->p2_uuid, tx->p2_set);
    if (tx->p2_set)
        n += snprintf(buf + n, sizeof(buf) - n, "|%.17g|", tx->p2_score);
    else
        n += snprintf(buf + n, sizeof(buf) - n, "|null|");
    if (tx->index < 0)
        n += snprintf(buf + n, sizeof(buf) - n, "null");
    else
        n += snprintf(buf + n, sizeof(buf) - n, "%d", tx->index);
    if (n < 0 || (size_t)n >= sizeof(buf) || (size_t)n >= outsz)
        return -1;
    memcpy(out, buf, (size_t)n + 1);
    return n;
}

void transaction_entry_hash(const transaction_t *tx, char out[TX_HASH_HEX_LEN + 1])
{
    /* blake2b over (canonical_bytes || prev_hash), hex-encoded. Matches
     * Python MerkleTree.get_hash(canonical + prev_hash): 32-byte digest,
     * lowercase hex. prev_hash is appended as its raw ASCII hex bytes (the
     * same concatenation Python performs on the b'' / 64-hex-byte value). */
    char canon[UUID_STRING_LEN * 3 + 128];
    int clen = transaction_canonical_bytes(tx, canon, sizeof(canon));
    if (clen < 0)
    {
        out[0] = '\0';
        return;
    }
    size_t plen = strnlen(tx->prev_hash, TX_HASH_HEX_LEN);
    unsigned char in[sizeof(canon) + TX_HASH_HEX_LEN];
    memcpy(in, canon, (size_t)clen);
    memcpy(in + clen, tx->prev_hash, plen);
    unsigned char digest[32];
    crypto_generichash(digest, sizeof(digest), in, (size_t)clen + plen, NULL, 0);
    sodium_bin2hex(out, TX_HASH_HEX_LEN + 1, digest, sizeof(digest));
}

bool tx_verify_chain_links(const transaction_t *chain, int count)
{
    const transaction_t *prev = NULL;
    for (int i = 0; i < count; i++)
    {
        const transaction_t *link = &chain[i];
        if (link->index < 0)
            continue;  /* pending entry — not part of the committed link */
        if (prev != NULL)
        {
            char expect[TX_HASH_HEX_LEN + 1];
            transaction_entry_hash(prev, expect);
            if (strncmp(link->prev_hash, expect, TX_HASH_HEX_LEN + 1) != 0)
                return false;
        }
        prev = link;
    }
    return true;
}

bool tx_history_verify_links(const tx_history_t *hist)
{
    return tx_verify_chain_links(hist->chain, hist->chain_len);
}

/****************************
 * Phase 2: ordered Merkle root over the resident window
 *
 * RFC 6962 Merkle Tree Hash with domain-separated leaf (0x00) and node (0x01)
 * prefixes, over each committed entry's entry_hash in resident order. The
 * construction is a pure function of the ordered leaf digests (no tree-shape
 * dependence), so it stays byte-identical to Python
 * TransactionHistory.window_root / _mth / _audit_path / verify_inclusion.
 ****************************/

#define MERKLE_LEAF_PREFIX 0x00
#define MERKLE_NODE_PREFIX 0x01

/* blake2b(in) -> TX_HASH_HEX_LEN lowercase hex chars + NUL. Same primitive as
 * transaction_entry_hash (crypto_generichash 32-byte digest, sodium_bin2hex),
 * i.e. Python MerkleTree.get_hash. */
static void merkle_hash_hex(const unsigned char *in, size_t len,
                            char out[TX_HASH_HEX_LEN + 1])
{
    unsigned char digest[32];
    crypto_generichash(digest, sizeof(digest), in, len, NULL, 0);
    sodium_bin2hex(out, TX_HASH_HEX_LEN + 1, digest, sizeof(digest));
}

/* RFC 6962 MTH over leaves[lo .. hi). Empty range -> H(""). */
static void mth_range(const char (*leaves)[TX_HASH_HEX_LEN + 1],
                      int lo, int hi, char out[TX_HASH_HEX_LEN + 1])
{
    int n = hi - lo;
    if (n <= 0)
    {
        merkle_hash_hex((const unsigned char *)"", 0, out);
        return;
    }
    if (n == 1)
    {
        unsigned char in[1 + TX_HASH_HEX_LEN];
        in[0] = MERKLE_LEAF_PREFIX;
        memcpy(in + 1, leaves[lo], TX_HASH_HEX_LEN);
        merkle_hash_hex(in, 1 + TX_HASH_HEX_LEN, out);
        return;
    }
    int k = 1;
    while (k * 2 < n)
        k *= 2;
    char left[TX_HASH_HEX_LEN + 1], right[TX_HASH_HEX_LEN + 1];
    mth_range(leaves, lo, lo + k, left);
    mth_range(leaves, lo + k, hi, right);
    unsigned char in[1 + 2 * TX_HASH_HEX_LEN];
    in[0] = MERKLE_NODE_PREFIX;
    memcpy(in + 1, left, TX_HASH_HEX_LEN);
    memcpy(in + 1 + TX_HASH_HEX_LEN, right, TX_HASH_HEX_LEN);
    merkle_hash_hex(in, 1 + 2 * TX_HASH_HEX_LEN, out);
}

/* RFC 6962 audit path for leaf position `m` within leaves[lo .. hi). Appends
 * (sibling_root, sibling_is_left) steps bottom-up at *cnt. */
static void audit_path(const char (*leaves)[TX_HASH_HEX_LEN + 1],
                       int lo, int hi, int m,
                       tx_merkle_step_t *steps, int *cnt)
{
    int n = hi - lo;
    if (n <= 1)
        return;
    int k = 1;
    while (k * 2 < n)
        k *= 2;
    char sib[TX_HASH_HEX_LEN + 1];
    if (m < lo + k)
    {
        audit_path(leaves, lo, lo + k, m, steps, cnt);
        mth_range(leaves, lo + k, hi, sib);
        memcpy(steps[*cnt].sibling, sib, TX_HASH_HEX_LEN + 1);
        steps[*cnt].sibling_is_left = false;
    }
    else
    {
        audit_path(leaves, lo + k, hi, m, steps, cnt);
        mth_range(leaves, lo, lo + k, sib);
        memcpy(steps[*cnt].sibling, sib, TX_HASH_HEX_LEN + 1);
        steps[*cnt].sibling_is_left = true;
    }
    (*cnt)++;
}

/* Collect the committed (index >= 0) window leaves in resident order; returns
 * the leaf count and, if want_index >= 0, the position of that absolute index
 * (or -1). */
static int collect_window_leaves(const tx_history_t *hist,
                                 char (*leaves)[TX_HASH_HEX_LEN + 1],
                                 int want_index, int *pos_out)
{
    int n = 0, pos = -1;
    for (int i = 0; i < hist->chain_len; i++)
    {
        if (hist->chain[i].index < 0)
            continue;
        if (want_index >= 0 && hist->chain[i].index == want_index)
            pos = n;
        transaction_entry_hash(&hist->chain[i], leaves[n]);
        n++;
    }
    if (pos_out != NULL)
        *pos_out = pos;
    return n;
}

void transaction_window_root(const tx_history_t *hist, char out[TX_HASH_HEX_LEN + 1])
{
    char leaves[MAX_CHAIN_LEN][TX_HASH_HEX_LEN + 1];
    int n = collect_window_leaves(hist, leaves, -1, NULL);
    mth_range(leaves, 0, n, out);
}

int transaction_window_proof(const tx_history_t *hist, int abs_index,
                             tx_merkle_step_t *steps, int *n_steps)
{
    char leaves[MAX_CHAIN_LEN][TX_HASH_HEX_LEN + 1];
    int pos = -1;
    int n = collect_window_leaves(hist, leaves, abs_index, &pos);
    if (pos < 0)
    {
        if (n_steps != NULL)
            *n_steps = 0;
        return -1;
    }
    int cnt = 0;
    audit_path(leaves, 0, n, pos, steps, &cnt);
    if (n_steps != NULL)
        *n_steps = cnt;
    return 0;
}

bool tx_merkle_verify(const char leaf_hex[TX_HASH_HEX_LEN + 1],
                      const tx_merkle_step_t *steps, int n_steps,
                      const char root_hex[TX_HASH_HEX_LEN + 1])
{
    char cur[TX_HASH_HEX_LEN + 1];
    unsigned char leaf_in[1 + TX_HASH_HEX_LEN];
    leaf_in[0] = MERKLE_LEAF_PREFIX;
    memcpy(leaf_in + 1, leaf_hex, TX_HASH_HEX_LEN);
    merkle_hash_hex(leaf_in, 1 + TX_HASH_HEX_LEN, cur);
    for (int i = 0; i < n_steps; i++)
    {
        unsigned char in[1 + 2 * TX_HASH_HEX_LEN];
        in[0] = MERKLE_NODE_PREFIX;
        if (steps[i].sibling_is_left)
        {
            memcpy(in + 1, steps[i].sibling, TX_HASH_HEX_LEN);
            memcpy(in + 1 + TX_HASH_HEX_LEN, cur, TX_HASH_HEX_LEN);
        }
        else
        {
            memcpy(in + 1, cur, TX_HASH_HEX_LEN);
            memcpy(in + 1 + TX_HASH_HEX_LEN, steps[i].sibling, TX_HASH_HEX_LEN);
        }
        merkle_hash_hex(in, 1 + 2 * TX_HASH_HEX_LEN, cur);
    }
    return strncmp(cur, root_hex, TX_HASH_HEX_LEN + 1) == 0;
}

/****************************
 * Transaction history
 ****************************/

/* Frama-C: skipped — [solver-timeout] smrt_ptr allocation postconditions */
int tx_history_create(tx_history_t **hist)
{
    *hist = calloc(1, sizeof(tx_history_t));
    if (*hist == NULL)
        return EXCEPTION(ENOMEM);
    return tx_history_init(*hist);
}

int tx_history_init(tx_history_t *hist)
{
    hist->chain_len = 0;
    hist->committed_count = 0;
    hist->next_index = 0;
    hist->first_index = 0;
    hist->evicted_ring_head = 0;
    hist->evicted_ring_len = 0;
    hist->head_hash[0] = '\0';  /* Phase 1: empty genesis link */
    int err = map_init(&hist->task_map);
    if (err != 0) return err;
    err = map_init(&hist->peer_map);
    if (err != 0) return err;
    return map_init(&hist->evicted_set);
}

static void tx_history_evict_oldest(tx_history_t *hist);

/* Append `slot` to peer_map[peer_uuid]'s index list, creating the list on
 * first sight. Factored out of tx_history_update so the LOADERS
 * (tx_history_era_from_json, _history_load_committed) can index a peer too.
 *
 * They previously did not, and that was a silent hole rather than a cosmetic
 * one: every scoring function — reputation_pure, reputation_contrite_tft,
 * reputation_consensus, reputation_consensus_by_tier — reaches its
 * transactions through tx_history_by_peer, which reads ONLY peer_map. A chain
 * arriving by catch-up (or restored from persisted evidence) therefore scored
 * as if it were empty: present in the window, invisible to every algorithm
 * that consumes it. */
static int _index_peer_slot(tx_history_t *hist, const uuid_t peer_uuid, int slot)
{
    char peer_str[UUID_STRING_LEN + 1];
    uuid_unparse_lower(peer_uuid, peer_str);
    data_t *peer_indices = NULL;
    if (map_get(&hist->peer_map, (map_key_t)peer_str, &peer_indices) != 0)
    {
        /* array_create, not smrt_create + array_init: init zeroes the smrt
         * header for the embedded case, and create is what re-asserts it for
         * a heap array_t. Hand-rolling the pair left this array_t with
         * refs==0, so the array_free in tx_history_free never released it. */
        array_t *arr = NULL;
        if (array_create(&arr) != 0) return EXCEPTION(ENOMEM);
        array_append(arr, integer_data(slot));
        map_set(&hist->peer_map, (map_key_t)peer_str,
                object_ptr_data(arr, sizeof(array_t)));
        return 0;
    }
    void *arr_ptr = NULL;
    data_object_ptr(peer_indices, &arr_ptr);
    if (arr_ptr == NULL) return -1;
    array_append((array_t *)arr_ptr, integer_data(slot));
    return 0;
}

/* Load one already-committed entry verbatim — index, prev_hash and scores as
 * they were persisted — and wire up the maps and counters around it.
 *
 * Verbatim is the whole point: tx_history_update would assign a fresh index
 * and recompute prev_hash from the local head, which is exactly what a
 * verifiable warm start must not do. The Merkle root only reproduces if the
 * entries hash to what they hashed to when they were signed. Assumes the
 * caller has already verified the segment's linkage. */
static void _history_load_committed(tx_history_t *hist, const transaction_t *src)
{
    if (hist == NULL || src == NULL)
        return;
    if (hist->chain_len >= MAX_CHAIN_LEN)
        tx_history_evict_oldest(hist);
    int slot = hist->chain_len;
    transaction_t *tx = &hist->chain[slot];
    *tx = *src;

    char task_key[UUID_STRING_LEN + 1];
    uuid_unparse_lower(tx->task_uuid, task_key);
    map_set(&hist->task_map, (map_key_t)task_key, integer_data(slot));
    if (tx->p1_set)
        _index_peer_slot(hist, tx->p1_uuid, slot);
    if (tx->p2_set && uuid_compare(tx->p1_uuid, tx->p2_uuid) != 0)
        _index_peer_slot(hist, tx->p2_uuid, slot);

    if (hist->committed_count == 0 || tx->index < hist->first_index)
        hist->first_index = tx->index;
    hist->committed_count++;
    hist->chain_len++;
    if (tx->index + 1 > hist->next_index)
        hist->next_index = tx->index + 1;
    /* Resume the link from the loaded tail so subsequent local commits chain
     * cleanly onto the restored history. */
    transaction_entry_hash(tx, hist->head_hash);
}

/* Evict chain[0] FIFO-style: drop its task_map entry, scrub
 * slot-0 references from peer_map (decrementing every other
 * slot index by 1 to track the memmove), then shift the chain
 * down and renumber tx->index across the remainder. O(N) per
 * eviction; with N=200, ~3 µs on modern hardware.
 *
 * Mirrors TransactionHistory._evict_oldest in
 * src/autonomous-trust/.../reputation/reputation.py — keep
 * semantics aligned (FIFO, full task_map + peer_map cleanup).
 */
/* Frama-C: skipped — [solver-timeout] memmove + map iteration */
static void tx_history_evict_oldest(tx_history_t *hist)
{
    if (hist->chain_len <= 0)
        return;

    /* Stash the evicted tx's identifiers before we shift over it. */
    transaction_t evicted = hist->chain[0];
    char task_str[UUID_STRING_LEN + 1];
    uuid_unparse_lower(evicted.task_uuid, task_str);
    bool evicted_committed = evicted.p1_set && evicted.p2_set;

    /* 1. Drop evicted's task_map entry. */
    map_remove(&hist->task_map, task_str);

    /* 1a. Push the evicted task_uuid onto the tombstone ring. If the
     * ring is full, the displaced key must first be removed from
     * the evicted_set so it doesn't outlive its slot. Mirrors
     * Python's _evicted_task_ids OrderedDict pop. */
    if (hist->evicted_ring_len == MAX_CHAIN_LEN)
    {
        map_remove(&hist->evicted_set,
                   hist->evicted_ring[hist->evicted_ring_head]);
    }
    else
    {
        hist->evicted_ring_len++;
    }
    snprintf(hist->evicted_ring[hist->evicted_ring_head],
             sizeof(hist->evicted_ring[0]), "%s", task_str);
    map_set(&hist->evicted_set,
            hist->evicted_ring[hist->evicted_ring_head],
            integer_data(1));
    hist->evicted_ring_head =
        (hist->evicted_ring_head + 1) % MAX_CHAIN_LEN;

    /* 2. Decrement every other task_map value by 1 to follow the
     *    memmove of the chain. */
    map_key_t tkey = NULL;
    data_t *tval = NULL;
    map_entries_for_each(&hist->task_map, tkey, tval)
    {
        int ival = 0;
        data_integer(tval, &ival);
        /* Replace with a new integer_data; map_set takes ownership
         * via the smart-pointer layer. */
        map_set(&hist->task_map, tkey, integer_data(ival - 1));
    }
    map_end_for_each

    /* 3. peer_map cleanup. For each peer that the evicted tx
     *    referenced (and we don't know all peers without scanning),
     *    the slot-0 reference must be removed. Easier and safer:
     *    walk every peer_map entry, remove slot-0 from its array
     *    (if present), decrement the rest. Drop empty arrays.
     *
     *    O(num_peers * avg_per_peer) per eviction. With N=200 and
     *    a handful of peers this is microseconds. */
    array_t *peer_keys = map_keys(&hist->peer_map);
    array_t empty_peers;
    array_init(&empty_peers);
    for (size_t pi = 0; pi < array_size(peer_keys); pi++)
    {
        data_t *kdat = NULL;
        if (array_get(peer_keys, (int)pi, &kdat) != 0)
            continue;
        char *pkey = NULL;
        if (data_string_ptr(kdat, &pkey) != 0 || pkey == NULL)
            continue;
        data_t *pval = NULL;
        if (map_get(&hist->peer_map, pkey, &pval) != 0 || pval == NULL)
            continue;
        void *arr_ptr = NULL;
        data_object_ptr(pval, &arr_ptr);
        array_t *arr = (array_t *)arr_ptr;
        if (arr == NULL)
            continue;

        /* Rewrite the array in-place: skip any slot-0 entries
         * (evicted ones; may legitimately appear more than once
         * because tx_history_update calls _map_peers on both the
         * p1-only and the completed states for the p1 side),
         * decrement everything else. */
        size_t write_idx = 0;
        size_t arr_n = array_size(arr);
        for (size_t ri = 0; ri < arr_n; ri++)
        {
            data_t *idat = NULL;
            if (array_get(arr, (int)ri, &idat) != 0)
                continue;
            int ival = 0;
            data_integer(idat, &ival);
            if (ival <= 0)
                continue;  /* evicted */
            array_set(arr, (int)write_idx,
                      integer_data(ival - 1));
            write_idx++;
        }
        /* Trim any stale tail. array_set doesn't shrink; pop until
         * size == write_idx. */
        while (array_size(arr) > write_idx)
        {
            data_t *tail = NULL;
            if (array_get(arr, (int)(array_size(arr) - 1), &tail) == 0
                && tail != NULL)
                array_remove(arr, tail);
            else
                break;
        }
        if (array_size(arr) == 0)
        {
            /* Defer the map_remove — modifying the map while we're
             * iterating via map_keys is unsafe. */
            data_t *marker = string_data(pkey, strlen(pkey));
            array_append(&empty_peers, marker);
        }
    }
    for (size_t ei = 0; ei < array_size(&empty_peers); ei++)
    {
        data_t *kdat = NULL;
        if (array_get(&empty_peers, (int)ei, &kdat) != 0)
            continue;
        char *pkey = NULL;
        if (data_string_ptr(kdat, &pkey) == 0 && pkey != NULL)
        {
            data_t *pval = NULL;
            if (map_get(&hist->peer_map, pkey, &pval) == 0
                && pval != NULL)
            {
                void *arr_ptr = NULL;
                data_object_ptr(pval, &arr_ptr);
                if (arr_ptr != NULL)
                    /* array_free already smrt_derefs the array_t; a second
                     * smrt_deref here would double-free it. */
                    array_free((array_t *)arr_ptr);
            }
            map_remove(&hist->peer_map, pkey);
        }
    }
    array_free(&empty_peers);

    /* 4. Memmove the chain down. tx->index is now monotonic absolute
     *    (mirrors Python `_next_index`) so we do NOT rewrite it after
     *    the shift — only the task_map slot-position values are
     *    decremented above. The committed-count and first_index
     *    bookkeeping is what Python's _evict_oldest tail does
     *    (reputation.py:182-185). */
    memmove(&hist->chain[0], &hist->chain[1],
            (size_t)(hist->chain_len - 1) * sizeof(transaction_t));
    hist->chain_len--;
    if (evicted_committed)
    {
        hist->committed_count--;
        /* Advance first_index past the evicted entry — to the next
         * still-committed entry's index, or to next_index when no
         * committed entry remains. Walk forward through the chain
         * because pending entries may sit between committed ones. */
        hist->first_index = hist->next_index;
        for (int i = 0; i < hist->chain_len; i++)
        {
            if (hist->chain[i].p1_set && hist->chain[i].p2_set)
            {
                hist->first_index = hist->chain[i].index;
                break;
            }
        }
    }
}

void tx_history_destroy(tx_history_t *hist)
{
    if (hist == NULL) return;
    tx_history_free(hist);
    free(hist);
}

/**
 * Update history with a score for a task+peer combination.
 * Finds or creates the transaction, fills p1 or p2 slot.
 */
/* Frama-C: skipped — [solver-timeout] map/array mutation preconditions */
int tx_history_update(tx_history_t *hist, const uuid_t task_uuid,
                      const uuid_t peer_uuid, double score)
{
    char task_str[UUID_STRING_LEN + 1];
    uuid_unparse_lower(task_uuid, task_str);

    char peer_str[UUID_STRING_LEN + 1];
    uuid_unparse_lower(peer_uuid, peer_str);

    /* Look up existing transaction by task UUID */
    data_t *idx_dat = NULL;
    int idx = -1;
    if (map_get((map_t *)&hist->task_map, task_str, &idx_dat) == 0)
    {
        int ival = 0;
        data_integer(idx_dat, &ival);
        idx = ival;
    }

    if (idx < 0)
    {
        /* Tombstone check: refuse to reanimate a task we already
         * committed and rolled out of the chain. Without this,
         * late `committed` broadcasts (common when handle_accepted's
         * dedup window is exceeded) would build a half-completed
         * Transaction in task_map that the counterparty's late
         * `committed` would complete and re-insert at the head of
         * the chain. Mirrors Python's _evicted_task_ids guard in
         * TransactionHistory.update. */
        data_t *tombstoned = NULL;
        if (map_get((map_t *)&hist->evicted_set, task_str, &tombstoned) == 0)
            return 0;

        /* Create new transaction. Evict the oldest entry when the
         * cap is reached so the chain stays bounded. Eviction shifts
         * all surviving slot indices down by 1, so any previously-
         * looked-up idx values (none in this branch — we're in the
         * "no existing tx for this task" arm) would be stale. */
        if (hist->chain_len >= MAX_CHAIN_LEN)
            tx_history_evict_oldest(hist);

        idx = hist->chain_len;
        transaction_t *tx = &hist->chain[idx];
        memset(tx, 0, sizeof(transaction_t));
        uuid_copy(tx->task_uuid, task_uuid);
        uuid_copy(tx->p1_uuid, peer_uuid);
        tx->p1_score = score;
        tx->p1_set = true;
        /* index is assigned monotonically only when the tx goes
         * bilateral (p2 also fills). Mark pending with -1 so callers
         * that look at tx->index for an unfinished tx see a sentinel.
         * Mirrors Python: _next_index advances inside the
         * `if len(tx) > 1` branch of update(), not at task creation. */
        tx->index = -1;
        hist->chain_len++;

        /* Record slot position in task_map. NOTE: this is the
         * positional index in chain[], not tx->index (those agree
         * only by coincidence before the first eviction). Python's
         * _task_mapping is keyed by task_id → Transaction directly;
         * the C twin uses an integer slot because chain[] is a flat
         * array. */
        data_t *new_idx = integer_data(idx);
        map_set(&hist->task_map, task_str, new_idx);
    }
    else
    {
        /* WHY a transaction has exactly two slots, and why an overflow is
         * silently dropped:
         *
         * A task in this reputation model is a bilateral interaction: one
         * requester (p1) and one worker (p2). The two peer UUIDs scoring
         * each other are the full universe of participants in that task.
         * When a third score arrives for the same task_uuid it almost
         * always indicates one of: a replayed message, a protocol bug
         * upstream, or a hostile peer trying to inflate another peer's
         * score by re-submitting. None of those are worth aborting the
         * chain over — but none should be counted either.
         *
         * Returning EXCEPTION(...) here would bubble up through the
         * message dispatcher and terminate the reputation process on
         * malformed peer input, which is a DoS vector. Silently ignoring
         * is the intentional hardening choice.
         *
         * If the model ever admits >2 parties per task, change the chain
         * entry from a struct-of-slots to an array keyed by peer UUID; do
         * NOT extend the slot count — the asymmetric p1/p2 scoring
         * semantics (requester ≠ worker) don't generalize. */
        transaction_t *tx = &hist->chain[idx];
        bool was_committed = tx->p1_set && tx->p2_set;
        if (!tx->p1_set)
        {
            uuid_copy(tx->p1_uuid, peer_uuid);
            tx->p1_score = score;
            tx->p1_set = true;
        }
        else if (!tx->p2_set)
        {
            /* Bilateral guard: a Transaction is intrinsically two-party.
             * If the same peer is about to occupy both slots — almost
             * always from a duplicate `committed` broadcast for the
             * same paxos round — silently drop and skip the peer_map
             * append. Without this, p2 = p1 = proposer, producing a
             * self-transaction that CTFT's `p1==peer && p2==self`
             * check then silently rejects. Mirrors Python
             * Transaction.add at reputation.py:46-58. */
            if (uuid_compare(tx->p1_uuid, peer_uuid) == 0)
                return 0;
            uuid_copy(tx->p2_uuid, peer_uuid);
            tx->p2_score = score;
            tx->p2_set = true;
        }
        else
        {
            /* Both slots already filled: silently drop AND skip the
             * peer_map append below. The previous fall-through
             * appended a duplicate index to peer_map[peer_str] on
             * every replayed/late message, inflating by_peer() counts
             * and skewing downstream reputation math. */
            return 0;
        }
        /* Bilateral promotion: this update just filled the second
         * slot — assign the monotonic absolute index and bump the
         * committed counter. Mirrors Python's
         * `if len(tx) > 1: tx.index = self._next_index;
         *  self._next_index += 1` in reputation.py:214-221. */
        if (!was_committed && tx->p1_set && tx->p2_set)
        {
            tx->index = hist->next_index;
            hist->next_index++;
            if (hist->committed_count == 0)
                hist->first_index = tx->index;
            hist->committed_count++;
            /* Phase 1 hash-linking: chain this entry to the current head,
             * then advance the head to this entry's digest. Eviction only
             * fires in the new-task arm above and never rewrites head_hash,
             * so the link survives the sliding window. Mirrors Python
             * TransactionHistory.update's `tx.prev_hash = self._head_hash;
             * self._head_hash = tx.entry_hash()`. */
            memcpy(tx->prev_hash, hist->head_hash, TX_HASH_HEX_LEN + 1);
            transaction_entry_hash(tx, hist->head_hash);
        }
    }

    /* Update peer_map: add this index to the peer's list */
    int perr = _index_peer_slot(hist, peer_uuid, idx);
    if (perr != 0)
        return perr;

    return 0;
}

/* Frama-C: skipped — [solver-timeout] map lookup preconditions */
int tx_history_by_task(const tx_history_t *hist, const uuid_t task_uuid, transaction_t *out)
{
    char task_str[UUID_STRING_LEN + 1];
    uuid_unparse_lower(task_uuid, task_str);

    data_t *idx_dat = NULL;
    if (map_get((map_t *)&hist->task_map, task_str, &idx_dat) != 0)
        return EXCEPTION(EREP_NOTX);

    int ival = 0;
    data_integer(idx_dat, &ival);
    *out = hist->chain[ival];
    return 0;
}

/* Frama-C: skipped — [solver-timeout] map lookup preconditions */
int tx_history_by_peer(const tx_history_t *hist, const uuid_t peer_uuid,
                       transaction_t *out, int *out_count, int max_out)
{
    char peer_str[UUID_STRING_LEN + 1];
    uuid_unparse_lower(peer_uuid, peer_str);

    data_t *peer_indices = NULL;
    if (map_get((map_t *)&hist->peer_map, peer_str, &peer_indices) != 0)
    {
        *out_count = 0;
        return 0;
    }

    void *arr_ptr = NULL;
    data_object_ptr(peer_indices, &arr_ptr);
    array_t *arr = (array_t *)arr_ptr;

    *out_count = 0;
    size_t arr_size = array_size(arr);
    for (size_t i = 0; i < arr_size && *out_count < max_out; i++)
    {
        data_t *idx_dat = NULL;
        if (array_get(arr, (int)i, &idx_dat) != 0)
            continue;
        int ival = 0;
        data_integer(idx_dat, &ival);
        out[*out_count] = hist->chain[ival];
        (*out_count)++;
    }
    return 0;
}

int tx_history_era(const tx_history_t *hist, int start_idx, int end_idx,
                   transaction_t *out, int *out_count)
{
    /* start_idx / end_idx are positional within the committed
     * subsequence — matches what rep_proc.c:1112-1113 expects
     * after calling tx_history_len() (which now returns the
     * committed count, not chain_len). Walk chain[] skipping
     * unilateral entries; emit the slice [start_idx, end_idx)
     * of the committed sequence. */
    if (start_idx < 0) start_idx = 0;
    if (end_idx > hist->committed_count) end_idx = hist->committed_count;

    *out_count = 0;
    int committed_seen = 0;
    for (int i = 0; i < hist->chain_len && committed_seen < end_idx; i++)
    {
        if (!hist->chain[i].p1_set || !hist->chain[i].p2_set)
            continue;
        if (committed_seen >= start_idx)
        {
            out[*out_count] = hist->chain[i];
            (*out_count)++;
        }
        committed_seen++;
    }
    return 0;
}

int tx_history_len(const tx_history_t *hist)
{
    /* Returns committed-bilateral count, mirroring Python
     * TransactionHistory.__len__ (reputation.py:223-224 returns
     * len(self._chain), and `_chain.append` runs only when
     * `len(tx) > 1`). Callers use this for paxos slot numbering
     * and chain-catchup era boundaries, so a unilateral tx
     * sitting in chain[] must not be counted. */
    return hist->committed_count;
}

/* Frama-C: skipped — [solver-timeout] container free cascade */
void tx_history_free(tx_history_t *hist)
{
    map_free(&hist->task_map);
    /* peer_map values are arrays that were smrt_created. array_free already
     * releases the array_t itself (its trailing smrt_deref(a)), so we must
     * NOT smrt_deref(arr_ptr) again here — that is a double-free of the
     * (refs==1) array_t. */
    map_key_t key = NULL;
    data_t *val = NULL;
    map_entries_for_each(&hist->peer_map, key, val)
    {
        void *arr_ptr = NULL;
        if (data_object_ptr(val, &arr_ptr) == 0 && arr_ptr != NULL)
            array_free((array_t *)arr_ptr);
    }
    map_end_for_each
    map_free(&hist->peer_map);
    map_free(&hist->evicted_set);
    hist->chain_len = 0;
    hist->committed_count = 0;
    hist->next_index = 0;
    hist->first_index = 0;
    hist->evicted_ring_head = 0;
    hist->evicted_ring_len = 0;
    hist->head_hash[0] = '\0';
}

/****************************
 * JSON serialization for chain sync
 ****************************/

/* Frama-C: skipped — [serialization] jansson JSON serialization */
int tx_history_era_to_json(const tx_history_t *hist, int start_idx, int end_idx, json_t **out)
{
    /* start_idx / end_idx are positional within the committed
     * subsequence (mirrors tx_history_era). Skip pending entries
     * so the wire never carries half-formed transactions — they
     * would otherwise be deserialized as committed on the
     * receiver and trigger spurious reputation math. */
    if (start_idx < 0) start_idx = 0;
    if (end_idx > hist->committed_count) end_idx = hist->committed_count;

    json_t *arr = json_array();
    if (arr == NULL) return EXCEPTION(ENOMEM);

    int committed_seen = 0;
    for (int i = 0; i < hist->chain_len && committed_seen < end_idx; i++)
    {
        const transaction_t *tx = &hist->chain[i];
        if (!tx->p1_set || !tx->p2_set)
            continue;
        if (committed_seen < start_idx)
        {
            committed_seen++;
            continue;
        }
        char task_str[UUID_STRING_LEN + 1];
        uuid_unparse_lower(tx->task_uuid, task_str);
        char p1_str[UUID_STRING_LEN + 1];
        uuid_unparse_lower(tx->p1_uuid, p1_str);
        char p2_str[UUID_STRING_LEN + 1];
        uuid_unparse_lower(tx->p2_uuid, p2_str);

        json_t *obj = json_pack("{s:s, s:s, s:f, s:b, s:s, s:f, s:b, s:i, s:s}",
            "task", task_str,
            "p1", p1_str, "p1_score", tx->p1_score, "p1_set", tx->p1_set,
            "p2", p2_str, "p2_score", tx->p2_score, "p2_set", tx->p2_set,
            "index", tx->index,
            "prev_hash", tx->prev_hash);  /* Phase 1 hash-link */
        if (obj == NULL)
        {
            json_decref(arr);
            return -1;
        }
        json_array_append_new(arr, obj);
        committed_seen++;
    }

    *out = arr;
    return 0;
}

/* Frama-C: skipped — [serialization] jansson JSON deserialization */
int tx_history_era_from_json(tx_history_t *hist, const json_t *arr)
{
    if (!json_is_array(arr))
        return -1;

    size_t idx;
    json_t *obj;
    int max_loaded_index = -1;

    /* Phase 1: verify the incoming segment's hash-linkage before loading
     * any of it. A peer (or a corrupted transfer) cannot slip an altered
     * committed entry past us — the "verifiable instead of social" sync win
     * (reputation-vs-blockchain-analysis.md §2.1). Mirrors Python
     * TransactionHistory.catchup's wholesale reject. We stream-verify with
     * just the previous committed entry so an over-long array needs no temp
     * buffer. */
    {
        transaction_t prev;
        bool have_prev = false;
        json_array_foreach(arr, idx, obj)
        {
            const char *task_str = json_string_value(json_object_get(obj, "task"));
            const char *p1_str = json_string_value(json_object_get(obj, "p1"));
            const char *p2_str = json_string_value(json_object_get(obj, "p2"));
            if (task_str == NULL || p1_str == NULL || p2_str == NULL)
                continue;
            transaction_t cur;
            memset(&cur, 0, sizeof(cur));
            uuid_parse(task_str, cur.task_uuid);
            uuid_parse(p1_str, cur.p1_uuid);
            cur.p1_score = json_number_value(json_object_get(obj, "p1_score"));
            cur.p1_set = json_boolean_value(json_object_get(obj, "p1_set"));
            uuid_parse(p2_str, cur.p2_uuid);
            cur.p2_score = json_number_value(json_object_get(obj, "p2_score"));
            cur.p2_set = json_boolean_value(json_object_get(obj, "p2_set"));
            cur.index = (int)json_integer_value(json_object_get(obj, "index"));
            const char *ph = json_string_value(json_object_get(obj, "prev_hash"));
            cur.prev_hash[0] = '\0';
            if (ph != NULL)
            {
                strncpy(cur.prev_hash, ph, TX_HASH_HEX_LEN);
                cur.prev_hash[TX_HASH_HEX_LEN] = '\0';
            }
            if (cur.index < 0)
                continue;  /* pending entry — not part of the committed link */
            if (have_prev)
            {
                char expect[TX_HASH_HEX_LEN + 1];
                transaction_entry_hash(&prev, expect);
                if (strncmp(cur.prev_hash, expect, TX_HASH_HEX_LEN + 1) != 0)
                    return 0;  /* broken link — reject the whole segment */
            }
            prev = cur;
            have_prev = true;
        }
    }

    json_array_foreach(arr, idx, obj)
    {
        const char *task_str = json_string_value(json_object_get(obj, "task"));
        const char *p1_str = json_string_value(json_object_get(obj, "p1"));
        const char *p2_str = json_string_value(json_object_get(obj, "p2"));
        if (task_str == NULL || p1_str == NULL || p2_str == NULL)
            continue;

        if (hist->chain_len >= MAX_CHAIN_LEN)
            tx_history_evict_oldest(hist);

        transaction_t *tx = &hist->chain[hist->chain_len];
        memset(tx, 0, sizeof(transaction_t));
        uuid_parse(task_str, tx->task_uuid);
        uuid_parse(p1_str, tx->p1_uuid);
        tx->p1_score = json_number_value(json_object_get(obj, "p1_score"));
        tx->p1_set = json_boolean_value(json_object_get(obj, "p1_set"));
        uuid_parse(p2_str, tx->p2_uuid);
        tx->p2_score = json_number_value(json_object_get(obj, "p2_score"));
        tx->p2_set = json_boolean_value(json_object_get(obj, "p2_set"));
        tx->index = (int)json_integer_value(json_object_get(obj, "index"));
        /* Preserve the wire prev_hash (consistent with preserving the wire
         * index above); the verified segment is self-consistent, so the
         * loaded chain's links hold. */
        const char *ph = json_string_value(json_object_get(obj, "prev_hash"));
        tx->prev_hash[0] = '\0';
        if (ph != NULL)
        {
            strncpy(tx->prev_hash, ph, TX_HASH_HEX_LEN);
            tx->prev_hash[TX_HASH_HEX_LEN] = '\0';
        }

        /* Update maps */
        char task_key[UUID_STRING_LEN + 1];
        uuid_unparse_lower(tx->task_uuid, task_key);
        data_t *idx_d = integer_data(hist->chain_len);
        map_set(&hist->task_map, task_key, idx_d);
        /* ...including peer_map, which this loader used to skip. Every scoring
         * function reaches its transactions through tx_history_by_peer, and
         * that reads peer_map only — so a caught-up chain was resident but
         * invisible to reputation_pure / _contrite_tft / _consensus. */
        if (tx->p1_set)
            _index_peer_slot(hist, tx->p1_uuid, hist->chain_len);
        if (tx->p2_set && uuid_compare(tx->p1_uuid, tx->p2_uuid) != 0)
            _index_peer_slot(hist, tx->p2_uuid, hist->chain_len);

        /* Loaded entries from era_to_json are always bilateral
         * (era_to_json filters unilateral out), but tolerate
         * malformed input that drops the *_set flags. Only
         * bilateral entries increment committed_count and feed
         * next_index. Matches Python catch-up flow where era()
         * + update() pair only commits whole pairs. */
        if (tx->p1_set && tx->p2_set)
        {
            if (hist->committed_count == 0 ||
                tx->index < hist->first_index)
                hist->first_index = tx->index;
            hist->committed_count++;
            if (tx->index > max_loaded_index)
                max_loaded_index = tx->index;
        }

        hist->chain_len++;
    }
    /* Seed next_index past the largest absolute index just loaded
     * so subsequent local commits don't collide. Mirrors Python's
     * `max_existing + 1` seed in TransactionHistory.__init__
     * (reputation.py:130-133). */
    if (max_loaded_index + 1 > hist->next_index)
        hist->next_index = max_loaded_index + 1;
    /* Phase 1: resume the link from the loaded tail so subsequent local
     * commits chain cleanly. The last committed slot is the head. */
    hist->head_hash[0] = '\0';
    for (int i = hist->chain_len - 1; i >= 0; i--)
    {
        if (hist->chain[i].p1_set && hist->chain[i].p2_set)
        {
            transaction_entry_hash(&hist->chain[i], hist->head_hash);
            break;
        }
    }
    return 0;
}

/****************************  *
 * Persisted reputation evidence (verifiable warm start, doc/architecture/reputation.md)
 * ************************** */

int rep_checkpoint_init(rep_checkpoint_t *ckpt)
{
    if (ckpt == NULL) return -1;
    memset(ckpt, 0, sizeof(*ckpt));
    return map_init(&ckpt->sigs);
}

void rep_checkpoint_free(rep_checkpoint_t *ckpt)
{
    if (ckpt == NULL) return;
    map_free(&ckpt->sigs);
    ckpt->present = false;
}

size_t rep_checkpoint_designation(const char *proposer, const char *root,
                                  int64_t epoch, int64_t first_index,
                                  int64_t count, const char *group_uuid,
                                  uint8_t *out, size_t cap)
{
    if (proposer == NULL || root == NULL || out == NULL)
        return 0;
    static const char tag[] = "AT-CKPT";
    size_t tag_len = sizeof(tag);   /* includes the NUL separator */
    if (cap <= tag_len)
        return 0;
    bool have_group = (group_uuid != NULL && group_uuid[0] != '\0');
    int n = snprintf((char *)out + tag_len, cap - tag_len,
                     "%s|%s|%lld|%lld|%lld%s%s", proposer, root,
                     (long long)epoch, (long long)first_index,
                     (long long)count,
                     have_group ? "|" : "",
                     have_group ? group_uuid : "");
    if (n < 0 || (size_t)n >= cap - tag_len)
        return 0;
    memcpy(out, tag, tag_len);
    return tag_len + (size_t)n;
}

int reputation_evidence_to_json(const tx_history_t *hist,
                                const rep_checkpoint_t *ckpt, json_t **out)
{
    if (hist == NULL || out == NULL) return -1;

    json_t *chain = json_array();
    if (chain == NULL) return EXCEPTION(ENOMEM);

    for (int i = 0; i < hist->chain_len; i++)
    {
        const transaction_t *tx = &hist->chain[i];
        /* An un-indexed entry is not yet evidence of anything: the index is
         * what a committed bilateral entry has. Mirrors the Python writer's
         * `if tx.index is None: continue`. */
        if (tx->index < 0 || !tx->p1_set || !tx->p2_set)
            continue;
        char task_str[UUID_STRING_LEN + 1];
        char p1_str[UUID_STRING_LEN + 1];
        char p2_str[UUID_STRING_LEN + 1];
        uuid_unparse_lower(tx->task_uuid, task_str);
        uuid_unparse_lower(tx->p1_uuid, p1_str);
        uuid_unparse_lower(tx->p2_uuid, p2_str);
        json_t *obj = json_pack("{s:s, s:s, s:f, s:s, s:f, s:i, s:s}",
            "task_id", task_str,
            "p1_id", p1_str, "p1_score", tx->p1_score,
            "p2_id", p2_str, "p2_score", tx->p2_score,
            "index", tx->index,
            "prev_hash", tx->prev_hash);
        if (obj == NULL)
        {
            json_decref(chain);
            return -1;
        }
        json_array_append_new(chain, obj);
    }

    json_t *ck_json = json_null();
    if (ckpt != NULL && ckpt->present)
    {
        json_t *sigs = json_object();
        if (sigs == NULL)
        {
            json_decref(chain);
            json_decref(ck_json);
            return EXCEPTION(ENOMEM);
        }
        map_key_t key = NULL;
        data_t *val = NULL;
        map_entries_for_each((map_t *)&ckpt->sigs, key, val)
        {
            string_t sig = NULL;
            if (data_string_ptr(val, &sig) == 0 && sig != NULL)
                json_object_set_new(sigs, key, json_string(sig));
        }
        map_end_for_each
        json_decref(ck_json);
        ck_json = json_pack("{s:s, s:s, s:I, s:i, s:i, s:s, s:o}",
            "proposer_uuid", ckpt->proposer_uuid,
            "root", ckpt->root,
            "epoch", (json_int_t)ckpt->epoch,
            "first_index", ckpt->first_index,
            "count", ckpt->count,
            /* Which chain the checkpoint covers ("" == primary). Part of the
             * signed designation when non-empty, so it has to travel with the
             * signatures or a restart could not re-derive the bytes they were
             * made over. Additive to schema 1: a reader predating child chains
             * ignores it, and this reader defaults it to "". */
            "group_uuid", ckpt->group_uuid,
            "sigs", sigs);
        if (ck_json == NULL)
        {
            json_decref(chain);
            json_decref(sigs);
            return -1;
        }
    }

    json_t *doc = json_pack("{s:s, s:o, s:o}",
                            "schema", REP_EVIDENCE_SCHEMA,
                            "chain", chain,
                            "checkpoint", ck_json);
    if (doc == NULL)
    {
        json_decref(chain);
        json_decref(ck_json);
        return -1;
    }
    *out = doc;
    return 0;
}

int reputation_evidence_from_json(const json_t *doc, tx_history_t *hist_out,
                                  rep_checkpoint_t *ckpt_out)
{
    if (doc == NULL || !json_is_object(doc) || hist_out == NULL)
        return -1;
    const char *schema = json_string_value(json_object_get((json_t *)doc, "schema"));
    if (schema == NULL || strcmp(schema, REP_EVIDENCE_SCHEMA) != 0)
        return -1;   /* pinned: refuse rather than misparse */
    json_t *chain = json_object_get((json_t *)doc, "chain");
    if (!json_is_array(chain))
        return -1;

    /* Stage the entries before touching hist_out: the linkage check below
     * must be able to reject the whole document, and a half-loaded history
     * would be worse than none. */
    int n = (int)json_array_size(chain);
    if (n > MAX_CHAIN_LEN)
        n = MAX_CHAIN_LEN;   /* the tail is what the checkpoint covers */
    transaction_t *staged = calloc(n > 0 ? (size_t)n : 1, sizeof(transaction_t));
    if (staged == NULL)
        return EXCEPTION(ENOMEM);
    int staged_n = 0;
    size_t idx;
    json_t *obj;
    json_array_foreach(chain, idx, obj)
    {
        if (staged_n >= n)
            break;
        if (!json_is_object(obj))
        {
            free(staged);
            return -1;
        }
        json_t *index_j = json_object_get(obj, "index");
        if (!json_is_integer(index_j))
        {
            free(staged);
            return -1;   /* no index == not a committed entry */
        }
        const char *task_str = json_string_value(json_object_get(obj, "task_id"));
        const char *p1_str = json_string_value(json_object_get(obj, "p1_id"));
        const char *p2_str = json_string_value(json_object_get(obj, "p2_id"));
        if (task_str == NULL || p1_str == NULL || p2_str == NULL)
        {
            free(staged);
            return -1;   /* an entry no counterparty agreed to is not evidence */
        }
        transaction_t *tx = &staged[staged_n];
        memset(tx, 0, sizeof(*tx));
        if (uuid_parse(task_str, tx->task_uuid) != 0
            || uuid_parse(p1_str, tx->p1_uuid) != 0
            || uuid_parse(p2_str, tx->p2_uuid) != 0)
        {
            free(staged);
            return -1;
        }
        tx->p1_score = json_number_value(json_object_get(obj, "p1_score"));
        tx->p2_score = json_number_value(json_object_get(obj, "p2_score"));
        /* The set flags are not on the wire: Python's document omits them, and
         * an entry naming both counterparties with an index IS bilateral by
         * construction. Deriving them beats trusting a field that could
         * disagree with the ids beside it. */
        tx->p1_set = true;
        tx->p2_set = true;
        tx->index = (int)json_integer_value(index_j);
        const char *ph = json_string_value(json_object_get(obj, "prev_hash"));
        tx->prev_hash[0] = '\0';
        if (ph != NULL)
        {
            strncpy(tx->prev_hash, ph, TX_HASH_HEX_LEN);
            tx->prev_hash[TX_HASH_HEX_LEN] = '\0';
        }
        staged_n++;
    }

    /* Hash-linkage before anything is adopted. A broken link means the file
     * was altered or truncated; the caller degrades to clamped restoration. */
    if (!tx_verify_chain_links(staged, staged_n))
    {
        free(staged);
        return -1;
    }

    for (int i = 0; i < staged_n; i++)
        _history_load_committed(hist_out, &staged[i]);
    free(staged);

    if (ckpt_out != NULL)
    {
        json_t *ck = json_object_get((json_t *)doc, "checkpoint");
        if (json_is_object(ck))
        {
            AT_JSON_STRING(ck, "proposer_uuid", ckpt_out->proposer_uuid);
            AT_JSON_STRING(ck, "root", ckpt_out->root);
            AT_JSON_STRING(ck, "group_uuid", ckpt_out->group_uuid);
            ckpt_out->epoch = (int64_t)json_integer_value(json_object_get(ck, "epoch"));
            ckpt_out->first_index = (int)json_integer_value(json_object_get(ck, "first_index"));
            ckpt_out->count = (int)json_integer_value(json_object_get(ck, "count"));
            json_t *sigs = json_object_get(ck, "sigs");
            if (json_is_object(sigs))
            {
                const char *voter;
                json_t *sig;
                json_object_foreach(sigs, voter, sig)
                {
                    const char *hex = json_string_value(sig);
                    if (hex == NULL)
                        continue;
                    map_set(&ckpt_out->sigs, (map_key_t)voter,
                            string_data((string_t)hex, strlen(hex)));
                }
            }
            ckpt_out->present = (ckpt_out->proposer_uuid[0] != '\0');
        }
    }
    return 0;
}

int reputation_checkpoint_window_root(const tx_history_t *hist,
                                      const rep_checkpoint_t *ckpt,
                                      char out[TX_HASH_HEX_LEN + 1])
{
    if (hist == NULL || ckpt == NULL || out == NULL || ckpt->count < 0)
        return -1;
    char leaves[MAX_CHAIN_LEN][TX_HASH_HEX_LEN + 1];
    int n = 0;
    int lo = ckpt->first_index;
    int hi = ckpt->first_index + ckpt->count;
    for (int i = 0; i < hist->chain_len && n < MAX_CHAIN_LEN; i++)
    {
        const transaction_t *tx = &hist->chain[i];
        if (tx->index < lo || tx->index >= hi)
            continue;
        transaction_entry_hash(tx, leaves[n]);
        n++;
    }
    /* Exactly `count` entries or nothing: a short window cannot reproduce the
     * root, and crediting a partial one would attest entries nobody signed. */
    if (n != ckpt->count)
        return -1;
    mth_range(leaves, 0, n, out);
    return 0;
}

int reputation_evidence_ceilings(const tx_history_t *hist,
                                 const rep_checkpoint_t *ckpt,
                                 const char *self_uuid_str, map_t *out)
{
    if (hist == NULL || ckpt == NULL || out == NULL)
        return -1;
    map_t sums, counts;
    if (map_init(&sums) != 0) return EXCEPTION(ENOMEM);
    if (map_init(&counts) != 0)
    {
        map_free(&sums);
        return EXCEPTION(ENOMEM);
    }
    int lo = ckpt->first_index;
    int hi = ckpt->first_index + ckpt->count;
    for (int i = 0; i < hist->chain_len; i++)
    {
        const transaction_t *tx = &hist->chain[i];
        if (tx->index < lo || tx->index >= hi)
            continue;
        if (!tx->p1_set || !tx->p2_set)
            continue;
        /* A peer's score in a tx is the COUNTERPARTY's side of it — the same
         * direction reputation_consensus folds. */
        const uuid_t *who[2] = { &tx->p1_uuid, &tx->p2_uuid };
        double score[2] = { tx->p2_score, tx->p1_score };
        for (int s = 0; s < 2; s++)
        {
            char key[UUID_STRING_LEN + 1];
            uuid_unparse_lower(*who[s], key);
            if (self_uuid_str != NULL && strcmp(key, self_uuid_str) == 0)
                continue;
            double prev_sum = 0.0;
            int prev_count = 0;
            data_t *d = NULL;
            if (map_get(&sums, (map_key_t)key, &d) == 0 && d != NULL)
                data_floating_pt_dbl(d, &prev_sum);
            if (map_get(&counts, (map_key_t)key, &d) == 0 && d != NULL)
                data_integer(d, &prev_count);
            map_set(&sums, (map_key_t)key,
                    floating_pt_dbl_data(prev_sum + score[s]));
            map_set(&counts, (map_key_t)key, integer_data(prev_count + 1));
        }
    }

    double k = REP_RESTORE_SHRINKAGE_K;
    double neutral = PREREP_NEUTRAL;
    map_key_t key = NULL;
    data_t *val = NULL;
    map_entries_for_each(&counts, key, val)
    {
        int count = 0;
        if (data_integer(val, &count) != 0 || count < REP_RESTORE_EVIDENCE_MIN_TX)
            continue;
        double sum = 0.0;
        data_t *sd = NULL;
        if (map_get(&sums, key, &sd) != 0 || sd == NULL
            || data_floating_pt_dbl(sd, &sum) != 0)
            continue;
        double observed = sum / (double)count;
        double ceiling = ((double)count * observed + k * neutral)
                         / ((double)count + k);
        if (ceiling < 0.0) ceiling = 0.0;
        if (ceiling > 1.0) ceiling = 1.0;
        map_set(out, key, floating_pt_dbl_data(ceiling));
    }
    map_end_for_each

    map_free(&sums);
    map_free(&counts);
    return 0;
}

/****************************
 * Staleness decay
 ****************************/

double reputation_decayed_score(double score, double idle_seconds)
{
    double asymptote = REP_DECAY_ASYMPTOTE;
    /* ASYMMETRIC: absence never rehabilitates a distrusted node. */
    if (score <= asymptote)
        return score;
    if (idle_seconds <= REP_DECAY_ONSET)
        return score;
    double elapsed = idle_seconds - REP_DECAY_ONSET;
    double factor = pow(0.5, elapsed / REP_DECAY_HALF_LIFE);
    double decayed = asymptote + (score - asymptote) * factor;
    return decayed < asymptote ? asymptote : decayed;
}

/****************************
 * Reputations map
 ****************************/

/* Frama-C: skipped — [solver-timeout] smrt_ptr/map allocation postconditions */
int reputations_create(reputations_t **reps)
{
    *reps = calloc(1, sizeof(reputations_t));
    if (*reps == NULL)
        return EXCEPTION(ENOMEM);
    return reputations_init(*reps);
}

int reputations_init(reputations_t *reps)
{
    return map_init(&reps->scores);
}

void reputations_destroy(reputations_t *reps)
{
    if (reps == NULL) return;
    reputations_free(reps);
    free(reps);
}

int reputations_update(reputations_t *reps, const uuid_t peer_uuid, double score)
{
    char uuid_str[UUID_STRING_LEN + 1];
    uuid_unparse_lower(peer_uuid, uuid_str);

    data_t *score_dat = floating_pt_data((float)score);  /* floating_pt_data accepts float; truncation from double is acceptable */
    return map_set(&reps->scores, uuid_str, score_dat);
}

/* Frama-C: skipped — [solver-timeout] map lookup preconditions */
int reputations_get(const reputations_t *reps, const uuid_t peer_uuid, double *score)
{
    char uuid_str[UUID_STRING_LEN + 1];
    uuid_unparse_lower(peer_uuid, uuid_str);

    data_t *score_dat = NULL;
    if (map_get((map_t *)&reps->scores, uuid_str, &score_dat) != 0)
        return EXCEPTION(EREP_NOPEER);

    float fval = 0.0f;
    data_floating_pt(score_dat, &fval);
    *score = (double)fval;
    return 0;
}

bool reputations_contains(const reputations_t *reps, const uuid_t peer_uuid)
{
    char uuid_str[UUID_STRING_LEN + 1];
    uuid_unparse_lower(peer_uuid, uuid_str);

    data_t *score_dat = NULL;
    return (map_get((map_t *)&reps->scores, uuid_str, &score_dat) == 0);
}

void reputations_free(reputations_t *reps)
{
    if (reps->scores.items == NULL) return;
    map_free(&reps->scores);
}

/**
 * Read a reputation threshold from the environment, falling back to @p dflt.
 * Mirrors repprocess.py _env_float: lets an operator re-adjust the trust
 * thresholds (neutral, communication cut-off) without a code change. A
 * missing or unparseable value uses the default. Called at use-time from the
 * PREREP_NEUTRAL / COMM_CUTOFF macros; kept cheap (a getenv + strtod), like
 * the existing per-call AT_PREREP_HEURISTIC lookup.
 */
double reputation_env_double(const char *name, double dflt)
{
    const char *raw = getenv(name);
    if (raw == NULL || raw[0] == '\0')
        return dflt;
    char *end = NULL;
    errno = 0;
    double val = strtod(raw, &end);
    if (errno != 0 || end == raw)
        return dflt;
    return val;
}

/****************************
 * Reputation algorithms
 ****************************/

/**
 * Pure socially-weighted average:
 *   For each transaction involving peer, find the counterparty.
 *   Sum = counterparty_score_in_tx * reputation[counterparty]
 *   Return sum / count
 */
double reputation_pure(const tx_history_t *hist, const reputations_t *reps,
                       const uuid_t peer_uuid,
                       const map_t *task_weights)
{
    transaction_t txns[MAX_CHAIN_LEN];
    int count = 0;
    tx_history_by_peer(hist, peer_uuid, txns, &count, MAX_CHAIN_LEN);

    if (count == 0)
        return PREREP_NEUTRAL;  /* Default neutral reputation */

    double sum = 0.0;
    int total_weight = 0;

    for (int i = 0; i < count; i++)
    {
        const transaction_t *tx = &txns[i];
        if (!tx->p1_set || !tx->p2_set)
            continue;

        /* Determine which side is our peer, which is counterparty */
        uuid_t counterparty;
        double counterparty_score;

        if (uuid_compare(tx->p1_uuid, peer_uuid) == 0)
        {
            uuid_copy(counterparty, tx->p2_uuid);
            counterparty_score = tx->p2_score;
        }
        else
        {
            uuid_copy(counterparty, tx->p1_uuid);
            counterparty_score = tx->p1_score;
        }

        /* Weight by counterparty's reputation */
        double cp_rep = PREREP_NEUTRAL;
        reputations_get(reps, counterparty, &cp_rep);

        /* Per-task transaction_weight from the cache. Lookup failure
         * → 1 (the conservative tier-0 default). NULL map → 1. */
        int w = 1;
        if (task_weights != NULL)
        {
            char tk[UUID_STRING_LEN + 1];
            uuid_unparse_lower(tx->task_uuid, tk);
            data_t *w_dat = NULL;
            if (map_get((map_t *)task_weights, tk, &w_dat) == 0
                && w_dat != NULL)
            {
                int wv = 0;
                if (data_integer(w_dat, &wv) == 0 && wv > 0)
                    w = wv;
            }
        }

        sum += counterparty_score * cp_rep * (double)w;
        total_weight += w;
    }

    if (total_weight == 0)
        return PREREP_NEUTRAL;

    return sum / (double)total_weight;
}

/**
 * Pre-reputation cold-start prior — mirrors repprocess.py
 * ReputationProcess._prereputation_prior (deferred.md §2.4).
 *
 * Before any *bilateral* history with us exists, mine the scores third
 * parties have assigned the peer (the counterparty-submitted side of each
 * committed transaction the peer took part in), weight each by the
 * counterparty's reputation, and shrink the mean toward PREREP_NEUTRAL by a
 * pseudo-count of PREREP_SHRINKAGE_K. Zero usable observations returns
 * PREREP_NEUTRAL exactly, so a genuinely-unknown peer is unchanged.
 *
 * Pure function of (hist, reps) like its Python twin; deliberately omits the
 * capability task-weight (sparse during cold-start) so the two sides stay a
 * straight port. Kill switch: AT_PREREP_HEURISTIC=0 restores the flat value.
 */
static double reputation_prereputation_prior(const tx_history_t *hist,
                                             const reputations_t *reps,
                                             const uuid_t self_uuid,
                                             const uuid_t peer_uuid)
{
    const char *kill = getenv("AT_PREREP_HEURISTIC");
    if (kill != NULL && strcmp(kill, "0") == 0)
        return PREREP_NEUTRAL;

    transaction_t txns[MAX_CHAIN_LEN];
    int count = 0;
    tx_history_by_peer(hist, peer_uuid, txns, &count, MAX_CHAIN_LEN);

    uuid_t seen[MAX_CHAIN_LEN];
    int    seen_count = 0;
    double total = 0.0;
    double total_weight = 0.0;
    int    n = 0;

    for (int i = 0; i < count; i++)
    {
        const transaction_t *tx = &txns[i];
        if (!tx->p1_set || !tx->p2_set)
            continue;

        bool peer_is_p1 = (uuid_compare(tx->p1_uuid, peer_uuid) == 0);
        bool peer_is_p2 = (uuid_compare(tx->p2_uuid, peer_uuid) == 0);
        double about_peer;
        const unsigned char *counterparty;
        if (peer_is_p1) {
            about_peer = tx->p2_score;
            counterparty = tx->p2_uuid;
        } else if (peer_is_p2) {
            about_peer = tx->p1_score;
            counterparty = tx->p1_uuid;
        } else {
            continue;
        }
        /* A bilateral-with-us tx is CTFT's job, not the cold-start prior. */
        if (uuid_compare(counterparty, self_uuid) == 0)
            continue;
        /* by_peer can list one tx under both p1 and p2; one tx == one obs. */
        bool dup = false;
        for (int j = 0; j < seen_count; j++)
            if (uuid_compare(seen[j], tx->task_uuid) == 0) { dup = true; break; }
        if (dup)
            continue;
        uuid_copy(seen[seen_count++], tx->task_uuid);

        double cp_rep = PREREP_NEUTRAL;  /* reputations_get leaves this if peer absent */
        reputations_get(reps, counterparty, &cp_rep);
        if (cp_rep <= 0.0)
            continue;
        total += about_peer * cp_rep;
        total_weight += cp_rep;
        n++;
    }

    if (n < 1 || total_weight <= 0.0)
        return PREREP_NEUTRAL;

    double observed = total / total_weight;
    double nn = (double)n;
    double prior = (nn * observed + PREREP_SHRINKAGE_K * PREREP_NEUTRAL)
                   / (nn + PREREP_SHRINKAGE_K);
    if (prior < 0.0) prior = 0.0;
    if (prior > 1.0) prior = 1.0;
    return prior;
}

/**
 * Contrite tit-for-tat — ports repprocess.py:363-386.
 *
 * Collects ALL direct peer↔self interactions, computes the peer's running
 * standing (mean of their scores) and our own standing (mean of our scores
 * in those same transactions), then blends them. The result is continuous
 * in [0.0, 1.0], not the binary 0.0/1.0 the previous implementation
 * returned from the last direct tx alone.
 *
 *   - No bilateral history with us → reputation_prereputation_prior (doc/architecture/networking.md),
 *       which is PREREP_NEUTRAL (0.2) when the chain knows nothing of the peer
 *   - peer defected last AND my standing is poor → max(0.51, peer_standing)
 *   - peer defected last AND my standing is good  → min(0.49, peer_standing)
 *   - cooperative case                            → max(0.51, peer_standing)
 */
double reputation_contrite_tft(const tx_history_t *hist, const reputations_t *reps,
                               const uuid_t self_uuid, const uuid_t peer_uuid)
{
    transaction_t txns[MAX_CHAIN_LEN];
    int count = 0;
    tx_history_by_peer(hist, peer_uuid, txns, &count, MAX_CHAIN_LEN);

    double peer_sum = 0.0;
    double my_sum   = 0.0;
    int    n        = 0;
    double peer_last = 0.0;

    for (int i = 0; i < count; i++)
    {
        const transaction_t *tx = &txns[i];
        if (!tx->p1_set || !tx->p2_set)
            continue;

        bool self_is_p1 = (uuid_compare(tx->p1_uuid, self_uuid) == 0);
        bool self_is_p2 = (uuid_compare(tx->p2_uuid, self_uuid) == 0);
        bool peer_is_p1 = (uuid_compare(tx->p1_uuid, peer_uuid) == 0);
        bool peer_is_p2 = (uuid_compare(tx->p2_uuid, peer_uuid) == 0);

        double peer_score, my_score;
        if (peer_is_p1 && self_is_p2) {
            peer_score = tx->p1_score;
            my_score   = tx->p2_score;
        } else if (peer_is_p2 && self_is_p1) {
            peer_score = tx->p2_score;
            my_score   = tx->p1_score;
        } else {
            continue;
        }
        peer_sum += peer_score;
        my_sum   += my_score;
        peer_last = peer_score;  /* iteration is forward, so this ends as the most-recent */
        n++;
    }

    if (n < 1)
        /* Cold-start: no bilateral history WITH us. Fall back to a
         * transaction-memory prior rather than a flat neutral (doc/architecture/networking.md). */
        return reputation_prereputation_prior(hist, reps, self_uuid, peer_uuid);

    double peer_standing = peer_sum / (double)n;
    double my_standing   = my_sum   / (double)n;

    if (peer_last < 0.5 && my_standing < 0.5) {
        /* Peer defected, but my standing is poor — be contrite. */
        return (peer_standing > 0.51) ? peer_standing : 0.51;
    } else if (peer_last < 0.5 && my_standing >= 0.5) {
        /* Peer defected, my standing is fine — retaliate. */
        return (peer_standing < 0.49) ? peer_standing : 0.49;
    } else {
        /* Cooperate/cooperate, possibly digging out of a hole. */
        return (peer_standing > 0.51) ? peer_standing : 0.51;
    }
}

/**
 * Gate on previous score > 0.5:
 * - If trusted (score > 0.5): use socially-weighted average
 * - Else: use game-theoretic tit-for-tat
 */
double reputation_compute(const tx_history_t *hist, const reputations_t *reps,
                          const uuid_t self_uuid, const uuid_t peer_uuid,
                          const map_t *task_weights)
{
    double current_score = PREREP_NEUTRAL;
    reputations_get(reps, peer_uuid, &current_score);

    if (current_score > 0.5)
        return reputation_pure(hist, reps, peer_uuid, task_weights);
    else
        return reputation_contrite_tft(hist, reps, self_uuid, peer_uuid);
}

/**
 * Consensus reputation — ports repprocess.py:_consensus_reputation.
 *
 * EMA over the counterparty-side score of every committed bilateral tx
 * involving @p peer_uuid, walked in chain order. Pure function of
 * @p hist — no self identity, no current reputations, no per-peer
 * latch — so every node with the same chain arrives at the same value.
 * Drives the dashboard's consensus_rep_req channel.
 *
 *   - No history or no bilateral txs → PREREP_NEUTRAL (0.2, neutral)
 *   - First tx                       → ema = counterparty_score
 *   - Subsequent txs                 → ema = α·x + (1-α)·ema,
 *                                      α = 1 - 0.5^(1/HALF_LIFE)
 */
double reputation_consensus(const tx_history_t *hist, const uuid_t peer_uuid,
                            const map_t *task_weights)
{
    transaction_t txns[MAX_CHAIN_LEN];
    int count = 0;
    tx_history_by_peer(hist, peer_uuid, txns, &count, MAX_CHAIN_LEN);
    if (count == 0)
        return PREREP_NEUTRAL;

    const double alpha = 1.0 - pow(0.5, 1.0 / (double)CONSENSUS_EMA_HALF_LIFE);
    double ema = 0.0;
    bool seeded = false;

    /* tx_history_by_peer fills the array in insertion order, which is
     * chain order in steady state. We deliberately don't sort by
     * transaction_t.index here: the Python twin sorts as a defensive
     * measure for catchup() replays, but the C tx_history insertion
     * path always appends, so insertion order is chain order. */
    for (int i = 0; i < count; i++)
    {
        const transaction_t *tx = &txns[i];
        if (!tx->p1_set || !tx->p2_set)
            continue;
        double cp_score;
        if (uuid_compare(tx->p1_uuid, peer_uuid) == 0)
            cp_score = tx->p2_score;
        else if (uuid_compare(tx->p2_uuid, peer_uuid) == 0)
            cp_score = tx->p1_score;
        else
            continue;
        /* Per-task transaction_weight: a tier-w transaction moves the
         * EMA exactly as far as w tier-1 transactions would. Mirrors
         * Python's _consensus_reputation inner `for _ in range(w)`. */
        int w = 1;
        if (task_weights != NULL)
        {
            char tk[UUID_STRING_LEN + 1];
            uuid_unparse_lower(tx->task_uuid, tk);
            data_t *w_dat = NULL;
            if (map_get((map_t *)task_weights, tk, &w_dat) == 0
                && w_dat != NULL)
            {
                int wv = 0;
                if (data_integer(w_dat, &wv) == 0 && wv > 0)
                    w = wv;
            }
        }
        for (int k = 0; k < w; k++)
        {
            if (!seeded) {
                ema = cp_score;
                seeded = true;
            } else {
                ema = alpha * cp_score + (1.0 - alpha) * ema;
            }
        }
    }
    return seeded ? ema : PREREP_NEUTRAL;
}

/**
 * Per-tier consensus reputation — ports repprocess.py
 * _consensus_reputation_by_tier (trust-tiers §12 / deferred.md §2.3).
 *
 * Like reputation_consensus, but instead of collapsing every tx into one
 * EMA it partitions the peer's committed bilateral txs by the tier of the
 * capability that produced each (@p task_tiers, default tier 0) and folds
 * each partition into its own weighted EMA. Writes one {tier, score} entry
 * per non-empty tier into @p out and returns the count. Deduped by task
 * (tx_history_by_peer can list a tx twice). Additive: reputation_consensus
 * is unchanged.
 */
int reputation_consensus_by_tier(const tx_history_t *hist, const uuid_t peer_uuid,
                                 const map_t *task_tiers, const map_t *task_weights,
                                 tier_score_t *out, int max_out)
{
    if (out == NULL || max_out <= 0)
        return 0;
    transaction_t txns[MAX_CHAIN_LEN];
    int count = 0;
    tx_history_by_peer(hist, peer_uuid, txns, &count, MAX_CHAIN_LEN);
    if (count == 0)
        return 0;

    const double alpha = 1.0 - pow(0.5, 1.0 / (double)CONSENSUS_EMA_HALF_LIFE);

    /* Per-tier accumulators. Trust tiers are small (0..4); clamp into a
     * bounded table and bucket anything larger into the top slot. */
    enum { TIER_TABLE = 16 };
    double ema[TIER_TABLE];
    bool   seeded[TIER_TABLE];
    for (int i = 0; i < TIER_TABLE; i++) { ema[i] = 0.0; seeded[i] = false; }

    uuid_t seen[MAX_CHAIN_LEN];
    int seen_count = 0;

    for (int i = 0; i < count; i++)
    {
        const transaction_t *tx = &txns[i];
        if (!tx->p1_set || !tx->p2_set)
            continue;
        double cp_score;
        if (uuid_compare(tx->p1_uuid, peer_uuid) == 0)
            cp_score = tx->p2_score;
        else if (uuid_compare(tx->p2_uuid, peer_uuid) == 0)
            cp_score = tx->p1_score;
        else
            continue;
        /* dedup by task: by_peer can list a tx under both p1 and p2. */
        bool dup = false;
        for (int j = 0; j < seen_count; j++)
            if (uuid_compare(seen[j], tx->task_uuid) == 0) { dup = true; break; }
        if (dup)
            continue;
        uuid_copy(seen[seen_count++], tx->task_uuid);

        char tk[UUID_STRING_LEN + 1];
        uuid_unparse_lower(tx->task_uuid, tk);

        int tier = 0;
        if (task_tiers != NULL)
        {
            data_t *t_dat = NULL;
            if (map_get((map_t *)task_tiers, tk, &t_dat) == 0 && t_dat != NULL)
            {
                int tv = 0;
                if (data_integer(t_dat, &tv) == 0 && tv > 0)
                    tier = tv;
            }
        }
        if (tier < 0) tier = 0;
        if (tier >= TIER_TABLE) tier = TIER_TABLE - 1;

        int w = 1;
        if (task_weights != NULL)
        {
            data_t *w_dat = NULL;
            if (map_get((map_t *)task_weights, tk, &w_dat) == 0 && w_dat != NULL)
            {
                int wv = 0;
                if (data_integer(w_dat, &wv) == 0 && wv > 0)
                    w = wv;
            }
        }
        for (int k = 0; k < w; k++)
        {
            if (!seeded[tier]) { ema[tier] = cp_score; seeded[tier] = true; }
            else ema[tier] = alpha * cp_score + (1.0 - alpha) * ema[tier];
        }
    }

    int n = 0;
    for (int t = 0; t < TIER_TABLE && n < max_out; t++)
    {
        if (seeded[t])
        {
            out[n].tier = t;
            out[n].score = ema[t];
            n++;
        }
    }
    return n;
}

/* paxos_id_index is now provided by algorithms/paxos.c */
