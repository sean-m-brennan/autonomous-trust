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

#include <string.h>
#include <math.h>
#include <errno.h>

#include "reputation/reputation.h"
#include "structures/map.h"
#include "structures/data.h"
#include "identity/identity.h"

DEFINE_ERROR(EREP_NOTX, "Transaction not found");
DEFINE_ERROR(EREP_NOPEER, "Peer not found in reputation map");
DEFINE_ERROR(EREP_CHAIN_FULL, "Transaction chain is full");

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
    hist->evicted_ring_head = 0;
    hist->evicted_ring_len = 0;
    int err = map_init(&hist->task_map);
    if (err != 0) return err;
    err = map_init(&hist->peer_map);
    if (err != 0) return err;
    return map_init(&hist->evicted_set);
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
                {
                    array_free((array_t *)arr_ptr);
                    smrt_deref(arr_ptr);
                }
            }
            map_remove(&hist->peer_map, pkey);
        }
    }
    array_free(&empty_peers);

    /* 4. Memmove the chain down, renumber tx->index in the remainder. */
    memmove(&hist->chain[0], &hist->chain[1],
            (size_t)(hist->chain_len - 1) * sizeof(transaction_t));
    hist->chain_len--;
    for (int i = 0; i < hist->chain_len; i++)
        hist->chain[i].index = i;
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
        tx->index = idx;
        hist->chain_len++;

        /* Record in task_map */
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
    }

    /* Update peer_map: add this index to the peer's list */
    data_t *peer_indices = NULL;
    if (map_get((map_t *)&hist->peer_map, peer_str, &peer_indices) != 0)
    {
        /* Create new array for this peer */
        array_t *arr = smrt_create(sizeof(array_t));
        if (arr == NULL) return EXCEPTION(ENOMEM);
        array_init(arr);
        data_t *new_idx = integer_data(idx);
        array_append(arr, new_idx);
        data_t *arr_dat = object_ptr_data(arr, sizeof(array_t));
        map_set(&hist->peer_map, peer_str, arr_dat);
    }
    else
    {
        void *arr_ptr = NULL;
        data_object_ptr(peer_indices, &arr_ptr);
        array_t *arr = (array_t *)arr_ptr;
        data_t *new_idx = integer_data(idx);
        array_append(arr, new_idx);
    }

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
    if (start_idx < 0) start_idx = 0;
    if (end_idx > hist->chain_len) end_idx = hist->chain_len;

    *out_count = 0;
    for (int i = start_idx; i < end_idx; i++)
    {
        out[*out_count] = hist->chain[i];
        (*out_count)++;
    }
    return 0;
}

int tx_history_len(const tx_history_t *hist)
{
    return hist->chain_len;
}

/* Frama-C: skipped — [solver-timeout] container free cascade */
void tx_history_free(tx_history_t *hist)
{
    map_free(&hist->task_map);
    /* peer_map values are arrays that were smrt_created */
    map_key_t key = NULL;
    data_t *val = NULL;
    map_entries_for_each(&hist->peer_map, key, val)
    {
        void *arr_ptr = NULL;
        if (data_object_ptr(val, &arr_ptr) == 0 && arr_ptr != NULL)
        {
            array_free((array_t *)arr_ptr);
            smrt_deref(arr_ptr);
        }
    }
    map_end_for_each
    map_free(&hist->peer_map);
    map_free(&hist->evicted_set);
    hist->chain_len = 0;
    hist->evicted_ring_head = 0;
    hist->evicted_ring_len = 0;
}

/****************************
 * JSON serialization for chain sync
 ****************************/

/* Frama-C: skipped — [serialization] jansson JSON serialization */
int tx_history_era_to_json(const tx_history_t *hist, int start_idx, int end_idx, json_t **out)
{
    if (start_idx < 0) start_idx = 0;
    if (end_idx > hist->chain_len) end_idx = hist->chain_len;

    json_t *arr = json_array();
    if (arr == NULL) return EXCEPTION(ENOMEM);

    for (int i = start_idx; i < end_idx; i++)
    {
        const transaction_t *tx = &hist->chain[i];
        char task_str[UUID_STRING_LEN + 1];
        uuid_unparse_lower(tx->task_uuid, task_str);
        char p1_str[UUID_STRING_LEN + 1];
        uuid_unparse_lower(tx->p1_uuid, p1_str);
        char p2_str[UUID_STRING_LEN + 1];
        uuid_unparse_lower(tx->p2_uuid, p2_str);

        json_t *obj = json_pack("{s:s, s:s, s:f, s:b, s:s, s:f, s:b, s:i}",
            "task", task_str,
            "p1", p1_str, "p1_score", tx->p1_score, "p1_set", tx->p1_set,
            "p2", p2_str, "p2_score", tx->p2_score, "p2_set", tx->p2_set,
            "index", tx->index);
        if (obj == NULL)
        {
            json_decref(arr);
            return -1;
        }
        json_array_append_new(arr, obj);
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

        /* Update maps */
        char task_key[UUID_STRING_LEN + 1];
        uuid_unparse_lower(tx->task_uuid, task_key);
        data_t *idx_d = integer_data(hist->chain_len);
        map_set(&hist->task_map, task_key, idx_d);

        hist->chain_len++;
    }
    return 0;
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
        return 0.5;  /* Default neutral reputation */

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
        double cp_rep = 0.5;
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
        return 0.5;

    return sum / (double)total_weight;
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
 *   - No direct history → 0.49 (slightly defect, lets reputation kick in)
 *   - peer defected last AND my standing is poor → max(0.51, peer_standing)
 *   - peer defected last AND my standing is good  → min(0.49, peer_standing)
 *   - cooperative case                            → max(0.51, peer_standing)
 */
double reputation_contrite_tft(const tx_history_t *hist, const reputations_t *reps,
                               const uuid_t self_uuid, const uuid_t peer_uuid)
{
    (void)reps;
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
        return 0.49;

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
    double current_score = 0.5;
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
 *   - No history or no bilateral txs → 0.5 (neutral)
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
        return 0.5;

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
    return seeded ? ema : 0.5;
}

/* paxos_id_index is now provided by algorithms/paxos.c */
