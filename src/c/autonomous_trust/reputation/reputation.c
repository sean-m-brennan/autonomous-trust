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
#include "structures/map_priv.h"
#include "structures/data_priv.h"
#include "identity/identity.h"

DEFINE_ERROR(EREP_NOTX, "Transaction not found");
DEFINE_ERROR(EREP_NOPEER, "Peer not found in reputation map");
DEFINE_ERROR(EREP_CHAIN_FULL, "Transaction chain is full");

/****************************
 * Transaction history
 ****************************/

int tx_history_create(tx_history_t **hist)
{
    *hist = calloc(1, sizeof(tx_history_t));
    if (*hist == NULL)
        return EXCEPTION(ENOMEM);
    return tx_history_init(*hist);
}

int tx_history_init(tx_history_t *hist)
{
    memset(hist->chain, 0, sizeof(hist->chain));
    hist->chain_len = 0;
    int err = map_init(&hist->task_map);
    if (err != 0) return err;
    return map_init(&hist->peer_map);
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
        /* Create new transaction */
        if (hist->chain_len >= MAX_CHAIN_LEN)
            return EXCEPTION(EREP_CHAIN_FULL);

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
        /* Fill the other slot */
        transaction_t *tx = &hist->chain[idx];
        if (!tx->p1_set)
        {
            uuid_copy(tx->p1_uuid, peer_uuid);
            tx->p1_score = score;
            tx->p1_set = true;
        }
        else if (!tx->p2_set)
        {
            uuid_copy(tx->p2_uuid, peer_uuid);
            tx->p2_score = score;
            tx->p2_set = true;
        }
        /* Both slots already filled: ignore (shouldn't happen in normal flow) */
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
    hist->chain_len = 0;
}

/****************************
 * JSON serialization for chain sync
 ****************************/

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
            return EXCEPTION(EREP_CHAIN_FULL);

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

    data_t *score_dat = floating_pt_data((float)score);
    return map_set(&reps->scores, uuid_str, score_dat);
}

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
                       const uuid_t peer_uuid)
{
    transaction_t txns[MAX_CHAIN_LEN];
    int count = 0;
    tx_history_by_peer(hist, peer_uuid, txns, &count, MAX_CHAIN_LEN);

    if (count == 0)
        return 0.5;  /* Default neutral reputation */

    double sum = 0.0;
    int valid = 0;

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

        sum += counterparty_score * cp_rep;
        valid++;
    }

    if (valid == 0)
        return 0.5;

    return sum / (double)valid;
}

/**
 * Contrite tit-for-tat:
 * - No history → 0.49 (slightly defect)
 * - Check last interaction with this peer
 * - If peer cooperated last time (score > 0.5), cooperate
 * - Else defect
 */
double reputation_contrite_tft(const tx_history_t *hist, const reputations_t *reps,
                               const uuid_t self_uuid, const uuid_t peer_uuid)
{
    transaction_t txns[MAX_CHAIN_LEN];
    int count = 0;
    tx_history_by_peer(hist, peer_uuid, txns, &count, MAX_CHAIN_LEN);

    if (count == 0)
        return 0.49;

    /* Find last transaction involving both self and peer */
    for (int i = count - 1; i >= 0; i--)
    {
        const transaction_t *tx = &txns[i];
        if (!tx->p1_set || !tx->p2_set)
            continue;

        bool self_is_p1 = (uuid_compare(tx->p1_uuid, self_uuid) == 0);
        bool self_is_p2 = (uuid_compare(tx->p2_uuid, self_uuid) == 0);
        bool peer_is_p1 = (uuid_compare(tx->p1_uuid, peer_uuid) == 0);
        bool peer_is_p2 = (uuid_compare(tx->p2_uuid, peer_uuid) == 0);

        if ((self_is_p1 && peer_is_p2) || (self_is_p2 && peer_is_p1))
        {
            /* Found a direct interaction */
            double peer_last_score;
            if (peer_is_p1)
                peer_last_score = tx->p1_score;
            else
                peer_last_score = tx->p2_score;

            /* Contrite: if peer cooperated (> 0.5), cooperate back */
            if (peer_last_score > 0.5)
                return 1.0;

            /* Check own standing - if we defected last and peer retaliated, forgive */
            double self_last_score;
            if (self_is_p1)
                self_last_score = tx->p1_score;
            else
                self_last_score = tx->p2_score;

            if (self_last_score <= 0.5)
                return 1.0;  /* Contrite: we defected, accept retaliation */

            return 0.0;  /* Defect */
        }
    }

    /* No direct interaction found, check general peer history */
    if (count > 0)
    {
        const transaction_t *last = &txns[count - 1];
        double last_score;
        if (uuid_compare(last->p1_uuid, peer_uuid) == 0)
            last_score = last->p1_score;
        else
            last_score = last->p2_score;

        return (last_score > 0.5) ? 1.0 : 0.0;
    }

    return 0.49;
}

/**
 * Gate on previous score > 0.5:
 * - If trusted (score > 0.5): use socially-weighted average
 * - Else: use game-theoretic tit-for-tat
 */
double reputation_compute(const tx_history_t *hist, const reputations_t *reps,
                          const uuid_t self_uuid, const uuid_t peer_uuid)
{
    double current_score = 0.5;
    reputations_get(reps, peer_uuid, &current_score);

    if (current_score > 0.5)
        return reputation_pure(hist, reps, peer_uuid);
    else
        return reputation_contrite_tft(hist, reps, self_uuid, peer_uuid);
}

/****************************
 * Paxos ID helpers
 ****************************/

double paxos_id_index(double id1, double id2)
{
    if (fabs(id2) < 1e-15)
        return id1;

    /* Count digits in id2 */
    int digits = 0;
    double tmp = fabs(id2);
    if (tmp < 1.0)
        digits = 1;
    else
    {
        while (tmp >= 1.0)
        {
            tmp /= 10.0;
            digits++;
        }
    }

    return id1 + id2 / pow(10.0, (double)digits);
}
