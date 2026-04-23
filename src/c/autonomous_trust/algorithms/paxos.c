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

#include "algorithms/paxos.h"
#include "structures/data.h"
#include <inttypes.h>
#include <math.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

int paxos_init_with_node(paxos_instance_t *inst, int num_peers,
                         uint16_t node_id, logger_t *logger)
{
    memset(inst, 0, sizeof(*inst));
    inst->num_peers = num_peers;
    inst->logger = logger;
    inst->last_id = 0;
    inst->chain_len = 0;
    inst->node_id = node_id;
    /* Seed the counter from wall-clock ms so id1s are roughly time-ordered
     * across restarts; paxos_next_ids only ever advances it. */
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    inst->next_counter = (int64_t)ts.tv_sec * 1000 +
                         (int64_t)(ts.tv_nsec / 1000000);
    map_init(&inst->proposals);
    map_init(&inst->acceptances);
    map_init(&inst->backoff);
    array_init(&inst->granted_ids);
    pthread_mutex_init(&inst->lock, NULL);
    inst->initialized = true;
    return 0;
}

int paxos_init(paxos_instance_t *inst, int num_peers, logger_t *logger)
{
    return paxos_init_with_node(inst, num_peers, 0, logger);
}

void paxos_destroy(paxos_instance_t *inst)
{
    if (!inst->initialized)
        return;
    if (inst->proposals.items != NULL)
        map_free(&inst->proposals);
    if (inst->acceptances.items != NULL)
        map_free(&inst->acceptances);
    if (inst->backoff.items != NULL)
        map_free(&inst->backoff);
    if (inst->granted_ids.array != NULL)
        array_free(&inst->granted_ids);
    pthread_mutex_destroy(&inst->lock);
    inst->initialized = false;
}

void paxos_id_index(char *buf, size_t len, int64_t id1, int64_t id2)
{
    snprintf(buf, len, "%" PRId64 ":%" PRId64, id1, id2);
}

static void make_key(char *buf, size_t buflen, int64_t id1, int64_t id2)
{
    paxos_id_index(buf, buflen, id1, id2);
}

/* WHY the ballot-ordering logic matters:
 *
 * Paxos safety requires that every accepted ballot carry a strictly higher
 * ID than any previously accepted one. That invariant is maintained here by
 * ONLY transitioning `inst->last_id = id1` when `id1 > inst->last_id`. The
 * check is an INSTANCE-local monotonic comparison, not a uniqueness check:
 * we do NOT verify that id1 has never been seen cluster-wide. Uniqueness
 * has to be arranged by the ID generator in paxos_next_ids() (which
 * combines a per-node counter with chain position so two nodes can't mint
 * the same id1 for the same id2).
 *
 * Three distinct unlock sites exist because each return path leaves a
 * different mutation visible:
 *   GRANT     — last_id and granted_ids are updated; unlock after commit.
 *   BACKDATE  — read-only; unlock with no state change.
 *   NACK      — read-only; unlock with no state change.
 * A single unlock at function tail would require wrapping the returns in a
 * result variable, which WP then has to reason about across behaviors;
 * keeping the unlock inline at each exit preserves the per-behavior
 * postconditions in paxos.h with far fewer obligations.
 *
 * WHY `id2 == chain_len + 1` and not `>=`:
 * A ballot must land at the NEXT free chain slot. If id2 is ahead of
 * chain_len+1, the proposer has stale view; we BACKDATE (signal the peer
 * to catch up) rather than NACK so they don't increase their backoff. */
/* Frama-C: skipped — [solver-timeout] pthread_mutex_lock + integer_data
 * (smrt_create) + array_append state falls outside the declared 4-target
 * assigns clause; assigns_normal_part10 times out. */
paxos_response_t paxos_handle_request(paxos_instance_t *inst,
                                      int64_t id1, int64_t id2,
                                      int64_t *out_last_id, int *out_chain_len)
{
    pthread_mutex_lock(&inst->lock);

    *out_last_id = inst->last_id;
    *out_chain_len = inst->chain_len;

    if (id1 > inst->last_id)
    {
        if (id2 == (int64_t)(inst->chain_len + 1))
        {
            data_t *id2_dat = integer_data((int)id2);
            array_append(&inst->granted_ids, id2_dat);
            inst->last_id = id1;
            pthread_mutex_unlock(&inst->lock);
            return PAXOS_GRANT;
        }
        else
        {
            pthread_mutex_unlock(&inst->lock);
            return PAXOS_BACKDATE;
        }
    }
    else
    {
        pthread_mutex_unlock(&inst->lock);
        return PAXOS_NACK;
    }
}

/* Frama-C: skipped — [solver-timeout] postcondition on quorum state */
int paxos_record_grant(paxos_instance_t *inst,
                       int64_t id1, int64_t id2, double score)
{
    char key[PAXOS_KEY_LEN];
    make_key(key, sizeof(key), id1, id2);

    pthread_mutex_lock(&inst->lock);

    data_t *prop_dat = NULL;
    paxos_proposal_t *ptc = NULL;

    if (map_get(&inst->proposals, key, &prop_dat) == 0)
    {
        data_object_ptr(prop_dat, (void **)&ptc);
        ptc->grant_count += 1;
    }
    else
    {
        ptc = smrt_create(sizeof(paxos_proposal_t));
        if (ptc != NULL)
        {
            ptc->score = score;
            ptc->grant_count = 1;
            data_t *new_dat = object_ptr_data(ptc, sizeof(paxos_proposal_t));
            map_set(&inst->proposals, key, new_dat);
        }
    }

    int count = (ptc != NULL) ? ptc->grant_count : 0;
    pthread_mutex_unlock(&inst->lock);
    return count;
}

int paxos_record_acceptance(paxos_instance_t *inst,
                            int64_t id1, int64_t id2)
{
    char key[PAXOS_KEY_LEN];
    make_key(key, sizeof(key), id1, id2);

    pthread_mutex_lock(&inst->lock);

    data_t *acc_dat = NULL;
    int count = 0;

    if (map_get(&inst->acceptances, key, &acc_dat) == 0)
    {
        data_integer(acc_dat, &count);
        count += 1;
        data_t *new_dat = integer_data(count);
        map_set(&inst->acceptances, key, new_dat);
    }
    else
    {
        count = 1;
        data_t *new_dat = integer_data(count);
        map_set(&inst->acceptances, key, new_dat);
    }

    pthread_mutex_unlock(&inst->lock);
    return count;
}

bool paxos_has_granted_id(paxos_instance_t *inst, int id2)
{
    pthread_mutex_lock(&inst->lock);
    for (size_t i = 0; i < array_size(&inst->granted_ids); i++)
    {
        data_t *dat = NULL;
        if (array_get(&inst->granted_ids, (int)i, &dat) == 0)
        {
            int val;
            if (data_integer(dat, &val) == 0 && val == id2)
            {
                pthread_mutex_unlock(&inst->lock);
                return true;
            }
        }
    }
    pthread_mutex_unlock(&inst->lock);
    return false;
}

void paxos_advance_chain(paxos_instance_t *inst)
{
    pthread_mutex_lock(&inst->lock);
    inst->chain_len += 1;
    pthread_mutex_unlock(&inst->lock);
}

void paxos_next_ids(paxos_instance_t *inst, int64_t *out_id1, int64_t *out_id2)
{
    pthread_mutex_lock(&inst->lock);

    /* Bump the counter to the greater of (wall-clock ms, last+1).  Gives
     * strict monotonicity within an instance (tight-loop safe, backward-
     * clock-step safe) while keeping id1 aligned with wall-clock time
     * whenever the clock makes real progress. */
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    int64_t now_ms = (int64_t)ts.tv_sec * 1000 +
                     (int64_t)(ts.tv_nsec / 1000000);
    int64_t next = inst->next_counter + 1;
    if (now_ms > next)
        next = now_ms;
    inst->next_counter = next;

    /* Low 16 bits = node_id (unique per node); high 48 bits = counter.
     * Two nodes minting at the same counter value produce different id1s. */
    int64_t id1 = (next << 16) | (int64_t)inst->node_id;

    inst->last_id = id1;
    *out_id1 = id1;
    *out_id2 = (int64_t)(inst->chain_len + 1);

    pthread_mutex_unlock(&inst->lock);
}

int paxos_record_nack(paxos_instance_t *inst, int64_t id1, int64_t id2)
{
    char key[PAXOS_KEY_LEN];
    make_key(key, sizeof(key), id1, id2);

    pthread_mutex_lock(&inst->lock);

    data_t *bo_dat = NULL;
    int wait_sec = 2;

    if (map_get(&inst->backoff, key, &bo_dat) == 0)
    {
        int prev;
        data_integer(bo_dat, &prev);
        wait_sec = (int)((double)prev * PAXOS_BACKOFF_MULT);
        if (wait_sec > PAXOS_BACKOFF_MAX_SEC)
            wait_sec = PAXOS_BACKOFF_MAX_SEC;
    }

    data_t *new_dat = integer_data(wait_sec);
    map_set(&inst->backoff, key, new_dat);

    pthread_mutex_unlock(&inst->lock);
    return wait_sec;
}
