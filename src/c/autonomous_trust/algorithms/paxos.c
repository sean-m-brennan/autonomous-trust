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
#include <math.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

int paxos_init(paxos_instance_t *inst, int num_peers, logger_t *logger)
{
    memset(inst, 0, sizeof(*inst));
    inst->num_peers = num_peers;
    inst->logger = logger;
    inst->last_id = 0.0;
    inst->chain_len = 0;
    map_init(&inst->proposals);
    map_init(&inst->acceptances);
    map_init(&inst->backoff);
    array_init(&inst->granted_ids);
    pthread_mutex_init(&inst->lock, NULL);
    inst->initialized = true;
    return 0;
}

void paxos_destroy(paxos_instance_t *inst)
{
    if (!inst->initialized)
        return;
    map_free(&inst->proposals);
    map_free(&inst->acceptances);
    map_free(&inst->backoff);
    array_free(&inst->granted_ids);
    pthread_mutex_destroy(&inst->lock);
    inst->initialized = false;
}

double paxos_id_index(double id1, double id2)
{
    if (fabs(id2) < 1e-15)
        return id1;
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

static void make_key(char *buf, size_t buflen, double id1, double id2)
{
    snprintf(buf, buflen, "%.0f:%.0f", id1, id2);
}

paxos_response_t paxos_handle_request(paxos_instance_t *inst,
                                      double id1, double id2,
                                      double *out_last_id, int *out_chain_len)
{
    pthread_mutex_lock(&inst->lock);

    *out_last_id = inst->last_id;
    *out_chain_len = inst->chain_len;

    if (id1 > inst->last_id)
    {
        if ((int)id2 == inst->chain_len + 1)
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

int paxos_record_grant(paxos_instance_t *inst,
                       double id1, double id2, double score)
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
                            double id1, double id2)
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

void paxos_next_ids(paxos_instance_t *inst, double *out_id1, double *out_id2)
{
    pthread_mutex_lock(&inst->lock);
    inst->last_id += 1.0;
    *out_id1 = paxos_id_index(inst->last_id, (double)inst->num_peers);
    *out_id2 = (double)(inst->chain_len + 1);
    pthread_mutex_unlock(&inst->lock);
}

int paxos_record_nack(paxos_instance_t *inst, double id1, double id2)
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
