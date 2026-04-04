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

#ifndef PAXOS_H
#define PAXOS_H

#include <stdbool.h>
#include <pthread.h>
#include "autonomous_trust/structures/map_priv.h"
#include "autonomous_trust/structures/array_priv.h"
#include "autonomous_trust/utilities/logger.h"

#define PAXOS_MAJORITY(n) (((n) / 2) + 1)
#define PAXOS_BACKOFF_MULT    1.5
#define PAXOS_BACKOFF_MAX_SEC 90
#define PAXOS_KEY_LEN 64

typedef enum {
    PAXOS_GRANT = 0,
    PAXOS_NACK,
    PAXOS_BACKDATE,
} paxos_response_t;

typedef struct {
    double score;
    int grant_count;
} paxos_proposal_t;

typedef struct {
    double last_id;
    int chain_len;
    int num_peers;
    map_t proposals;
    map_t acceptances;
    map_t backoff;
    array_t granted_ids;
    pthread_mutex_t lock;
    logger_t *logger;
    bool initialized;
} paxos_instance_t;

int paxos_init(paxos_instance_t *inst, int num_peers, logger_t *logger);
void paxos_destroy(paxos_instance_t *inst);
double paxos_id_index(double id1, double id2);

paxos_response_t paxos_handle_request(paxos_instance_t *inst,
                                      double id1, double id2,
                                      double *out_last_id, int *out_chain_len);

int paxos_record_grant(paxos_instance_t *inst,
                       double id1, double id2, double score);

int paxos_record_acceptance(paxos_instance_t *inst,
                            double id1, double id2);

bool paxos_has_granted_id(paxos_instance_t *inst, int id2);
void paxos_advance_chain(paxos_instance_t *inst);
void paxos_next_ids(paxos_instance_t *inst, double *out_id1, double *out_id2);
int paxos_record_nack(paxos_instance_t *inst, double id1, double id2);

#endif /* PAXOS_H */
