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
#include <stdint.h>
#include <pthread.h>
#include "autonomous_trust/structures/map_priv.h"
#include "autonomous_trust/structures/array_priv.h"
#include "autonomous_trust/utilities/logger.h"

#define PAXOS_MAJORITY(n) (((n) / 2) + 1)
#define PAXOS_BACKOFF_MULT    1.5
#define PAXOS_BACKOFF_MAX_SEC 90
#define PAXOS_KEY_LEN 64
#define PAXOS_PROTOCOL_TIMEOUT_SEC  30
#define PAXOS_EXPIRATION_SEC       300

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
    int64_t last_id;
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

/*@
  requires \valid(inst);
  requires num_peers >= 0;
  assigns *inst;
  ensures \result == 0;
  ensures inst->initialized == \true;
  ensures inst->last_id == 0;
  ensures inst->chain_len == 0;
  ensures inst->num_peers == num_peers;
*/
int paxos_init(paxos_instance_t *inst, int num_peers, logger_t *logger);

/*@
  requires \valid(inst);
  assigns inst->proposals, inst->acceptances, inst->backoff,
          inst->granted_ids, inst->lock, inst->initialized;
  ensures inst->initialized == \false;
*/
void paxos_destroy(paxos_instance_t *inst);

/*@
  requires \valid(buf + (0 .. len - 1));
  requires len > 0;
  assigns buf[0 .. len - 1];
*/
void paxos_id_index(char *buf, size_t len, int64_t id1, int64_t id2);

/*@
  requires \valid(inst);
  requires inst->initialized == \true;
  requires \valid(out_last_id);
  requires \valid(out_chain_len);
  assigns inst->last_id, inst->granted_ids,
          *out_last_id, *out_chain_len;
  ensures \result == PAXOS_GRANT || \result == PAXOS_NACK || \result == PAXOS_BACKDATE;
  ensures \result == PAXOS_GRANT ==> inst->last_id == id1;
*/
paxos_response_t paxos_handle_request(paxos_instance_t *inst,
                                      int64_t id1, int64_t id2,
                                      int64_t *out_last_id, int *out_chain_len);

/*@
  requires \valid(inst);
  requires inst->initialized == \true;
  assigns inst->proposals;
  ensures \result >= 0;
*/
int paxos_record_grant(paxos_instance_t *inst,
                       int64_t id1, int64_t id2, double score);

/*@
  requires \valid(inst);
  requires inst->initialized == \true;
  assigns inst->acceptances;
  ensures \result >= 1;
*/
int paxos_record_acceptance(paxos_instance_t *inst,
                            int64_t id1, int64_t id2);

/*@
  requires \valid(inst);
  requires inst->initialized == \true;
  assigns \nothing;
  ensures \result == \true || \result == \false;
*/
bool paxos_has_granted_id(paxos_instance_t *inst, int id2);

/*@
  requires \valid(inst);
  requires inst->initialized == \true;
  assigns inst->chain_len;
  ensures inst->chain_len == \old(inst->chain_len) + 1;
*/
void paxos_advance_chain(paxos_instance_t *inst);

/*@
  requires \valid(inst);
  requires inst->initialized == \true;
  requires \valid(out_id1);
  requires \valid(out_id2);
  assigns inst->last_id, *out_id1, *out_id2;
  ensures *out_id2 == \old(inst->chain_len) + 1;
*/
void paxos_next_ids(paxos_instance_t *inst, int64_t *out_id1, int64_t *out_id2);

/*@
  requires \valid(inst);
  requires inst->initialized == \true;
  assigns inst->backoff;
  ensures \result >= 2;
  ensures \result <= PAXOS_BACKOFF_MAX_SEC;
*/
int paxos_record_nack(paxos_instance_t *inst, int64_t id1, int64_t id2);

#endif /* PAXOS_H */
