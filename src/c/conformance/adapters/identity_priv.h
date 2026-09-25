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

/* The C identity conformance adapter's extension points (FEATURE_SPLIT_PLAN
 * Phase 5): what a feature adapter that rides the identity process -- social,
 * adapters/social.c -- needs from identity.c. The C twin of the Python
 * IdentityAdapter's FIXTURE_HOOKS / TRIGGERS / INBOUND_BUILDERS / STATE_CHECKS.
 * Private to the conformance runner. */
#ifndef AT_CONFORMANCE_IDENTITY_PRIV_H
#define AT_CONFORMANCE_IDENTITY_PRIV_H

#include <stdbool.h>
#include <stdint.h>

#include <jansson.h>
#include <uuid/uuid.h>

#include "identity/identity.h"
#include "processes/processes.h"
#include "utilities/message.h"

#include "../case_result.h"
#include "../scenario_engine.h"
#include "../scenario_loader.h"

/* ------------------------------------------------------------------------- */
/* Per-participant impl carries a process_t plus a public_identity_t copy    */
/* for the to_whom→id resolution path.                                        */
/* ------------------------------------------------------------------------- */

typedef struct {
    identity_t *full;
    public_identity_t *pub;
    process_t *proc;
    /* The scenario's participant id, so a result can be reported under the name
     * the scenario uses rather than a uuid. */
    char id[SCE_ID_LEN];
    /* Result of a trigger_subtree_roster enumeration: a json array of the
     * flattened subtree's member participant ids (sorted). Read by the
     * subtree_roster expected-state check. Mirrors the Python adapter's
     * _Participant.subtree_roster. */
    json_t *subtree_roster;
    /* Result of trigger_hierarchy: the DERIVED parent gateway as a participant
     * id, or "" for a node that tops its own cohort. Mirrors the Python
     * adapter's _Participant.parent_gateway_pid. */
    char parent_gateway_pid[SCE_ID_LEN];
    /* Results of trigger_attest_pull / trigger_attest_replay with this
     * participant as the PULLER (ethne D8/Q9): the attested-now stamp the last
     * ACCEPTED pull yielded, the accept/reject verdict of each pull in order,
     * and the last answer kept so a replay can re-present it. Mirrors the
     * Python adapter's _Participant.attest_* fields. */
    double attest_stamp;
    json_t *attest_accepted;    /* json array of booleans */
    json_t *attest_last_answer;
    double attest_clock;        /* pinned clock from operator_session / clocks */
    /* Cohort clock samples this participant MEASURED as the puller, keyed by
     * the TARGET's participant id so expected_state can name a peer
     * language-agnostically. Values are {offset, delay, usable} read out of the
     * production handler's store (identity_get_peer_clock_sample) -- the
     * adapter relabels, it does not compute. Mirrors the Python adapter's
     * _Participant.attest_clock_samples.
     * See doc/architecture/cohort-clock-skew.md. */
    json_t *attest_clock_samples;
    /* Where trigger_first_contact_initiate actually addressed its hello: the
     * host on the outbound to_whom, recorded by _send_hook. Read by the
     * first_contact_hello_endpoint check, which pins that `initiate` prefers
     * the invitation's rendezvous hint over the inviter's advertised address.
     * Mirrors the Python adapter's _Participant.fc_hello_endpoint. */
    char fc_hello_endpoint[ADDR_LEN + 1];
    /* A feature adapter's own per-participant state (ic_ext_t; the social
     * adapter keeps each side's opt-in exact position here), freed by its
     * impl_free. NULL for a core-only scenario. */
    void *ext;
} ic_impl_t;

/* One feature's hooks. Every member may be NULL. Return conventions: 1 means
 * "not mine, carry on", 0 handled, -1 failed (ctx->err set). */
typedef struct ic_ext {
    const char *name;
    /* After the core fixtures, with the scenario's fixtures object. */
    void (*fixtures)(sce_run_ctx_t *ctx, json_t *fixtures);
    /* Build a step's inbound (out is already typed, addressed, from_whom set). */
    int (*inbound)(sce_run_ctx_t *ctx, sce_participant_t *sender,
                   ic_impl_t *sender_impl, const char *from_id,
                   const char *to_id, const char *function, json_t *payload,
                   generic_msg_t *out);
    /* A pseudo-function (trigger_*) delivered to target. */
    int (*dispatch)(sce_run_ctx_t *ctx, sce_participant_t *target,
                    generic_msg_t *inbound);
    /* One expected_state key of participant pid. */
    int (*check_key)(sce_run_ctx_t *ctx, const char *pid, ic_impl_t *impl,
                     process_t *proc, const char *key, json_t *val);
    /* Every outbound message the send hook sees, before it is captured. */
    void (*on_send)(message_type_t type, const char *function,
                    generic_msg_t *msg);
    /* A participant going away: free what the feature hung on impl->ext. */
    void (*impl_free)(ic_impl_t *impl);
} ic_ext_t;

/* Run one identity-shaped case with ext's hooks (NULL: core only). */
void at_identity_run_ext(const at_case_t *c, at_case_result_t *out,
                         const ic_ext_t *ext);

/* identity.c's state and helpers a feature adapter uses. */
extern sce_run_ctx_t *g_active_ctx;
ic_impl_t *_ic_impl_for_uuid(sce_run_ctx_t *ctx, const uuid_t uuid);
void _ic_uuid_str(ic_impl_t *impl, char out[UUID_STRING_LEN + 1]);
int64_t _ic_step_seq(json_t *payload, const char *key);
void _ic_set_seq(json_t *body, json_t *payload);
int _send_hook(const char *key, const message_type_t type, generic_msg_t *msg,
               bool blocking);

#endif /* AT_CONFORMANCE_IDENTITY_PRIV_H */
