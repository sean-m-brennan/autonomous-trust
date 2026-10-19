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

#ifndef FLEET_GATE_H
#define FLEET_GATE_H

/** @addtogroup internal_fleet
 *  @{
 */

/**
 * fleet_gate — who may propose a fleet or config update, and when a vote
 * carries one (doc/architecture/extensions.md,
 * "Who may propose an update").
 *
 * Shared by the fleet and config processes. Each runs it on a proposal it
 * receives, every voter runs it before granting, and every node runs it again
 * on an acceptance before acting on it:
 *
 * - The signer is a member of this node's group (its uuid is in the group
 *   address map) or this node itself.
 * - The proposal's signature verifies under the signing key this node holds
 *   for that member, not under a key the message carries.
 * - The member is operator-bound (its operator credential was verified).
 * - The member's reputation, asked of the local reputation process, reaches
 *   the bar in THIS node's `fleet.cfg.json` (`min_proposer_reputation`). The
 *   bar a proposal carries is ignored. A node does not hold its own
 *   reputation, so its own proposals skip this check; every other node runs it.
 *
 * A vote carries when ⌊N/2⌋ members other than the proposer have granted it,
 * where N is the group's size (this node included) at the moment of counting.
 * Each grant is signed by its granter, and an acceptance carries the grants,
 * so every node counts them itself.
 */

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include <jansson.h>
#include <sodium.h>
#include <uuid/uuid.h>

#include "processes/processes.h"
#include "utilities/message.h"
#include "fleet/fleet_proc.h"   /* FLEET_DEFAULT_MIN_REPUTATION */

/** The configuration file (under the cfg dir) the bar is read from. */
#define FLEET_GATE_CFG_NAME "fleet"

typedef enum {
    FLEET_GATE_PASS = 0,
    FLEET_GATE_REFUSE = 1,
    /** The proposer's reputation is not known yet: it was asked for, and the
     *  caller should hold the message (@ref fleet_gate_hold). */
    FLEET_GATE_PENDING = 2,
} fleet_gate_t;

/** Verify a proposal's signature under @p pk: 0 when it verifies. */
typedef int (*fleet_gate_verify_fn)(const void *prop, const uint8_t *pk);

/** A handler to run a held message again. */
typedef bool (*fleet_gate_handler_fn)(const process_t *proc, directory_t *queues,
                                      generic_msg_t *msg);

/** N: the group's size, this node included. */
size_t fleet_gate_group_size(const process_t *proc);

/** Grants a vote needs from members other than the proposer: ⌊N/2⌋. */
size_t fleet_gate_quorum(size_t group_size);

/** Whether @p uuid is this node or a member of its group, and if so the
 *  signing key and operator_bound this node holds for it. */
bool fleet_gate_member(const process_t *proc, const uuid_t uuid,
                       uint8_t pk_out[crypto_sign_PUBLICKEYBYTES],
                       bool *operator_bound_out);

/** The peers that are members of our group (this node excluded), copied out
 *  of the peer list: *@p out is malloc'd, the caller frees it. */
size_t fleet_gate_members(const process_t *proc, public_identity_t **out);

/** Whether @p uuid is this node. */
bool fleet_gate_is_self(const process_t *proc, const uuid_t uuid);

/** The proposer checks above, for the proposal @p prop signed by @p signer.
 *  On refusal, @p why says which check failed. */
fleet_gate_t fleet_gate_proposer(const process_t *proc, const uuid_t signer,
                                 fleet_gate_verify_fn verify, const void *prop,
                                 char *why, size_t why_len);

/** The bytes a granter signs: @p kind ("update" or "config"), the proposal's
 *  uuid, the ballot and the content hash. Returns the length written. */
size_t fleet_gate_grant_signable(const char *kind, const uuid_t proposal_uuid,
                                 int64_t id1, int64_t id2,
                                 const uint8_t hash[32], uint8_t *buf, size_t len);

/** A grant this node signs: {granter, id1, id2, proposal_uuid, signature}.
 *  NULL without an identity to sign with. */
json_t *fleet_gate_sign_grant(const process_t *proc, const char *kind,
                              const uuid_t proposal_uuid, int64_t id1, int64_t id2,
                              const uint8_t hash[32]);

/** Whether @p grant is a member's valid signature over this proposal and
 *  ballot. Writes the granter to @p granter_out. */
bool fleet_gate_grant_valid(const process_t *proc, const json_t *grant,
                            const char *kind, const uuid_t proposal_uuid,
                            int64_t id1, int64_t id2, const uint8_t hash[32],
                            uuid_t granter_out);

/** Counts the valid grants in @p grants from distinct members other than
 *  @p proposer, each for ballot (@p id1, @p id2). */
size_t fleet_gate_count_grants(const process_t *proc, const json_t *grants,
                               const char *kind, const uuid_t proposal_uuid,
                               const uuid_t proposer, int64_t id1, int64_t id2,
                               const uint8_t hash[32]);

/** Keep a copy of @p msg to run through @p handler when a reputation reply
 *  arrives. */
void fleet_gate_hold(const process_t *proc, const generic_msg_t *msg,
                     fleet_gate_handler_fn handler);

/** The local reputation reply (REP_PROTO_LOCAL_RESP): record it, then run the
 *  held messages again. */
bool fleet_gate_handle_rep_reply(const process_t *proc, directory_t *queues,
                                 generic_msg_t *msg);

/** The bar this node holds proposers to. */
double fleet_gate_min_reputation(void);

/* Test hooks. */
void fleet_gate_set_reputation(const uuid_t uuid, double score, bool found);
void fleet_gate_set_min_reputation(double bar);   /* < 0: read the file again */
size_t fleet_gate_held(void);
void fleet_gate_reset(void);

/** @} */ /* end of internal_fleet */

#endif /* FLEET_GATE_H */
