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

#ifndef FLEET_PROC_H
#define FLEET_PROC_H

#include <stdbool.h>
#include <stdint.h>

#include "autonomous_trust/processes/processes.h"
#include "autonomous_trust/fleet/update_proposal.h"

#define FLEET_PROTO_PROPOSE      "update proposal"
#define FLEET_PROTO_VOTE_REQ     "update vote request"
#define FLEET_PROTO_VOTE_GRANT   "update vote grant"
#define FLEET_PROTO_VOTE_NACK    "update vote nack"
#define FLEET_PROTO_ACCEPTED     "update accepted"
#define FLEET_PROTO_REJECTED     "update rejected"

#define FLEET_DEFAULT_MIN_REPUTATION 0.7

/**
 * fleet_validate_proposal - verify the proposal signature.
 * @prop:      the proposal to verify
 * @signer_pk: public key of the expected signer (crypto_sign_PUBLICKEYBYTES)
 * Returns true if the signature is valid, false otherwise.
 */
bool fleet_validate_proposal(const update_proposal_t *prop, const uint8_t *signer_pk);

/**
 * fleet_check_reputation_threshold - test whether a peer meets the minimum
 * reputation requirement.
 * @peer_reputation: the peer's current reputation score
 * @min_threshold:   the minimum required reputation
 * Returns true if peer_reputation >= min_threshold.
 */
bool fleet_check_reputation_threshold(double peer_reputation, double min_threshold);

/**
 * fleet_should_accept_proposal - combined validation + reputation gate.
 * @prop:               the proposal to validate
 * @signer_pk:          public key of the proposer
 * @proposer_reputation: the proposer's current reputation score
 * Returns true only if the signature is valid AND reputation meets the
 * threshold embedded in the proposal (prop->min_proposer_reputation).
 */
bool fleet_should_accept_proposal(const update_proposal_t *prop,
                                  const uint8_t *signer_pk,
                                  double proposer_reputation);

int fleet_run(process_t *proc, directory_t *queues, queue_id_t signal, logger_t *logger);

#endif /* FLEET_PROC_H */
