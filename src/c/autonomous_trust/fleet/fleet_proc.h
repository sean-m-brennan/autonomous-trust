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

#ifndef FLEET_PROC_H
#define FLEET_PROC_H

/** @addtogroup internal_fleet
 *  @{
 */

#include <stdbool.h>
#include <stdint.h>

#include "autonomous_trust/processes/processes.h"
#include "autonomous_trust/fleet/update_proposal.h"

/* Writable char arrays — definitions in `fleet_proc.c`. Avoids the
 * `(char *)` const-cast at every assignment to `net_msg.function`
 * under `-Wwrite-strings`. */
extern char FLEET_PROTO_PROPOSE[];
extern char FLEET_PROTO_VOTE_REQ[];
extern char FLEET_PROTO_VOTE_GRANT[];
extern char FLEET_PROTO_VOTE_NACK[];
extern char FLEET_PROTO_ACCEPTED[];
extern char FLEET_PROTO_REJECTED[];

#define FLEET_DEFAULT_MIN_REPUTATION 0.7

/**
 * fleet_validate_proposal - verify the proposal signature.
 * @prop:      the proposal to verify
 * @signer_pk: public key of the expected signer (crypto_sign_PUBLICKEYBYTES)
 * Returns true if the signature is valid, false otherwise.
 */
/*@
  requires \valid(prop);
  requires \valid_read(signer_pk + (0 .. crypto_sign_PUBLICKEYBYTES - 1));
  assigns \nothing;
  ensures \result == \true || \result == \false;
*/
bool fleet_validate_proposal(const update_proposal_t *prop, const uint8_t *signer_pk);

/**
 * fleet_check_reputation_threshold - test whether a peer meets the minimum
 * reputation requirement.
 * @peer_reputation: the peer's current reputation score
 * @min_threshold:   the minimum required reputation
 * Returns true if peer_reputation >= min_threshold.
 */
/*@
  assigns \nothing;
  ensures \result == (peer_reputation >= min_threshold);
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
/*@
  requires \valid(prop);
  requires \valid_read(signer_pk + (0 .. crypto_sign_PUBLICKEYBYTES - 1));
  assigns \nothing;
  ensures \result == \true || \result == \false;
*/
bool fleet_should_accept_proposal(const update_proposal_t *prop,
                                  const uint8_t *signer_pk,
                                  double proposer_reputation);

/**
 * fleet_store_artifact - read a file, hash it, and store it in the
 * artifact store as chunks.
 *
 * @file_path:  path to the file to store
 * @version:    version string to attach to the manifest
 * @logger:     logger for diagnostics (may be NULL)
 * @hash_out:   receives the raw blake2b-256 hash (UPDATE_HASH_LEN bytes)
 * @hash_hex_out: receives the hex-encoded hash string (must be at least
 *                UPDATE_HASH_LEN*2+1 bytes)
 *
 * Returns 0 on success, -1 on error.
 */
/*@
  requires file_path != \null && \valid_read(file_path);
  requires version != \null && \valid_read(version);
  requires \valid(hash_out + (0 .. UPDATE_HASH_LEN - 1));
  requires \valid(hash_hex_out + (0 .. UPDATE_HASH_LEN * 2));
  assigns hash_out[0 .. UPDATE_HASH_LEN - 1],
          hash_hex_out[0 .. UPDATE_HASH_LEN * 2];
  ensures \result == 0 || \result == -1;
*/
int fleet_store_artifact(const char *file_path, const char *version,
                         logger_t *logger,
                         uint8_t *hash_out, char *hash_hex_out);

/**
 * fleet_propose_update - build, sign, and submit an update proposal to
 * the local fleet process via IPC.
 *
 * @artifact_hash:  raw blake2b-256 hash of the artifact (UPDATE_HASH_LEN)
 * @version:        version string
 * @target_arch:    target architecture (e.g. "amd64", "arm64")
 * @signing_pk:     proposer's public key (crypto_sign_PUBLICKEYBYTES)
 * @signing_sk:     proposer's secret key (crypto_sign_SECRETKEYBYTES)
 * @logger:         logger for diagnostics (may be NULL)
 *
 * Returns 0 on success, -1 on error.
 */
/*@
  requires \valid_read(artifact_hash + (0 .. UPDATE_HASH_LEN - 1));
  requires version != \null && \valid_read(version);
  requires target_arch != \null && \valid_read(target_arch);
  requires \valid_read(signing_pk + (0 .. crypto_sign_PUBLICKEYBYTES - 1));
  requires \valid_read(signing_sk + (0 .. crypto_sign_SECRETKEYBYTES - 1));
  assigns \nothing;
  ensures \result == 0 || \result == -1;
*/
int fleet_propose_update(const uint8_t *artifact_hash, const char *version,
                         const char *target_arch,
                         const uint8_t *signing_pk, const uint8_t *signing_sk,
                         logger_t *logger);

/*@
  requires \valid(proc);
  requires \valid_read(signal);
  requires logger == \null || \valid(logger);
  assigns *proc;
*/
int fleet_run(process_t *proc, directory_t *queues, queue_id_t signal, logger_t *logger);


/** @} */ /* end of internal_fleet */

#endif /* FLEET_PROC_H */
