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

#ifndef HISTORY_H
#define HISTORY_H

/** @addtogroup internal_identity
 *  @{
 */

#include <stdbool.h>
#include <stddef.h>

#include "identity.h"
#include "peers.h"
#include "structures/dag.h"
#include "structures/merkle.h"
#include "algorithms/agreement.h"
#include "utilities/logger.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    merkle_blob_t base;             /* must be first for casting */
    public_identity_t *identity;
    char originator_uuid[MERKLE_UUID_LEN];
} identity_obj_t;

/*@
  requires identity != \null && \valid(identity);
  requires \valid(obj);
  allocates *obj;
  behavior success:
    ensures \result == 0;
    ensures *obj != \null;
  behavior null_args:
    assumes identity == \null || obj == \null;
    ensures \result == EINVAL;
  behavior oom:
    ensures \result == ENOMEM;
  disjoint behaviors null_args, success;
*/
int identity_obj_create(public_identity_t *identity, const char *originator_uuid,
                        identity_obj_t **obj);

/*@
  requires obj != \null && \valid(obj);
  requires \valid(out);
  requires \valid(out_len);
  allocates *out;
  behavior success:
    ensures \result == 0;
    ensures *out != \null && *out_len > 0;
  behavior failure:
    ensures \result != 0;
  disjoint behaviors;
*/
int identity_obj_designation(const identity_obj_t *obj, uint8_t **out, size_t *out_len);

/*@
  requires obj == \null || \valid(obj);
  frees obj;
*/
void identity_obj_free(identity_obj_t *obj);

typedef struct {
    step_dag_t dag;
    merkle_tree_t *merkle;
    agreement_protocol_t *agreement;
    peers_t *peers;
    logger_t *logger;
    int timeout;
    array_t *blacklist;
} identity_history_t;

/*@
  requires \valid(history);
  allocates *history;
  behavior success:
    ensures \result == 0;
    ensures *history != \null;
  behavior null_out:
    assumes history == \null;
    ensures \result == EINVAL;
  behavior failure:
    ensures \result != 0;
  disjoint behaviors null_out, success;
*/
int identity_history_create(agreement_voter_t *myself,
                            peers_t *peers,
                            logger_t *logger,
                            int timeout,
                            identity_history_t **history);

/*@
  requires history == \null || \valid(history);
  requires who == \null || \valid(who);
  behavior null_args:
    assumes history == \null || who == \null;
    ensures \result == EINVAL;
  behavior success:
    assumes history != \null && who != \null;
    ensures \result == 0 || \result != 0;
  disjoint behaviors;
*/
int identity_history_insert_peer(identity_history_t *history,
                                 public_identity_t *who);

/*@
  requires history == \null || \valid(history);
  requires item == \null || \valid(item);
  requires \valid(proof_out);
  requires \valid(proof_len);
  behavior null_args:
    assumes history == \null || item == \null;
    ensures \result == EINVAL;
  behavior success:
    assumes history != \null && item != \null;
    ensures \result == 0 ==> *proof_out != \null && *proof_len >= 0;
  disjoint behaviors;
*/
int identity_history_prove_existence(identity_history_t *history,
                                     merkle_blob_t *item,
                                     merkle_proof_step_t **proof_out,
                                     int *proof_len);

/*@
  requires history == \null || \valid(history);
  requires item == \null || \valid(item);
  requires proof_len >= 0;
  requires proof_len == 0 || \valid(proof + (0 .. proof_len - 1));
  behavior null_args:
    assumes history == \null || item == \null;
    ensures \result == \false;
  behavior valid_args:
    assumes history != \null && item != \null;
    ensures \result == \true || \result == \false;
  disjoint behaviors;
  complete behaviors;
*/
bool identity_history_verify_existence(identity_history_t *history,
                                       merkle_blob_t *item,
                                       merkle_proof_step_t *proof,
                                       int proof_len);

/**
 * @brief Serialize the main DAG branch to a signed JSON wire buffer.
 *
 * @param history  History instance.
 * @param signer   Full identity (with private key) used to sign the payload.
 * @param wire_out Output: caller must free() the returned buffer.
 * @param wire_len Output: length of the signed wire buffer.
 * @return 0 on success, error code on failure.
 */
/*@
  requires history == \null || \valid(history);
  requires signer == \null || \valid(signer);
  requires wire_out == \null || \valid(wire_out);
  requires wire_len == \null || \valid(wire_len);
  allocates *wire_out;
  behavior null_args:
    assumes history == \null || signer == \null ||
            wire_out == \null || wire_len == \null;
    ensures \result == EINVAL;
  behavior success:
    assumes history != \null && signer != \null &&
            wire_out != \null && wire_len != \null;
    ensures \result == 0 ==> *wire_out != \null && *wire_len > 0;
  behavior failure:
    assumes history != \null && signer != \null &&
            wire_out != \null && wire_len != \null;
    ensures \result != 0;
  disjoint behaviors null_args, success;
*/
int identity_history_share(identity_history_t *history,
                           const identity_t *signer,
                           uint8_t **wire_out, size_t *wire_len);

/**
 * @brief Verify and ingest a signed JSON history buffer from a peer.
 *
 * @param history  History instance.
 * @param sender   Public identity of the sender (used for signature verification).
 * @param wire     Signed wire buffer received from the peer.
 * @param wire_len Length of the wire buffer.
 * @return 0 on success, -1 on signature failure, or other error code.
 */
/*@
  requires history == \null || \valid(history);
  requires sender == \null || \valid(sender);
  requires wire == \null || \valid_read(wire + (0 .. wire_len - 1));
  behavior null_args:
    assumes history == \null || sender == \null ||
            wire == \null || wire_len == 0;
    ensures \result == EINVAL;
  behavior success:
    assumes history != \null && sender != \null &&
            wire != \null && wire_len > 0;
    ensures \result == 0 || \result != 0;
  disjoint behaviors;
*/
int identity_history_hear(identity_history_t *history,
                          const public_identity_t *sender,
                          const uint8_t *wire, size_t wire_len);

/*@
  requires history == \null || \valid(history);
  behavior null_history:
    assumes history == \null;
    assigns \nothing;
  behavior valid_history:
    assumes history != \null;
    frees history;
  disjoint behaviors;
  complete behaviors;
*/
void identity_history_free(identity_history_t *history);

int identity_history_by_authority_create(public_identity_t *myself,
                                         peers_t *peers,
                                         logger_t *logger,
                                         int timeout,
                                         int threshold_rank,
                                         identity_history_t **history);

int identity_history_by_stake_create(public_identity_t *myself,
                                     peers_t *peers,
                                     logger_t *logger,
                                     int timeout,
                                     double (*get_stake)(agreement_voter_t *),
                                     identity_history_t **history);

int identity_history_by_work_create(public_identity_t *myself,
                                    peers_t *peers,
                                    logger_t *logger,
                                    int timeout,
                                    int difficulty,
                                    identity_history_t **history);

/* Blacklist entry — minimal {uuid, address} record. Either field may be
 * zeroed to mean "match anything"; at least one must be set. Stored in
 * history->blacklist as data-wrapped pointers; freed with the history. */
typedef struct {
    uuid_t uuid;
    bool   uuid_set;
    char   address[ADDR_LEN + 1];
} identity_blacklist_entry_t;

/** Add an entry to the history's blacklist. Either @p uuid or @p address
 *  may be NULL/zero to leave that field unmatched; at least one must be
 *  set. Mirrors the per-entry attributes Python checks in
 *  poa.py:38-41 and pos.py:36-39. */
int identity_history_blacklist_add(identity_history_t *history,
                                   const uuid_t uuid,
                                   const char *address);

/** Return true iff a blacklist entry matches by uuid or address.
 *  Consulted by identity_history_prove() to short-circuit proof
 *  generation; callers verifying inbound traffic may use it directly. */
bool identity_history_is_blacklisted(const identity_history_t *history,
                                     const uuid_t uuid,
                                     const char *address);

/** Identity-aware wrapper around agreement_prove(). Returns EACCES
 *  (without allocating *proof_out) if the blob's wrapped identity is
 *  blacklisted by uuid or address; otherwise delegates to
 *  agreement_prove. Mirrors the Python PoA/PoS prove() overrides
 *  (poa.py:37-42, pos.py:35-40) which return None for blacklisted
 *  blobs. PoW uses the same wrapper for consistency even though Python
 *  PoW inherits the no-op base prove(). */
int identity_history_prove(identity_history_t *history,
                           merkle_blob_t *blob,
                           agreement_proof_t **proof_out);

/** Structural + signature verification on an identity blob before its
 *  vote is counted. Mirrors Python's IdentityHistory.verify_object
 *  (history.py:170-213): rejects bad blob shape, missing identity
 *  fields, unknown voters, and bad signatures. The agreement layer's
 *  pre_verify hooks remain protocol-generic; this check sits on top.
 *  Use identity_history_verify() to combine both checks.
 *
 *  @p sig / @p sig_len may be (NULL, 0) to skip the signature step (the
 *  Python equivalent of `sig is None`). */
bool identity_history_verify_object(identity_history_t *history,
                                    merkle_blob_t *blob,
                                    agreement_proof_t *proof,
                                    const uint8_t *sig, size_t sig_len);

/** Identity-aware wrapper around agreement_verify(). Returns false if
 *  identity_history_verify_object() rejects the blob; otherwise
 *  delegates to agreement_verify. */
bool identity_history_verify(identity_history_t *history,
                             merkle_blob_t *blob,
                             agreement_proof_t *proof,
                             const uint8_t *sig, size_t sig_len);

/** Serialize a single DAG step (uuid + ISO timestamp + hex'd payload)
 *  to a fresh JSON object. Caller owns the returned ref and must
 *  json_decref. Returns NULL on allocation failure or NULL @p step. */
json_t *linked_step_to_json(const linked_step_t *step);

/** Inverse of @ref linked_step_to_json — allocate a fresh
 *  @ref linked_step_t and populate it. The payload, if present, is
 *  unhex'd into a freshly-malloc'd MERKLE_DIGEST_LEN buffer owned by
 *  the step. Returns 0 on success. */
int linked_step_from_json(const json_t *obj, linked_step_t **step_out);

#ifdef __cplusplus
} // extern "C"
#endif


/** @} */ /* end of internal_identity */

#endif  // HISTORY_H
