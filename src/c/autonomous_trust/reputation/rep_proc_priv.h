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
 ********************/
#ifndef REP_PROC_PRIV_H
#define REP_PROC_PRIV_H

#include <stdbool.h>
#include <stdint.h>
#include <uuid/uuid.h>

#include "processes/processes.h"

/*@
  requires \valid(proc);
  requires \valid_read(signal);
  requires logger == \null || \valid(logger);
  assigns *proc;
*/
int reputation_run(process_t *proc, directory_t *queues, queue_id_t signal, logger_t *logger);

/** Register the reputation protocol's message handlers on @p proc.
 *  Exposed so the conformance harness can drive handler dispatch
 *  without going through reputation_run's full process_run loop.
 *  reputation_run still calls this internally on entry. */
int reputation_register_handlers(process_t *proc);

/** Toggle synchronous-dispatch mode for the conformance harness.
 *  When enabled, handle_nack emits a retry "ask permission" inline to
 *  broadcast (Python parity — Python's _try_again thread is inlined
 *  under sync dispatch). Production must leave this off. */
void reputation_set_synchronous_dispatch(bool enabled);

/** Reset the file-scope rep_state to a clean baseline (paxos
 *  reinitialized for @p num_peers, history/reputations cleared,
 *  my_requests cleared, requested_reps cleared, sync_dispatch left
 *  unchanged). The harness calls this between scenario steps so each
 *  participant's handler runs against its own pre-installed state.
 *  Idempotent. */
void reputation_reset_state(int num_peers);

/** Pre-install the dispatching participant's chain length so
 *  handle_request's id2 == chain_len + 1 check is gated as if the
 *  participant had committed @p len entries. */
void reputation_set_chain_len(int len);

/** Pre-install the dispatching participant's paxos last_id so
 *  handle_request's id1 > last_id check rejects stale ballots. */
void reputation_set_last_id(int64_t id);

/** Pre-set the catch-up quorum (rep_state.num_updates). Conformance
 *  scenarios lower it to 1 so a single `latest update` step triggers the
 *  chain merge — the harness resets state per step, so the production
 *  default of 3 could never accumulate across steps. */
void reputation_set_num_updates(int n);

/** Pre-install an outstanding paxos round on the dispatching
 *  participant. handle_grant looks the entry up by @p proposer_uuid.
 *  @p task_uuid carries through into the broadcast tx payload on
 *  majority. */
void reputation_install_my_request(int64_t id1, int64_t id2,
                                   const uuid_t proposer_uuid,
                                   double score,
                                   const uuid_t task_uuid);

/** Pre-install an accepted (granted) round on the dispatching
 *  participant — i.e., add @p id1 to paxos.granted_ids so
 *  paxos_has_granted_id(id2)... actually paxos_has_granted_id checks
 *  the LAST id1 against id2; see paxos_record_grant. The harness uses
 *  this to satisfy handle_transaction's "did we grant this round?"
 *  check. */
void reputation_install_accepted(int64_t id1, int64_t id2);

/** Read the current chain length (committed history entries) for
 *  expected_state assertions. Returns -1 if state is uninitialized.
 *  NOTE: this returns rep_state.paxos.chain_len (the ballot-gating
 *  counter set by the history_len fixture), NOT the live tx_history. For
 *  the count of transactions actually resident in rep_state.history (e.g.
 *  after a catch-up replay), use reputation_get_committed_tx_count. */
int reputation_get_chain_len(void);

/** Read the number of committed transactions resident in
 *  rep_state.history (the hash-linked chain) for the `committed_tx_count`
 *  expected_state assertion. Mirrors Python's len(self.process.history).
 *  Returns -1 if state is uninitialized. */
int reputation_get_committed_tx_count(void);

/** Write the RFC 6962 ordered Merkle root over the resident committed window
 *  (transaction_window_root) into `out` (must hold TX_HASH_HEX_LEN + 1 bytes)
 *  for the `window_root` expected_state assertion. Mirrors Python
 *  TransactionHistory.window_root. Empty / invalid state yields an empty
 *  string. */
void reputation_get_window_root(char *out);

/** Write the latest finalized checkpoint root (handle_checkpoint_final) into
 *  `out` (TX_HASH_HEX_LEN + 1 bytes) for the `checkpoint_root` expected_state
 *  assertion. Empty string if no checkpoint has been stored. Mirrors Python
 *  ReputationProcess._checkpoint.root. */
void reputation_get_checkpoint_root(char *out);

/** Pre-seed a finalized checkpoint (root hex + epoch) for the `checkpoint`
 *  fixture, so an evidence-bearing slash can be verified against it within a
 *  single conformance step. Mirrors setting Python's
 *  ReputationProcess._checkpoint. */
void reputation_install_checkpoint(const char *root, int64_t epoch);

/** Read the count of granted Paxos rounds for the
 *  `requests_count` expected_state assertion. */
int reputation_get_request_count(void);

/** Read the current Paxos `last_id` for the `last_id_set`
 *  expected_state assertion. Returns 0 if state is uninitialized OR
 *  if last_id has never been advanced — Python's `self.last_id is
 *  not None` maps to `> 0` here (paxos_handle_request only ever
 *  sets last_id to id1, which scenarios pin > 0). */
int64_t reputation_get_last_id(void);

/** Pre-install a transaction_weight in rep_state.task_weights for
 *  @p task_uuid. The conformance harness calls this so scenarios can
 *  pin per-task weights without driving the full
 *  Capability-registration → handle_grant → handle_transaction wire
 *  flow. Production code MUST NOT call this. Mirrors the existing
 *  install_my_request / install_accepted test hooks. */
void reputation_install_task_weight(const uuid_t task_uuid, int weight);

/** Pre-install a bilateral Transaction (@p task_uuid) in
 *  rep_state.history: p1_uuid scored at @p p1_score, p2_uuid at
 *  @p p2_score. Drives `tx_history_update` twice under the same task
 *  so both `_peer_mapping` entries get populated, matching how
 *  handle_committed builds bilateral history. Conformance hook only. */
void reputation_install_tx_pair(const uuid_t task_uuid,
                                const uuid_t p1_uuid, double p1_score,
                                const uuid_t p2_uuid, double p2_score);

/** Pre-install a peer's reputation in rep_state.reputations.
 *  Conformance scenarios use this to set the counterparty's reputation
 *  (consumed by reputation_pure) and the subject peer's `previous`
 *  reputation (consumed by _compute_reputation's coop-mode latch). */
void reputation_install_peer_reputation(const uuid_t peer_uuid, double score);

/** Pre-install the coop-mode latch entry for @p peer_uuid. When @p
 *  in_coop is true, the next compute uses COOP_EXIT (0.45) as the
 *  pure-vs-CTFT gate; when false, COOP_ENTER (0.55). Mirrors Python's
 *  self._coop_mode dict (keyed by peer uuid). */
void reputation_install_coop_mode(const uuid_t peer_uuid, bool in_coop);

/** Read a peer's reputation from rep_state.reputations for
 *  expected_state assertions. Returns 0 on success (writing to @p out),
 *  -1 if uninitialized or @p peer_uuid is absent. */
int reputation_get_peer_reputation(const uuid_t peer_uuid, double *out);

#define EREP_PAXOS 253
DECLARE_ERROR(EREP_PAXOS, "Paxos consensus error");

#endif  /* REP_PROC_PRIV_H */
