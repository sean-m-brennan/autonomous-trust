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
 *  expected_state assertions. Returns -1 if state is uninitialized. */
int reputation_get_chain_len(void);

/** Read the count of granted Paxos rounds for the
 *  `requests_count` expected_state assertion. */
int reputation_get_request_count(void);

#define EREP_PAXOS 253
DECLARE_ERROR(EREP_PAXOS, "Paxos consensus error");

#endif  /* REP_PROC_PRIV_H */
