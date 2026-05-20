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

#ifndef ID_PROC_PRIV_H
#define ID_PROC_PRIV_H

#include <stdbool.h>

#include "processes/processes.h"

/*@
  requires \valid(proc);
  requires \valid_read(signal);
  requires logger == \null || \valid(logger);
  assigns *proc;
*/
int identity_run(process_t *proc, directory_t *queues, queue_id_t signal, logger_t *logger);

/** Register the identity protocol's message handlers on @p proc.
 *
 *  Exposed so the conformance harness (and other test rigs) can drive
 *  handler dispatch without going through the full identity_run process
 *  loop, which daemonizes and assumes a real messaging socket. The full
 *  identity_run path also calls this helper internally. */
int identity_register_handlers(process_t *proc);

/* Vote-collection critical section, exposed for concurrency regression tests.
 * Both helpers are thread-safe; they internally acquire id_state.lock.
 *
 * vote_collection_increment: read-or-insert, increment, write back.  Returns
 * the post-increment count.
 *
 * vote_collection_get: read-only lookup.  Returns 0 and writes the count on
 * hit, -1 on miss or bad arguments. */
int vote_collection_increment(const char *uuid_key);
int vote_collection_get(const char *uuid_key, int *out_count);

/** Install a per-process own-capability allowlist for the conformance
 *  harness. `cap_names` is an array of `n_caps` C-string capability
 *  names (e.g. "sensor_validation"). The list is dup'd and owned by
 *  the identity state; pass cap_names=NULL or n_caps=0 to clear.
 *
 *  Production code MUST NOT call this — capabilities normally flow in
 *  through the autonomous_ability fan-put. Mirrors
 *  `negotiation_set_own_capabilities` in neg_proc_priv.h.
 *
 *  Consumed by handle_caps_query, which emits the list as a JSON array
 *  in the caps_response payload (BUGS.md note 2026-05-12: was a stub;
 *  now reads the test-installed list verbatim). */
void identity_set_own_capabilities(const process_t *proc,
                                   const char *const *cap_names,
                                   size_t n_caps);

/** Return the number of capabilities recorded for @p uuid in the
 *  shared peer_capabilities map, or 0 if no entry exists. The map is
 *  populated by handle_caps_response on inbound `peer_caps_response`
 *  messages; conformance scenarios assert against this via the
 *  `peer_caps_count` expected_state key. */
int identity_get_peer_caps_count(const uuid_t uuid);

/** Return the reputation-derived rank tier last published for @p uuid via
 *  the ID_RANK local-IPC handler (handle_rank_update). Returns 0 if no
 *  entry exists. The map is populated by ReputationProcess crossing a
 *  RANK_TIERS boundary. Mirrors Python's per-peer `peer._rank` field
 *  consulted by AgreementByAuthority voter weighting (BUGS.md §P2). */
int identity_get_peer_rank(const uuid_t uuid);

/** Return the rank last applied to the local identity via ID_RANK. */
int identity_get_self_rank(void);

/** Read the current partition-recovery target group uuid (string) into
 *  @p out. Returns the number of bytes written (excluding the trailing
 *  NUL), or 0 if no recovery is in flight. Test-only accessor for the
 *  conformance harness and the C unit test. See
 *  doc/architecture/partition-recovery.md. */
size_t identity_get_partition_recovery_target(char *out, size_t out_len);

/** Build the canonical signature input for a partition_probe payload.
 *  Mirrors Python's `IdentityProcess._partition_probe_canonical`:
 *  `"%s|%d"` of (group_uuid, group_size). Returns bytes written
 *  (excluding the NUL), -1 on buffer overflow. Exposed for the test
 *  suite to verify byte-for-byte interop with Python. */
int identity_partition_canonical_probe(const char *group_uuid,
                                       int group_size,
                                       char *out, size_t out_len);

/** As @ref identity_partition_canonical_probe but for partition_response:
 *  `"%s|%d|%s"` of (group_uuid, group_size, in_response_to). */
int identity_partition_canonical_response(const char *group_uuid,
                                          int group_size,
                                          const char *in_response_to,
                                          char *out, size_t out_len);

/** Toggle synchronous-dispatch mode for the conformance harness.
 *
 *  When @p enabled is true, handle_welcoming_committee runs the propose +
 *  self-vote + finalize cascade inline instead of waiting for inbound vote
 *  messages, and propose_peer / peer_accepted emit as a single broadcast
 *  (to_whom zeroed) so a bg-only scenario still produces one outbound for
 *  each. Mirrors Python's `IdentityProcess.synchronous_dispatch` class
 *  flag. Must be called after the first identity_run invocation (or any
 *  call that goes through the file-scope state init), as it consults the
 *  same id_state struct. Production code MUST leave this off. */
void identity_set_synchronous_dispatch(bool enabled);

/** Wipe the entire identity singleton state (histories, peer_potentials,
 *  vote_collection, peer_caps_map, and conformance-only override maps),
 *  resetting choosing_group to false. Preserves synchronous_dispatch so
 *  callers can set it once at adapter init. The harness calls this at
 *  the start of every scenario; production must not call it. */
void identity_reset_state(void);

#define EID_NOQ 215
DECLARE_ERROR(EID_NOQ, "Required process queue missing");

#endif  // ID_PROC_PRIV_H
