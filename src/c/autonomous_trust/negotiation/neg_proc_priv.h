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
#ifndef NEG_PROC_PRIV_H
#define NEG_PROC_PRIV_H

#include <stdbool.h>
#include <uuid/uuid.h>

#include "processes/processes.h"

/*@
  requires \valid(proc);
  requires \valid_read(signal);
  requires logger == \null || \valid(logger);
  assigns *proc;
*/
int negotiation_run(process_t *proc, directory_t *queues, queue_id_t signal, logger_t *logger);

/** Register the negotiation protocol's message handlers on @p proc.
 *
 *  Exposed so the conformance harness can drive handler dispatch
 *  without going through negotiation_run's full process_run loop.
 *  negotiation_run still calls this internally on entry. */
int negotiation_register_handlers(process_t *proc);

/** Set the per-process own-capability allowlist for handle_invite.
 *
 *  Production code resolves capability ownership by walking the static
 *  capability_table populated at compile time via DEFINE_CAPABILITY —
 *  process-wide and identical for every process_t alive in the same
 *  binary. The conformance harness needs per-participant differentiation
 *  ("bob has data_fetch, alice does not"), so this hook lets a test
 *  install a per-process override list keyed by @p proc.
 *
 *  Pass @p cap_names = NULL or @p n_caps = 0 to clear the override and
 *  fall back to the static table. Production code MUST NOT call this. */
void negotiation_set_own_capabilities(const process_t *proc,
                                      const char *const *cap_names,
                                      size_t n_caps);

/** Set the reputation-derived trust tier for a specific peer as seen
 *  by @p proc.
 *
 *  Production code reads peer trust tiers via identity_get_peer_tier
 *  from the reputation-driven map populated by handle_tier_update;
 *  the harness can't easily wire that without going through paxos,
 *  so this hook installs an override keyed by (proc, peer_uuid).
 *  handle_invite consults this before falling back to
 *  identity_get_peer_tier, then to 0 if neither is populated. */
void negotiation_set_peer_tier(const process_t *proc,
                               const uuid_t peer_uuid,
                               int tier);

/** Set the required_tier on a named capability as seen by @p proc.
 *
 *  Production code reads required_tier from the Capability registered
 *  via find_capability(name). Conformance scenarios that exercise the
 *  trust-tier gate need to vary required_tier per scenario without
 *  modifying the static capability_table — this hook installs an
 *  override keyed by (proc, cap_name). handle_invite consults this
 *  before falling back to find_capability(name)->required_tier, then
 *  to 0 if neither is populated. */
void negotiation_set_capability_required_tier(const process_t *proc,
                                              const char *cap_name,
                                              int required_tier);

/** Reset all conformance-only per-process overrides for @p proc.
 *  Idempotent. The harness calls this between scenarios. */
void negotiation_clear_test_state(const process_t *proc);

/** Wipe the entire negotiation singleton state (task_stack,
 *  proposed_tasks, my_tasks, confirmed, status_pending, and all
 *  conformance-only override maps) and re-init each container.
 *  Conformance-only. The harness calls this at the start of every
 *  scenario so negative observables (`task_in_stack: false`,
 *  `has_my_task: false` for a slug-derived uuid, etc.) are not
 *  polluted by prior scenarios run in alphabetical order. */
void negotiation_reset_state(void);

/** Read the current size of the shared task_stack for
 *  `task_in_stack` expected_state assertions. Returns -1 if neg_state
 *  is uninitialized. Mirrors the Python adapter's check on
 *  `process.task_stack._heap` non-emptiness. */
int negotiation_get_task_stack_size(void);

/** Returns true iff the shared `confirmed` map has at least one
 *  entry, for the `confirmed` expected_state assertion. Mirrors the
 *  Python adapter's `if not self.process.confirmed` check. */
bool negotiation_has_confirmed_any(void);

/** Returns true iff the shared `my_tasks` map has an entry keyed by
 *  the given uuid (its string form, as the production code stores).
 *  For the `has_my_task: <slug>` expected_state assertion in the
 *  conformance corpus — the adapter derives the uuid from the slug
 *  using the same uuid5 namespace+format Python's adapter uses, so
 *  the two adapters compare against bit-equal keys. */
bool negotiation_has_my_task_uuid(const uuid_t uuid);

/** Read the per-task flood counter the negotiation handler updates on
 *  every observed invite (see `handle_invite` flood-detection block).
 *  Stored on the shared `proposed_tasks` map keyed by
 *  "flood:<task-uuid>" — Python's equivalent is
 *  `proposed_tasks[uuid].count`. Returns 0 if the task has no flood
 *  record yet (i.e., the handler has not been called with this
 *  task uuid), or if neg_state is uninitialized. For the
 *  `flood_count: {task:<slug>, count:<int>}` expected_state
 *  assertion exercised by the flood-probe scenario. */
int negotiation_get_task_flood_count(const uuid_t uuid);

#define ENEG_NOPEERS 243
DECLARE_ERROR(ENEG_NOPEERS, "No capable peers available");

#endif  /* NEG_PROC_PRIV_H */
