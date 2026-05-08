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

/** Set the peer-level for a specific peer as seen by @p proc.
 *
 *  Production code derives peer levels from the richer `peers_t`
 *  hierarchy that lives in configuration; the harness can't easily
 *  populate that on a stripped-down test process_t. Instead, store an
 *  override level keyed by (proc, peer_uuid). handle_invite consults
 *  this before falling back to "level unknown" (which preserves the
 *  pre-test acceptance behavior). */
void negotiation_set_peer_level(const process_t *proc,
                                const uuid_t peer_uuid,
                                int level);

/** Reset all conformance-only per-process overrides for @p proc.
 *  Idempotent. The harness calls this between scenarios. */
void negotiation_clear_test_state(const process_t *proc);

#define ENEG_NOPEERS 243
DECLARE_ERROR(ENEG_NOPEERS, "No capable peers available");

#endif  /* NEG_PROC_PRIV_H */
