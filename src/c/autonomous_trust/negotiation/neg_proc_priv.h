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

/** Score a returned task result the way the requestor-side path does, and
 *  name the evidence channel it came from (R+D.md §12.7 / §12.8).
 *
 *  @p cap_name and @p kwargs_json are what the REQUESTOR asked for -- in
 *  production, the record `handle_results` reads off the task tracker, never
 *  anything the responder sent back. A known-answer capability is checked
 *  against its expected value (0.9 correct / 0.5 forgivable clock drift / 0.1
 *  wrong) and reports the `probe` channel; anything else is scored on
 *  completion (0.8 with a result, 0.3 without) and reports `task_outcome`.
 *
 *  Between those two, physical consistency (R+D.md §12.2): a claim that is
 *  impossible, or that no consistent story leaves honest, reports `physical`
 *  (0.1); a peer implicated by a conflict that does not name it uniquely
 *  reports `swarm_disagreement` (0.3). The layer speaks only to refute, so a
 *  claim it has nothing to say about falls through to the completion arm.
 *  @p subject is the peer the observation is filed under -- NULL for a fan-out,
 *  which runs only the checks needing no identity -- and @p now is monotonic
 *  seconds, a parameter rather than a clock read so a replay produces the
 *  verdicts the live path did.
 *
 *  Then the coverage audit (R+D.md §12.4): @p prediction_json is the peer's
 *  attached prediction set and claimed coverage, judged against the record of
 *  its OWN previously resolved predictions — `calibration` at 0.1 for a
 *  coverage claim the exact test rejects, 0.3 for a capability declared
 *  predictive that produced no usable set. Falsification only; a peer that has
 *  not been caught over-claiming earns nothing here.
 *
 *  Then certificate-carrying interfaces (R+D.md §12.3): @p certificate_json is
 *  the witness the peer attached, checked against the problem in
 *  @p kwargs_json -- OUR record, never the peer's account of it -- to give
 *  `certificate` at 0.9 (proved right), 0.1 (proved wrong) or 0.3 (declared to
 *  certify and did not). @p seed is this verifier's challenge for the one
 *  probabilistic checker and must not be derivable from the problem; see
 *  certificates/rng.h.
 *
 *  Exported so tests and the conformance adapter exercise the same function
 *  production does. @p channel_out may be NULL. */
double negotiation_score_task_result(const char *cap_name,
                                     const char *kwargs_json,
                                     const char *result_str, size_t result_len,
                                     const char *certificate_json,
                                     const char *prediction_json,
                                     const char *subject, double now,
                                     uint64_t seed,
                                     const char **channel_out);

/** The learned EMA weight multiplier for @p subject on @p cap_name
 *  (R+D.md §12.5), NOT a score.
 *
 *  Prequential competence is deliberately not one of the arms of
 *  ::negotiation_score_task_result: a peer whose forecasts are wide or wrong
 *  has told no lie, so it earns no evidence channel and no score. What it
 *  produces is a multiplier on how much this score weighs in the EMA,
 *  composed with the capability's authored `transaction_weight` and §12.8's
 *  channel weight in the reputation process.
 *
 *  Confined to the declared band around 1.0, and exactly
 *  ::AT_PREQ_NEUTRAL_COMPETENCE (1.0, the authored weight verbatim) with the
 *  layer off, the capability undeclared, @p subject unknown or NULL, or the
 *  peer's record shorter than `min_samples`. @p subject is a peer uuid string,
 *  the same key ::negotiation_score_task_result files observations under.
 *
 *  Exported for the same reason the scorer is: tests and the conformance
 *  adapter must exercise the function production uses.
 *  See doc/architecture/prequential-competence.md. */
double negotiation_competence_weight(const char *cap_name,
                                     const char *subject);

/** Python type tags carried by every negotiation payload (doc/architecture/negotiation.md).
 *
 *  Shared constants rather than language artifacts -- the same argument that
 *  keeps the wire protocol strings byte-identical to Python's enum values.
 *  Declared here, not inside neg_proc.c, so the conformance adapter builds its
 *  inbound payloads from the SAME tags the serializer emits: a mirrored copy is
 *  a copy that can drift, and a drifted adapter is exactly how the two
 *  runtimes' payload shapes stayed divergent through a green corpus.
 *  @{ */
#define PY_NEG_MOD          "autonomous_trust.core._python.negotiation.negotiation."
#define PY_TYPE_TASK        PY_NEG_MOD "Task"
#define PY_TYPE_TASK_STATUS PY_NEG_MOD "TaskStatus"
#define PY_TYPE_TASK_RESULT PY_NEG_MOD "TaskResult"
#define PY_TYPE_TASK_PARAMS PY_NEG_MOD "TaskParameters"
#define PY_TYPE_CAPABILITY  "autonomous_trust.core._python.capabilities.Capability"
#define PY_ENUM_STATUS      "Enumcfg:" PY_NEG_MOD "Status"
/** @} */

/** @brief Parse a negotiation payload and re-emit it, for the corpus's
 *         byte-pinned payload-shape vectors.
 *
 *  Negotiation payloads are Python's `__type__`-tagged Configuration dump,
 *  except `requestor`, which is the flat DRY canonical PUBLIC identity
 *  (doc/architecture/negotiation.md). The corpus pins that shape by round-tripping ONE fixture
 *  through both runtimes: parse the pinned bytes, re-emit, compare. Neither
 *  side can then drift without failing, which is exactly what the
 *  envelope-only pinning allowed for months.
 *
 *  @param verb      NEG_PROTO_RESULT for a TaskResult, NEG_PROTO_STAT_RSP for
 *                   a TaskStatus, anything else for a Task.
 *  @param in_json   The payload to parse.
 *  @param requestor Identity the re-emitted `requestor` field is built from;
 *                   production resolves it from the peer table instead.
 *  @param out_json  Receives a compact, key-sorted dump. Caller frees.
 *  @return 0, or EINVAL / ENOMEM.
 */
int negotiation_payload_roundtrip(const char *verb, const char *in_json,
                                  const public_identity_t *requestor,
                                  char **out_json);

#define ENEG_NOPEERS 243
DECLARE_ERROR(ENEG_NOPEERS, "No capable peers available");

#endif  /* NEG_PROC_PRIV_H */
