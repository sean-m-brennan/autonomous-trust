/********************
 *  Copyright 2024 TekFive, Inc., Sean M. Brennan, and contributors
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
#include <jansson.h>

#include "processes/processes.h"
#include "identity/group.h"
#include "utilities/clock.h"    /* at_clock_sample_t (cohort clock skew) */

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

/** This node's own PUBLISHED identity (public-only, freshly serialized from
 *  the identity config). Exposed for the sibling translation units that need
 *  it -- identity/first_contact.c must check that an invitation presented to
 *  it was minted by US. Returns 0 on success. The caller frees any
 *  `operator_key_binding` on the result. */
int identity_own_public_identity(const process_t *proc, public_identity_t *out);

/** No-vote, no-group-key admission of a DIRECT (1:1) peer: the seam the
 *  optional first-contact handshake admits through. Records the peer as a
 *  PROVISIONAL admission does -- peers[], the local activity broadcast, the
 *  app-facing peer_observed -- but never propagates the group key and never
 *  inserts into the identity history: a contact is not a group member.
 *  Idempotent on the UUID. Mirrors Python first_contact._admit_direct_peer. */
int identity_admit_direct_peer(process_t *proc, directory_t *queues,
                               const public_identity_t *who);

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

/** Set (or clear) THIS node's opt-in coarse position (Increment 2, the
 *  "with-distance" feature) in the singleton id_state. A valid non-empty
 *  geohash opts in; NULL/""/invalid opts out (the default). The harness analog
 *  of the app's set-position IPC verb; conformance installs it from
 *  `fixtures.positions`. */
void identity_set_own_geohash(const char *geohash);

/** Copy the coarse geohash recorded for peer @p uuid_str (lowercased uuid
 *  string) into @p buf, always NUL-terminated. Returns true iff a position is
 *  stored. The map is filled by handle_position_response; conformance asserts
 *  via the `peer_position` expected_state key. */
bool identity_get_peer_position(const char *uuid_str, char *buf, size_t buflen);

/** Copy the size-bounded capability descriptor recorded for @p cap_name (from
 *  the descriptor form of `peer_caps_response`) into @p buf as a JSON string
 *  ({required_tier, description, kind, arg_schema}; name excluded). Returns 0
 *  on success, -1 if no descriptor is stored for that name (or on bad args).
 *  Output is NUL-terminated and truncated to @p buflen. Conformance scenarios
 *  assert against this via the `peer_caps_descriptor` expected_state key. */
int identity_get_peer_cap_descriptor(const char *cap_name, char *buf, size_t buflen);

/** Number of peers @p proc is holding PROVISIONAL under two-phase admission
 * (doc/architecture/identity-protocol.md) — a confirm was seen but the distinct-confirmer quorum
 *  is not yet met, so the group key is withheld. Conformance scenarios assert
 *  against this via the `provisional_peer_count` expected_state key. */
size_t identity_provisional_count(const process_t *proc);

/** Test accessor: install @p n_caps capability names for @p uuid directly
 *  into the shared peer_caps_map, bypassing the caps_response wire path.
 *  Mirrors how handle_caps_response populates the map. Used by the
 *  late-joiner cap-resync unit test to set up cap-less vs cap-bearing
 *  peers. Strings are copied. */
void identity_install_peer_caps(const uuid_t uuid,
                                const char *const *caps, size_t n_caps);

/** Max directed caps_query emissions per resync sweep — bounds the burst
 *  a large degraded group can put on the network queue. */
#define CAPS_RESYNC_MAX_PER_SWEEP 16

/** Periodic backstop for the late-joiner capability-loss UDP case:
 *  re-send a directed caps_query to every admitted peer in
 *  @p proc->protocol.peers[] that has ZERO registered caps. Mirrors
 *  Python's IdentityProcess._periodic_caps_resync. Invoked from
 *  identity_run's main loop on an interval; exposed here so the unit
 *  test can drive it directly. Self-limiting and bounded
 *  (CAPS_RESYNC_MAX_PER_SWEEP). See memory feedback_late_joiner_caps. */
void identity_periodic_caps_resync(const process_t *proc);

/** Periodic backstop for the cold/late-joiner identity-loss case: a node
 *  that adopted a group via the merge/partition path holds the members'
 *  addresses (group.address_map) but not their full Identities (peers[]
 *  stays sparse), so consensus reputations can't be named. Broadcasts a
 *  peer_identity_query listing our group uuid + the uuids we already hold;
 *  matching members reply with their published identity, which we add to
 *  peers[]. Mirrors Python's IdentityProcess._periodic_identity_resync.
 *  Invoked from identity_run's main loop on the caps-resync interval;
 *  exposed for the unit test. See dod-coordinator-partition-nonconvergence.md. */
void identity_periodic_identity_resync(const process_t *proc);

/** Return the reputation-derived trust tier last published for @p uuid
 *  via the ID_TIER local-IPC handler (handle_tier_update). Returns 0 if
 *  no entry exists. The map is populated by ReputationProcess crossing
 *  a TIER_FLOORS boundary. Mirrors Python's per-peer `peer._tier`
 *  field consulted by negotiation's capability tier-gate. Distinct
 *  from topology rank (identity_t::rank); see
 * doc/architecture/trust-tiers.md §1. */
int identity_get_peer_tier(const uuid_t uuid);

/** Return the trust tier last applied to the local identity via ID_TIER. */
int identity_get_self_tier(void);

/** Read the current partition-recovery target group uuid (string) into
 *  @p out. Returns the number of bytes written (excluding the trailing
 *  NUL), or 0 if no recovery is in flight. Test-only accessor for the
 *  conformance harness and the C unit test. See
 * doc/architecture/partition-recovery.md. */
size_t identity_get_partition_recovery_target(char *out, size_t out_len);

/** Build the canonical signature input for a partition_probe payload.
 *  Mirrors Python's `IdentityProcess._partition_probe_canonical`:
 *  `"%s|%d|%lld"` of (group_uuid, group_size, seq). Returns bytes written
 *  (excluding the NUL), -1 on buffer overflow. Exposed for the test
 *  suite to verify byte-for-byte interop with Python.
 *
 *  `seq` is the prober's monotonic freshness sequence and is part of the
 *  SIGNED bytes: without it the pre-image covered only the group uuid and
 *  size, neither of which changes between rounds, so a captured probe was
 *  replayable indefinitely by anyone on the wire. */
int identity_partition_canonical_probe(const char *group_uuid,
                                       int group_size, int64_t seq,
                                       char *out, size_t out_len);

/** As @ref identity_partition_canonical_probe but for partition_response:
 *  `"%s|%d|%s|%lld|%lld"` of (group_uuid, group_size, in_response_to,
 *  probe_seq, seq). `probe_seq` echoes the probe round being answered —
 *  `in_response_to` is only the prober's uuid, which never changes, so it
 *  cannot distinguish an answer to the current round from one captured
 *  earlier. `seq` is the responder's own freshness sequence. */
int identity_partition_canonical_response(const char *group_uuid,
                                          int group_size,
                                          const char *in_response_to,
                                          int64_t probe_seq, int64_t seq,
                                          char *out, size_t out_len);

/** Messages this process refused as stale, for @p verb (NULL: every verb).
 *
 *  Reads the identity process's freshness state; see @ref freshness_refusals
 *  for what is and is not counted. Unlike the marks it reports, this is not
 *  security state — it is the evidence that a refusal happened, which is
 *  otherwise unobservable from outside: the per-sender cooldowns above these
 *  handlers suppress a second delivery on their own, so a scenario that only
 *  counts emissions cannot tell a working mark from a rate limiter.
 *
 *  Process-global, like the rest of `id_state` — every participant in a C
 *  conformance run shares it — so a case asserting it must arrange for exactly
 *  one participant to do the refusing. Same compromise as
 *  @ref identity_get_peer_caps_count. */
int64_t identity_freshness_refusals(const char *verb);

/** Test-only: clear the per-sender partition probe/response cooldown windows.
 *
 *  The cooldown and the freshness mark refuse an immediate re-probe for
 *  different reasons — the cooldown rate-limits a legitimate prober, the mark
 *  rejects a replayed round — and on a live node they overlap, with the
 *  cooldown firing first in wall-clock terms. A test that wants to observe the
 *  MARK has to take the cooldown out of the way, or it proves only that the
 *  rate limiter works. Python's twin does the same thing by clearing
 *  `_partition_response_cooldown` between deliveries.
 *
 *  Production code must never call this: it reopens exactly the window the
 *  cooldown exists to close. */
void identity_clear_partition_cooldowns(void);

/** Test-only: declare the freshness sequence of the probe round this node is
 *  to be treated as currently running (0 = none).
 *
 *  `handle_partition_response` refuses any response whose echoed round does
 *  not match this, so a test that delivers a response without having driven a
 *  real probe first must state the round the response answers. Mirrors setting
 *  `_probe_seq` directly in the Python twin. */
void identity_set_partition_probe_round(int64_t seq);

/** Test-only: clear the in-flight partition-recovery marker.
 *
 *  Adoption sets the marker and `handle_partition_response` returns early
 *  while it is set, so it would refuse a replay on its own. Clearing it
 *  between deliveries leaves the freshness mark as the only thing that can
 *  refuse — the same isolation the Python twin gets by assigning
 *  `_partition_recovery_in_progress = None`. Deliberately narrower than
 *  @ref identity_reset_state, which would also wipe the marks under test. */
void identity_clear_partition_recovery(void);

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

/** Set a participant's border-guard flag (doc/architecture/identity-protocol.md, Policy B).
 *  Per-process (mirrors Python's per-instance
 *  IdentityProcess.border_guard_mode), so it takes the target @p proc rather
 *  than touching the global id_state. Defaults true in
 *  identity_register_handlers; clear it to make @p proc abstain from voting on
 *  received proposals (border-guards-only quorum). */
void identity_set_border_guard_mode(process_t *proc, bool enabled);

/** Set a participant's two-phase admission quorum (doc/architecture/identity-protocol.md).
 *  Per-process (mirrors Python's per-instance
 *  IdentityProcess._admission_quorum). Default 1 = promote on the first
 *  confirm; higher values withhold the group key until that many DISTINCT
 *  border-guards have confirmed the admission. Values < 1 clamp to 1. */
void identity_set_admission_quorum(process_t *proc, int quorum);

/** Wipe the entire identity singleton state (histories, peer_potentials,
 *  vote_collection, peer_caps_map, and conformance-only override maps),
 *  resetting choosing_group to false. Preserves synchronous_dispatch so
 *  callers can set it once at adapter init. The harness calls this at
 *  the start of every scenario; production must not call it. */
void identity_reset_state(void);

/* ---- Subtree member-roster enumeration (requestor-side + opt-out) --------
 * The C twin of Python idprocess enumerate_local_members /
 * handle_roster_request / aggregate_subtree_roster. See
 * doc/architecture/gateway-reputation-tree.md. */

/** This node's own membership contribution (self + primary group + each
 *  gatewayed child group), as a NEW json array of {uuid,nickname,address}
 *  deduped and sorted by uuid. Caller owns (json_decref). Pure/local. */
json_t *identity_enumerate_local_members(const process_t *proc);

/** This node's roster-query answer as a NEW json object {members,
 *  child_gateways, private} (caller owns). Shared by handle_roster_request
 *  (wire) and the aggregation's fetch (tests / conformance). */
json_t *identity_roster_response(const process_t *proc);

/** Identity-protocol handler for a roster_req: replies with this node's local
 *  members + child gateways to recurse into, or an empty `private` marker when
 *  the node opted out. Registered internally; exposed for test rigs. */
bool handle_roster_request(const process_t *proc, directory_t *queues,
                           generic_msg_t *msg);

/** This node's attended-now answer as a NEW json object (caller owns): the
 *  admission-path attestation shape plus the echoed @p nonce and an
 *  always-present operator_attested_at (0 = nobody attending). Shared by
 *  handle_attest_request (wire) and tests / conformance.
 *  See doc/architecture/operator-attended.md.
 *
 *  @param received_at when this node took the pull in (the round trip's t2);
 *         emitted with the answer's own send time so the puller can measure our
 *         clock without charging our processing time to it. Pass 0 to omit --
 *         then no clock sample is possible from this exchange.
 *         See doc/architecture/cohort-clock-skew.md. */
json_t *identity_attest_response(const process_t *proc, const char *nonce,
                                 double received_at);

/** This node's clock as the attestation path sees it: the injected value when
 *  one is pinned (conformance needs determinism), else wall clock. Callers that
 *  build an answer outside the wire handler need it for @p received_at. */
double identity_attest_clock(const process_t *proc);

/** Newest cohort clock sample for @p uuid_str (lowercased uuid), or false when
 *  none has been measured. Measurement only -- see cohort-clock-skew.md.
 *  Assertion surface for tests / conformance; mirrors reading Python's
 *  IdentityProcess._peer_clock_samples. */
bool identity_get_peer_clock_sample(const char *uuid_str,
                                    at_clock_sample_t *out);

/** Identity-protocol handler for an attest_req: answers with a freshly stamped
 *  attestation. Refuses an un-nonced pull (an attestation bound to nothing is
 *  replayable). Registered internally; exposed for test rigs. */
bool handle_attest_request(const process_t *proc, directory_t *queues,
                           generic_msg_t *msg);

/** Identity-protocol handler for an attest_resp: records the peer's stamp only
 *  if the nonce is one we minted, the responder is the node we asked, the
 *  operator credential re-verifies against the operator anchor, and the stamp
 *  is inside the acceptance window. Otherwise records not-attended. */
bool handle_attest_response(process_t *proc, directory_t *queues,
                            generic_msg_t *msg);

/** Issue an attended-now pull to @p peer, minting the binding nonce (copied
 *  into @p out_nonce when non-NULL; needs >= 33 bytes). Returns 0 on success.
 *  C twin of Python IdentityProcess.handle_attest_trigger. */
int identity_request_attestation(process_t *proc, const public_identity_t *peer,
                                 char *out_nonce, size_t nonce_len);

/** True while @p nonce names a pull this node issued and has not resolved.
 *  The observable behind "was this answer bound to a request we made?"; an
 *  answer consumes its nonce, so a replay finds nothing outstanding.
 *  Conformance assertion surface (Python tests `nonce in _attest_sent`). */
bool identity_attest_pull_outstanding(const char *nonce);

/** Declare whether a human is at this node's console (and optionally the stamp
 *  to report; <= 0 stamps at answer time). C has no OperatorSession and no
 *  console app, so attendance is asserted through this seam rather than polled
 *  — the documented Python/C asymmetry in the state SOURCE. The verb shape and
 *  verification rules are identical in both languages. */
void identity_set_operator_attended(process_t *proc, bool attended,
                                    double attested_at);

/** Pin the clock used for attestation stamping and window checks (0 restores
 *  wall clock) so conformance can compare a deterministic value. */
void identity_set_attest_clock(process_t *proc, double epoch);

/** Per-gateway fetch for the requestor-side aggregation: returns a NEW
 *  response object {members, child_gateways, private} for @p gateway_uuid
 *  (the aggregator decrefs it), or NULL on failure. A network round-trip in
 *  production; an injected stub in tests / the conformance adapter. */
typedef json_t *(*roster_fetch_fn)(void *ctx, const char *gateway_uuid);

/** Requestor-side breadth-first flatten of a gateway's subtree. See the
 *  implementation comment for the out-parameter contract. Returns 0 on
 *  success, -1 on bad args. */
int identity_aggregate_subtree_roster(const char *top_uuid,
                                      roster_fetch_fn fetch, void *ctx,
                                      json_t **out_members, bool *out_complete,
                                      json_t **out_private);

/** Ask a cohort we are NOT in to admit us, so a gateway can acquire a child
 *  cohort at runtime rather than from a seeded key file
 * (doc/architecture/gateway-reputation-tree.md). The
 *  cohort decides: this only sends the ordinary request_access naming
 *  @p group_uuid and records that we solicited it. Returns 0 on success.
 *  C twin of Python IdentityProcess.request_cohort_join. */
int identity_request_cohort_join(process_t *proc, directory_t *queues,
                                 const char *group_uuid);

/** Whether a cohort join we solicited is still awaiting admission. Assertion
 *  surface for tests. */
bool identity_join_pending(const char *group_uuid);

/** Seed a child cohort this node gateways (C twin of Python child_groups
 *  seeding). @p gateway_uuid names the deeper gateway to recurse into for that
 *  child group (NULL for a 2-level gateway). Returns 0 on success. */
int identity_add_child_group(process_t *proc, group_t *group,
                             const char *gateway_uuid);

/** Set a participant's roster-privacy opt-out (AT config AT_ROSTER_PRIVATE).
 *  Per-process, mirrors Python IdentityProcess.roster_private. */
void identity_set_roster_private(process_t *proc, bool enabled);

/** Record a peer's rank for rank-based child-gateway discovery — the seam that
 *  substitutes for the rank C peers drop (public_identity_t carries none).
 *  Discovery reads it (default 0). Returns 0 on success. */
int identity_set_peer_rank(process_t *proc, const char *uuid, int rank);

/** Seed child groups from group_child_*.cfg.json under @p cfg_dir (C twin of
 *  Python IdentityProcess._load_child_groups). Returns the count adopted.
 *  Bridges the on-disk Python `Group` schema (_uuid / _address_map). */
int identity_load_child_groups(process_t *proc, const char *cfg_dir);

/** Fan this node's child-group set out to the sibling processes (one
 *  CHILD_GROUP message per cohort), so the reputation process can keep a
 *  transaction chain per child group. C twin of Python's
 *  _record_child_groups. Returns the number of messages sent; 0 on a leaf. */
int identity_propagate_child_groups(const process_t *proc, directory_t *queues);

/** Re-derive this node's parent gateway and advertise its position if it moved (protocol
 * step 7, doc/architecture/gateway-reputation-tree.md). Cheap and idempotent, so every
 * input change may call it. C twin of Python's _refresh_hierarchy. */
void identity_refresh_hierarchy(const process_t *proc);

/** Ask the group to state their hierarchy positions. One-shot: a node joining a
 *  settled mesh would otherwise wait for somebody's next change. C twin of
 *  Python's _request_hierarchy. */
void identity_request_hierarchy(const process_t *proc);

/** Write this node's DERIVED parent-gateway uuid into @p out (empty string when
 *  it is the root of its own cohort), for the `parent_gateway` expected_state
 *  assertion. Derived on demand: the harness installs ranks and asks, with no
 *  run loop to tick. Mirrors Python's _derive_parent_gateway. */
int identity_get_parent_gateway(const process_t *proc, char *out, size_t cap);

/** Read back what this node RECORDED from a peer's hierarchy claim
 *  (protocol step 7, doc/architecture/gateway-reputation-tree.md).
 *
 *  For the conformance adapter. The recording is gated on proved gateway
 *  authority, on the claim naming its own sender, and on a freshness sequence
 *  above the mark; none of those refusals shows up in emitted traffic, so
 *  without this a scenario could assert only that an answer was sent, never
 *  that it was believed. Mirrors the Python twin's `peer_hierarchy`.
 *
 *  @return false when nothing is recorded for @p peer_uuid — the observable a
 *          refusal produces, and deliberately distinct from a record of
 *          zeros. */
bool identity_get_peer_hierarchy(const char *peer_uuid, int *rank_out,
                                 int *n_children_out);

/** Emit ONE peer on the app-facing carrier (PEER_OBSERVED via AT_MAIN_QUEUE).
 *  Carries the peer's signing key, its rank from the peer_ranks seam, and
 *  both operator signals; the attendance stamp is zeroed unless the peer is
 *  operator_bound. Returns 0 on success.
 *  See doc/architecture/app-peer-carrier.md. */
int identity_emit_peer_observed(const process_t *proc,
                                const public_identity_t *peer);

/** Re-emit every peer this process holds (the app's roster pull). Returns the
 *  number emitted. Snapshots under the peers lock and sends outside it. */
int identity_emit_all_peers(const process_t *proc);

#define EID_NOQ 215
DECLARE_ERROR(EID_NOQ, "Required process queue missing");

#endif  // ID_PROC_PRIV_H
