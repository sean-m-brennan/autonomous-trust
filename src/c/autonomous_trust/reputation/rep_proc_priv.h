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
#ifndef REP_PROC_PRIV_H
#define REP_PROC_PRIV_H

#include <stdbool.h>
#include <stdint.h>
#include <uuid/uuid.h>

#include "processes/processes.h"
#include "identity/join_policy.h"

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

/** Propose our half for one locally-observed score: file it, follow it until
 *  it is in the chain, and send it to the group to co-sign (_propose_half).
 *  THE production proposer path — reputation_run's loop calls it for every
 *  TRANSACTION_SCORE that arrives over IPC. Declared here so a test can drive
 *  the real proposer rather than staging a round by hand.
 *
 *  @p peer_uuid is the PROPOSER (us), echoed on the wire as "peer_uuid";
 *  @p subject_uuid is who the score is about, and may be zeroed for a
 *  fan-out that names no single peer. */
void _forward_transaction(const process_t *proc, const uuid_t task_uuid,
                          const uuid_t peer_uuid, double score,
                          const char *capability_name, const char *channel,
                          const uuid_t subject_uuid, double competence);

/** Re-propose every half of OURS still not in the chain REP_COMMIT_TIMEOUT
 *  (AT_REP_COMMIT_TIMEOUT_SEC, default 15 s) after it was last proposed, up to
 *  REP_COMMIT_RETRIES times, then park it (ISSUES §2.24, §2.60). A
 *  granted round whose transaction never commits, and a round nobody answers,
 *  are otherwise lost for good. Called once per pass from reputation_run's
 *  loop; @p present is a parameter so a test can advance the clock. */
void _retry_uncommitted_halves(const process_t *proc, double present);

/** Hand our committed-but-unpaired halves on the primary chain to each peer
 *  that joined the roster after we committed them, at 5, 15 and 30 s after it
 *  is first seen (ISSUES §2.62): a join carries only bilateral entries, so
 *  without this the late member holds our counterpart's half alone and its
 *  chain forks from ours. Called once per pass from reputation_run's loop;
 *  @p present is a parameter so a test can advance the clock. Returns how
 *  many `tx committed` frames went out. */
size_t _hand_off_pending_halves(const process_t *proc, double present,
                                const uuid_t self_uuid, bool have_self);

/** Record that @p peer sent us a reputation frame at @p when (epoch seconds).
 *  reputation_run calls it for every inbound net frame; a half whose retries
 *  run out is parked only if fewer than a majority of the group, counting us,
 *  were heard within two commit timeouts (ISSUES §2.60). A test seam too. */
void reputation_note_heard(const uuid_t peer, double when);

/** Probe backpressure (ISSUES §2.60): may a NEW half of ours for @p task_uuid
 *  be proposed? Always, unless @p capability_name is one of AT's own probes
 *  ("at." prefix) and either an app half of ours is pending or
 *  AT_REP_MAX_PROBE_HALVES (default 4) probe halves are already followed.
 *  A refused probe is logged and dropped. */
bool _admit_new_half(const process_t *proc, const uuid_t task_uuid,
                     const char *capability_name);

/** Test seam: how many of our halves are waiting to reach the chain. */
size_t reputation_awaiting_commit_count(void);
/** Test seam: how many of those are parked (ISSUES §2.60). */
size_t reputation_parked_count(void);

/** Co-sign every parked checkpoint proposal whose range our chain now holds
 *  with the proposed root, and drop those parked longer than one checkpoint
 *  interval (ISSUES §2.29). A proposal is parked when it arrives before our
 *  chain has caught up to the proposer's. Called once per pass from
 *  reputation_run's loop; @p present is a parameter so a test can advance the
 *  clock. Returns how many were co-signed. */
size_t _recheck_parked_cosigns(const process_t *proc, double present);

/** Test seam: how many checkpoint proposals are parked for a later co-sign. */
size_t reputation_parked_cosign_count(void);
/* The equivocation records chain @p key ("" = primary) holds (R+D.md §14.1),
 * as a new JSON array. */
json_t *reputation_fork_records(const char *key);

/** Toggle synchronous-dispatch mode for the conformance harness, as the
 *  Python adapter sets synchronous_dispatch. Production must leave this
 *  off. */
void reputation_set_synchronous_dispatch(bool enabled);

/** Reset the file-scope rep_state to a clean baseline (paxos
 *  reinitialized for @p num_peers, history/reputations cleared,
 *  my_requests cleared, requested_reps cleared, sync_dispatch left
 *  unchanged). The harness calls this between scenario steps so each
 *  participant's handler runs against its own pre-installed state.
 *  Idempotent. */
void reputation_reset_state(int num_peers);

/** The join policy reputation marks catch-up under (RD_14.4 plan, D2 (b));
 *  NULL: inert. Read from $AT_JOIN_POLICY at start; reset by
 *  reputation_reset_state. Mirrors Python ReputationProcess.join_policy. */
void reputation_set_join_policy(const at_join_policy_t *policy);

/** Whether chain @p key's ("" or NULL: primary) entry at absolute @p index
 *  arrived by catch-up under the join policy and names us in neither slot.
 *  Mirrors Python ReputationProcess.is_told. */
bool reputation_is_told(const char *key, int index);

/** The catch-up marks, chain key -> indices: a new object the caller decrefs. */
json_t *reputation_catchup_marks(void);

/** Pre-install the dispatching participant's chain length, as if it had
 *  committed @p len entries. */
void reputation_set_chain_len(int len);

/** Pre-set the catch-up quorum (rep_state.num_updates). Conformance
 *  scenarios lower it to 1 so a single `latest update` step triggers the
 *  chain merge — the harness resets state per step, so the production
 *  default of 3 could never accumulate across steps. */
void reputation_set_num_updates(int n);

/** Page catch-up replies whose window serializes to more than @p bytes
 *  (0 restores REP_UPDATE_PAGE_BYTES). Test and conformance seam; reset by
 *  reputation_reset_state. */
void reputation_set_update_page_bytes(size_t bytes);

/** Pre-install OUR round (@p id1, @p id2) as _forward_transaction leaves it
 *  for handle_accepted: its score, @p task_uuid's evidence @p channel (NULL or
 *  "" for the default), and whom our half names, @p subject (NULL for none,
 *  R+D.md §14.2). The conformance `proposals` fixture. */
void reputation_install_proposal(int64_t id1, int64_t id2, double score,
                                 const uuid_t task_uuid, const char *channel,
                                 const uuid_t subject);

/** Keep placement state under @p dir rather than the config directory, or
 *  NULL for the config directory. Test and conformance seam: every
 *  participant shares one process there, and a promise must not survive into
 *  the next case. */
void reputation_set_placement_dir(const char *dir);

/** Stage the primary chain's promised placement ballot (@p n, @p by). */
void reputation_install_place_promise(int64_t n, const uuid_t by);

/** The primary chain's promised placement ballot: true and @p n / @p by, or
 *  false when nothing is promised. */
bool reputation_get_place_promise(int64_t *n, uuid_t by);

/** The task uuids of the primary chain's resident entries, in index order,
 *  up to @p max. Returns how many. */
int reputation_get_chain_tasks(uuid_t *out, int max);
/* The primary chain's pooled tasks, in pool order. */
int reputation_get_pool_tasks(uuid_t *out, int max);
/* Load a catch-up segment into the primary chain verbatim, every entry taken
 * as certified (placement certificates and commit certificates included), as
 * the local_chain fixture of a placed chain needs. */
int reputation_install_chain_json(const json_t *arr);

/** Put a committed half in the primary chain's pool, as a commit does under
 *  ordered placement. Returns tx_history_record_half's status. */
int reputation_record_half(const uuid_t task, const uuid_t scorer, double score,
                           const char *channel, const char *cert_json);

/** reputation_record_half_on for a half that names @p counterparty (NULL for
 *  none) and carries its scorer's signature @p half_sig (may be NULL), R+D.md
 *  §14.2. Returns tx_history_record_signed_half's status. */
int reputation_record_named_half_on(const char *chain_key, const uuid_t task,
                                    const uuid_t scorer, double score,
                                    const char *channel, const char *cert_json,
                                    const uuid_t counterparty,
                                    const char *half_sig);

/** reputation_record_half on chain @p chain_key ("" is the primary, else a
 *  child group's uuid), creating the child chain on first use. */
int reputation_record_half_on(const char *chain_key, const uuid_t task,
                              const uuid_t scorer, double score,
                              const char *channel, const char *cert_json);

/** Take @p members ([[uuid, signing key hex], ...]) as the roster in force on
 *  the primary chain below every resident roster entry (a conformance
 *  fixture's stand-in for a roster logged earlier). Returns 0, or -1 for a
 *  malformed list. */
int reputation_set_roster_anchor(const json_t *members);

/** Reset a placing primary chain that holds entries but no roster, as boot
 *  does. True when it was reset. */
bool reputation_reset_pre_roster(const process_t *proc);

/** Tenure (doc/architecture/reputation.md, "Tenure"): take @p since (seconds
 *  since the epoch) as when this node first held @p peer_uuid as a member,
 *  with signing key @p key_hex (NULL: whatever key the next sweep sees).
 *  Marks roster.cfg.json as already read. */
void reputation_set_member_since(const uuid_t peer_uuid, const char *key_hex,
                                 double since);
/** Tenure: use @p seconds as the minimum instead of AT_REP_MIN_TENURE_SEC
 *  (negative: back to the environment). Reset by reputation_reset_state. */
void reputation_set_min_tenure(double seconds);

/** Write each placing chain's pool if it changed, as the process loop does. */
void reputation_persist_pools(const process_t *proc);
/** Put the primary chain's persisted pool back, as boot does (once per state
 *  reset). */
void reputation_restore_pool(const process_t *proc);
/** The primary chain's pool as persisted, compact JSON text (caller frees). */
char *reputation_pool_json(void);
/** Put a persisted pool document into the primary chain's pool. Returns how
 *  many items are pooled afterwards, or -1 when it is not a pool document. */
int reputation_pool_load_json(const char *text);
/** The primary chain's pool revision. */
unsigned reputation_pool_rev(void);

/** Open a placement round on the primary chain now, as _maybe_place does
 *  once it is this node's turn. */
void reputation_place_start(const process_t *proc);
/** One pass of the proposer over every placing chain, as the process loop
 *  runs it. */
void reputation_maybe_place(const process_t *proc);

/** The primary chain's head hash ("" for an empty chain). */
void reputation_get_head_hash(char *out);   /* TX_HASH_HEX_LEN + 1 */

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

/** Count the ordinary halves rep_state.history holds (pending, committed, or
 *  waiting in its pool) and how many of them carry a commit certificate, for the `halves_held` /
 *  `certified_halves` expected_state assertions (doc/architecture/reputation.md, "Commit certificates").
 *  Mirrors the Python adapter's reading of Transaction.commit_sigs. */
void reputation_get_commit_cert_counts(int *halves_held, int *certified_halves);
/** How many of those halves carry their scorer's own signature (R+D.md
 *  §14.2), for the `signed_halves` expected_state assertion. Mirrors the
 *  Python adapter's reading of Transaction.half_sigs. */
int reputation_get_signed_half_count(void);

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

/** Build the persisted-evidence document this node would write right now (the
 *  resident window plus the finalized checkpoint over it), for the
 *  `evidence_doc` expected_state assertion. Caller owns *out (json_decref).
 *
 *  The document is SHARED with the Python runtime, so pinning it in the corpus
 *  pins the one artifact both warm starts read. Mirrors Python
 *  evidence_to_dict(self.history, SignedCheckpoint(...)). */
int reputation_get_evidence_doc(json_t **out);

/** Write the evidence-derived score ceiling for @p peer_uuid over the resident
 *  committed window into @p out, for the `evidence_ceiling_of` assertion.
 *  Returns non-zero when the window bounds nothing for that peer.
 *
 *  Worth pinning cross-language on its own: this is the arithmetic that decides
 *  how much standing a restored peer may hold, so a drift between runtimes
 *  would silently hand the same peer different tiers on the two
 *  implementations. Mirrors Python _evidence_ceilings. */
int reputation_get_evidence_ceiling(const uuid_t self_uuid,
                                   const uuid_t peer_uuid, double *out);

/** Pre-seed a finalized checkpoint (root hex + epoch) for the `checkpoint`
 *  fixture, so an evidence-bearing slash can be verified against it within a
 *  single conformance step. Mirrors setting Python's
 *  ReputationProcess._checkpoint. */
void reputation_install_checkpoint(const char *root, int64_t epoch);
void reputation_install_checkpoint_window(const char *root, int64_t epoch,
                                          int first_index, int count);

/** Originate a checkpoint over @p chain_key's committed window right now, as
 *  the periodic path does ("" is the primary chain). Test hook only: the
 *  production trigger is _maybe_checkpoint inside reputation_run, which a unit
 *  test cannot reach, and the round it records has to OUTLIVE the call for an
 *  ack to tally against it -- which the conformance harness cannot express
 *  either, because it resets rep_state before every dispatch. Mirrors calling
 *  Python's forward_checkpoint directly. */
void reputation_force_checkpoint(const process_t *proc,
                                const char *self_uuid_str,
                                const char *chain_key);

/** Pre-install a transaction_weight in rep_state.task_weights for
 *  @p task_uuid. The conformance harness calls this so scenarios can
 *  pin per-task weights without driving the full
 *  Capability-registration → _forward_transaction → handle_transaction
 *  wire flow. Production code MUST NOT call this. */
void reputation_install_task_weight(const uuid_t task_uuid, int weight);

/** Pre-install a bilateral Transaction (@p task_uuid) in
 *  rep_state.history: p1_uuid scored at @p p1_score, p2_uuid at
 *  @p p2_score. Drives `tx_history_update` twice under the same task
 *  so both `_peer_mapping` entries get populated, matching how
 *  handle_committed builds bilateral history. Conformance hook only. */
void reputation_install_tx_pair(const uuid_t task_uuid,
                                const uuid_t p1_uuid, double p1_score,
                                const uuid_t p2_uuid, double p2_score);

/** reputation_install_tx_pair with each half's evidence channel (NULL for the
 *  default). The conformance `tx_history` fixture's p1_channel / p2_channel. */
void reputation_install_tx_pair_tagged(const uuid_t task_uuid,
                                       const uuid_t p1_uuid, double p1_score,
                                       const char *p1_channel,
                                       const uuid_t p2_uuid, double p2_score,
                                       const char *p2_channel);

/** Pre-install ONE SIDE of a Transaction (@p task_uuid): @p peer_uuid scored
 *  at @p score, the counterparty slot left open.
 *
 *  Exists so a single-step scenario can drive the arrival that COMPLETES the
 *  entry and then assert on the committed window -- which a two-step scenario
 *  cannot do here, because this harness resets rep_state between steps. Used
 *  by `reputation/committed-channel-in-the-entry-hash` to pin that both
 *  runtimes hash a channel-bearing entry identically (R+D.md §12.8).
 *
 *  Untagged deliberately: the staged side is an ordinary task outcome, and the
 *  channel under test arrives on the wire. Conformance hook only. */
/** Propose a locally produced verifier-attested score (@p ts->attested) to
 *  the group as its verifier @p self_uuid: sign, file it pending, fan out the
 *  propose, and start its re-propose clock. */
void _forward_attestation(const process_t *proc, const tx_score_msg_t *ts,
                          const uuid_t self_uuid);

/** One pass of the attestation re-propose clock (ISSUES §2.40): resend each
 *  pending round's propose once REP_ATTEST_RETRY has passed since the last, up
 *  to REP_ATTEST_RETRIES times, then abandon it; forget rounds already in the
 *  chain. @return proposes sent. */
size_t _retry_pending_attestations(const process_t *proc, double present);

/** Our attestation rounds still awaiting a quorum. */
size_t reputation_attest_pending_count(void);

/** Co-signatures recorded for attestation rounds still in flight (test seam). */
size_t reputation_attest_cosig_count(void);

/* Commit a verifier-attested entry directly (test/conformance hook): the
 * chain's half of the rule, without the quorum round. Returns
 * tx_history_append_attested's result. */
int reputation_install_tx_attested(const uuid_t verifier_uuid, double score,
                                   const char *channel,
                                   const uuid_t subject_uuid,
                                   const char *evidence_digest);
/** Replace the attestation conflict set (ISSUES §2.54) with @p json_text,
 *  {"teams": [[uuid, ...], ...]}, instead of etc/at/attest_conflicts.cfg.json;
 *  NULL goes back to the file. For tests and the conformance adapter. Returns
 *  -1, changing nothing, on a malformed set. */
int reputation_set_attest_conflicts(const char *json_text);

/** Whether @p a and @p b are two different nodes of one team in the conflict
 *  set in force (ISSUES §2.54). For tests. */
bool reputation_attest_conflicted(const char *a, const char *b);

/** @ref reputation_install_tx_attested with an attest scope (NULL for none)
 *  and its quorum certificate as JSON text (NULL for none). */
int reputation_install_tx_attested_scoped(const uuid_t verifier_uuid,
                                          double score, const char *channel,
                                          const uuid_t subject_uuid,
                                          const char *evidence_digest,
                                          const char *scope,
                                          const char *cert_json);

/** Pool a verifier-attested entry (test hook): where a certified
 *  attestation waits to be placed, without the quorum round. Returns
 *  tx_history_pool_attested's result. */
int reputation_install_pooled_attested(const uuid_t verifier_uuid,
                                       double score, const char *channel,
                                       const uuid_t subject_uuid,
                                       const char *evidence_digest);

/** Store a checkpoint as a finalized one arriving would (test hook): the
 *  evidence file, the finality record, and the durable attested records
 *  (_archive_attested) for every attested entry it covers. @p sigs are
 *  {voter: sig hex}, taken as already verified, as every caller's are. */
/** Our committed head hash ("" for an empty chain) into @p out, which holds
 *  @p cap bytes (TX_HASH_HEX_LEN + 1 fits it); returns the chain length. What
 *  a request's fork probe compares (ISSUES §2.51). */
int reputation_head_hash(char *out, size_t cap);

void reputation_test_store_checkpoint(const process_t *proc, const char *proposer,
                                      const char *root, int64_t epoch,
                                      int first_index, int count,
                                      const char *chain_key, json_t *sigs);
void reputation_install_tx_single(const uuid_t task_uuid,
                                  const uuid_t peer_uuid, double score);

/** Pre-install a peer's reputation in rep_state.reputations.
 *  Conformance scenarios use this to set the counterparty's reputation
 *  (consumed by reputation_pure) and the subject peer's `previous`
 *  reputation (consumed by _compute_reputation's coop-mode latch). */
void reputation_install_peer_reputation(const uuid_t peer_uuid, double score);

/** Run the rescore sweep now, as the process loop does (Phase 4 P4.1): score
 *  every peer whose chain advanced since it was last scored plus every
 *  admitted peer never scored, and publish each tier and app event.
 *  Throttled to AT_REP_RESCORE_SEC; @p self_uuid (may be NULL) is skipped.
 *  Returns the number of peers scored. */
int reputation_rescore_sweep(const process_t *proc, double present,
                             const uuid_t self_uuid);

/** What every commit does to its peer (the idle clock, and marking it due for
 *  the next rescore sweep), without driving a Paxos round. Test hook. */
void reputation_note_interaction(const uuid_t peer_uuid);

/** Pre-install the coop-mode latch entry for @p peer_uuid. When @p
 *  in_coop is true, the next compute uses COOP_EXIT (0.45) as the
 *  pure-vs-CTFT gate; when false, COOP_ENTER (0.55). Mirrors Python's
 *  self._coop_mode dict (keyed by peer uuid). */
void reputation_install_coop_mode(const uuid_t peer_uuid, bool in_coop);

/** Read a peer's reputation from rep_state.reputations for
 *  expected_state assertions. Returns 0 on success (writing to @p out),
 *  -1 if uninitialized or @p peer_uuid is absent. */
int reputation_get_peer_reputation(const uuid_t peer_uuid, double *out);

/** The brought score (RD_14.4 Phase 4) of @p peer_uuid: 0 and @p out, or -1
 *  when this node holds none. */
int reputation_get_brought(const uuid_t peer_uuid, double *out);

/** What a decision about @p peer_uuid reads (bounded): 0 and @p out, or -1
 *  when no told score is held. */
int reputation_get_bounded(const uuid_t peer_uuid, double *out);

/** Record identity's judgement that @p peer_uuid is (or is no longer) an
 *  anchor, as a PEER_ANCHOR message does. Reset by reputation_reset_state. */
void reputation_set_anchored(const uuid_t peer_uuid, bool anchored);

/** Replace the primary chain's catch-up marks with @p indices (conformance). */
void reputation_install_catchup_told(const int64_t *indices, size_t n);

/** Offer one extension seed for @p who, as a provider would (FIRST_CONTACT
 *  §10.5; under the join policy, RD_14.4 Phase 4). @p label names the
 *  provider in the log. */
void reputation_offer_seed(const process_t *proc, const char *label,
                           const uuid_t who, double seed, const char *what);

/** Deliver one peer standing exactly as the process loop would
 * (doc/architecture/zta-integration.md), so a test or conformance step can exercise the
 * DDIL cap and the retroactive unwind without standing up the identity process.
 *
 * Worth reaching for deliberately: the defect this whole entry exists to fix was a
 * ZTA→reputation path that no test could see, so the seam is exposed rather than left
 * to an integration run nobody performs. Returns 0 when the standing was applied, -1 if
 * uninitialized.
 *
 * NO LONGER UNDER #ifdef AT_ZTA_ENABLED (Phase 4 P4.1). ZTA was the first
 * authority to need a ceiling, not the only one — an Ethne expulsion reaches
 * this same seam on a build with ZTA off. */
int reputation_apply_peer_standing(const process_t *proc,
                                   const peer_standing_msg_t *standing);

/** Read the ceiling currently bounding @p peer_uuid, for expected_state
 *  assertions. Returns 0 and writes @p out when one is set, -1 when the peer
 *  is unbounded (proved, or never spoken about). */
int reputation_get_peer_ceiling(const uuid_t peer_uuid, double *out);

/** The score a peer is unwound to when NO pre-verification evidence supports
 *  it — the unverified-restore tier's ceiling. Exposed so a test names the
 *  runtime's own bound instead of duplicating the tier arithmetic beside it. */
double reputation_unverified_ceiling(void);

/** Re-emit every peer's reputation on the app-facing carrier (PEER_REPUTATION
 *  via AT_MAIN_QUEUE) — the reputation half of the app's roster pull. Peers
 *  AT holds no rating for are emitted with rated=false rather than skipped;
 *  this is the ONLY path on which rated=false can cross, since every
 *  change-driven emission is by construction rated.
 *  Returns the number emitted. See doc/architecture/app-peer-carrier.md. */
int reputation_emit_all(const process_t *proc);

/** Slash reasons. The slash designation that co-signers sign covers the reason
 *  STRING, so these spellings must match Python SlashAttestation.REASON_*
 *  exactly — a divergence here is a co-signature that verifies on neither side.
 *  Shared with the conformance adapter, which builds slash payloads. */
#define REP_SLASH_REASON_SUSTAINED_ANOMALY "sustained_anomaly"
#define REP_SLASH_REASON_PEER_EXCLUDE      "peer_exclude"
#define REP_SLASH_REASON_INVALID_TX        "invalid_tx"

/** Originate a deep-resolution query for one peer (doc/architecture/gateway-reputation-tree.md).
 *
 *  Fire-and-forget: the answer arrives later on rep_resolved and lands where
 *  @ref reputation_resolved_get reads it. Returns the number of child groups
 *  the query went to -- 0 means this node gateways nothing and no answer can
 *  come back. @p query_id is caller-chosen so a test or conformance step can
 *  correlate; pass NULL for a generated one. Mirrors Python
 *  ReputationProcess.resolve_reputation. */
size_t reputation_deep_resolve(const process_t *proc, const char *query_id,
                               const char *peer_uuid, int ttl);

/** Read the outcome of a deep resolution for @p peer_uuid.
 *
 *  Returns true when an answer (accepted OR refused) has been recorded.
 *  @p verified_out distinguishes the two, and @p reason carries WHICH gate
 *  decided it -- an operator reading "unverified" needs that, and so does a
 *  conformance assertion that would otherwise pass for the wrong reason. */
bool reputation_resolved_get(const char *peer_uuid, double *score_out,
                             bool *have_score_out, bool *verified_out,
                             char *reason_out, size_t reason_cap);

/** Number of queries this node is currently relaying, and the number it has
 *  outstanding of its own. The relay table is the capability's only state, so
 *  a scenario that asserts it is released is asserting the thing that would
 *  otherwise leak. */
size_t reputation_resolve_pending_count(void);
size_t reputation_resolve_outstanding_count(void);

#define EREP_PAXOS 253
DECLARE_ERROR(EREP_PAXOS, "Paxos consensus error");

#endif  /* REP_PROC_PRIV_H */
