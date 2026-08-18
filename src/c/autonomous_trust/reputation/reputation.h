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

#ifndef REPUTATION_H
#define REPUTATION_H

/** @addtogroup internal_reputation
 *  @{
 */

#include <stdbool.h>
#include <stdint.h>
#include <uuid/uuid.h>
#include <jansson.h>

#include "structures/map.h"
#include "structures/array.h"
#include "identity/identity.h"
#include "utilities/exception.h"
#include "processes/capabilities.h"   /* CAP_NAMELEN */
#include "autonomous_trust/algorithms/paxos.h"

/****************************
 * Protocol constants — must match the Python ReputationProtocol enum
 * (src/autonomous-trust/.../reputation/protocol.py) verbatim so a
 * Python node and a C node can interoperate. The conformance corpus
 * uses these strings as the `function` field on every reputation
 * scenario step. Changing any of these is a wire-protocol break.
 *
 * Declared as writable char arrays (not `#define` string literals) so
 * `net_msg.function = REP_PROTO_X` is type-correct under
 * `-Wwrite-strings` without the `(char *)` cast that used to obscure
 * the const violation. Definitions live in `rep_proc.c`.
 *
 * Note on string literals: `REP_PROTO_REP_REQ` etc. matches Python's
 * `ReputationProtocol.rep_req` verbatim; do NOT tidy
 * `"request reputation"` back to "reputation request" — breaks
 * Python↔C interop. See BUGS.md §P9.
 ****************************/

extern char REP_PROTO_REQUEST[];
extern char REP_PROTO_GRANT[];
extern char REP_PROTO_NACK[];
extern char REP_PROTO_BACKDATE[];
extern char REP_PROTO_TX[];
extern char REP_PROTO_ACCEPTED[];
/* Phase 3 — proposer broadcasts the committed (task_id, peer_id,
 * score) tuple to the group after handle_accepted reaches majority.
 * Acceptors handle this by writing the entry to their own history,
 * which is how bilateral Transactions form across all peers' views.
 * Matches Python's ReputationProtocol.committed verbatim. */
extern char REP_PROTO_COMMITTED[];
extern char REP_PROTO_OUTDATED[];
extern char REP_PROTO_UPDATE[];
extern char REP_PROTO_REP_REQ[];
extern char REP_PROTO_REP_RESP[];
/* History-only reputation score for observer/dashboard use. Distinct
 * request op so peer-side callers keep their identity-dependent CTFT
 * scoring via rep_req; reply reuses REP_PROTO_REP_RESP so the existing
 * response dispatch consumes it unchanged. Mirrors Python's
 * ReputationProtocol.consensus_rep_req — string must match verbatim. */
extern char REP_PROTO_CONSENSUS_REP_REQ[];
extern char REP_PROTO_LOCAL_QUERY[];
extern char REP_PROTO_LOCAL_RESP[];
extern char REP_PROTO_APP_ROSTER[];
/* Slashing — fast-penalty path. A detector broadcasts SLASH_PROPOSE;
 * members co-sign with SLASH_SIGN; on quorum the slasher broadcasts
 * SLASH_FINAL and every node floors the target's reputation, bypassing
 * the slow consensus EMA. Strings must match Python verbatim
 * (ReputationProtocol.slash_propose / slash_sign / slash_final). See
 * reputation-vs-blockchain-analysis.md (slashing == PoS-style penalty). */
extern char REP_PROTO_SLASH_PROPOSE[];
extern char REP_PROTO_SLASH_SIGN[];
extern char REP_PROTO_SLASH_FINAL[];
/* Phase 2 quorum-signed Merkle checkpoint ops
 * (ReputationProtocol.checkpoint_propose / checkpoint_sign / checkpoint_final).
 * A member co-signs only when its own transaction_window_root matches the
 * proposed root; on quorum the agreed root is stored. See
 * reputation-vs-blockchain-analysis.md §2.1. */
extern char REP_PROTO_CHECKPOINT_PROPOSE[];
extern char REP_PROTO_CHECKPOINT_SIGN[];
extern char REP_PROTO_CHECKPOINT_FINAL[];

/* Deep resolution: one peer, on demand, at any depth (doc/architecture/gateway-reputation-tree.md).
 * A node holds chains only for its own groups, so a peer two levels down is
 * unscoreable locally; the query is relayed toward whoever holds its chain and
 * the answer comes back along the reverse path carrying the quorum-signed
 * window that backs it. Wire strings match Python ReputationProtocol
 * verbatim -- see the REP_PROTO alignment note above. */
extern char REP_PROTO_REP_RESOLVE[];
extern char REP_PROTO_REP_RESOLVED[];

/****************************
 * Reputation tuning constants — mirror Python class attributes in
 * src/autonomous-trust/.../reputation/repprocess.py:ReputationProcess.
 ****************************/

/* Hysteresis band for the CTFT ↔ pure-reputation mode switch in
 * reputation_compute / handle_rep_request. A single 0.5 threshold
 * made peers hovering near 0.5 flip scoring functions every tick;
 * widening the switch band so a peer must clear COOP_ENTER to graduate
 * and fall below COOP_EXIT to fall back removes the chatter without
 * altering either scoring function. */
#define COOP_ENTER 0.55
#define COOP_EXIT  0.45

/* Reputation thresholds are on the [0, 1] scale (NO negatives). Each has a
 * compile-time DEFAULT and an environment override read at use-time via
 * reputation_env_double(), mirroring repprocess.py _env_float so Python<->C
 * stay byte-comparable under the SAME environment. The macros expand to the
 * accessor so every existing PREREP_NEUTRAL/COMM_CUTOFF use keeps working as
 * a double-valued expression.
 *
 * PREREP_NEUTRAL is the "no information" STARTING reputation: a peer we know
 * nothing about starts at NEUTRAL (0.2) -- a small leeway above the
 * COMM_CUTOFF (0.1) communication cut-off so a newcomer survives a minor
 * mistake -- and must EARN its way up toward 1.0, rather than being handed a
 * near-threshold ~0.5 for free (which let unknown peers read as almost-trusted
 * and made the trust graph a flat all-to-all mesh). A catastrophically-failed
 * peer is driven to the slash floor (0.0), below the cut-off. The
 * transaction-memory prior shrinks a peer's observed third-party standing
 * toward PREREP_NEUTRAL by a pseudo-count of PREREP_SHRINKAGE_K, so a
 * genuinely-unknown peer (zero observations) reads exactly PREREP_NEUTRAL.
 * This is the STARTING point only -- the CTFT bilateral pivots
 * (min(0.49,.)/max(0.51,.) around the 0.5 cooperate threshold) are the earned
 * near-threshold outputs and are deliberately unchanged. Mirror of
 * repprocess.py PREREP_NEUTRAL / PREREP_SHRINKAGE_K / COMM_CUTOFF.
 * Disable the prior heuristic via AT_PREREP_HEURISTIC=0; re-adjust values via
 * AT_REP_NEUTRAL / AT_REP_COMM_CUTOFF. */
double reputation_env_double(const char *name, double dflt);
#define PREREP_NEUTRAL_DEFAULT 0.2
#define COMM_CUTOFF_DEFAULT    0.1
#define PREREP_NEUTRAL (reputation_env_double("AT_REP_NEUTRAL", PREREP_NEUTRAL_DEFAULT))
/* Communication cut-off: a peer whose aggregate reputation falls BELOW this
 * is EXCLUDED from the network (gateways stop forwarding to/for it, LAN nodes
 * ignore it); recovery is explicit-only (rehabilitation -> PREREP_NEUTRAL). */
#define COMM_CUTOFF (reputation_env_double("AT_REP_COMM_CUTOFF", COMM_CUTOFF_DEFAULT))
#define PREREP_SHRINKAGE_K 3.0

/* The scale every absolute measure in AT — and in the tiers above it — assumes.
 * Mirror of TX_SCORE_MIN / TX_SCORE_MAX in repprocess.py's reputation.py.
 *
 * The [0, 1] score bound, enforced (doc/architecture/reputation.md; asked for by
 * kith-covenant's erosion-legibility audit). The
 * bound was a convention rather than something checked, so an out-of-range score
 * was GRADED rather than rejected — folded into the weighted average, moving a
 * reputation by an unbounded amount. @ref tx_score_in_range rejects instead of
 * clamping: a submitter sending 5.0 has a bug, and quietly recording 1.0 hides
 * it while still rewarding the peer more than any honest score could. */
#define TX_SCORE_MIN 0.0
#define TX_SCORE_MAX 1.0

/** True iff @p score is a real number on AT's [0, 1] scale.
 *
 * NaN fails by the same comparison that rejects 5.0 (every comparison against
 * NaN is false), which matters because NaN is the value that would otherwise
 * poison an average with no way back. */
static inline bool tx_score_in_range(double score)
{
    return score >= TX_SCORE_MIN && score <= TX_SCORE_MAX;
}

/* EMA half-life (in committed bilateral txs) for reputation_consensus.
 * Smaller → faster crash on a peer that begins producing bad scores,
 * slower rebuild for the rest. 20 gives α ≈ 0.034. */
#define CONSENSUS_EMA_HALF_LIFE 20

/* FIFO cap on rep_state.committed_paxos_rounds (rep_proc.c). Paired
 * with MAX_CHAIN_LEN so neither dedup structure grows without bound.
 * Mirrors Python's ReputationProcess.COMMITTED_ROUNDS_CAP. Sized for
 * ~2 min of in-flight protection at ~16 paxos commits/sec — small
 * caps let late ACCEPTEDs bypass the dedup and trigger redundant
 * commit re-broadcasts that fan out to every peer (cheap on the
 * receivers thanks to the tx_history tombstone, but still real
 * network/dispatch cost). 2000 eliminates the spurious traffic
 * entirely. */
#define COMMITTED_ROUNDS_CAP 2000

/****************************
 * Transaction score (pending Paxos request)
 ****************************/

typedef struct {
    smrt_ptr_t;
    uuid_t task_uuid;
    double score;
    /* Optional: name of the Capability that produced this TS. Used by
     * _pure_reputation to look up transaction_weight (Slice 3). Empty
     * string == "unknown / legacy" — weight defaults to 1. Mirrors
     * Python TransactionScore.capability_name. See
     * doc/architecture/trust-tiers.md §4.4. */
    char capability_name[CAP_NAMELEN+1];
} tx_score_t;

/****************************
 * Transaction record (chain entry)
 ****************************/

/* blake2b digest of the reputation chain, hex-encoded. 32-byte digest
 * (crypto_generichash default) -> 64 lowercase hex chars + NUL. Matches
 * Python's MerkleTree.get_hash output (nacl blake2b, HexEncoder, 32-byte
 * digest). Keep in lockstep so the languages agree on entry hashes. */
#define TX_HASH_HEX_LEN 64

typedef struct {
    uuid_t task_uuid;
    uuid_t p1_uuid;
    double p1_score;
    bool   p1_set;
    uuid_t p2_uuid;
    double p2_score;
    bool   p2_set;
    int    index;
    /* Phase 1 hash-linking (reputation-vs-blockchain-analysis.md §2.1):
     * entry_hash of the entry committed immediately before this one in the
     * resident chain; empty string for the genesis entry (or the oldest
     * resident entry whose predecessor has been evicted). Assigned when the
     * tx goes bilateral. Mirrors Python Transaction.prev_hash. */
    char   prev_hash[TX_HASH_HEX_LEN + 1];
} transaction_t;

/****************************
 * Transaction history (block chain)
 ****************************/

/* Cap on the resident chain. When full, tx_history_update evicts
 * chain[0] (FIFO) and shifts the remainder down by one slot,
 * renumbering map entries to match. Mirrors Python's
 * TransactionHistory.DEFAULT_MAX_CHAIN_LEN — keep in lockstep with
 * src/autonomous-trust/.../reputation/reputation.py.
 *
 * Chain admission: tx_history_update writes to chain[] on the very
 * first slot fill (so task_map can route the second-slot fill back
 * to the same entry), but tx->index is monotonic absolute and only
 * assigned once the transaction goes bilateral — matching Python's
 * "_chain.append only on len(tx) > 1" rule. tx_history_len /
 * by_peer / era* therefore filter for tx->p1_set && tx->p2_set,
 * so unilateral txs are invisible to consumers until they commit. */
#define MAX_CHAIN_LEN 200

typedef struct {
    transaction_t chain[MAX_CHAIN_LEN];
    int           chain_len;          /* Total slots in use (committed + pending). */
    /* Number of bilateral entries in chain[]. Mirrors Python
     * `len(_chain)`, which is what TransactionHistory.__len__
     * returns. Without this counter, callers that asked
     * `tx_history_len()` after a single unilateral update would
     * see 1 while Python saw 0 — and any era-based serialization
     * pulled the half-tx onto the wire as if it were committed. */
    int           committed_count;
    /* Monotonic insertion counter, assigned to tx->index when a tx
     * goes bilateral. Survives evictions so indices keep growing
     * forever — matches Python `_next_index`. Eviction's old
     * "renumber slots" pass no longer rewrites tx->index. */
    int           next_index;
    /* Absolute index of the oldest committed entry (chain[0] if
     * the head is committed; otherwise the first committed slot's
     * index). Equals `next_index` when there are zero committed
     * entries. Mirrors Python `_first_index` — used by era() to
     * translate absolute requests into chain-relative offsets. */
    int           first_index;
    map_t         task_map;   /* uuid_str -> int (chain index) */
    map_t         peer_map;   /* uuid_str -> array_t* (list of indices) */
    /* Tombstone of evicted task_uuids — FIFO ring sized to
     * MAX_CHAIN_LEN so we remember the most-recent MAX_CHAIN_LEN
     * evictions. tx_history_update refuses to re-create entries
     * for tombstoned tasks; without this, a late `committed`
     * broadcast for an evicted task would build a half-completed
     * Transaction in task_map that the counterparty's late
     * `committed` would complete and re-insert at the head of
     * the chain (silently evicting a legitimate recent entry).
     * Mirrors Python's TransactionHistory._evicted_task_ids. */
    char          evicted_ring[MAX_CHAIN_LEN][UUID_STRING_LEN + 1];
    int           evicted_ring_head;  /* next slot to overwrite */
    int           evicted_ring_len;   /* up to MAX_CHAIN_LEN */
    map_t         evicted_set;        /* uuid_str -> integer_data(1) */
    /* Phase 1 hash-linking: entry_hash of the current chain head (the most
     * recently committed entry) — the prev_hash the next bilateral commit
     * will carry. Empty string before the first commit. Eviction never
     * rewrites it (it tracks the tail), so the link survives the sliding
     * window. Mirrors Python TransactionHistory._head_hash. */
    char          head_hash[TX_HASH_HEX_LEN + 1];
} tx_history_t;

/*@
  requires \valid(hist);
  allocates *hist;
  behavior success:
    ensures \result == 0;
    ensures *hist != \null;
  behavior failure:
    ensures \result != 0;
  disjoint behaviors;
*/
int  tx_history_create(tx_history_t **hist);

/*@
  requires \valid(hist);
  assigns *hist;
  ensures \result == 0 || \result != 0;
  ensures \result == 0 ==> hist->chain_len == 0 &&
                           hist->committed_count == 0 &&
                           hist->next_index == 0 &&
                           hist->first_index == 0;
*/
int  tx_history_init(tx_history_t *hist);

/*@
  requires hist == \null || \valid(hist);
  frees hist;
*/
void tx_history_destroy(tx_history_t *hist);

/*@
  requires \valid(hist);
  requires score >= 0.0 && score <= 1.0;
  assigns hist->chain[0 .. MAX_CHAIN_LEN - 1],
          hist->chain_len, hist->committed_count,
          hist->next_index, hist->first_index,
          hist->task_map, hist->peer_map;
  ensures \result == 0;
*/
int  tx_history_update(tx_history_t *hist, const uuid_t task_uuid,
                       const uuid_t peer_uuid, double score);

/*@
  requires \valid(hist);
  requires \valid(out);
  assigns *out;
  behavior found:
    ensures \result == 0;
  behavior not_found:
    ensures \result != 0;
  disjoint behaviors;
*/
int  tx_history_by_task(const tx_history_t *hist, const uuid_t task_uuid,
                        transaction_t *out);

/* Phase 1 hash-linking. transaction_entry_hash writes the blake2b digest
 * (TX_HASH_HEX_LEN lowercase hex chars + NUL) of the canonical content
 * chained with tx->prev_hash into `out` — the value the next entry records
 * as its prev_hash. transaction_canonical_bytes writes the deterministic,
 * language-agnostic serialization (everything EXCEPT prev_hash) used as the
 * hash input; it MUST stay byte-identical to Python Transaction._canonical_bytes
 * (pipe-joined fields, "%.17g" floats, lowercase-hyphenated UUIDs, "null" for
 * unset). Returns the string length written (excluding NUL), or -1 on overflow. */
int  transaction_canonical_bytes(const transaction_t *tx, char *out, size_t outsz);
void transaction_entry_hash(const transaction_t *tx, char out[TX_HASH_HEX_LEN + 1]);

/* Verify the hash-linkage of a contiguous committed chain: every adjacent
 * pair must satisfy chain[i].prev_hash == entry_hash(chain[i-1]). The first
 * entry's predecessor lies outside the segment and is not checked. Pending
 * (index < 0) entries are skipped. Returns true if the segment is
 * self-consistent (empty/single-entry chains trivially pass). Mirrors Python
 * TransactionHistory.verify_chain_links / verify_links. */
bool tx_verify_chain_links(const transaction_t *chain, int count);
bool tx_history_verify_links(const tx_history_t *hist);

/* Phase 2 ordered Merkle root (reputation-vs-blockchain-analysis.md §2.1).
 * RFC 6962 Merkle Tree Hash with domain-separated leaf (0x00) and node (0x01)
 * prefixes over each committed entry's entry_hash, in resident order. A single
 * root commits to every resident entry; an inclusion proof confirms one tx
 * belongs to the committed window in O(log n) without the whole chain. Pure
 * function of the ordered leaf digests -> byte-identical to Python
 * TransactionHistory.window_root. Empty window -> blake2b of the empty string.
 * Writes TX_HASH_HEX_LEN hex chars + NUL to out. */
void transaction_window_root(const tx_history_t *hist, char out[TX_HASH_HEX_LEN + 1]);

/* One step of an inclusion (audit) path: a sibling subtree root and whether it
 * sits on the LEFT of the running digest. Mirrors Python's
 * (sibling_root, sibling_is_left) tuples. */
typedef struct {
    char sibling[TX_HASH_HEX_LEN + 1];
    bool sibling_is_left;
} tx_merkle_step_t;

/* Build the RFC 6962 audit path proving the committed entry at absolute
 * `abs_index` belongs to transaction_window_root(hist). Writes the step count
 * into *n_steps (at most ceil(log2(window)) steps; `steps` must hold up to
 * MAX_CHAIN_LEN). Returns 0 on success, -1 if abs_index is not resident.
 * Mirrors Python TransactionHistory.inclusion_proof. */
int  transaction_window_proof(const tx_history_t *hist, int abs_index,
                              tx_merkle_step_t *steps, int *n_steps);

/* Fold a leaf entry_hash up its audit path and check it reproduces root_hex.
 * Mirrors Python TransactionHistory.verify_inclusion. */
bool tx_merkle_verify(const char leaf_hex[TX_HASH_HEX_LEN + 1],
                      const tx_merkle_step_t *steps, int n_steps,
                      const char root_hex[TX_HASH_HEX_LEN + 1]);

/*@
  requires \valid(hist);
  requires \valid(out + (0 .. max_out - 1));
  requires max_out > 0;
  requires \valid(out_count);
  assigns out[0 .. max_out - 1], *out_count;
  ensures *out_count >= 0 && *out_count <= max_out;
  ensures \result == 0;
*/
int  tx_history_by_peer(const tx_history_t *hist, const uuid_t peer_uuid,
                        transaction_t *out, int *out_count, int max_out);

/*@
  requires \valid(hist);
  requires \valid(out_count);
  assigns *out_count;
  ensures *out_count >= 0;
  ensures \result == 0;
*/
int  tx_history_era(const tx_history_t *hist, int start_idx, int end_idx,
                    transaction_t *out, int *out_count);

/*@
  requires \valid(hist);
  assigns \nothing;
  ensures \result == hist->committed_count;
  ensures \result >= 0;
*/
int  tx_history_len(const tx_history_t *hist);

/*@
  requires \valid(hist);
  assigns hist->task_map, hist->peer_map, hist->chain_len,
          hist->committed_count, hist->next_index, hist->first_index;
  ensures hist->chain_len == 0;
  ensures hist->committed_count == 0;
*/
void tx_history_free(tx_history_t *hist);

int  tx_history_era_to_json(const tx_history_t *hist, int start_idx, int end_idx,
                            json_t **out);
int  tx_history_era_from_json(tx_history_t *hist, const json_t *arr);

/****************************
 * Reputations map
 ****************************/

typedef struct {
    map_t scores;   /* uuid_str -> data_t* (float score) */
} reputations_t;

/*@
  requires \valid(reps);
  allocates *reps;
  behavior success:
    ensures \result == 0;
    ensures *reps != \null;
  behavior failure:
    ensures \result != 0;
  disjoint behaviors;
*/
int  reputations_create(reputations_t **reps);

/*@
  requires \valid(reps);
  assigns reps->scores;
  ensures \result == 0 || \result != 0;
*/
int  reputations_init(reputations_t *reps);

/*@
  requires reps == \null || \valid(reps);
  frees reps;
*/
void reputations_destroy(reputations_t *reps);

/*@
  requires \valid(reps);
  requires score >= 0.0 && score <= 1.0;
  assigns reps->scores;
  ensures \result == 0 || \result != 0;
*/
int  reputations_update(reputations_t *reps, const uuid_t peer_uuid, double score);

/*@
  requires \valid(reps);
  requires \valid(score);
  assigns *score;
  behavior found:
    ensures \result == 0;
    ensures *score >= 0.0 && *score <= 1.0;
  behavior not_found:
    ensures \result != 0;
  disjoint behaviors;
*/
int  reputations_get(const reputations_t *reps, const uuid_t peer_uuid, double *score);

/*@
  requires \valid(reps);
  assigns \nothing;
  ensures \result == \true || \result == \false;
*/
bool reputations_contains(const reputations_t *reps, const uuid_t peer_uuid);

/*@
  requires \valid(reps);
  requires reps->scores.length <= reps->scores.capacity;
  assigns reps->scores;
*/
void reputations_free(reputations_t *reps);

/****************************
 * Reputation algorithms
 ****************************/

typedef struct {
    smrt_ptr_t;
    double score;
    int    grant_count;
} paxos_tx_count_t;

/*@
  requires \valid(hist);
  requires \valid(reps);
  assigns \nothing;
  ensures \result >= 0.0 && \result <= 1.0;
*/
/** Pure socially-weighted average. @p task_weights is a uuid_str -> int
 *  map of per-task transaction_weight values (populated by the
 *  reputation process at proposer + receiver time); pass NULL to
 *  treat every transaction as weight 1. The weighted form lines up
 *  with Python's _pure_reputation (trust-tiers.md §5). */
double reputation_pure(const tx_history_t *hist, const reputations_t *reps,
                       const uuid_t peer_uuid,
                       const map_t *task_weights);

/*@
  requires \valid(hist);
  requires \valid(reps);
  assigns \nothing;
  ensures \result >= 0.0 && \result <= 1.0;
*/
double reputation_contrite_tft(const tx_history_t *hist, const reputations_t *reps,
                               const uuid_t self_uuid, const uuid_t peer_uuid);

/*@
  requires \valid(hist);
  requires \valid(reps);
  assigns \nothing;
  ensures \result >= 0.0 && \result <= 1.0;
*/
/** @p task_weights forwarded to reputation_pure on the pure branch; NULL
 *  → unweighted aggregator. CTFT branch ignores it. */
double reputation_compute(const tx_history_t *hist, const reputations_t *reps,
                          const uuid_t self_uuid, const uuid_t peer_uuid,
                          const map_t *task_weights);

/*@
  requires \valid(hist);
  assigns \nothing;
  ensures \result >= 0.0 && \result <= 1.0;
*/
/** Deterministic, history-only reputation score over the consensus tx
 *  chain. Walks committed bilateral transactions involving @p peer_uuid
 *  in chain order and folds each counterparty-side score into an
 *  exponentially-weighted moving average with half-life
 *  CONSENSUS_EMA_HALF_LIFE. @p task_weights weights each EMA update by
 *  running it @c w times (a tier-w transaction moves the EMA exactly
 *  as far as @c w tier-1 transactions would, preserving the [0,1]
 *  range). NULL → unweighted. Mirrors Python's
 *  ReputationProcess._consensus_reputation. */
double reputation_consensus(const tx_history_t *hist, const uuid_t peer_uuid,
                            const map_t *task_weights);

/* One {tier, score} pair from the per-tier consensus view. */
typedef struct {
    int    tier;
    double score;
} tier_score_t;

/** Per-tier consensus reputation (trust-tiers §12 / deferred.md §2.3).
 *  Partition @p peer_uuid's committed bilateral txs by the tier of the
 *  capability that produced each (@p task_tiers: uuid_str -> integer tier,
 *  default 0) and fold each partition into its own weighted EMA — same
 *  alpha/weighting as reputation_consensus. Writes one {tier, score} entry
 *  per tier with >=1 observation into @p out (up to @p max_out) and returns
 *  the entry count. Additive: reputation_consensus (the collapsed score) is
 *  unchanged. Deduped by task. Mirrors Python
 *  ReputationProcess._consensus_reputation_by_tier. */
int reputation_consensus_by_tier(const tx_history_t *hist, const uuid_t peer_uuid,
                                 const map_t *task_tiers, const map_t *task_weights,
                                 tier_score_t *out, int max_out);

/****************************
 * Persisted reputation evidence (verifiable warm start)
 ****************************/

/* `reputation.cfg.json` records a CONCLUSION -- {peer: score} -- and nothing
 * about how it was reached. Reloading it makes trust durable, not verifiable:
 * on its own the file says only that some process with write access to the
 * config directory believed a number, which is as true of a hand-edited file
 * as of an earned one. The evidence is persisted beside it in
 * `reputation-history.cfg.json`: the hash-linked committed window plus the
 * quorum-signed Merkle checkpoint over it.
 *
 * ONE file serves BOTH runtimes, so this is plain JSON with the field names
 * Python's evidence_to_dict writes -- deliberately NOT the C config framework
 * (whose `typename` envelope Python cannot read) and deliberately NOT the
 * `task`/`p1`/`p1_set` key names of the tx catch-up wire form. Same reasoning
 * as the trust ladder (doc/architecture/trust-tiers.md). Mirrors
 * src/autonomous-trust/.../reputation/reputation.py EVIDENCE_* and
 * See doc/architecture/reputation.md, warm start.
 *
 * The schema is pinned so a future shape change is a refusal to rebuild --
 * which degrades safely to clamped restoration -- rather than a misparse. */
#define REP_EVIDENCE_SCHEMA "1"
#define REP_EVIDENCE_FILE   "reputation-history"

/* Hex length of a detached Ed25519 signature (crypto_sign_BYTES * 2). Defined
 * here rather than only in rep_proc.c because the evidence document carries
 * these signatures across the file boundary. */
#define REP_EVIDENCE_SIG_HEX_LEN 128

/** A finalized checkpoint plus the co-signatures that finalized it —
 *  the C mirror of Python's Checkpoint/SignedCheckpoint pair, flattened
 *  because C has no need for the two-level object. */
typedef struct {
    bool    present;      /**< false when the document carried no checkpoint */
    char    proposer_uuid[UUID_STRING_LEN + 1];
    char    root[TX_HASH_HEX_LEN + 1];
    int64_t epoch;
    int     first_index;
    int     count;
    /** Which chain this checkpoint commits to: "" is the node's PRIMARY chain,
     *  a group-uuid is one of a gateway's child-group chains. A gateway keeps
     *  one history per child group, so without this a receiver could not tell
     *  which of its chains to compare the proposed root against. Mirrors
     *  Python Checkpoint.group_uuid (doc/architecture/gateway-reputation-tree.md). */
    char    group_uuid[UUID_STRING_LEN + 1];
    /** voter uuid-str -> string_data(detached hex signature over the
     *  checkpoint designation). Same voter-keyed shape as rep_state's
     *  checkpoint_sigs, and for the same reason: a signature that cannot be
     *  attributed cannot be counted. */
    map_t   sigs;
} rep_checkpoint_t;

/** Initialize (zero + map_init). Every rep_checkpoint_t must be initialized
 *  before use and released with rep_checkpoint_free. */
int  rep_checkpoint_init(rep_checkpoint_t *ckpt);
void rep_checkpoint_free(rep_checkpoint_t *ckpt);

/** Canonical bytes a checkpoint co-signer signs, byte-identical to Python
 *  `Checkpoint.designation`:
 *    "AT-CKPT\0" proposer "|" root "|" epoch "|" first_index "|" count
 *    ["|" group_uuid ]
 *  `nonce` is excluded on both sides (anti-replay only, carried alongside).
 *
 *  @p group_uuid is appended ONLY when non-empty (NULL/"" = the primary chain),
 *  which does two things at once. A primary-chain designation stays
 *  byte-identical to what it was before child chains existed, so every existing
 *  co-signature, pinned corpus scenario and the Python twin keep verifying. And
 *  a child-chain designation can never collide with a primary one, so a
 *  co-signature harvested from a child-group round cannot be replayed as
 *  agreement about the primary chain — which it otherwise could, since two
 *  chains can perfectly well produce the same root, epoch and bounds.
 *
 *  Returns the byte count written, or 0 on truncation/bad input. */
size_t rep_checkpoint_designation(const char *proposer, const char *root,
                                  int64_t epoch, int64_t first_index,
                                  int64_t count, const char *group_uuid,
                                  uint8_t *out, size_t cap);

/** Build the persisted-evidence document for @p hist and @p ckpt.
 *
 *  Only entries with an assigned index are written: an index is what a
 *  committed bilateral entry has, and an un-indexed one is not evidence of
 *  anything yet. Pass a @p ckpt with `present == false` (or NULL) to write a
 *  document whose `checkpoint` is null. Caller owns *out (json_decref). */
int  reputation_evidence_to_json(const tx_history_t *hist,
                                 const rep_checkpoint_t *ckpt, json_t **out);

/** Parse a persisted-evidence document into @p hist_out and @p ckpt_out.
 *
 *  Returns non-zero on anything malformed — wrong schema, non-array chain, an
 *  entry with no index — and on a chain whose hash-linkage does not hold. The
 *  caller treats that as "no usable evidence", which is a SAFE outcome
 *  (restoration falls back to clamped), so strictness costs nothing here while
 *  a misparse would cost a great deal.
 *
 *  @p hist_out is loaded preserving each entry's on-disk index and prev_hash —
 *  it must be, or the Merkle root could not be reproduced. */
int  reputation_evidence_from_json(const json_t *doc, tx_history_t *hist_out,
                                   rep_checkpoint_t *ckpt_out);

/** Merkle root over the sub-window of @p hist that @p ckpt commits to.
 *
 *  The window is selected by ABSOLUTE index rather than taken as the whole
 *  chain: a persisted chain may legitimately run past its checkpoint (commits
 *  land after the checkpoint finalizes, and the file is rewritten when the
 *  fuller co-signature set arrives). It may not fall SHORT — a missing entry
 *  makes the root unreproducible — so this returns non-zero unless exactly
 *  `ckpt->count` contiguous entries are present. */
int  reputation_checkpoint_window_root(const tx_history_t *hist,
                                       const rep_checkpoint_t *ckpt,
                                       char out[TX_HASH_HEX_LEN + 1]);

/** Per-peer upper bound on a restored score, derived from the attested window
 *  and NOTHING else: writes uuid_str -> float_data(ceiling) into @p out.
 *
 *  Appearing in an attested window is not the same as having earned a number.
 *  Verifying only presence leaves the original hole open — a score hand-raised
 *  in `reputation.cfg.json` is still restored in full, because the peer really
 *  does transact. So the evidence bounds the VALUE: the mean of the
 *  counterparty-side scores the window records for the peer, shrunk toward
 *  PREREP_NEUTRAL by REP_RESTORE_SHRINKAGE_K. Shrinkage is what makes a SHORT
 *  attested history unable to justify a high score, so a forger cannot mint
 *  the shortest window that verifies.
 *
 *  @p self_uuid_str is excluded (our own score is not a peer judgement); pass
 *  NULL to include every peer. Mirrors Python
 *  ReputationProcess._evidence_ceilings. */
int  reputation_evidence_ceilings(const tx_history_t *hist,
                                  const rep_checkpoint_t *ckpt,
                                  const char *self_uuid_str, map_t *out);

/* Committed bilateral transactions a peer needs inside the attested window
 * before the evidence bounds its score at all; below this it is uncovered and
 * clamped to the unverified tier. Mirrors RESTORE_EVIDENCE_MIN_TX. */
#define REP_RESTORE_EVIDENCE_MIN_TX 1
/* Pseudo-count shrinking the evidence-derived ceiling toward PREREP_NEUTRAL.
 * This is the security parameter of the whole mechanism: it sets how MUCH
 * attested history a peer needs before the window can justify an elevated
 * restored tier. Larger -> more history required. Mirrors Python
 * RESTORE_SHRINKAGE_K; override with AT_REP_RESTORE_SHRINKAGE_K. */
#define REP_RESTORE_SHRINKAGE_K_DEFAULT 3.0
#define REP_RESTORE_SHRINKAGE_K \
    (reputation_env_double("AT_REP_RESTORE_SHRINKAGE_K", \
                           REP_RESTORE_SHRINKAGE_K_DEFAULT))

/****************************
 * Staleness decay (why warm start is safe)
 ****************************/

/* Earned reputation is a MEMORY, and memory must fade: otherwise a
 * warm-started score would be trusted forever on the strength of activity
 * hours or days old. These mirror repprocess.py's REPUTATION_DECAY_*.
 *
 * ASYMMETRIC by design: decay only erodes reputation ABOVE the asymptote. A
 * score at or below it is returned unchanged, because mere absence must never
 * rehabilitate a distrusted node. */
#define REP_DECAY_ASYMPTOTE_DEFAULT 0.21   /* just above neutral, above cut-off */
#define REP_DECAY_ASYMPTOTE \
    (reputation_env_double("AT_REP_DECAY_ASYMPTOTE", REP_DECAY_ASYMPTOTE_DEFAULT))
#define REP_DECAY_ONSET      3600.0        /* s idle before decay begins */
#define REP_DECAY_HALF_LIFE  86400.0       /* s for the above-asymptote gap to halve */
#define REP_DECAY_SWEEP_INTERVAL 60.0      /* min s between live sweeps */

/** Relax an operational reputation toward almost-neutral as a function of
 *  idle time. A score at or below REP_DECAY_ASYMPTOTE is returned unchanged;
 *  above it, the gap decays exponentially after the onset grace period and
 *  never overshoots below the asymptote. Pure function — mirrors Python
 *  ReputationProcess._decayed_score. */
double reputation_decayed_score(double score, double idle_seconds);

/* paxos_id_index is provided by algorithms/paxos.h */

/****************************
 * Error codes
 ****************************/

#define EREP_NOTX 250
DECLARE_ERROR(EREP_NOTX, "Transaction not found");

#define EREP_NOPEER 251
DECLARE_ERROR(EREP_NOPEER, "Peer not found in reputation map");

#define EREP_CHAIN_FULL 252
DECLARE_ERROR(EREP_CHAIN_FULL, "Transaction chain is full");


/** @} */ /* end of internal_reputation */

#endif  /* REPUTATION_H */
