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

#include <string.h>
#include <math.h>
#include <time.h>
#include <pthread.h>
#include <unistd.h>
#include <sys/stat.h>

#include "processes/processes.h"
#include "processes/capabilities.h"
#include "reputation/reputation.h"
#include "algorithms/paxos.h"
#include "structures/map.h"
#include "structures/array.h"
#include "structures/data.h"
#include "utilities/message.h"
#include "utilities/msg_types_priv.h"
#include "utilities/exception.h"
#include "utilities/probes.h"
#include "network/net_message.h"
#include "identity/identity_priv.h"   /* public_identity_to/from_json, unhexlify */
#include "zta/zta_verifier.h"
#include "zta/zta_policy.h"
#include "config/configuration.h"   /* get_cfg_dir, CFG_PATH_LEN */
#include "config/discover.h"        /* CFG_FILE_EXT */
#include "reputation/rep_proc_priv.h"

#define EREP_PAXOS 253
DEFINE_ERROR(EREP_PAXOS, "Paxos consensus error");

/****************************
 * Reputation-derived trust-tier elevation — mirrors Python
 * ReputationProcess TIER_FLOORS / _trust_tier / _publish_tier_change
 * (repprocess.py:52-57, 583-619). Each entry is (score_floor, tier).
 * Walks top-down so the highest matching floor wins; scores below
 * the lowest map to 0.
 *
 * Keep monotonically increasing in floor and tier to preserve the
 * walk-from-top invariant. Any change here must land in Python's
 * TIER_FLOORS at the same time.
 *
 * NOTE: trust tier is distinct from network rank (peer->rank) — rank
 * is topology / one-hop reachability, populated from identity.json.
 * See doc/architecture/trust-tiers.md §1 for the disambiguation.
 ****************************/

typedef struct { double floor; int tier; } tier_floor_t;
static const tier_floor_t TIER_FLOORS[] = {
    {0.50, 1},
    {0.65, 2},
    {0.80, 3},
    {0.90, 4},
};
#define NUM_TIER_FLOORS (sizeof(TIER_FLOORS) / sizeof(TIER_FLOORS[0]))

static int _trust_tier(double score)
{
    for (int i = (int)NUM_TIER_FLOORS - 1; i >= 0; i--) {
        if (score >= TIER_FLOORS[i].floor)
            return TIER_FLOORS[i].tier;
    }
    return 0;
}

/* The highest score that still maps to @p tier — the next tier's floor,
 * stepped down by one representable double.
 *
 * Derived from TIER_FLOORS rather than written as a literal so retuning the
 * ladder cannot leave a stale ceiling behind that quietly grants the tier
 * above. nextafter (not a hand-picked epsilon) because the clamp has to
 * satisfy _trust_tier(ceiling) == tier exactly: an epsilon too small rounds
 * back onto the floor and grants the very tier the clamp exists to withhold.
 * The top tier has no ceiling. Mirrors Python _tier_ceiling. */
static double _tier_ceiling(int tier)
{
    for (size_t i = 0; i < NUM_TIER_FLOORS; i++) {
        if (TIER_FLOORS[i].tier == tier + 1)
            return nextafter(TIER_FLOORS[i].floor, 0.0);
    }
    return 1.0;
}

/****************************
 * Verifiable warm start constants — mirror repprocess.py.
 ****************************/

/* Tier a peer may hold on restoration when the persisted evidence does not
 * cover it. Tier 1 (presence/communication) because an
 * authenticated-but-COMPROMISED asset passes ZTA admission by definition —
 * credentials are exactly what it holds — so restoring a historically-earned
 * high tier the instant it is admitted re-opens the hole the system exists to
 * close, and for a short-lived asset there is no time for behavioural
 * re-evaluation to catch it first. Mirrors UNVERIFIED_RESTORE_TIER. */
#define REP_UNVERIFIED_RESTORE_TIER 1

/* Basename of the operational reputation snapshot, whose evidence
 * `reputation-history.cfg.json` attests. Its MTIME is what the offline-gap
 * decay measures from (_seed_idle_from_snapshot). */
#define REP_SNAPSHOT_FILE "reputation"

/* Seconds between checkpoint proposals this node originates (0 disables).
 * Checkpointing used to be reactive only — nothing ever triggered it — so no
 * deployment held a checkpoint, which meant no warm start could verify: the
 * mechanism above would have been unreachable in practice. Mirrors Python
 * CHECKPOINT_INTERVAL / AT_REP_CHECKPOINT_SEC. */
#define REP_CHECKPOINT_INTERVAL_DEFAULT 300.0
#define REP_CHECKPOINT_INTERVAL \
    (reputation_env_double("AT_REP_CHECKPOINT_SEC", \
                           REP_CHECKPOINT_INTERVAL_DEFAULT))

/* Forward declaration — definition follows _ensure_init/state struct.
 * Emits a local-IPC tier_update to the identity process queue iff the
 * peer's trust tier has changed since the last publication, and an
 * exclude/readmit control message to the network process iff the peer
 * crossed the COMM_CUTOFF communication cut-off. Mirrors Python's
 * `_publish_tier_change` in repprocess.py. Takes @p proc to resolve the
 * peer's address (from proc->protocol.peers) for the exclusion message. */
static void _publish_tier_change(const process_t *proc,
                                 const uuid_t peer_uuid, double score);
/* Resolve @p peer_uuid to an address and send a Network exclude/readmit
 * control message to the network process. Mirrors Python
 * ReputationProcess._publish_exclusion. */
static void _publish_exclusion(const process_t *proc,
                               const uuid_t peer_uuid, bool excluded);
/* Forward declaration — definition sits with the rest of the verifiable
 * warm-start code (ISSUES §10.3), below the state struct it writes. Records a
 * finalized checkpoint's root, window bounds and co-signatures, and persists
 * the evidence document. */
static void _store_checkpoint(const process_t *proc, const char *proposer,
                              const char *root, int64_t epoch,
                              int first_index, int count,
                              const char *chain_key, json_t *sigs);
/* Forward declaration — stamps "we just transacted with this peer" so the
 * staleness sweep leaves an actively-interacting peer alone. Takes
 * rep_state.lock itself, so callers must NOT hold it. */
static void _note_interaction(const uuid_t peer_uuid);

/* Slash "reason" that lifts (rather than floors) a target: releases the
 * slash floor, restores the score to PREREP_NEUTRAL, and re-admits it.
 * Recovery is explicit-only. Mirror: Python SlashAttestation.REASON_REHABILITATE. */
#define REP_SLASH_REASON_REHABILITATE "rehabilitate"
/* The other reasons are not branched on here, but the slash designation covers
 * the reason string, so the spellings have to match Python's
 * SlashAttestation.REASON_* exactly or a co-signature verifies nowhere.
 * Declared in rep_proc_priv.h so the conformance adapter shares them rather
 * than repeating the literals. */

/****************************
 * Protocol-string definitions (declared `extern char[]` in
 * reputation.h). Writable arrays so `net_msg.function` (typed
 * `char *`) accepts them without a `(char *)` cast under
 * `-Wwrite-strings`.
 ****************************/

char REP_PROTO_REQUEST[]     = "ask permission";
char REP_PROTO_GRANT[]       = "permission granted";
char REP_PROTO_NACK[]        = "try again";
char REP_PROTO_BACKDATE[]    = "out of date";
char REP_PROTO_TX[]          = "transaction";
char REP_PROTO_ACCEPTED[]    = "tx accepted";
char REP_PROTO_COMMITTED[]   = "tx committed";
char REP_PROTO_OUTDATED[]    = "update needed";
char REP_PROTO_UPDATE[]      = "latest update";
char REP_PROTO_REP_REQ[]     = "request reputation";
char REP_PROTO_REP_RESP[]    = "reputation response";
char REP_PROTO_CONSENSUS_REP_REQ[] = "request consensus reputation";
char REP_PROTO_LOCAL_QUERY[] = "local_rep_query";
char REP_PROTO_LOCAL_RESP[]  = "local_rep_response";
/* App -> AT (via the daemon main loop): re-emit the peer view on the
 * app-facing carrier. See doc/architecture/app-peer-carrier.md. */
char REP_PROTO_APP_ROSTER[]  = AT_APP_ROSTER_REQUEST;
char REP_PROTO_SLASH_PROPOSE[] = "slash propose";
char REP_PROTO_SLASH_SIGN[]    = "slash sign";
char REP_PROTO_SLASH_FINAL[]   = "slash final";
char REP_PROTO_CHECKPOINT_PROPOSE[] = "checkpoint propose";
char REP_PROTO_CHECKPOINT_SIGN[]    = "checkpoint sign";
char REP_PROTO_CHECKPOINT_FINAL[]   = "checkpoint final";
char REP_PROTO_REP_RESOLVE[]        = "resolve reputation";
char REP_PROTO_REP_RESOLVED[]       = "resolved reputation";

/* Local-IPC `function` field for the tier_update message reputation
 * emits to identity. Writable buffer so the assignment to
 * `nmsg->function` (typed `char *`) compiles under -Wwrite-strings.
 * Value must match Python IdentityProtocol.tier_update verbatim. */
static char ID_TIER_FUNC[] = "tier_update";
/* Local-IPC function field for the tier_lost message reputation emits
 * to negotiation when a peer's tier drops. Mirrors Python
 * IdentityProtocol.tier_lost verbatim. See doc/architecture/
 * trust-tiers.md §7.2 — negotiation's handle_tier_lost cancels any
 * in-flight tasks whose capability.required_tier exceeds the new tier.
 */
static char NEG_TIER_LOST_FUNC[] = "tier_lost";
/* Local-IPC function fields for the reputation communication cut-off:
 * reputation emits these to the network process, which excludes/readmits the
 * carried address. Matched by value against net_proc's NET_FN_EXCLUDE /
 * NET_FN_READMIT (network.h) — same cross-process string-match convention as
 * ID_TIER_FUNC above. Value must match Python Network.exclude / readmit. */
static char NET_EXCLUDE_FUNC[] = "exclude";
static char NET_READMIT_FUNC[] = "readmit";

/****************************
 * Process state (file-scope static, thread-safe via mutex)
 ****************************/

#define STALE_TIMEOUT    300  /* seconds */

static struct {
    tx_history_t history;
    /* Gateway reputation tree: one chain per child group this node gateways,
     * keyed by group-uuid string -> object_ptr_data(tx_history_t *). Empty on a
     * leaf node, and every code path below falls back to the single `history`
     * when it is, so leaf behaviour is unchanged. Mirrors Python
     * ReputationProcess.child_histories. See
     * doc/architecture/gateway-reputation-tree.md and ISSUES.md §10.2. */
    map_t child_hist;
    /* Per-chain finalized checkpoints: chain key ("" = primary) ->
     * object_ptr_data(rep_chain_ckpt_t *). See _ckpt_slot_locked. */
    map_t chain_ckpts;
    /* Per-paxos-round group binding: paxos key -> string_data(group-uuid), set
     * by the proposer so the accept/commit path routes to the round's own chain
     * and sizes its quorum against that group rather than the conflated peer
     * list. Mirrors Python's round_group. */
    map_t round_group;
    /* --- Deep resolution: one peer, on demand (ISSUES.md 10.2) ------------
     * resolve_pending: query-id -> object_ptr_data(rep_resolve_t *), a query
     * we are RELAYING and the neighbour its answer must go back to. The only
     * state the capability adds anywhere, and it exists because the answer
     * travels the reverse path -- nobody outside a boundary ever exchanges a
     * message with anybody inside it, so each hop must remember its caller.
     * resolve_outstanding: query-id -> rep_resolve_t *, queries WE originated.
     * resolve_seen: query-id -> integer_data(1), the loop guard; a briefly
     * cyclic tree would otherwise circulate a query until its TTL burned down
     * at every node it touched. Mirrors Python _resolve_pending /
     * _resolve_outstanding / _resolve_seen. */
    map_t resolve_pending;
    map_t resolve_outstanding;
    map_t resolve_seen;
    /* peer uuid-str -> object_ptr_data(rep_resolved_t *): answers we accepted
     * or refused, with the reason kept beside the verdict. */
    map_t resolved_reps;
    reputations_t reputations;
    map_t my_requests;     /* uuid_str -> tx_score_t* (pending Paxos requests) */
    map_t updates;         /* uuid_str -> json_t* (pending chain updates) */
    array_t requested_reps; /* array of pending reputation responses */
    paxos_instance_t paxos;
    int num_peers;
    pthread_mutex_t lock;
    bool initialized;
    /* Conformance-only: when true, handle_nack inlines a retry "ask
     * permission" emission (Python's _try_again thread is skipped under
     * sync dispatch). Production must leave this false; default 0
     * preserves existing behavior. */
    bool synchronous_dispatch;
    /* Last published trust tier per peer uuid-string. Suppresses
     * redundant tier_update IPC when the tier hasn't changed.
     * Mirrors Python's self.peer_tiers in repprocess.py. */
    map_t peer_tiers;
    /* Paxos rounds already committed locally. Keyed by paxos_id_index
     * (id1,id2), value is integer_data(1) — used as a set. Prevents
     * handle_accepted from re-firing its commit block on every late
     * ACCEPTED that arrives after majority is crossed; without this,
     * the same proposer would broadcast `committed` once per peer above
     * majority, and duplicate broadcasts corrupt the bilateral
     * Transaction (tx_history_update would set p2 = p1 = proposer).
     *
     * Capped at COMMITTED_ROUNDS_CAP (FIFO). The ring buffer tracks
     * insertion order so we can evict the oldest key when full.
     * Without this, the map grew without bound during long runs.
     * Mirrors Python's OrderedDict-based ordered set in
     * ReputationProcess.committed_paxos_rounds. */
    map_t committed_paxos_rounds;
    char committed_paxos_ring[COMMITTED_ROUNDS_CAP][64];
    int  committed_paxos_ring_head;  /* next slot to overwrite */
    int  committed_paxos_ring_len;   /* up to COMMITTED_ROUNDS_CAP */
    /* Per-peer latch for the CTFT/pure-reputation dispatch in
     * handle_rep_request. uuid_str -> integer_data(0|1). Combined
     * with COOP_ENTER/COOP_EXIT to give the mode switch hysteresis;
     * mirrors Python's self._coop_mode in repprocess.py. */
    map_t coop_mode;
    /* Per-task transaction_weight cache (task_uuid_str -> int).
     * Populated at proposer time (handle_grant before broadcasting
     * REP_PROTO_TX) and at receiver time (handle_transaction) so both
     * sides agree on the weight for any given task. Consumed by
     * reputation_pure / reputation_consensus to apply the
     * Capability.transaction_weight multiplier from
     * doc/architecture/trust-tiers.md §5. FIFO-bounded at
     * 2 * MAX_CHAIN_LEN entries; ring tracks insertion order so the
     * oldest is evictable. Mirrors Python's self.task_weights. */
    map_t task_weights;
    char  task_weights_ring[2 * MAX_CHAIN_LEN][UUID_STRING_LEN + 1];
    int   task_weights_ring_head;
    int   task_weights_ring_len;
    /* Per-task capability tier cache (task_uuid_str -> int), parallel to
     * task_weights and evicted in lockstep with it (every task_tiers key is
     * also a task_weights key; _record_task_weight_locked removes both at the
     * same points, so no separate ring is needed). Feeds the per-tier
     * consensus view (reputation_consensus_by_tier). Mirrors Python's
     * self.task_tiers (deferred.md §2.3). */
    map_t task_tiers;
    /* --- Slashing (fast-penalty path) ---
     * Mirrors Python ReputationProcess._slashed / _slash_sigs /
     * _slash_pending. A finalized slash floors the target's reputation
     * immediately (bypassing the consensus EMA). The floor value is
     * mirrored into rep_state.reputations so reputation_get_peer_reputation
     * (and the consensus handler) reflect it. */
    map_t slashed;        /* target_uuid_str -> integer_data(epoch) */
    /* "target:epoch:voter" -> string_data(detached hex signature over the
     * attestation designation). Keyed by VOTER, not a bare count: the count
     * this replaced had no voter identity, so replaying one ack drove it past
     * quorum and a single peer could finalize alone. */
    map_t slash_sigs;
    /* "target:epoch" -> string_data(JSON {slasher_uuid, reason, floor_score}).
     * The whole round, because a co-signer and the finalizer must both
     * reproduce the proposer's designation byte for byte. */
    map_t slash_pending;
    int64_t slash_epoch;
    /* Communication cut-off exclusion set: peers whose reputation fell below
     * COMM_CUTOFF and were excluded at the network layer. Tracks the crossing
     * so _publish_tier_change emits exclude/readmit only on an actual
     * transition. Mirrors Python ReputationProcess._excluded. (C has no
     * reputation persistence, so there is no snapshot to boot-reseed from —
     * the Python two-sided persist filter + _seed_exclusions_from_snapshot
     * have no C counterpart; see REPUTATION_THRESHOLDS_TODO.md.) */
    map_t excluded;       /* peer_uuid_str -> integer_data(1) */
    /* --- Phase 2: quorum-signed Merkle checkpoints ---
     * Mirrors Python ReputationProcess._checkpoint / _checkpoint_sigs /
     * _checkpoint_pending. A member co-signs a proposed checkpoint only when
     * its own transaction_window_root matches; on quorum the proposer
     * finalizes and every node stores the agreed root. */
    /* "proposer:epoch:voter" -> string_data(detached hex signature over the
     * checkpoint designation); same voter-keyed shape and same reason as
     * slash_sigs above. */
    map_t checkpoint_sigs;
    /* "proposer:epoch" -> string_data(JSON {root, first_index, count}) -- the
     * window bounds travel because the designation covers them. */
    map_t checkpoint_pending;
    char  checkpoint_root[TX_HASH_HEX_LEN + 1];  /* latest finalized root */
    int64_t checkpoint_epoch;  /* epoch of the latest finalized checkpoint */
    bool  checkpoint_set;      /* a checkpoint has been finalized/stored */
    /* --- Verifiable warm start (ISSUES §10.3) ---
     * The rest of the finalized checkpoint, kept because the PERSISTED
     * evidence has to carry it: a boot-time rebuild verifies the same quorum a
     * live receiver does, and a root with no window bounds and no signatures
     * beside it is a number anyone with write access to the config directory
     * could have chosen. Mirrors Python's _checkpoint / _checkpoint_sigs_final.
     */
    int   checkpoint_first_index;
    int   checkpoint_count;
    char  checkpoint_proposer[UUID_STRING_LEN + 1];
    map_t checkpoint_sigs_final;   /* voter uuid-str -> string_data(hex sig) */
    /* Monotonic epoch for checkpoints THIS node originates (distinct from
     * checkpoint_epoch, which is whatever epoch we last stored — possibly
     * another node's). Resumed past the persisted checkpoint at boot so a
     * restart cannot reuse an epoch its peers have already deduped. */
    int64_t checkpoint_own_epoch;
    /* Periodic-origination clocks (see _maybe_checkpoint). The flag rather
     * than a sentinel value because the host build is -Wfloat-equal: a "not
     * set yet" double cannot be tested for equality. -1 head == no window has
     * been checkpointed. */
    double  next_checkpoint_at;
    bool    checkpoint_phase_taken;
    int     last_checkpoint_head;
    /* Staleness decay: peer uuid-str -> float_data(epoch seconds of our most
     * recent committed transaction with that peer). Seeded at boot from the
     * persisted snapshot's mtime, so the gap a peer spent out of contact while
     * we were down counts as idle time. Mirrors Python _last_interaction. */
    map_t   last_interaction;
    double  last_decay_sweep;
    bool    decay_swept;
    /* Child-group chains already attempted by _restore_child_evidence, and the
     * persisted score each clamped peer was clamped away FROM -- the upper
     * bound on any later lift, so late evidence restores standing instead of
     * inventing it (§10.2). */
    map_t   child_evidence_tried;
    map_t   restore_clamped;
    /* Catch-up quorum: handle_update fires the chain merge once this many
     * peers have reported. Production default is 3 (mirrors Python's
     * self.num_updates); a conformance fixture may lower it to 1 so a
     * single-step scenario can exercise the verifiable catch-up path
     * (the harness resets state per step, so cross-step accumulation
     * isn't portable). */
    int num_updates;
} rep_state;

static void _ensure_init(void)
{
    if (!rep_state.initialized)
    {
        tx_history_init(&rep_state.history);
        map_init(&rep_state.child_hist);
        map_init(&rep_state.chain_ckpts);
        map_init(&rep_state.round_group);
        map_init(&rep_state.resolve_pending);
        map_init(&rep_state.resolve_outstanding);
        map_init(&rep_state.resolve_seen);
        map_init(&rep_state.resolved_reps);
        reputations_init(&rep_state.reputations);
        map_init(&rep_state.my_requests);
        map_init(&rep_state.updates);
        array_init(&rep_state.requested_reps);
        map_init(&rep_state.peer_tiers);
        map_init(&rep_state.committed_paxos_rounds);
        rep_state.committed_paxos_ring_head = 0;
        rep_state.committed_paxos_ring_len = 0;
        map_init(&rep_state.coop_mode);
        map_init(&rep_state.task_weights);
        rep_state.task_weights_ring_head = 0;
        rep_state.task_weights_ring_len = 0;
        map_init(&rep_state.task_tiers);
        map_init(&rep_state.slashed);
        map_init(&rep_state.slash_sigs);
        map_init(&rep_state.slash_pending);
        rep_state.slash_epoch = 0;
        map_init(&rep_state.excluded);
        map_init(&rep_state.checkpoint_sigs);
        map_init(&rep_state.checkpoint_pending);
        rep_state.checkpoint_root[0] = '\0';
        rep_state.checkpoint_epoch = 0;
        rep_state.checkpoint_set = false;
        map_init(&rep_state.checkpoint_sigs_final);
        rep_state.checkpoint_first_index = 0;
        rep_state.checkpoint_count = 0;
        rep_state.checkpoint_proposer[0] = '\0';
        rep_state.checkpoint_own_epoch = 0;
        rep_state.next_checkpoint_at = 0.0;
        rep_state.checkpoint_phase_taken = false;
        rep_state.last_checkpoint_head = -1;
        map_init(&rep_state.last_interaction);
        rep_state.last_decay_sweep = 0.0;
        rep_state.decay_swept = false;
        map_init(&rep_state.child_evidence_tried);
        map_init(&rep_state.restore_clamped);
        rep_state.num_updates = 3;  /* catch-up quorum; mirrors Python default */
        /* paxos_init is called in reputation_run after num_peers is known */
        rep_state.num_peers = 0;
        pthread_mutex_init(&rep_state.lock, NULL);
        rep_state.initialized = true;
    }
}

/* ---- Gateway reputation tree: chain routing (ISSUES.md §10.2) -------------
 *
 * A gateway belongs to more than one cohort, and their transaction histories
 * must not be merged: a subtree's reputation is that subtree's, and the parent
 * cohort has its own. So a commit tagged with a child group's uuid routes to
 * that group's chain, created on first use. Mirrors Python
 * ReputationProcess._chain_for_group / _chain_key.
 */

/* True if `key` names a cohort this node gateways. */
static bool _is_child_group(const process_t *proc, const char *key)
{
    if (proc == NULL || key == NULL || key[0] == '\0'
        || proc->protocol.child_groups == NULL)
        return false;
    data_t *unused = NULL;
    return map_get(proc->protocol.child_groups, (map_key_t)key, &unused) == 0;
}

/* Normalize a group-uuid to a CHAIN KEY: "" for the primary chain, the
 * group-uuid for a child chain.
 *
 * NULL, empty, our own primary group's uuid, and any uuid we do NOT gateway all
 * resolve to the primary chain. That last case is deliberate: an unrecognized
 * group must not be able to mint a chain, or a peer could make us accumulate
 * history under a cohort we have nothing to do with. */
static void _chain_key(const process_t *proc, const char *group_uuid,
                       char *out, size_t cap)
{
    out[0] = '\0';
    if (group_uuid == NULL || group_uuid[0] == '\0')
        return;
    char primary[UUID_STRING_LEN + 1] = {0};
    if (proc != NULL)
        uuid_unparse_lower(proc->protocol.group.uuid, primary);
    if (strncmp(group_uuid, primary, UUID_STRING_LEN + 1) == 0)
        return;
    if (!_is_child_group(proc, group_uuid))
        return;
    snprintf(out, cap, "%s", group_uuid);
}

/* The history a chain key names, creating a child chain on first use. Caller
 * holds rep_state.lock. */
static tx_history_t *_chain_for_key_locked(const char *chain_key)
{
    if (chain_key == NULL || chain_key[0] == '\0')
        return &rep_state.history;
    data_t *existing = NULL;
    if (map_get(&rep_state.child_hist, (map_key_t)chain_key, &existing) == 0
        && existing != NULL)
    {
        void *hp = NULL;
        if (data_object_ptr(existing, &hp) == 0 && hp != NULL)
            return (tx_history_t *)hp;
    }
    tx_history_t *fresh = calloc(1, sizeof(tx_history_t));
    if (fresh == NULL)
        return &rep_state.history;   /* degrade to the primary chain, never NULL */
    tx_history_init(fresh);
    data_t *d = object_ptr_data(fresh, sizeof(tx_history_t));
    if (d == NULL || map_set(&rep_state.child_hist, (map_key_t)chain_key, d) != 0)
    {
        tx_history_free(fresh);
        free(fresh);
        return &rep_state.history;
    }
    return fresh;
}

/* Convenience: resolve a group-uuid straight to its chain. Caller holds the
 * lock. */
static tx_history_t *_chain_for_group_locked(const process_t *proc,
                                             const char *group_uuid)
{
    char key[UUID_STRING_LEN + 1];
    _chain_key(proc, group_uuid, key, sizeof(key));
    return _chain_for_key_locked(key);
}

/* Remember which group a paxos round belongs to, so the accept/commit path can
 * route to the round's chain. Caller holds the lock. */
static void _set_round_group_locked(const char *paxos_key, const char *group_uuid)
{
    if (paxos_key == NULL || group_uuid == NULL || group_uuid[0] == '\0')
        return;
    map_set(&rep_state.round_group, (map_key_t)paxos_key,
            string_data((string_t)group_uuid, strlen(group_uuid)));
}

/* The group a paxos round was bound to, or "" (primary). Caller holds the
 * lock. */
static void _get_round_group_locked(const char *paxos_key, char *out, size_t cap)
{
    out[0] = '\0';
    if (paxos_key == NULL)
        return;
    data_t *d = NULL;
    if (map_get(&rep_state.round_group, (map_key_t)paxos_key, &d) != 0
        || d == NULL)
        return;
    string_t s = NULL;
    if (data_string_ptr(d, &s) == 0 && s != NULL)
        snprintf(out, cap, "%s", s);
}

/* Members of a group, by filtering the peer list against the group's address
 * map -- the C twin of Python's _members_of_group. `Group` carries an address
 * map rather than a uuid roster, and a gateway's peer list conflates every
 * group it belongs to, so this is how a per-group quorum gets sized. */
static group_t *_child_group_locked(const process_t *proc, const char *group_uuid)
{
    if (proc == NULL || group_uuid == NULL || group_uuid[0] == '\0'
        || proc->protocol.child_groups == NULL)
        return NULL;
    data_t *gd = NULL;
    if (map_get(proc->protocol.child_groups, (map_key_t)group_uuid, &gd) != 0
        || gd == NULL)
        return NULL;
    void *gp = NULL;
    if (data_object_ptr(gd, &gp) != 0 || gp == NULL)
        return NULL;
    return (group_t *)gp;
}

/* Whether one peer belongs to a group, by address. Factored out of
 * _members_of_group because deep resolution forwards to a group's members and
 * must decide membership by exactly the same rule the quorum is sized by --
 * two answers to "is this peer in that group" would eventually disagree. */
static bool _peer_in_group(const process_t *proc, const public_identity_t *peer,
                           const char *group_uuid)
{
    group_t *grp = _child_group_locked(proc, group_uuid);
    if (grp == NULL || peer == NULL)
        return false;
    map_key_t akey = NULL;
    data_t *aval = NULL;
    bool found = false;
    map_entries_for_each(&grp->address_map, akey, aval)
    {
        string_t addr = NULL;
        if (data_string_ptr(aval, &addr) == 0 && addr != NULL
            && strncmp(addr, peer->address, sizeof(peer->address)) == 0)
            found = true;
    }
    map_end_for_each
    return found;
}

static size_t _members_of_group(const process_t *proc, const char *group_uuid)
{
    if (proc == NULL || group_uuid == NULL || group_uuid[0] == '\0')
        return proc == NULL ? 0 : proc->protocol.num_peers;
    if (_child_group_locked(proc, group_uuid) == NULL)
        return proc->protocol.num_peers;
    size_t count = 0;
    for (size_t i = 0; i < proc->protocol.num_peers; i++)
        if (_peer_in_group(proc, &proc->protocol.peers[i], group_uuid))
            count++;
    return count;
}

/* Majority threshold for a round in `group_uuid`. A non-gateway (no child
 * groups) always uses the historical num_peers/2, so leaf quorum math is
 * unchanged. Mirrors Python _quorum_for_group. */
static size_t _quorum_for_group(const process_t *proc, const char *group_uuid)
{
    if (proc == NULL)
        return 0;
    if (proc->protocol.child_groups == NULL
        || map_size(proc->protocol.child_groups) == 0
        || group_uuid == NULL || group_uuid[0] == '\0')
        return proc->protocol.num_peers / 2;
    return _members_of_group(proc, group_uuid) / 2;
}

/* Per-chain finalized-checkpoint state. A gateway checkpoints each of its
 * chains separately: its own epoch counter, its own quorum, its own evidence
 * file. Keyed by CHAIN KEY ("" = primary), so a leaf node simply has one slot
 * and behaves as before. Mirrors Python's _checkpoints /
 * _checkpoint_sigs_final / _checkpoint_epochs (ISSUES.md §10.2). */
typedef struct {
    char    proposer[UUID_STRING_LEN + 1];
    char    root[TX_HASH_HEX_LEN + 1];
    int64_t epoch;
    int     first_index;
    int     count;
    bool    set;
    map_t   sigs_final;    /* voter uuid-str -> string_data(hex sig) */
    int64_t own_epoch;     /* monotonic epoch for rounds WE originate */
    int     last_head;     /* -1 == this chain has never been checkpointed */
} rep_chain_ckpt_t;

/* The slot for a chain key, created on first use. Caller holds the lock. */
static rep_chain_ckpt_t *_ckpt_slot_locked(const char *chain_key)
{
    const char *key = (chain_key == NULL) ? "" : chain_key;
    data_t *existing = NULL;
    if (map_get(&rep_state.chain_ckpts, (map_key_t)key, &existing) == 0
        && existing != NULL)
    {
        void *sp = NULL;
        if (data_object_ptr(existing, &sp) == 0 && sp != NULL)
            return (rep_chain_ckpt_t *)sp;
    }
    rep_chain_ckpt_t *slot = calloc(1, sizeof(rep_chain_ckpt_t));
    if (slot == NULL)
        return NULL;
    map_init(&slot->sigs_final);
    slot->last_head = -1;
    data_t *d = object_ptr_data(slot, sizeof(rep_chain_ckpt_t));
    if (d == NULL || map_set(&rep_state.chain_ckpts, (map_key_t)key, d) != 0)
    {
        map_free(&slot->sigs_final);
        free(slot);
        return NULL;
    }
    return slot;
}

/* Mirror the primary slot into the flat fields the older observables read
 * (reputation_get_checkpoint_root, the conformance snapshot, slash evidence's
 * fast path). Keeping one mirror in one place beats branching on "primary or
 * not" at a dozen call sites. Caller holds the lock. */
static void _mirror_primary_ckpt_locked(void)
{
    rep_chain_ckpt_t *slot = _ckpt_slot_locked("");
    if (slot == NULL)
        return;
    snprintf(rep_state.checkpoint_root, sizeof(rep_state.checkpoint_root),
             "%s", slot->root);
    snprintf(rep_state.checkpoint_proposer,
             sizeof(rep_state.checkpoint_proposer), "%s", slot->proposer);
    rep_state.checkpoint_epoch = slot->epoch;
    rep_state.checkpoint_first_index = slot->first_index;
    rep_state.checkpoint_count = slot->count;
    rep_state.checkpoint_set = slot->set;
}

/* Look up the transaction_weight for a capability by name. Mirrors
 * Python's _resolve_tx_weight: empty name → 1, unknown cap → 1,
 * otherwise the cap's transaction_weight (clamped to ≥1 because
 * proto3's 0-sentinel normalises to 1 in sync_from_message). */
static int _resolve_tx_weight(const char *cap_name)
{
    if (cap_name == NULL || cap_name[0] == '\0')
        return 1;
    capability_t *cap = find_capability(cap_name);
    if (cap == NULL)
        return 1;
    int w = cap->transaction_weight;
    return w > 0 ? w : 1;
}

/* Look up the required_tier for a capability by name (deferred.md §2.3).
 * Mirrors Python's _resolve_tx_tier: empty name → 0, unknown cap → 0,
 * otherwise the cap's required_tier (clamped to ≥0). Feeds the per-tier
 * consensus view via the task_tiers cache. */
static int _resolve_tx_tier(const char *cap_name)
{
    if (cap_name == NULL || cap_name[0] == '\0')
        return 0;
    capability_t *cap = find_capability(cap_name);
    if (cap == NULL)
        return 0;
    int t = cap->required_tier;
    return t > 0 ? t : 0;
}

/* Insert into rep_state.task_weights with FIFO eviction at the cap.
 * Caller must hold rep_state.lock. Refreshes order on re-insert so a
 * recent update isn't immediately evicted by an unrelated insert —
 * matches Python's _record_task_weight (pop-then-insert).
 *
 * Key type is `char *` (no const view) because that is what the
 * project's map_t API expects; the helper copies the key into the
 * map's internal storage and the ring buffer, so the caller's
 * buffer lifetime is not extended beyond this call. */
static void _record_task_weight_locked(char *task_uuid_str, int weight)
{
    if (task_uuid_str == NULL || task_uuid_str[0] == '\0') return;
    /* If present, drop the existing entry from both map AND ring so
     * the re-insert puts it at the tail. */
    data_t *existing = NULL;
    if (map_get(&rep_state.task_weights, task_uuid_str, &existing) == 0
        && existing != NULL)
    {
        map_remove(&rep_state.task_weights, task_uuid_str);
        map_remove(&rep_state.task_tiers, task_uuid_str);  /* lockstep (§2.3) */
        /* Best-effort ring compaction: walk and remove matching slot.
         * O(N) but N <= 2*MAX_CHAIN_LEN, and refresh hits are rare. */
        for (int i = 0; i < rep_state.task_weights_ring_len; i++)
        {
            int slot = (rep_state.task_weights_ring_head
                        - rep_state.task_weights_ring_len + i
                        + (int)(sizeof(rep_state.task_weights_ring)
                                / sizeof(rep_state.task_weights_ring[0])))
                       % (int)(sizeof(rep_state.task_weights_ring)
                               / sizeof(rep_state.task_weights_ring[0]));
            if (strncmp(rep_state.task_weights_ring[slot],
                        task_uuid_str, UUID_STRING_LEN) == 0)
            {
                rep_state.task_weights_ring[slot][0] = '\0';
                break;
            }
        }
    }

    /* Insert new entry. */
    data_t *w_dat = integer_data(weight > 0 ? weight : 1);
    if (w_dat == NULL) return;
    map_set(&rep_state.task_weights, task_uuid_str, w_dat);

    int cap = (int)(sizeof(rep_state.task_weights_ring)
                    / sizeof(rep_state.task_weights_ring[0]));
    if (rep_state.task_weights_ring_len >= cap)
    {
        /* Evict oldest non-empty slot. */
        int evict_slot = (rep_state.task_weights_ring_head + 1) % cap;
        while (rep_state.task_weights_ring[evict_slot][0] == '\0'
               && evict_slot != rep_state.task_weights_ring_head)
        {
            evict_slot = (evict_slot + 1) % cap;
        }
        if (rep_state.task_weights_ring[evict_slot][0] != '\0')
        {
            map_remove(&rep_state.task_weights,
                       rep_state.task_weights_ring[evict_slot]);
            map_remove(&rep_state.task_tiers,           /* lockstep (§2.3) */
                       rep_state.task_weights_ring[evict_slot]);
            rep_state.task_weights_ring[evict_slot][0] = '\0';
        }
    }
    else
    {
        rep_state.task_weights_ring_len++;
    }
    rep_state.task_weights_ring_head =
        (rep_state.task_weights_ring_head + 1) % cap;
    strncpy(rep_state.task_weights_ring[rep_state.task_weights_ring_head],
            task_uuid_str, UUID_STRING_LEN);
    rep_state.task_weights_ring[rep_state.task_weights_ring_head][UUID_STRING_LEN] = '\0';
}

/* Record a task's capability tier into rep_state.task_tiers (deferred.md
 * §2.3). No own ring: every tier key is recorded together with its weight
 * key, and _record_task_weight_locked removes both at the same eviction
 * points, so the tier map stays bounded in lockstep with task_weights.
 * Caller must hold rep_state.lock. */
static void _record_task_tier_locked(char *task_uuid_str, int tier)
{
    if (task_uuid_str == NULL || task_uuid_str[0] == '\0') return;
    data_t *t_dat = integer_data(tier > 0 ? tier : 0);
    if (t_dat == NULL) return;
    map_set(&rep_state.task_tiers, task_uuid_str, t_dat);
}

static void _publish_tier_change(const process_t *proc,
                                 const uuid_t peer_uuid, double score)
{
    int new_tier = _trust_tier(score);
    char uuid_str[UUID_STRING_LEN + 1];
    uuid_unparse_lower(peer_uuid, uuid_str);

    pthread_mutex_lock(&rep_state.lock);

    /* Communication cut-off crossing. Checked BEFORE the tier dedup
     * early-return because COMM_CUTOFF (0.1) lies WITHIN tier 0 ([0,0.5)):
     * a 0.15 -> 0.05 move is a tier-0 -> tier-0 no-op for the tier logic
     * yet must still exclude the peer. The exclusion set is the authority;
     * the network process is notified only on an actual crossing. Mirrors
     * Python repprocess._publish_tier_change. */
    int exclusion_action = 0;  /* +1 exclude, -1 readmit, 0 unchanged */
    bool now_excluded = (score < COMM_CUTOFF);
    data_t *ex_dat = NULL;
    bool was_excluded =
        (map_get(&rep_state.excluded, uuid_str, &ex_dat) == 0);
    (void)ex_dat;  /* membership only; value unused */
    if (now_excluded && !was_excluded) {
        map_set(&rep_state.excluded, uuid_str, integer_data(1));
        exclusion_action = 1;
    } else if (was_excluded && !now_excluded) {
        map_remove(&rep_state.excluded, uuid_str);
        exclusion_action = -1;
    }

    /* Dedup: skip if the tier hasn't changed from the last publication
     * for this peer. Mirrors Python's `self.peer_tiers.get(key) == new_tier`
     * guard in repprocess.py. */
    int prior = -1;
    data_t *prior_dat = NULL;
    if (map_get(&rep_state.peer_tiers, uuid_str, &prior_dat) == 0 &&
        prior_dat != NULL) {
        data_integer(prior_dat, &prior);
    }
    if (prior == new_tier) {
        pthread_mutex_unlock(&rep_state.lock);
        /* Still enforce the cut-off crossing even when the tier is
         * unchanged (the whole reason the cut-off check precedes this). */
        if (exclusion_action != 0)
            _publish_exclusion(proc, peer_uuid, exclusion_action > 0);
        return;
    }
    /* Capture demotion BEFORE we overwrite the cache so the
     * subsequent tier_lost emission sees a coherent old→new step.
     * Tier 0 is the floor — prior == -1 means "never published",
     * not a demotion. Mirrors Python's
     * `is_demotion = (old_tier is not None and new_tier < old_tier)`
     * in repprocess.py. */
    bool is_demotion = (prior >= 0 && new_tier < prior);
    data_t *tier_dat = integer_data(new_tier);
    if (tier_dat != NULL)
        map_set(&rep_state.peer_tiers, uuid_str, tier_dat);
    pthread_mutex_unlock(&rep_state.lock);

    /* Enforce the cut-off crossing (network exclude/readmit) alongside the
     * tier change. Done outside rep_state.lock because _publish_exclusion
     * takes the peers read-lock and sends IPC. */
    if (exclusion_action != 0)
        _publish_exclusion(proc, peer_uuid, exclusion_action > 0);

    /* Build the tier_update payload — a 2-element JSON array
     * [uuid_str, tier_int] matching Python's
     * `to_json_string((key, new_tier))` in repprocess.py. */
    json_t *arr = json_array();
    if (arr == NULL) return;
    json_array_append_new(arr, json_string(uuid_str));
    json_array_append_new(arr, json_integer(new_tier));

    generic_msg_t ipc = {0};
    ipc.type = NET_MESSAGE;
    strncpy(ipc.info.net_msg.process, "identity", PROC_NAME_LEN);
    ipc.info.net_msg.function = ID_TIER_FUNC;
    ipc.info.net_msg.encrypt = false;  /* local IPC, no wire egress */
    strncpy(ipc.info.net_msg.return_to, "reputation", PROC_NAME_LEN);
    net_msg_pack_json(&ipc.info.net_msg, arr);

    /* messaging_send keys by process name; "identity" routes to the
     * IdentityProcess queue directly, bypassing the network process. */
    messaging_send("identity", NET_MESSAGE, &ipc, false);

    /* On demotion, also publish tier_lost to negotiation. The
     * payload is identical (uuid_str, new_tier); the receiver is
     * negotiation's handle_tier_lost, which cancels any in-flight
     * tasks the demoted peer can no longer authorize. */
    if (is_demotion) {
        generic_msg_t ipc_neg = {0};
        ipc_neg.type = NET_MESSAGE;
        strncpy(ipc_neg.info.net_msg.process, "negotiation", PROC_NAME_LEN);
        ipc_neg.info.net_msg.function = NEG_TIER_LOST_FUNC;
        ipc_neg.info.net_msg.encrypt = false;
        strncpy(ipc_neg.info.net_msg.return_to, "reputation", PROC_NAME_LEN);
        net_msg_pack_json(&ipc_neg.info.net_msg, arr);
        messaging_send("negotiation", NET_MESSAGE, &ipc_neg, false);
    }

    json_decref(arr);
}


/****************************
 * The app-facing reputation carrier (ethne D5/D18; see
 * doc/architecture/app-peer-carrier.md).
 *
 * Deliberately NOT folded into _publish_tier_change: that function is gated
 * on a tier CROSSING, and a consumer tracking earned reputation needs every
 * change, not only the ones that step over one of four floors. It is also
 * not folded into the tier_update IPC, because that message exists to tell
 * the identity process a coarse tier and giving it the raw score would put a
 * cached second copy of the score store where nothing needs one.
 ****************************/

/* @p rated is the load-bearing argument: an unrated peer reads as
 * PREREP_NEUTRAL, which is also a score a peer can genuinely earn, so a
 * consumer given only the number cannot tell "no information" from
 * "rated 0.2". The score is zeroed when unrated so a consumer that ignores
 * the flag cannot silently read a plausible-looking number. */
static int _publish_reputation(const uuid_t peer_uuid, double score, bool rated)
{
    generic_msg_t msg = {0};
    msg.type = PEER_REPUTATION;
    msg.size = sizeof(peer_reputation_msg_t);
    uuid_copy(msg.info.peer_reputation.peer_uuid, peer_uuid);
    msg.info.peer_reputation.score = rated ? score : 0.0;
    msg.info.peer_reputation.rated = rated;
    return messaging_send(AT_MAIN_QUEUE, PEER_REPUTATION, &msg, false);
}

/* A score this process just committed is by construction rated. */
static void _publish_reputation_change(const uuid_t peer_uuid, double score)
{
    _publish_reputation(peer_uuid, score, true);
}

int reputation_emit_all(const process_t *proc)
{
    if (proc == NULL || !rep_state.initialized)
        return 0;
    uuid_t uuids[DEFAULT_MAX_PEERS];
    peers_read_lock(proc);
    size_t n = proc->protocol.num_peers;
    if (n > DEFAULT_MAX_PEERS)
        n = DEFAULT_MAX_PEERS;
    for (size_t i = 0; i < n; i++)
        uuid_copy(uuids[i], proc->protocol.peers[i].uuid);
    peers_read_unlock(proc);

    int emitted = 0;
    for (size_t i = 0; i < n; i++)
    {
        /* A peer with no rating is reported AS unrated rather than skipped:
         * silence would leave a consumer unable to distinguish "we hold no
         * rating" from "the message was lost". This pull is the only place
         * rated=false can cross, since every change emission is rated. */
        double score = 0.0;
        pthread_mutex_lock(&rep_state.lock);
        bool rated = (reputations_get(&rep_state.reputations, uuids[i], &score) == 0);
        pthread_mutex_unlock(&rep_state.lock);
        if (_publish_reputation(uuids[i], score, rated) == 0)
            emitted++;
    }
    return emitted;
}

/* Handler: the app asked for the current peer view. */
static bool handle_app_roster_request(const process_t *proc,
                                      directory_t *queues, generic_msg_t *msg)
{
    (void)queues;
    (void)msg;
    int n = reputation_emit_all(proc);
    log_debug(proc->logger,
              "Reputation: peer roster request -> %d reputation(s)\n", n);
    return true;
}

/* Resolve @p peer_uuid to its address from the live peer roster and send a
 * Network exclude/readmit control message to the network process. Local IPC
 * only (no wire egress). No-op if the address is unknown (nothing to key the
 * network-layer gate on). Mirrors Python ReputationProcess._publish_exclusion
 * (address resolution + Message(CfgIds.network, Network.exclude/readmit, addr)). */
static void _publish_exclusion(const process_t *proc,
                               const uuid_t peer_uuid, bool excluded)
{
    if (proc == NULL)
        return;
    char address[ADDR_LEN + 1];
    address[0] = '\0';
    peers_read_lock(proc);
    for (size_t i = 0; i < proc->protocol.num_peers; i++) {
        if (uuid_compare(proc->protocol.peers[i].uuid, peer_uuid) == 0) {
            snprintf(address, sizeof(address), "%s",
                     proc->protocol.peers[i].address);
            break;
        }
    }
    peers_read_unlock(proc);
    if (address[0] == '\0') {
        char uuid_str[UUID_STRING_LEN + 1];
        uuid_unparse_lower(peer_uuid, uuid_str);
        log_debug(proc->logger,
                  "Reputation: exclusion %s for %s: no address, gate skipped\n",
                  excluded ? "add" : "remove", uuid_str);
        return;
    }
    generic_msg_t ipc = {0};
    ipc.type = NET_MESSAGE;
    strncpy(ipc.info.net_msg.process, "network", PROC_NAME_LEN);
    ipc.info.net_msg.function = excluded ? NET_EXCLUDE_FUNC : NET_READMIT_FUNC;
    ipc.info.net_msg.encrypt = false;  /* local IPC, no wire egress */
    strncpy(ipc.info.net_msg.return_to, "reputation", PROC_NAME_LEN);
    json_t *body = json_string(address);
    if (body == NULL)
        return;
    net_msg_pack_json(&ipc.info.net_msg, body);
    messaging_send("network", NET_MESSAGE, &ipc, false);
    json_decref(body);
    log_info(proc->logger, "Reputation: %s %s at the network layer\n",
             excluded ? "excluded" : "readmitted", address);
}

/****************************
 * Handler: handle_request (ask permission) — Paxos Phase 1a
 * Validate peer, check id1 > last_id AND chain index matches → grant/nack/backdate
 ****************************/

/*@
  requires \valid(proc);
  requires \valid(queues);
  requires \valid(msg);
  requires proc->logger == \null || \valid(proc->logger);
*/
static bool handle_request(const process_t *proc, directory_t *queues, generic_msg_t *msg)
{
    net_msg_t *nmsg = &msg->info.net_msg;
    log_debug(proc->logger, "Reputation: permission request from %s\n", nmsg->from_whom.nickname);

    /* Unpack (id1, id2, peer_uuid) from JSON payload */
    json_t *payload = NULL;
    if (net_msg_unpack_json(nmsg, &payload) != 0 || payload == NULL)
    {
        log_error(proc->logger, "Reputation: handle_request: failed to unpack JSON\n");
        return false;
    }

    json_t *j_id1     = json_object_get(payload, "id1");
    json_t *j_id2     = json_object_get(payload, "id2");
    json_t *j_peer_uuid = json_object_get(payload, "peer_uuid");

    if (!j_id1 || !j_id2 || !j_peer_uuid)
    {
        json_decref(payload);
        log_error(proc->logger, "Reputation: handle_request: missing JSON fields\n");
        return false;
    }

    int64_t id1 = json_integer_value(j_id1);
    int64_t id2 = json_integer_value(j_id2);
    /* peer_uuid_str is a borrowed pointer into `payload`; copy it out before
     * the json_decref below so the GRANT branch can echo it back without a
     * use-after-free. Preserve NULL (non-string field) so the grant payload
     * omits the key exactly as before rather than emitting an empty string. */
    const char *peer_uuid_borrowed = json_string_value(j_peer_uuid);
    char peer_uuid_buf[UUID_STRING_LEN + 1];
    bool have_peer_uuid = peer_uuid_borrowed != NULL;
    if (have_peer_uuid)
    {
        strncpy(peer_uuid_buf, peer_uuid_borrowed, UUID_STRING_LEN);
        peer_uuid_buf[UUID_STRING_LEN] = '\0';
    }
    const char *peer_uuid_str = have_peer_uuid ? peer_uuid_buf : NULL;

    int64_t out_last_id = 0;
    int out_chain_len = 0;
    paxos_response_t result = paxos_handle_request(&rep_state.paxos, id1, id2,
                                                   &out_last_id, &out_chain_len);

    json_decref(payload);

    if (result == PAXOS_GRANT)
    {
        /* Build grant payload: (id1, id2, peer_uuid, last_id, chain_len) */
        json_t *grant_json = json_object();
        if (grant_json == NULL) {
            log_error(proc->logger, "Reputation: json_object OOM (grant)\n");
            return true;
        }
        json_object_set_new(grant_json, "id1", json_integer(id1));
        json_object_set_new(grant_json, "id2", json_integer(id2));
        json_object_set_new(grant_json, "peer_uuid", json_string(peer_uuid_str));
        json_object_set_new(grant_json, "last_id", json_integer(out_last_id));
        json_object_set_new(grant_json, "chain_len", json_integer(out_chain_len));

        generic_msg_t grant = {0};
        grant.type = NET_MESSAGE;
        strncpy(grant.info.net_msg.process, "reputation", PROC_NAME_LEN);
        grant.info.net_msg.function = REP_PROTO_GRANT;
        grant.info.net_msg.encrypt = true;
        memcpy(&grant.info.net_msg.to_whom, &nmsg->from_whom, sizeof(public_identity_t));
        strncpy(grant.info.net_msg.return_to, "reputation", PROC_NAME_LEN);
        net_msg_pack_json(&grant.info.net_msg, grant_json);
        json_decref(grant_json);

        log_debug(proc->logger, "Reputation: Request granted\n");
        messaging_send("network", NET_MESSAGE, &grant, false);
    }
    else if (result == PAXOS_BACKDATE)
    {
        /* BACKDATE: chain index mismatch */
        json_t *bd_json = json_object();
        if (bd_json == NULL) {
            log_error(proc->logger, "Reputation: json_object OOM (backdate)\n");
            return true;
        }
        json_object_set_new(bd_json, "id1", json_integer(id1));
        json_object_set_new(bd_json, "id2", json_integer(id2));

        generic_msg_t backdate = {0};
        backdate.type = NET_MESSAGE;
        strncpy(backdate.info.net_msg.process, "reputation", PROC_NAME_LEN);
        backdate.info.net_msg.function = REP_PROTO_BACKDATE;
        backdate.info.net_msg.encrypt = true;
        memcpy(&backdate.info.net_msg.to_whom, &nmsg->from_whom, sizeof(public_identity_t));
        strncpy(backdate.info.net_msg.return_to, "reputation", PROC_NAME_LEN);
        net_msg_pack_json(&backdate.info.net_msg, bd_json);
        json_decref(bd_json);

        log_debug(proc->logger, "Reputation: Request backdated\n");
        messaging_send("network", NET_MESSAGE, &backdate, false);
    }
    else
    {
        /* NACK: id1 <= last_id */
        json_t *nack_json = json_object();
        if (nack_json == NULL) {
            log_error(proc->logger, "Reputation: json_object OOM (nack)\n");
            return true;
        }
        json_object_set_new(nack_json, "id1", json_integer(id1));
        json_object_set_new(nack_json, "id2", json_integer(id2));

        generic_msg_t nack = {0};
        nack.type = NET_MESSAGE;
        strncpy(nack.info.net_msg.process, "reputation", PROC_NAME_LEN);
        nack.info.net_msg.function = REP_PROTO_NACK;
        nack.info.net_msg.encrypt = true;
        memcpy(&nack.info.net_msg.to_whom, &nmsg->from_whom, sizeof(public_identity_t));
        strncpy(nack.info.net_msg.return_to, "reputation", PROC_NAME_LEN);
        net_msg_pack_json(&nack.info.net_msg, nack_json);
        json_decref(nack_json);

        log_debug(proc->logger, "Reputation: Request refused\n");
        messaging_send("network", NET_MESSAGE, &nack, false);
    }

    return true;
}

/****************************
 * Handler: handle_grant (permission granted) — Paxos Phase 1b
 * Count grants; on majority, broadcast REP_PROTO_TX
 ****************************/

/*@
  requires \valid(proc);
  requires \valid(queues);
  requires \valid(msg);
  requires proc->logger == \null || \valid(proc->logger);
  requires rep_state.paxos.initialized == \true;
*/
static bool handle_grant(const process_t *proc, directory_t *queues, generic_msg_t *msg)
{
    net_msg_t *nmsg = &msg->info.net_msg;
    log_debug(proc->logger, "Reputation: grant from %s\n", nmsg->from_whom.nickname);

    /* Unpack (id1, id2, peer_uuid, last_id, chain_len) */
    json_t *payload = NULL;
    if (net_msg_unpack_json(nmsg, &payload) != 0 || payload == NULL)
    {
        log_error(proc->logger, "Reputation: handle_grant: failed to unpack JSON\n");
        return false;
    }

    json_t *j_id1      = json_object_get(payload, "id1");
    json_t *j_id2      = json_object_get(payload, "id2");
    json_t *j_peer_uuid = json_object_get(payload, "peer_uuid");

    if (!j_id1 || !j_id2 || !j_peer_uuid)
    {
        json_decref(payload);
        log_error(proc->logger, "Reputation: handle_grant: missing JSON fields\n");
        return false;
    }

    int64_t id1 = json_integer_value(j_id1);
    int64_t id2 = json_integer_value(j_id2);
    const char *peer_uuid_str = json_string_value(j_peer_uuid);

    pthread_mutex_lock(&rep_state.lock);

    /* Look up this request in my_requests (keyed by peer_uuid) */
    char peer_uuid_key[UUID_STRING_LEN + 2];
    strncpy(peer_uuid_key, peer_uuid_str, sizeof(peer_uuid_key) - 1);
    peer_uuid_key[sizeof(peer_uuid_key) - 1] = '\0';
    data_t *tx_dat = NULL;
    if (map_get(&rep_state.my_requests, peer_uuid_key, &tx_dat) != 0)
    {
        /* Grant not for one of our requests */
        pthread_mutex_unlock(&rep_state.lock);
        json_decref(payload);
        log_debug(proc->logger, "Reputation: Grant for already-completed or unknown request\n");
        return true;
    }

    tx_score_t *tx = NULL;
    data_object_ptr(tx_dat, (void **)&tx);
    double tx_score = (tx != NULL) ? tx->score : 0.0;

    int count = paxos_record_grant(&rep_state.paxos, id1, id2, tx_score);
    bool send_tx = (count >= PAXOS_MAJORITY(rep_state.num_peers));

    /* Capture task_uuid + capability_name before potential removal.
     * The proposer caches its own weight here so reputation_pure (and
     * its EMA twin) on this side use the same weight as the
     * receivers, who will cache via handle_transaction below. */
    char task_uuid_str[UUID_STRING_LEN + 1] = {0};
    char cap_name_local[CAP_NAMELEN + 1] = {0};
    if (send_tx && tx != NULL)
    {
        uuid_unparse_lower(tx->task_uuid, task_uuid_str);
        strncpy(cap_name_local, tx->capability_name, CAP_NAMELEN);
        cap_name_local[CAP_NAMELEN] = '\0';
        if (task_uuid_str[0] != '\0')
            _record_task_weight_locked(task_uuid_str,
                                       _resolve_tx_weight(cap_name_local));
    }

    if (send_tx)
    {
        /* Remove from my_requests */
        map_remove(&rep_state.my_requests, peer_uuid_key);
        /* Bind the round to OUR primary group, the C twin of Python's
         * _start_paxos(round_group). The tag then travels on the commit
         * broadcast, and each receiver maps it through its own view: a sibling
         * member sees its primary group, while a GATEWAY sees one of its child
         * groups and routes the entry to that subtree's chain (§10.2). */
        char own_group[UUID_STRING_LEN + 1];
        uuid_unparse_lower(proc->protocol.group.uuid, own_group);
        char round_key[PAXOS_KEY_LEN];
        paxos_id_index(round_key, sizeof(round_key), id1, id2);
        _set_round_group_locked(round_key, own_group);
    }

    pthread_mutex_unlock(&rep_state.lock);

    if (send_tx)
    {
        /* Broadcast REP_PROTO_TX to all peers */
        json_t *tx_json = json_object();
        if (tx_json == NULL) {
            log_error(proc->logger, "Reputation: json_object OOM (tx)\n");
            json_decref(payload);
            return true;
        }
        json_object_set_new(tx_json, "id1", json_integer(id1));
        json_object_set_new(tx_json, "id2", json_integer(id2));
        json_object_set_new(tx_json, "peer_uuid", json_string(peer_uuid_str));
        json_object_set_new(tx_json, "score", json_real(tx_score));
        if (task_uuid_str[0] != '\0')
            json_object_set_new(tx_json, "task_uuid", json_string(task_uuid_str));
        if (cap_name_local[0] != '\0')
            json_object_set_new(tx_json, "capability_name",
                                json_string(cap_name_local));

        log_debug(proc->logger, "Reputation: Submit transaction score\n");

        peers_read_lock(proc);
        for (size_t i = 0; i < proc->protocol.num_peers; i++)
        {
            generic_msg_t tx_msg = {0};
            tx_msg.type = NET_MESSAGE;
            strncpy(tx_msg.info.net_msg.process, "reputation", PROC_NAME_LEN);
            tx_msg.info.net_msg.function = REP_PROTO_TX;
            tx_msg.info.net_msg.encrypt = true;
            memcpy(&tx_msg.info.net_msg.to_whom, &proc->protocol.peers[i], sizeof(public_identity_t));
            strncpy(tx_msg.info.net_msg.return_to, "reputation", PROC_NAME_LEN);
            net_msg_pack_json(&tx_msg.info.net_msg, tx_json);
            messaging_send("network", NET_MESSAGE, &tx_msg, false);
        }
        peers_read_unlock(proc);
        json_decref(tx_json);
    }

    json_decref(payload);
    return true;
}

/****************************
 * Handler: handle_nack (try again) — exponential backoff retry
 ****************************/

/*@
  requires \valid(proc);
  requires \valid(queues);
  requires \valid(msg);
  requires proc->logger == \null || \valid(proc->logger);
  requires rep_state.paxos.initialized == \true;
*/
static bool handle_nack(const process_t *proc, directory_t *queues, generic_msg_t *msg)
{
    net_msg_t *nmsg = &msg->info.net_msg;
    log_debug(proc->logger, "Reputation: nack from %s\n", nmsg->from_whom.nickname);

    /* Unpack (id1, id2) from payload for retry capability */
    json_t *payload = NULL;
    int64_t id1 = 0, id2 = 0;
    if (net_msg_unpack_json(nmsg, &payload) == 0 && payload != NULL)
    {
        json_t *j_id1 = json_object_get(payload, "id1");
        json_t *j_id2 = json_object_get(payload, "id2");
        if (j_id1) id1 = json_integer_value(j_id1);
        if (j_id2) id2 = json_integer_value(j_id2);
        json_decref(payload);
    }

    int wait_sec = paxos_record_nack(&rep_state.paxos, id1, id2);

    log_debug(proc->logger, "Reputation: nack backoff %d seconds\n", wait_sec);
    (void)wait_sec;

    /* Synchronous-dispatch retry: Python's _try_again thread sleeps for
     * backoff[idx] then re-emits an "ask permission" to self.group.
     * Under sync dispatch we inline that emission so the conformance
     * scenario engine sees the retry on the same step's outbox. The
     * retry uses fresh ids via paxos_next_ids — chain position stays
     * the same but id1 grows monotonically. */
    if (rep_state.synchronous_dispatch)
    {
        int64_t retry_id1 = 0, retry_id2 = 0;
        paxos_next_ids(&rep_state.paxos, &retry_id1, &retry_id2);

        char proposer_str[UUID_STRING_LEN + 1];
        /* Use this proc's identity uuid as the proposer; the harness
         * stamps the participant's pub uuid on the from_whom field of
         * inbound messages, but here we want the OUTBOUND payload to
         * carry our own uuid. proc->protocol has no direct identity
         * field; pull it from peers if present, else zero. The harness
         * keys on function name + to=broadcast for matching, so the
         * payload uuid is informational only. */
        memset(proposer_str, 0, sizeof(proposer_str));
        char zero_uuid[UUID_STRING_LEN + 1] = "00000000-0000-0000-0000-000000000000";
        memcpy(proposer_str, zero_uuid, sizeof(proposer_str));

        json_t *retry_json = json_object();
        if (retry_json)
        {
            json_object_set_new(retry_json, "id1", json_integer(retry_id1));
            json_object_set_new(retry_json, "id2", json_integer(retry_id2));
            json_object_set_new(retry_json, "peer_uuid", json_string(proposer_str));

            generic_msg_t retry = {0};
            retry.type = NET_MESSAGE;
            strncpy(retry.info.net_msg.process, "reputation", PROC_NAME_LEN);
            retry.info.net_msg.function = REP_PROTO_REQUEST;
            retry.info.net_msg.encrypt = false;
            /* to_whom zeroed → broadcast. The conformance hook resolves
             * a zero uuid to "broadcast" so this matches scenarios that
             * assert `to: broadcast` on the retry. */
            net_msg_pack_json(&retry.info.net_msg, retry_json);
            json_decref(retry_json);
            messaging_send("network", NET_MESSAGE, &retry, false);
        }
    }

    return true;
}

/****************************
 * Handler: handle_backdate (out of date)
 * Remote peer tells us our chain index is behind; request update.
 ****************************/

/* Frama-C: skipped — [solver-timeout] memcpy of public_identity_t triggers
 * "Hide sub-term definition" cast warning blocking valid_dest/src/separation */
/*@
  requires \valid(proc);
  requires \valid(queues);
  requires \valid(msg);
  requires proc->logger == \null || \valid(proc->logger);
*/
static bool handle_backdate(const process_t *proc, directory_t *queues, generic_msg_t *msg)
{
    net_msg_t *nmsg = &msg->info.net_msg;
    log_info(proc->logger, "Reputation: backdate notification from %s\n", nmsg->from_whom.nickname);

    /* Request chain update from this peer */
    generic_msg_t update_req = {0};
    update_req.type = NET_MESSAGE;
    strncpy(update_req.info.net_msg.process, "reputation", PROC_NAME_LEN);
    update_req.info.net_msg.function = REP_PROTO_OUTDATED;
    update_req.info.net_msg.encrypt = true;
    memcpy(&update_req.info.net_msg.to_whom, &nmsg->from_whom, sizeof(public_identity_t));
    strncpy(update_req.info.net_msg.return_to, "reputation", PROC_NAME_LEN);

    messaging_send("network", NET_MESSAGE, &update_req, false);
    return true;
}

/****************************
 * Handler: handle_transaction (transaction) — Paxos Phase 2a
 * Validate that we granted this proposal, then send accepted.
 ****************************/

/*@
  requires \valid(proc);
  requires \valid(queues);
  requires \valid(msg);
  requires proc->logger == \null || \valid(proc->logger);
  requires rep_state.paxos.initialized == \true;
*/
static bool handle_transaction(const process_t *proc, directory_t *queues, generic_msg_t *msg)
{
    net_msg_t *nmsg = &msg->info.net_msg;
    log_debug(proc->logger, "Reputation: transaction from %s\n", nmsg->from_whom.nickname);

    /* Reject unverified Paxos proposals. Mirrors Python
     * repprocess.handle_transaction:390 — without this guard a peer
     * with no private key (or an attacker who can deliver bytes to
     * net_proc) can drive consensus by submitting unsigned
     * transactions and have us grant them. Note we drop after
     * logging but before paxos_has_granted_id, so we don't even
     * leak which proposal indices we've granted. */
    if (!nmsg->verified)
    {
        log_warn(proc->logger,
                    "Reputation: rejecting unverified Paxos proposal from %s\n",
                    nmsg->from_whom.nickname);
        return true;
    }

    /* Unpack (id1, id2, peer_uuid, score) */
    json_t *payload = NULL;
    if (net_msg_unpack_json(nmsg, &payload) != 0 || payload == NULL)
    {
        log_error(proc->logger, "Reputation: handle_transaction: failed to unpack JSON\n");
        return false;
    }

    json_t *j_id1      = json_object_get(payload, "id1");
    json_t *j_id2      = json_object_get(payload, "id2");
    json_t *j_peer_uuid = json_object_get(payload, "peer_uuid");
    json_t *j_score    = json_object_get(payload, "score");

    if (!j_id1 || !j_id2 || !j_peer_uuid || !j_score)
    {
        json_decref(payload);
        log_error(proc->logger, "Reputation: handle_transaction: missing JSON fields\n");
        return false;
    }

    int64_t id2 = json_integer_value(j_id2);
    int64_t id1 = json_integer_value(j_id1);
    double score = json_real_value(j_score);
    /* §11.2: reject a peer-supplied score off AT's [0, 1] scale rather than
     * grading it. Mirrors the Python twin, which raises in TransactionScore's
     * constructor and drops the message in handle_transaction. */
    if (!tx_score_in_range(score))
    {
        json_decref(payload);
        log_warn(proc->logger,
                 "Reputation: handle_transaction: score %f is off the [%g, %g] "
                 "scale; dropping proposal\n", score, TX_SCORE_MIN, TX_SCORE_MAX);
        return true;   /* consumed: a malformed proposal is not another handler's */
    }
    /* peer_uuid / task_uuid are borrowed from `payload` but are echoed back
     * into the ACCEPTED reply AFTER json_decref(payload) below; copy them out
     * now to avoid a use-after-free. Preserve NULL so an absent field stays
     * absent in the reply rather than becoming an empty string. cap_name is
     * only consumed before the decref, so it can stay borrowed. */
    const char *peer_uuid_borrowed = json_string_value(j_peer_uuid);
    char peer_uuid_buf[UUID_STRING_LEN + 1];
    bool have_peer_uuid = peer_uuid_borrowed != NULL;
    if (have_peer_uuid)
    {
        strncpy(peer_uuid_buf, peer_uuid_borrowed, UUID_STRING_LEN);
        peer_uuid_buf[UUID_STRING_LEN] = '\0';
    }
    const char *peer_uuid_str = have_peer_uuid ? peer_uuid_buf : NULL;

    const char *task_uuid_borrowed =
        json_string_value(json_object_get(payload, "task_uuid"));
    char task_uuid_str_buf[UUID_STRING_LEN + 1];
    bool have_task_uuid = task_uuid_borrowed != NULL;
    if (have_task_uuid)
    {
        strncpy(task_uuid_str_buf, task_uuid_borrowed, UUID_STRING_LEN);
        task_uuid_str_buf[UUID_STRING_LEN] = '\0';
    }
    const char *task_uuid_str = have_task_uuid ? task_uuid_str_buf : NULL;

    const char *cap_name = json_string_value(
        json_object_get(payload, "capability_name"));

    if (!paxos_has_granted_id(&rep_state.paxos, (int)id2))
    {
        json_decref(payload);
        log_debug(proc->logger, "Reputation: Transaction not granted by us, dropping\n");
        return true;
    }

    /* Record the grant (score) in the paxos proposals for later acceptance tracking */
    paxos_record_grant(&rep_state.paxos, id1, id2, score);

    /* Cache the per-task transaction_weight so reputation_pure /
     * reputation_consensus can apply it when this transaction lands
     * in the chain. Mirrors Python handle_transaction's
     * _record_task_weight call. If the local registry doesn't know
     * the capability, weight falls back to 1. */
    if (task_uuid_str != NULL && task_uuid_str[0] != '\0')
    {
        char task_uuid_buf[UUID_STRING_LEN + 1];
        strncpy(task_uuid_buf, task_uuid_str, UUID_STRING_LEN);
        task_uuid_buf[UUID_STRING_LEN] = '\0';
        pthread_mutex_lock(&rep_state.lock);
        _record_task_weight_locked(task_uuid_buf, _resolve_tx_weight(cap_name));
        _record_task_tier_locked(task_uuid_buf, _resolve_tx_tier(cap_name));
        pthread_mutex_unlock(&rep_state.lock);
    }

    json_decref(payload);

    /* Send ACCEPTED back */
    json_t *acc_json = json_object();
    if (acc_json == NULL) {
        log_error(proc->logger, "Reputation: json_object OOM (accepted)\n");
        return true;
    }
    json_object_set_new(acc_json, "id1", json_integer(id1));
    json_object_set_new(acc_json, "id2", json_integer(id2));
    json_object_set_new(acc_json, "peer_uuid", json_string(peer_uuid_str));
    if (task_uuid_str)
        json_object_set_new(acc_json, "task_uuid", json_string(task_uuid_str));

    generic_msg_t accepted = {0};
    accepted.type = NET_MESSAGE;
    strncpy(accepted.info.net_msg.process, "reputation", PROC_NAME_LEN);
    accepted.info.net_msg.function = REP_PROTO_ACCEPTED;
    accepted.info.net_msg.encrypt = true;
    memcpy(&accepted.info.net_msg.to_whom, &nmsg->from_whom, sizeof(public_identity_t));
    strncpy(accepted.info.net_msg.return_to, "reputation", PROC_NAME_LEN);
    net_msg_pack_json(&accepted.info.net_msg, acc_json);
    json_decref(acc_json);

    messaging_send("network", NET_MESSAGE, &accepted, false);
    return true;
}

/****************************
 * Handler: handle_accepted (tx accepted) — Paxos Phase 2b
 * Count acceptances; commit to history on majority.
 ****************************/

/*@
  requires \valid(proc);
  requires \valid(queues);
  requires \valid(msg);
  requires proc->logger == \null || \valid(proc->logger);
  requires rep_state.paxos.initialized == \true;
*/
static bool handle_accepted(const process_t *proc, directory_t *queues, generic_msg_t *msg)
{
    net_msg_t *nmsg = &msg->info.net_msg;
    log_debug(proc->logger, "Reputation: tx accepted by %s\n", nmsg->from_whom.nickname);

    /* Reject unverified Paxos acceptances. Mirrors Python
     * repprocess.handle_accepted:439 — a forged ACCEPTED can push
     * acc_count over the majority threshold and force a commit on a
     * proposal the honest cohort would have rejected. */
    if (!nmsg->verified)
    {
        log_warn(proc->logger,
                    "Reputation: rejecting unverified Paxos acceptance from %s\n",
                    nmsg->from_whom.nickname);
        return true;
    }

    /* Unpack (id1, id2, peer_uuid) */
    json_t *payload = NULL;
    if (net_msg_unpack_json(nmsg, &payload) != 0 || payload == NULL)
    {
        log_error(proc->logger, "Reputation: handle_accepted: failed to unpack JSON\n");
        return false;
    }

    json_t *j_id1      = json_object_get(payload, "id1");
    json_t *j_id2      = json_object_get(payload, "id2");
    json_t *j_peer_uuid = json_object_get(payload, "peer_uuid");

    if (!j_id1 || !j_id2 || !j_peer_uuid)
    {
        json_decref(payload);
        log_error(proc->logger, "Reputation: handle_accepted: missing JSON fields\n");
        return false;
    }

    int64_t id1 = json_integer_value(j_id1);
    int64_t id2 = json_integer_value(j_id2);
    const char *peer_uuid_str = json_string_value(j_peer_uuid);

    /* Look up score from paxos proposals */
    char paxos_key[PAXOS_KEY_LEN];
    paxos_id_index(paxos_key, sizeof(paxos_key), id1, id2);

    pthread_mutex_lock(&rep_state.paxos.lock);
    data_t *prop_dat = NULL;
    double score = 0.0;
    if (map_get(&rep_state.paxos.proposals, paxos_key, &prop_dat) == 0)
    {
        paxos_proposal_t *ptc = NULL;
        data_object_ptr(prop_dat, (void **)&ptc);
        if (ptc != NULL) score = ptc->score;
    }
    pthread_mutex_unlock(&rep_state.paxos.lock);

    int acc_count = paxos_record_acceptance(&rep_state.paxos, id1, id2);
    bool commit = (acc_count >= PAXOS_MAJORITY(rep_state.num_peers));

    if (commit)
    {
        /* Idempotency guard: every ACCEPTED that arrives after the
         * majority threshold has been crossed would otherwise re-fire
         * the commit-and-broadcast block. That fans out ~N-majority
         * extra `committed` broadcasts per round, and duplicate
         * broadcasts corrupt the Transaction (tx_history_update would
         * set p2 = p1 = proposer because the bilateral guard there
         * would also be needed if this slipped through). Mirrors
         * repprocess.handle_accepted's `committed_paxos_rounds` set. */
        data_t *already = NULL;
        if (map_get(&rep_state.committed_paxos_rounds, paxos_key, &already) == 0)
        {
            json_decref(payload);
            return true;
        }
        data_t *mark = integer_data(1);
        map_set(&rep_state.committed_paxos_rounds, paxos_key, mark);
        /* FIFO ring: if we're at cap, the head slot already holds the
         * oldest key — drop it from the map before overwriting the
         * slot. ring_len caps at COMMITTED_ROUNDS_CAP; once steady
         * state, head wraps and each insert evicts one. Mirrors
         * Python's OrderedDict.popitem(last=False) loop in
         * repprocess.handle_accepted. */
        if (rep_state.committed_paxos_ring_len == COMMITTED_ROUNDS_CAP)
        {
            map_remove(&rep_state.committed_paxos_rounds,
                       rep_state.committed_paxos_ring[
                           rep_state.committed_paxos_ring_head]);
        }
        else
        {
            rep_state.committed_paxos_ring_len++;
        }
        /* snprintf rather than strncpy to silence -Wstringop-truncation
         * while still guaranteeing NUL termination. paxos_key is a
         * compact decimal string well under 64 bytes; truncation
         * cannot happen in practice. */
        snprintf(rep_state.committed_paxos_ring[
                     rep_state.committed_paxos_ring_head],
                 sizeof(rep_state.committed_paxos_ring[0]),
                 "%s", paxos_key);
        rep_state.committed_paxos_ring_head =
            (rep_state.committed_paxos_ring_head + 1)
            % COMMITTED_ROUNDS_CAP;

        /* Parse UUIDs and commit to history */
        uuid_t peer_uuid;
        uuid_t task_uuid;
        uuid_parse(peer_uuid_str, peer_uuid);

        const char *task_uuid_str = json_string_value(json_object_get(payload, "task_uuid"));
        bool have_task_uuid = (task_uuid_str
                               && uuid_parse(task_uuid_str, task_uuid) == 0);
        /* Route to the chain this round belongs to: a gateway keeps one per
         * child group, and merging a subtree's history into the primary chain
         * would make every group's reputation everyone else's (§10.2). */
        char round_group[UUID_STRING_LEN + 1] = {0};
        _get_round_group_locked(paxos_key, round_group, sizeof(round_group));
        if (round_group[0] == '\0')
        {
            /* Unbound round (a peer that predates the binding, or a replayed
             * key): it is ours, so it belongs to our primary group. */
            uuid_unparse_lower(proc->protocol.group.uuid, round_group);
        }
        tx_history_t *chain = _chain_for_group_locked(proc, round_group);
        if (have_task_uuid)
        {
            tx_history_update(chain, task_uuid, peer_uuid, score);
        }
        else
        {
            tx_history_update(chain, peer_uuid, peer_uuid, score);
        }
        paxos_advance_chain(&rep_state.paxos);
        /* Reset this peer's idle clock: the staleness sweep must leave an
         * actively-transacting peer alone (ISSUES §10.3). */
        _note_interaction(peer_uuid);
        log_info(proc->logger, "Reputation: Transaction committed\n");

        /* Phase 3 — broadcast committed (task_id, peer_id, score) to
         * the group so acceptors can write the same entry to their
         * own histories.  Bilateral Transactions form across peers
         * when both sides eventually run this for each other's
         * submissions. */
        json_t *commit_json = json_object();
        if (commit_json != NULL)
        {
            if (have_task_uuid)
                json_object_set_new(commit_json, "task_uuid",
                                    json_string(task_uuid_str));
            json_object_set_new(commit_json, "peer_uuid",
                                json_string(peer_uuid_str));
            json_object_set_new(commit_json, "score", json_real(score));
            /* Tag the chain so receivers route it the same way we just did.
             * Omitted for the primary chain, which keeps the payload
             * byte-identical for every leaf node. */
            if (round_group[0] != '\0')
                json_object_set_new(commit_json, "group_uuid",
                                    json_string(round_group));

            generic_msg_t bcast = {0};
            bcast.type = NET_MESSAGE;
            strncpy(bcast.info.net_msg.process, "reputation", PROC_NAME_LEN);
            bcast.info.net_msg.function = REP_PROTO_COMMITTED;
            bcast.info.net_msg.encrypt = true;
            /* Group broadcast — handlers use the group key.  Mirror
             * the convention used by _forward_transaction's REQUEST
             * broadcast at rep_proc.c:1113-1122 (a per-peer loop on
             * the proc->protocol.peers list). */
            net_msg_pack_json(&bcast.info.net_msg, commit_json);
            json_decref(commit_json);

            peers_read_lock(proc);
            for (size_t i = 0; i < proc->protocol.num_peers; i++)
            {
                generic_msg_t per = bcast;  /* shallow copy */
                memcpy(&per.info.net_msg.to_whom,
                       &proc->protocol.peers[i],
                       sizeof(public_identity_t));
                messaging_send("network", NET_MESSAGE, &per, false);
            }
            peers_read_unlock(proc);
        }
    }
    else
    {
        log_debug(proc->logger, "Reputation: Tx accepted (%d so far)\n", acc_count);
    }

    json_decref(payload);
    return true;
}

/****************************
 * Handler: handle_committed (tx committed) — Phase 3
 * Acceptor receives the proposer's commit announcement and writes
 * (task_id, peer_id, score) to local history.  The proposer's own
 * broadcast bounces back to itself — we skip the self-update because
 * handle_accepted already wrote the entry locally.
 ****************************/

/*@
  requires \valid(proc);
  requires \valid(msg);
  requires proc->logger == \null || \valid(proc->logger);
*/
static bool handle_committed(const process_t *proc, directory_t *queues, generic_msg_t *msg)
{
    (void)queues;
    net_msg_t *nmsg = &msg->info.net_msg;

    json_t *payload = NULL;
    if (net_msg_unpack_json(nmsg, &payload) != 0 || payload == NULL)
    {
        log_error(proc->logger, "Reputation: handle_committed: failed to unpack JSON\n");
        return false;
    }

    json_t *j_peer_uuid = json_object_get(payload, "peer_uuid");
    json_t *j_task_uuid = json_object_get(payload, "task_uuid");
    json_t *j_score     = json_object_get(payload, "score");

    if (!j_peer_uuid || !j_score)
    {
        json_decref(payload);
        log_error(proc->logger, "Reputation: handle_committed: missing JSON fields\n");
        return false;
    }

    const char *peer_uuid_str = json_string_value(j_peer_uuid);
    double score = json_real_value(j_score);
    /* §11.2, and this is the path that WRITES history on every acceptor, so the
     * bound matters most here. Same rejection as handle_transaction. */
    if (!tx_score_in_range(score))
    {
        json_decref(payload);
        log_warn(proc->logger,
                 "Reputation: handle_committed: score %f is off the [%g, %g] "
                 "scale; dropping\n", score, TX_SCORE_MIN, TX_SCORE_MAX);
        return true;
    }

    /* No self-bounce check needed in C — handle_accepted's broadcast
     * loop iterates proc->protocol.peers, which excludes self.  The
     * Python twin keeps a self-skip as a safety net because its
     * encrypted-group broadcast may or may not loop back through
     * the local network process. */

    uuid_t peer_uuid;
    if (uuid_parse(peer_uuid_str, peer_uuid) != 0)
    {
        json_decref(payload);
        log_error(proc->logger, "Reputation: handle_committed: bad peer_uuid\n");
        return false;
    }

    uuid_t task_uuid;
    const char *task_uuid_str = j_task_uuid ? json_string_value(j_task_uuid) : NULL;
    /* An untagged commit (or one naming a group we do not gateway) lands on the
     * primary chain, so a leaf node behaves exactly as it did. */
    const char *group_str = json_string_value(json_object_get(payload,
                                                             "group_uuid"));
    pthread_mutex_lock(&rep_state.lock);
    tx_history_t *chain = _chain_for_group_locked(proc, group_str);
    if (task_uuid_str && uuid_parse(task_uuid_str, task_uuid) == 0)
    {
        tx_history_update(chain, task_uuid, peer_uuid, score);
    }
    else
    {
        /* Same fallback handle_accepted uses when task_uuid is
         * missing: key the entry by peer_uuid. */
        tx_history_update(chain, peer_uuid, peer_uuid, score);
    }
    pthread_mutex_unlock(&rep_state.lock);
    _note_interaction(peer_uuid);   /* idle clock; see §10.3 decay */
    log_debug(proc->logger, "Reputation: Recorded committed tx from %s\n",
              peer_uuid_str);

    json_decref(payload);
    return true;
}

/****************************
 * Handler: handle_outdated (update needed)
 * Send chain slice to requesting peer.
 ****************************/

/* Frama-C: skipped — [solver-timeout] memcpy of public_identity_t triggers
 * "Hide sub-term definition" cast warning blocking valid_dest/src/separation */
/*@
  requires \valid(proc);
  requires \valid(queues);
  requires \valid(msg);
  requires proc->logger == \null || \valid(proc->logger);
*/
static bool handle_outdated(const process_t *proc, directory_t *queues, generic_msg_t *msg)
{
    net_msg_t *nmsg = &msg->info.net_msg;
    log_info(proc->logger, "Reputation: update requested by %s\n", nmsg->from_whom.nickname);

    pthread_mutex_lock(&rep_state.lock);

    json_t *era_json = NULL;
    int chain_len = tx_history_len(&rep_state.history);
    tx_history_era_to_json(&rep_state.history, 0, chain_len, &era_json);

    pthread_mutex_unlock(&rep_state.lock);

    /* Send update with the era JSON packed into the message */
    generic_msg_t update = {0};
    update.type = NET_MESSAGE;
    strncpy(update.info.net_msg.process, "reputation", PROC_NAME_LEN);
    update.info.net_msg.function = REP_PROTO_UPDATE;
    update.info.net_msg.encrypt = true;
    memcpy(&update.info.net_msg.to_whom, &nmsg->from_whom, sizeof(public_identity_t));
    strncpy(update.info.net_msg.return_to, "reputation", PROC_NAME_LEN);

    if (era_json != NULL)
    {
        net_msg_pack_json(&update.info.net_msg, era_json);
        json_decref(era_json);
    }

    log_debug(proc->logger, "Reputation: Sent update\n");
    messaging_send("network", NET_MESSAGE, &update, false);
    return true;
}

/****************************
 * Handler: handle_update (latest update)
 * Collect chain slices, vote on consistency, merge.
 ****************************/

/*@
  requires \valid(proc);
  requires \valid(queues);
  requires \valid(msg);
  requires proc->logger == \null || \valid(proc->logger);
*/
static bool handle_update(const process_t *proc, directory_t *queues, generic_msg_t *msg)
{
    net_msg_t *nmsg = &msg->info.net_msg;
    log_info(proc->logger, "Reputation: chain update from %s\n", nmsg->from_whom.nickname);

    /* Unpack chain JSON from payload */
    json_t *chain_json = NULL;
    if (net_msg_unpack_json(nmsg, &chain_json) != 0 || chain_json == NULL)
    {
        log_error(proc->logger, "Reputation: handle_update: failed to unpack JSON\n");
        return false;
    }

    /* Key by sender UUID */
    char sender_uuid[UUID_STRING_LEN + 1];
    uuid_unparse_lower(nmsg->from_whom.uuid, sender_uuid);

    pthread_mutex_lock(&rep_state.lock);

    /* Store in rep_state.updates keyed by sender UUID */
    data_t *chain_dat = object_ptr_data(chain_json, sizeof(json_t));
    map_set(&rep_state.updates, sender_uuid, chain_dat);

    size_t up_count = map_size(&rep_state.updates);

    if (up_count >= (size_t)rep_state.num_updates)
    {
        /* Group identical updates: find majority by comparing JSON dumps */
        /* Build parallel arrays of keys and serialized strings */
        array_t *keys = map_keys(&rep_state.updates);
        size_t nkeys = array_size(keys);

        /* Allocate string representations */
        char **strs = calloc(nkeys, sizeof(char *));
        json_t **jsons = calloc(nkeys, sizeof(json_t *));
        if (strs != NULL && jsons != NULL)
        {
            for (size_t ki = 0; ki < nkeys; ki++)
            {
                data_t *kdat = NULL;
                if (array_get(keys, (int)ki, &kdat) != 0) continue;
                char *kstr = NULL;
                if (data_string_ptr(kdat, &kstr) != 0 || kstr == NULL) continue;
                data_t *vdat = NULL;
                if (map_get(&rep_state.updates, kstr, &vdat) != 0) continue;
                void *jptr = NULL;
                if (data_object_ptr(vdat, &jptr) != 0 || jptr == NULL) continue;
                jsons[ki] = (json_t *)jptr;
                strs[ki] = json_dumps(jsons[ki], JSON_COMPACT);
            }

            /* Find best candidate */
            char *best_str = NULL;
            json_t *best_json = NULL;
            int best_count = 0;

            for (size_t oi = 0; oi < nkeys; oi++)
            {
                if (strs[oi] == NULL) continue;
                int count = 0;
                for (size_t ci = 0; ci < nkeys; ci++)
                {
                    if (strs[ci] != NULL && strcmp(strs[oi], strs[ci]) == 0)
                        count++;
                }
                if (count > best_count)
                {
                    best_count = count;
                    best_str = strs[oi];
                    best_json = jsons[oi];
                }
            }

            if (best_json != NULL && best_count > (int)(up_count / 2))
            {
                tx_history_era_from_json(&rep_state.history, best_json);
                log_debug(proc->logger, "Reputation: Updated\n");
            }
            else
            {
                log_error(proc->logger,
                          "Reputation: Closest %zu peers unable to agree on history\n",
                          up_count);
            }

            /* Free all string dumps */
            for (size_t fi = 0; fi < nkeys; fi++)
            {
                if (strs[fi] != NULL && strs[fi] != best_str)
                    free(strs[fi]);
            }
            if (best_str != NULL)
                free(best_str);
        }
        if (strs != NULL) free(strs);
        if (jsons != NULL) free(jsons);
    }

    pthread_mutex_unlock(&rep_state.lock);
    return true;
}

/****************************
 * Handler: handle_consensus_rep_request (consensus reputation request)
 *
 * Replies with reputation_consensus(history, peer_uuid) — a
 * deterministic, history-only EMA score every node arrives at
 * identically given the same chain state. Backs the inspector
 * dashboard. Deliberately skips reputations_update and the rank
 * publish: that dict feeds the rep_req path's mode selection and
 * pure-reputation weighting, so overwriting it with the consensus
 * value would corrupt the local trust path for any rep_req caller.
 * Mirrors Python's handle_consensus_reputation_request.
 ****************************/

/*@
  requires \valid(proc);
  requires \valid(queues);
  requires \valid(msg);
  requires proc->logger == \null || \valid(proc->logger);
*/
static bool handle_consensus_rep_request(const process_t *proc, directory_t *queues, generic_msg_t *msg)
{
    (void)queues;
    net_msg_t *nmsg = &msg->info.net_msg;
    log_debug(proc->logger, "Reputation: consensus rep request from %s\n",
              nmsg->from_whom.nickname);
    probes_counter("rep.consensus", "enter", NULL);

    json_t *payload = NULL;
    if (net_msg_unpack_json(nmsg, &payload) != 0 || payload == NULL)
    {
        log_error(proc->logger,
                  "Reputation: handle_consensus_rep_request: failed to unpack JSON\n");
        probes_counter("rep.consensus", "exception", "unpack_failed");
        return false;
    }

    json_t *j_peer_uuid = json_object_get(payload, "peer_uuid");
    json_t *j_req_proc  = json_object_get(payload, "requesting_process");
    if (!j_peer_uuid || !j_req_proc)
    {
        json_decref(payload);
        log_error(proc->logger,
                  "Reputation: handle_consensus_rep_request: missing JSON fields\n");
        return false;
    }
    const char *peer_uuid_str = json_string_value(j_peer_uuid);
    const char *req_proc_str  = json_string_value(j_req_proc);

    uuid_t peer_uuid;
    double score = 0.5;
    if (uuid_parse(peer_uuid_str, peer_uuid) == 0)
    {
        pthread_mutex_lock(&rep_state.lock);
        /* Slash override (fast-penalty path): a finalized slash floors
         * the score, bypassing the chain/EMA. Mirrors Python
         * _consensus_reputation's top-of-function check. The floor value
         * lives in rep_state.reputations (written by _apply_slash). */
        data_t *sl = NULL;
        if (map_get(&rep_state.slashed, (map_key_t)peer_uuid_str, &sl) == 0)
        {
            double floor = 0.0;
            reputations_get(&rep_state.reputations, peer_uuid, &floor);
            score = floor;
        }
        else
        {
            score = reputation_consensus(&rep_state.history, peer_uuid,
                                         &rep_state.task_weights);
        }
        pthread_mutex_unlock(&rep_state.lock);
        probes_counter("rep.consensus", "queued", NULL);
    }

    json_t *resp_json = json_object();
    if (resp_json == NULL) {
        log_error(proc->logger, "Reputation: json_object OOM (consensus rep_resp)\n");
        json_decref(payload);
        return true;
    }
    json_object_set_new(resp_json, "peer_uuid", json_string(peer_uuid_str));
    json_object_set_new(resp_json, "score", json_real(score));
    json_object_set_new(resp_json, "requesting_process", json_string(req_proc_str));
    json_decref(payload);

    generic_msg_t resp = {0};
    resp.type = NET_MESSAGE;
    strncpy(resp.info.net_msg.process, "reputation", PROC_NAME_LEN);
    resp.info.net_msg.function = REP_PROTO_REP_RESP;
    resp.info.net_msg.encrypt = true;
    memcpy(&resp.info.net_msg.to_whom, &nmsg->from_whom, sizeof(public_identity_t));
    strncpy(resp.info.net_msg.return_to, "reputation", PROC_NAME_LEN);
    net_msg_pack_json(&resp.info.net_msg, resp_json);
    json_decref(resp_json);

    messaging_send("network", NET_MESSAGE, &resp, false);
    return true;
}

/****************************
 * Handler: handle_rep_request (reputation request)
 * Compute reputation for a peer and respond.
 ****************************/

/*@
  requires \valid(proc);
  requires \valid(queues);
  requires \valid(msg);
  requires proc->logger == \null || \valid(proc->logger);
*/
static bool handle_rep_request(const process_t *proc, directory_t *queues, generic_msg_t *msg)
{
    net_msg_t *nmsg = &msg->info.net_msg;
    log_debug(proc->logger, "Reputation: rep request from %s\n", nmsg->from_whom.nickname);
    /* Mirrors Python's `_probes.counter('rep.compute', 'enter')` at
     * repprocess.py:429; the rep.compute layer correlates handle_req
     * → compute → forward across the reputation pipeline. */
    probes_counter("rep.compute", "enter", NULL);

    /* Unpack (peer_uuid, requesting_process) */
    json_t *payload = NULL;
    if (net_msg_unpack_json(nmsg, &payload) != 0 || payload == NULL)
    {
        log_error(proc->logger, "Reputation: handle_rep_request: failed to unpack JSON\n");
        probes_counter("rep.compute", "exception", "unpack_failed");
        return false;
    }

    json_t *j_peer_uuid  = json_object_get(payload, "peer_uuid");
    json_t *j_req_proc   = json_object_get(payload, "requesting_process");

    if (!j_peer_uuid || !j_req_proc)
    {
        json_decref(payload);
        log_error(proc->logger, "Reputation: handle_rep_request: missing JSON fields\n");
        return false;
    }

    const char *peer_uuid_str = json_string_value(j_peer_uuid);
    const char *req_proc_str  = json_string_value(j_req_proc);

    /* Parse UUID and compute reputation */
    uuid_t peer_uuid;
    double score = 0.0;
    bool have_uuid = false;
    if (uuid_parse(peer_uuid_str, peer_uuid) == 0)
    {
        have_uuid = true;
        pthread_mutex_lock(&rep_state.lock);
        /* Use a dummy self uuid (zero) for now — process doesn't carry self identity */
        uuid_t self_uuid;
        uuid_clear(self_uuid);

        /* Hysteresis: switch to pure mode only after the previous score
         * crosses COOP_ENTER; fall back to CTFT only after it drops
         * below COOP_EXIT. Mirrors Python's self._coop_mode latch in
         * repprocess.py. A single 0.5 gate caused peers hovering near
         * 0.5 to flip scoring functions every tick (CTFT's 0.51 →
         * pure_reputation's 0.4 → CTFT's 0.51 → …). reputation_compute
         * remains a single-gate pure function (used by unit tests);
         * the hysteresis lives here, at the protocol boundary, where
         * the per-peer state is available. */
        double current_score = 0.0;
        reputations_get(&rep_state.reputations, peer_uuid, &current_score);

        char coop_key[UUID_STRING_LEN + 1];
        uuid_unparse_lower(peer_uuid, coop_key);
        int in_coop = 0;
        data_t *mode_dat = NULL;
        if (map_get(&rep_state.coop_mode, coop_key, &mode_dat) == 0 &&
            mode_dat != NULL) {
            data_integer(mode_dat, &in_coop);
        }
        bool use_pure = in_coop
            ? (current_score > COOP_EXIT)
            : (current_score > COOP_ENTER);
        map_set(&rep_state.coop_mode, coop_key,
                integer_data(use_pure ? 1 : 0));

        if (use_pure) {
            score = reputation_pure(&rep_state.history,
                                    &rep_state.reputations, peer_uuid,
                                    &rep_state.task_weights);
        } else {
            score = reputation_contrite_tft(&rep_state.history,
                                            &rep_state.reputations,
                                            self_uuid, peer_uuid);
        }
        reputations_update(&rep_state.reputations, peer_uuid, score);
        pthread_mutex_unlock(&rep_state.lock);
    }

    /* Publish a tier_update IPC to identity if the score crossed a tier.
     * Mirrors Python's _publish_tier_change drain in repprocess.py.
     * Done inline here (rather than queued) because handle_rep_request
     * already holds the send context; Python uses a queue because its
     * _compute_reputation runs in a spawned thread without queue access. */
    if (have_uuid) {
        _publish_tier_change(proc, peer_uuid, score);
        _publish_reputation_change(peer_uuid, score);
        probes_counter("rep.compute", "queued", NULL);
    }

    /* Pack response (peer_uuid, score, requesting_process) */
    json_t *resp_json = json_object();
    if (resp_json == NULL) {
        log_error(proc->logger, "Reputation: json_object OOM (rep_resp)\n");
        json_decref(payload);
        return true;
    }
    json_object_set_new(resp_json, "peer_uuid", json_string(peer_uuid_str));
    json_object_set_new(resp_json, "score", json_real(score));
    json_object_set_new(resp_json, "requesting_process", json_string(req_proc_str));

    json_decref(payload);

    generic_msg_t resp = {0};
    resp.type = NET_MESSAGE;
    strncpy(resp.info.net_msg.process, "reputation", PROC_NAME_LEN);
    resp.info.net_msg.function = REP_PROTO_REP_RESP;
    resp.info.net_msg.encrypt = true;
    memcpy(&resp.info.net_msg.to_whom, &nmsg->from_whom, sizeof(public_identity_t));
    strncpy(resp.info.net_msg.return_to, "reputation", PROC_NAME_LEN);
    net_msg_pack_json(&resp.info.net_msg, resp_json);
    json_decref(resp_json);

    messaging_send("network", NET_MESSAGE, &resp, false);
    return true;
}

/****************************
 * Handler: handle_rep_response (reputation response)
 ****************************/

/*@
  requires \valid(proc);
  requires \valid(queues);
  requires \valid(msg);
  requires proc->logger == \null || \valid(proc->logger);
*/
static bool handle_rep_response(const process_t *proc, directory_t *queues, generic_msg_t *msg)
{
    net_msg_t *nmsg = &msg->info.net_msg;
    log_debug(proc->logger, "Reputation: rep response from %s\n", nmsg->from_whom.nickname);

    /* Unpack and store in requested_reps array */
    json_t *payload = NULL;
    if (net_msg_unpack_json(nmsg, &payload) != 0 || payload == NULL)
    {
        log_error(proc->logger, "Reputation: handle_rep_response: failed to unpack JSON\n");
        return false;
    }

    /* Store the JSON payload in requested_reps for later processing */
    data_t *resp_dat = object_ptr_data(payload, sizeof(json_t));
    pthread_mutex_lock(&rep_state.lock);
    array_append(&rep_state.requested_reps, resp_dat);
    pthread_mutex_unlock(&rep_state.lock);

    return true;
}

/****************************
 * Handler: handle_local_rep_query (local IPC reputation query)
 * Another local process (e.g. ZTA) asks for a peer's reputation score.
 * Responds via local IPC to the requesting process.
 ****************************/

/*@
  requires \valid(proc);
  requires \valid(queues);
  requires \valid(msg);
  requires proc->logger == \null || \valid(proc->logger);
*/
static bool handle_local_rep_query(const process_t *proc, directory_t *queues, generic_msg_t *msg)
{
    net_msg_t *nmsg = &msg->info.net_msg;

    json_t *payload = NULL;
    if (net_msg_unpack_json(nmsg, &payload) != 0 || payload == NULL)
    {
        log_error(proc->logger, "Reputation: handle_local_rep_query: failed to unpack JSON\n");
        return false;
    }

    json_t *j_peer_uuid  = json_object_get(payload, "peer_uuid");
    json_t *j_return_proc = json_object_get(payload, "return_process");

    if (!j_peer_uuid || !j_return_proc)
    {
        json_decref(payload);
        log_error(proc->logger, "Reputation: handle_local_rep_query: missing JSON fields\n");
        return false;
    }

    const char *peer_uuid_str = json_string_value(j_peer_uuid);
    const char *return_proc   = json_string_value(j_return_proc);

    uuid_t peer_uuid;
    double score = 0.0;
    bool found = false;
    if (uuid_parse(peer_uuid_str, peer_uuid) == 0)
    {
        pthread_mutex_lock(&rep_state.lock);
        if (reputations_contains(&rep_state.reputations, peer_uuid))
        {
            reputations_get(&rep_state.reputations, peer_uuid, &score);
            found = true;
        }
        pthread_mutex_unlock(&rep_state.lock);
    }

    /* Build response */
    json_t *resp_json = json_object();
    if (resp_json == NULL) {
        log_error(proc->logger, "Reputation: json_object OOM (local_resp)\n");
        json_decref(payload);
        return true;
    }
    json_object_set_new(resp_json, "peer_uuid", json_string(peer_uuid_str));
    json_object_set_new(resp_json, "score", json_real(score));
    json_object_set_new(resp_json, "found", json_boolean(found));

    json_decref(payload);

    generic_msg_t resp = {0};
    resp.type = NET_MESSAGE;
    strncpy(resp.info.net_msg.process, return_proc, PROC_NAME_LEN);
    resp.info.net_msg.function = REP_PROTO_LOCAL_RESP;
    net_msg_pack_json(&resp.info.net_msg, resp_json);
    json_decref(resp_json);

    messaging_send(return_proc, NET_MESSAGE, &resp, false);
    return true;
}

/****************************
 * Forward transaction: start Paxos for a local score
 * Called when TRANSACTION_SCORE message arrives from negotiation.
 ****************************/

/* Frama-C: skipped — [solver-timeout] uuid_unparse + strncpy + memcpy +
 * json_object_set_new + smrt_create cascade with peer-loop too complex for SMT */
/*@
  requires \valid(proc);
  requires proc->logger == \null || \valid(proc->logger);
  requires rep_state.paxos.initialized == \true;
*/
void _forward_transaction(const process_t *proc, const uuid_t task_uuid,
                          const uuid_t peer_uuid, double score,
                          const char *capability_name)
{
    char task_str[UUID_STRING_LEN + 1];
    uuid_unparse_lower(task_uuid, task_str);
    log_info(proc->logger, "Reputation: forwarding transaction for task %s, score %.2f (cap %s)\n",
             task_str, score,
             (capability_name && capability_name[0]) ? capability_name : "-");

    pthread_mutex_lock(&rep_state.lock);

    /* Store in my_requests */
    tx_score_t *tx = smrt_create(sizeof(tx_score_t));
    if (tx != NULL)
    {
        uuid_copy(tx->task_uuid, task_uuid);
        tx->score = score;
        /* Carry the capability name so _pure_reputation weights this tx by
         * its tier (mirrors Python TransactionScore.capability_name). */
        if (capability_name != NULL)
            strncpy(tx->capability_name, capability_name, CAP_NAMELEN);
        else
            tx->capability_name[0] = '\0';
        tx->capability_name[CAP_NAMELEN] = '\0';
        data_t *tx_dat = object_ptr_data(tx, sizeof(tx_score_t));
        map_set(&rep_state.my_requests, task_str, tx_dat);
    }

    /* Cache the weight for this task so _pure_reputation can aggregate it
     * (mirrors Python _start_paxos → _record_task_weight). Done under the
     * same lock as the my_requests insert. */
    _record_task_weight_locked(task_str, _resolve_tx_weight(capability_name));
    _record_task_tier_locked(task_str, _resolve_tx_tier(capability_name));

    pthread_mutex_unlock(&rep_state.lock);

    /* Compute Paxos IDs via shared engine */
    int64_t id1, id2;
    paxos_next_ids(&rep_state.paxos, &id1, &id2);

    /* Get identity UUID for the request */
    char identity_uuid[UUID_STRING_LEN + 1];
    uuid_unparse_lower(peer_uuid, identity_uuid);

    /* Broadcast Paxos Phase 1a: request permission from all peers */
    peers_read_lock(proc);
    for (size_t i = 0; i < proc->protocol.num_peers; i++)
    {
        generic_msg_t req = {0};
        req.type = NET_MESSAGE;
        strncpy(req.info.net_msg.process, "reputation", PROC_NAME_LEN);
        req.info.net_msg.function = REP_PROTO_REQUEST;
        req.info.net_msg.encrypt = true;
        memcpy(&req.info.net_msg.to_whom, &proc->protocol.peers[i], sizeof(public_identity_t));
        strncpy(req.info.net_msg.return_to, "reputation", PROC_NAME_LEN);

        /* Pack (id1, id2, identity_uuid) as JSON into the request */
        json_t *req_json = json_object();
        if (req_json == NULL) {
            log_error(proc->logger, "Reputation: json_object OOM (start_paxos)\n");
            continue;
        }
        json_object_set_new(req_json, "id1", json_integer(id1));
        json_object_set_new(req_json, "id2", json_integer(id2));
        json_object_set_new(req_json, "peer_uuid", json_string(identity_uuid));
        net_msg_pack_json(&req.info.net_msg, req_json);
        json_decref(req_json);

        messaging_send("network", NET_MESSAGE, &req, false);
    }
    peers_read_unlock(proc);

}

/****************************
 * Reputation process main entry
 ****************************/

/****************************
 * Slashing (fast-penalty path) — Phase 0 C twin.
 * Mirrors Python repprocess.handle_slash_propose / _sign / _final +
 * _apply_slash. A finalized slash floors the target's reputation
 * immediately, bypassing the consensus EMA. Wire payloads are plain
 * JSON objects (per-implementation shape; byte_pinning:false conformance
 * checks state equivalence, not injected-message bytes). C has no direct
 * self-identity here (see handle_rep_request), so there is no self-skip
 * — handle_committed documents the same: the broadcast loop excludes
 * self, and applying an idempotent floor twice is harmless.
 ****************************/

/* Mirror the floor into the reputations store (so
 * reputation_get_peer_reputation + handle_consensus_rep_request reflect
 * it) and record the target in the slashed set. Caller holds the lock.
 * Idempotent per target. */
static void _apply_slash_locked(const char *target_str,
                                const uuid_t target_uuid,
                                double floor, int64_t epoch)
{
    data_t *seen = NULL;
    if (map_get(&rep_state.slashed, (map_key_t)target_str, &seen) == 0)
        return;  /* already slashed */
    reputations_update(&rep_state.reputations, target_uuid, floor);
    map_set(&rep_state.slashed, (map_key_t)target_str,
            integer_data((int)epoch));
}

/* Phase 3: gate a slash on Merkle evidence. Mirrors Python
 * ReputationProcess._verify_slash_evidence.
 *  - evidence absent/null -> true (Phase 0 trust-the-detector fallback).
 *  - evidence present -> the offending tx's inclusion proof
 *    {leaf, proof:[[sibling,is_left],...], root} must verify, AND root must
 *    equal a checkpoint this node has FINALIZED (rep_state.checkpoint_root),
 *    so the accuser cannot pick the root. Malformed/mismatched -> false. */
static bool _verify_slash_evidence(json_t *evidence)
{
    if (evidence == NULL || json_is_null(evidence))
        return true;
    const char *leaf = json_string_value(json_object_get(evidence, "leaf"));
    const char *root = json_string_value(json_object_get(evidence, "root"));
    json_t *proof = json_object_get(evidence, "proof");
    if (leaf == NULL || root == NULL || !json_is_array(proof))
        return false;
    size_t n = json_array_size(proof);
    if (n > MAX_CHAIN_LEN)
        return false;
    tx_merkle_step_t steps[MAX_CHAIN_LEN];
    for (size_t i = 0; i < n; i++)
    {
        json_t *step = json_array_get(proof, i);
        if (!json_is_array(step) || json_array_size(step) < 2)
            return false;
        const char *sib = json_string_value(json_array_get(step, 0));
        if (sib == NULL)
            return false;
        strncpy(steps[i].sibling, sib, TX_HASH_HEX_LEN);
        steps[i].sibling[TX_HASH_HEX_LEN] = '\0';
        steps[i].sibling_is_left = json_is_true(json_array_get(step, 1));
    }
    /* ANY chain we have finalized counts, not only the primary one: a gateway
     * finalizes a checkpoint per child group, and a tx that offended inside a
     * child group is anchored in THAT group's root. Accepting only the primary
     * root would refuse every legitimate subtree slash while adding no
     * security — each root cleared the same quorum test (§10.2). */
    pthread_mutex_lock(&rep_state.lock);
    bool root_ok = false;
    map_key_t ck_key = NULL;
    data_t *ck_val = NULL;
    map_entries_for_each(&rep_state.chain_ckpts, ck_key, ck_val)
    {
        void *sp = NULL;
        if (data_object_ptr(ck_val, &sp) != 0 || sp == NULL)
            continue;
        rep_chain_ckpt_t *slot = (rep_chain_ckpt_t *)sp;
        if (slot->set
            && strncmp(root, slot->root, TX_HASH_HEX_LEN + 1) == 0)
            root_ok = true;
    }
    map_end_for_each
    pthread_mutex_unlock(&rep_state.lock);
    if (!root_ok)
        return false;
    return tx_merkle_verify(leaf, steps, (int)n, root);
}

/****************************
 * Quorum co-signatures (slash + checkpoint)
 *
 * Mirrors Python repprocess._detached_sig / _cosigner_identity /
 * _verify_cosignature / _verified_cosigners / _quorum_met.
 *
 * Both rounds used to carry no attestation whatsoever. This side was the
 * thinner of the two: the co-sign ack reported `uuid_clear`'d bytes as its
 * signer and no signature at all, and the tally was a BARE COUNT
 * (integer_data) with no voter identity — so replaying one ack drove the count
 * past quorum and a single peer finalized alone. The `*_final` handlers then
 * applied whatever arrived, on transport authentication only. Since a slash
 * floors a peer below COMM_CUTOFF into exclusion that is sticky (recovery only
 * by explicit REASON_REHABILITATE), that was a permanent-exclusion primitive
 * available to any admitted member.
 *
 * Now: a co-signer signs the round's designation with its own key, the tally is
 * keyed by VOTER (so one voter is one vote however many acks arrive), the
 * finalizer carries the retained signatures, and every receiver re-verifies
 * them against the member keys it holds before acting. Designation bytes are
 * byte-identical to Python's SlashAttestation.designation /
 * Checkpoint.designation — the hazard to watch when editing either side.
 *
 * Signature form follows _partition_sign_hex / _partition_verify_hex in
 * id_proc.c: detached Ed25519, carried as ASCII hex.
 ****************************/

/* Longest designation: tag + 2 uuids (or uuid + 64-hex root) + reason +
 * fixed-form floor + three integers, plus separators. 512 is generous. */
#define REP_DESIG_MAX 512
#define REP_SIG_HEX_LEN (crypto_sign_BYTES * 2)
/* A pending round record, held as a small JSON string. It carries EVERY field
 * the round's designation covers, not just the floor / root the maps used to
 * hold: a co-signer and the finalizer both have to reproduce the proposer's
 * exact bytes, and a field missing here is a signature that verifies nowhere. */
#define REP_PENDING_MAX 256

static void _store_pending_locked(map_t *pending, const char *key, json_t *rec)
{
    if (rec == NULL)
        return;
    char *text = json_dumps(rec, JSON_COMPACT | JSON_SORT_KEYS);
    if (text != NULL && strlen(text) < REP_PENDING_MAX)
        map_set(pending, (map_key_t)key,
                string_data((string_t)text, strlen(text) + 1));
    free(text);
}

/* Read a pending round record back. Caller owns the returned reference. */
static json_t *_load_pending_locked(map_t *pending, const char *key)
{
    data_t *dat = NULL;
    if (map_get(pending, (map_key_t)key, &dat) != 0 || dat == NULL)
        return NULL;
    char text[REP_PENDING_MAX] = {0};
    if (data_string(dat, text, sizeof(text)) != 0)
        return NULL;
    json_error_t err;
    return json_loads(text, 0, &err);
}

/* Self identity (with the private signing key) out of proc->configs — the same
 * access path _resolve_self_uuid, net_proc.c and zta_process.c use. */
static const identity_t *_resolve_self_identity(const process_t *proc)
{
    if (proc == NULL || proc->configs == NULL)
        return NULL;
    data_t *id_dat = NULL;
    char id_key[] = "identity";
    if (map_get(proc->configs, id_key, &id_dat) != 0 || id_dat == NULL)
        return NULL;
    config_t *id_cfg = NULL;
    if (data_object_ptr(id_dat, (void **)&id_cfg) != 0 || id_cfg == NULL
        || id_cfg->data_struct == NULL)
        return NULL;
    return (const identity_t *)id_cfg->data_struct;
}

/* Canonical bytes a slash co-signer signs. MUST stay byte-identical to
 * Python SlashAttestation.designation:
 *   "AT-SLASH\0" slasher "|" target "|" reason "|" %.6f floor "|" epoch
 * The float is fixed-precision because that is the one byte-pinning hazard
 * across the two languages. Returns the length, or 0 on bad input. */
static size_t _slash_designation(const char *slasher, const char *target,
                                 const char *reason, double floor,
                                 int64_t epoch, uint8_t *out, size_t cap)
{
    if (slasher == NULL || target == NULL || reason == NULL || out == NULL)
        return 0;
    static const char tag[] = "AT-SLASH";
    size_t tag_len = sizeof(tag);   /* includes the NUL separator */
    int n = snprintf((char *)out + tag_len, cap - tag_len,
                     "%s|%s|%s|%.6f|%lld", slasher, target, reason, floor,
                     (long long)epoch);
    if (n < 0 || (size_t)n >= cap - tag_len)
        return 0;
    memcpy(out, tag, tag_len);
    return tag_len + (size_t)n;
}

/* Sign `desig` with our own key, ASCII hex out (REP_SIG_HEX_LEN + 1 bytes). */
static int _cosign_hex(const process_t *proc, const uint8_t *desig,
                       size_t dlen, char *hex_out, size_t hex_cap)
{
    const identity_t *self = _resolve_self_identity(proc);
    if (self == NULL || desig == NULL || dlen == 0
        || hex_cap < REP_SIG_HEX_LEN + 1)
        return -1;
    unsigned char sig[crypto_sign_BYTES];
    if (crypto_sign_detached(sig, NULL, desig, dlen,
                             self->signature.private) != 0)
        return -1;
    hexlify(sig, crypto_sign_BYTES, (unsigned char *)hex_out);
    return 0;
}

/* Copy out the signing public key for `voter_str`: self first (a proposer
 * counts its own signature), then the peer roster. False when the claimed
 * voter is unknown to us — an unknown voter's signature cannot be verified, so
 * it cannot count. Copies rather than returning a pointer into peers[], which
 * is only valid under the rwlock. */
static bool _cosigner_pubkey(const process_t *proc, const char *voter_str,
                             unsigned char out[crypto_sign_PUBLICKEYBYTES])
{
    if (proc == NULL || voter_str == NULL || out == NULL)
        return false;
    const identity_t *self = _resolve_self_identity(proc);
    if (self != NULL)
    {
        char self_str[UUID_STRING_LEN + 1];
        uuid_unparse_lower(self->uuid, self_str);
        if (strncmp(self_str, voter_str, sizeof(self_str)) == 0)
        {
            memcpy(out, self->signature.public, crypto_sign_PUBLICKEYBYTES);
            return true;
        }
    }
    bool found = false;
    peers_read_lock(proc);
    for (size_t i = 0; i < proc->protocol.num_peers; i++)
    {
        char peer_str[UUID_STRING_LEN + 1];
        uuid_unparse_lower(proc->protocol.peers[i].uuid, peer_str);
        if (strncmp(peer_str, voter_str, sizeof(peer_str)) == 0)
        {
            memcpy(out, proc->protocol.peers[i].signature.public,
                   crypto_sign_PUBLICKEYBYTES);
            found = true;
            break;
        }
    }
    peers_read_unlock(proc);
    return found;
}

/* True iff `sig_hex` is `voter_str`'s signature over `desig`. Any malformed /
 * unknown / bad-signature case is false: a co-signature that cannot be checked
 * must never be counted. */
static bool _verify_cosignature(const process_t *proc, const char *voter_str,
                                const uint8_t *desig, size_t dlen,
                                const char *sig_hex)
{
    if (voter_str == NULL || sig_hex == NULL || desig == NULL || dlen == 0)
        return false;
    if (strnlen(sig_hex, REP_SIG_HEX_LEN + 2) != REP_SIG_HEX_LEN)
        return false;
    unsigned char pubkey[crypto_sign_PUBLICKEYBYTES];
    if (!_cosigner_pubkey(proc, voter_str, pubkey))
        return false;
    unsigned char sig[crypto_sign_BYTES];
    if (unhexlify((const unsigned char *)sig_hex, REP_SIG_HEX_LEN, sig) != 0)
        return false;
    return crypto_sign_verify_detached(sig, desig, dlen, pubkey) == 0;
}

/* Count the DISTINCT voters in the `sigs` object whose signature over `desig`
 * verifies. JSON object keys are unique by construction, so distinctness comes
 * for free — the property Python gets from keying a dict by voter, and the one
 * the old bare count lacked. */
static size_t _verified_cosigners(const process_t *proc, json_t *sigs,
                                  const uint8_t *desig, size_t dlen)
{
    if (sigs == NULL || !json_is_object(sigs))
        return 0;
    size_t count = 0;
    const char *voter = NULL;
    json_t *val = NULL;
    json_object_foreach(sigs, voter, val)
    {
        if (_verify_cosignature(proc, voter, desig, dlen,
                                json_string_value(val)))
            count++;
    }
    return count;
}

/* Receiver-side quorum test: more than floor(N/2) distinct voters must have
 * signed the exact bytes we re-derive. Sized against OUR OWN roster
 * (proc->protocol.num_peers, the mirror of Python's len(peers.all)), so the
 * finalizer cannot also choose the bar it has to clear. */
static bool _quorum_met_for(const process_t *proc, json_t *sigs,
                            const uint8_t *desig, size_t dlen,
                            const char *group_uuid)
{
    if (proc == NULL)
        return false;
    peers_read_lock(proc);
    /* Sized against the group whose chain the round covers: a child-group
     * checkpoint must clear THAT group's majority, not the conflated roster a
     * gateway sees across every group it belongs to. A leaf node (no child
     * groups) gets num_peers/2 exactly as before. */
    size_t quorum = _quorum_for_group(proc, group_uuid);
    peers_read_unlock(proc);
    return _verified_cosigners(proc, sigs, desig, dlen) > quorum;
}

static bool _quorum_met(const process_t *proc, json_t *sigs,
                        const uint8_t *desig, size_t dlen)
{
    return _quorum_met_for(proc, sigs, desig, dlen, NULL);
}

/* Record one verified co-signature for a round. The map is keyed
 * "<round>:<voter>" so a voter re-sending its ack overwrites rather than
 * increments: one voter, one vote. */
static void _record_cosig_locked(map_t *sigs, const char *round_key,
                                 const char *voter, const char *sig_hex)
{
    char key[UUID_STRING_LEN * 2 + 48];
    snprintf(key, sizeof(key), "%s:%s", round_key, voter);
    map_set(sigs, (map_key_t)key,
            string_data((string_t)sig_hex, strlen(sig_hex) + 1));
}

/* Collect a round's recorded co-signatures into a fresh JSON object
 * {voter: sig_hex} for the finalizer to carry, and report how many there are.
 * Caller owns the returned reference. */
static json_t *_cosigs_json_locked(map_t *sigs, const char *round_key,
                                   size_t *count_out)
{
    json_t *out = json_object();
    size_t count = 0;
    if (out == NULL)
    {
        if (count_out) *count_out = 0;
        return NULL;
    }
    size_t prefix_len = strlen(round_key) + 1;   /* "<round>:" */
    map_key_t key = NULL;
    data_t *value = NULL;
    map_entries_for_each(sigs, key, value)
    {
        if (strncmp(key, round_key, prefix_len - 1) != 0
            || key[prefix_len - 1] != ':')
            continue;
        char sig_hex[REP_SIG_HEX_LEN + 1] = {0};
        if (data_string(value, sig_hex, sizeof(sig_hex)) != 0)
            continue;
        json_object_set_new(out, key + prefix_len, json_string(sig_hex));
        count++;
    }
    map_end_for_each;
    if (count_out) *count_out = count;
    return out;
}

static bool handle_slash_propose(const process_t *proc, directory_t *queues, generic_msg_t *msg)
{
    (void)queues;
    net_msg_t *nmsg = &msg->info.net_msg;
    if (!nmsg->verified)
    {
        log_warn(proc->logger,
                 "Reputation: rejecting unverified slash_propose from %s\n",
                 nmsg->from_whom.nickname);
        return true;
    }
    json_t *payload = NULL;
    if (net_msg_unpack_json(nmsg, &payload) != 0 || payload == NULL)
        return false;
    const char *target_str =
        json_string_value(json_object_get(payload, "target_uuid"));
    double floor = json_real_value(json_object_get(payload, "floor_score"));
    int64_t epoch = json_integer_value(json_object_get(payload, "epoch"));
    const char *slasher_str =
        json_string_value(json_object_get(payload, "slasher_uuid"));
    const char *propose_reason =
        json_string_value(json_object_get(payload, "reason"));
    if (target_str == NULL)
    {
        json_decref(payload);
        return false;
    }
    /* Phase 3: refuse to co-sign a slash whose Merkle evidence does not
     * verify against our finalized checkpoint (evidence-free -> trusted). */
    if (!_verify_slash_evidence(json_object_get(payload, "evidence")))
    {
        log_warn(proc->logger,
                 "Reputation: declining slash_propose, evidence failed verification\n");
        json_decref(payload);
        return true;
    }
    char key[UUID_STRING_LEN + 32];
    snprintf(key, sizeof(key), "%s:%lld", target_str, (long long)epoch);
    json_t *pending_rec = json_object();
    if (pending_rec != NULL)
    {
        json_object_set_new(pending_rec, "slasher_uuid",
                            json_string(slasher_str ? slasher_str : ""));
        json_object_set_new(pending_rec, "reason",
                            json_string(propose_reason ? propose_reason : ""));
        json_object_set_new(pending_rec, "floor_score", json_real(floor));
    }
    pthread_mutex_lock(&rep_state.lock);
    _store_pending_locked(&rep_state.slash_pending, key, pending_rec);
    pthread_mutex_unlock(&rep_state.lock);
    json_decref(pending_rec);

    /* Co-sign: sign the attestation designation with our own key and emit
     * slash_sign back to the proposer, naming ourselves. A round we cannot
     * fully identify (no slasher / no reason) cannot be signed — the
     * designation covers both fields — so decline rather than sign different
     * bytes than the proposer will verify. */
    const identity_t *self = _resolve_self_identity(proc);
    uint8_t desig[REP_DESIG_MAX];
    size_t dlen = (slasher_str != NULL && propose_reason != NULL)
        ? _slash_designation(slasher_str, target_str, propose_reason, floor,
                             epoch, desig, sizeof(desig))
        : 0;
    char sig_hex[REP_SIG_HEX_LEN + 1] = {0};
    if (self == NULL || dlen == 0
        || _cosign_hex(proc, desig, dlen, sig_hex, sizeof(sig_hex)) != 0)
    {
        log_warn(proc->logger,
                 "Reputation: cannot sign slash_propose (%s); declining to co-sign\n",
                 self == NULL ? "no self identity"
                              : "round not fully identified");
        json_decref(payload);
        return true;
    }
    char self_str[UUID_STRING_LEN + 1];
    uuid_unparse_lower(self->uuid, self_str);
    json_t *sign_json = json_object();
    if (sign_json == NULL)
    {
        json_decref(payload);
        return true;
    }
    json_object_set_new(sign_json, "target_uuid", json_string(target_str));
    json_object_set_new(sign_json, "epoch", json_integer(epoch));
    json_object_set_new(sign_json, "signer_uuid", json_string(self_str));
    json_object_set_new(sign_json, "signature", json_string(sig_hex));
    json_decref(payload);

    generic_msg_t sign = {0};
    sign.type = NET_MESSAGE;
    strncpy(sign.info.net_msg.process, "reputation", PROC_NAME_LEN);
    sign.info.net_msg.function = REP_PROTO_SLASH_SIGN;
    sign.info.net_msg.encrypt = true;
    memcpy(&sign.info.net_msg.to_whom, &nmsg->from_whom,
           sizeof(public_identity_t));
    strncpy(sign.info.net_msg.return_to, "reputation", PROC_NAME_LEN);
    net_msg_pack_json(&sign.info.net_msg, sign_json);
    json_decref(sign_json);
    messaging_send("network", NET_MESSAGE, &sign, false);
    return true;
}

static bool handle_slash_sign(const process_t *proc, directory_t *queues, generic_msg_t *msg)
{
    (void)queues;
    net_msg_t *nmsg = &msg->info.net_msg;
    if (!nmsg->verified)
        return true;
    json_t *payload = NULL;
    if (net_msg_unpack_json(nmsg, &payload) != 0 || payload == NULL)
        return false;
    const char *target_str =
        json_string_value(json_object_get(payload, "target_uuid"));
    int64_t epoch = json_integer_value(json_object_get(payload, "epoch"));
    const char *claimed =
        json_string_value(json_object_get(payload, "signer_uuid"));
    const char *ack_sig =
        json_string_value(json_object_get(payload, "signature"));
    if (target_str == NULL)
    {
        json_decref(payload);
        return false;
    }
    char key[UUID_STRING_LEN + 32];
    snprintf(key, sizeof(key), "%s:%lld", target_str, (long long)epoch);

    /* Credit the AUTHENTICATED sender, never the uuid the payload claims. */
    char voter[UUID_STRING_LEN + 1];
    uuid_unparse_lower(nmsg->from_whom.uuid, voter);
    if (claimed != NULL && strncmp(claimed, voter, sizeof(voter)) != 0)
    {
        log_warn(proc->logger,
                 "Reputation: slash_sign claims voter %s but was sent by %s; refused\n",
                 claimed, voter);
        json_decref(payload);
        return true;
    }

    /* Rebuild the proposer's designation from the pending round and verify the
     * ack against it. An unverifiable co-signature is not a vote. */
    pthread_mutex_lock(&rep_state.lock);
    json_t *pending = _load_pending_locked(&rep_state.slash_pending, key);
    pthread_mutex_unlock(&rep_state.lock);
    if (pending == NULL)
    {
        json_decref(payload);
        return true;   /* not our round, or already finalized */
    }
    const char *slasher_str =
        json_string_value(json_object_get(pending, "slasher_uuid"));
    const char *reason_str =
        json_string_value(json_object_get(pending, "reason"));
    double floor = json_real_value(json_object_get(pending, "floor_score"));
    uint8_t desig[REP_DESIG_MAX];
    size_t dlen = _slash_designation(slasher_str, target_str, reason_str, floor,
                                    epoch, desig, sizeof(desig));
    if (dlen == 0 || !_verify_cosignature(proc, voter, desig, dlen, ack_sig))
    {
        log_warn(proc->logger,
                 "Reputation: slash_sign co-signature from %s failed verification; not counted\n",
                 voter);
        json_decref(pending);
        json_decref(payload);
        return true;
    }

    pthread_mutex_lock(&rep_state.lock);
    _record_cosig_locked(&rep_state.slash_sigs, key, voter, ack_sig);
    size_t count = 0;
    json_t *sigs = _cosigs_json_locked(&rep_state.slash_sigs, key, &count);
    pthread_mutex_unlock(&rep_state.lock);
    peers_read_lock(proc);
    size_t quorum = proc->protocol.num_peers / 2;
    peers_read_unlock(proc);
    bool finalize = count > quorum;
    json_decref(pending);
    json_decref(payload);

    if (finalize)
    {
        json_t *final_json = json_object();
        if (final_json == NULL)
        {
            json_decref(sigs);
            return true;
        }
        json_object_set_new(final_json, "target_uuid",
                            json_string(target_str));
        json_object_set_new(final_json, "floor_score", json_real(floor));
        json_object_set_new(final_json, "epoch", json_integer(epoch));
        /* The round's identity travels too: a receiver has to re-derive this
         * designation to check the co-signatures it is being handed. */
        json_object_set_new(final_json, "slasher_uuid",
                            json_string(slasher_str ? slasher_str : ""));
        json_object_set_new(final_json, "reason",
                            json_string(reason_str ? reason_str : ""));
        json_object_set(final_json, "sigs", sigs);
        generic_msg_t bcast = {0};
        bcast.type = NET_MESSAGE;
        strncpy(bcast.info.net_msg.process, "reputation", PROC_NAME_LEN);
        bcast.info.net_msg.function = REP_PROTO_SLASH_FINAL;
        bcast.info.net_msg.encrypt = true;
        net_msg_pack_json(&bcast.info.net_msg, final_json);
        json_decref(final_json);
        peers_read_lock(proc);
        for (size_t i = 0; i < proc->protocol.num_peers; i++)
        {
            generic_msg_t per = bcast;
            memcpy(&per.info.net_msg.to_whom, &proc->protocol.peers[i],
                   sizeof(public_identity_t));
            messaging_send("network", NET_MESSAGE, &per, false);
        }
        peers_read_unlock(proc);
    }
    json_decref(sigs);
    return true;
}

static bool handle_slash_final(const process_t *proc, directory_t *queues, generic_msg_t *msg)
{
    (void)queues;
    net_msg_t *nmsg = &msg->info.net_msg;
    if (!nmsg->verified)
    {
        log_warn(proc->logger,
                 "Reputation: rejecting unverified slash_final from %s\n",
                 nmsg->from_whom.nickname);
        return true;
    }
    json_t *payload = NULL;
    if (net_msg_unpack_json(nmsg, &payload) != 0 || payload == NULL)
        return false;
    const char *target_str =
        json_string_value(json_object_get(payload, "target_uuid"));
    double floor = json_real_value(json_object_get(payload, "floor_score"));
    int64_t epoch = json_integer_value(json_object_get(payload, "epoch"));
    const char *reason =
        json_string_value(json_object_get(payload, "reason"));
    if (target_str == NULL)
    {
        json_decref(payload);
        return false;
    }
    uuid_t target_uuid;
    if (uuid_parse(target_str, target_uuid) != 0)
    {
        json_decref(payload);
        return false;
    }
    /* Phase 3: apply an evidence-bearing slash only if its inclusion proof
     * verifies against our finalized checkpoint (evidence-free -> trusted). */
    if (!_verify_slash_evidence(json_object_get(payload, "evidence")))
    {
        log_warn(proc->logger,
                 "Reputation: rejecting slash_final, evidence failed verification\n");
        json_decref(payload);
        return true;
    }
    /* Quorum is verified HERE, by us, over the retained co-signatures.
     * Transport authentication says only that some admitted member sent this;
     * it says nothing about whether a majority agreed, and a slash floors a
     * peer into sticky exclusion. A finalizer carrying no verifiable
     * co-signatures is refused — the flag day noted in reputation.md. */
    {
        const char *slasher_str =
            json_string_value(json_object_get(payload, "slasher_uuid"));
        uint8_t desig[REP_DESIG_MAX];
        size_t dlen = (slasher_str != NULL && reason != NULL)
            ? _slash_designation(slasher_str, target_str, reason, floor, epoch,
                                 desig, sizeof(desig))
            : 0;
        json_t *sigs = json_object_get(payload, "sigs");
        if (dlen == 0 || !_quorum_met(proc, sigs, desig, dlen))
        {
            log_warn(proc->logger,
                     "Reputation: rejecting slash_final for %s: %zu verified "
                     "co-signature(s) do not meet quorum\n", target_str,
                     dlen == 0 ? (size_t)0
                               : _verified_cosigners(proc, sigs, desig, dlen));
            json_decref(payload);
            return true;
        }
    }
    /* Rehabilitation (explicit-only recovery): release the slash floor and
     * LIFT the score to PREREP_NEUTRAL (above the comm cut-off) so the peer
     * is re-admitted and must re-earn elevated trust from neutral. Mirrors
     * Python _apply_slash's REASON_REHABILITATE branch. (Python also clears
     * _consensus_ema/_consensus_last/_consensus_folded_idx so the lift is
     * visible past the slash-override; the C twin keeps no such running-EMA
     * latch — the score store is authoritative — so there is nothing to
     * clear here.) The tier recompute below drives the readmit through
     * _publish_tier_change (score above the cut-off -> exclusion_action -1). */
    if (reason != NULL && strcmp(reason, REP_SLASH_REASON_REHABILITATE) == 0)
    {
        pthread_mutex_lock(&rep_state.lock);
        map_remove(&rep_state.slashed, (map_key_t)target_str);
        reputations_update(&rep_state.reputations, target_uuid, PREREP_NEUTRAL);
        pthread_mutex_unlock(&rep_state.lock);
        _publish_tier_change(proc, target_uuid, PREREP_NEUTRAL);
        _publish_reputation_change(target_uuid, PREREP_NEUTRAL);
        log_info(proc->logger,
                 "Reputation: slash lifted (rehabilitate) target=%s -> %.2f\n",
                 target_str, PREREP_NEUTRAL);
        json_decref(payload);
        return true;
    }
    pthread_mutex_lock(&rep_state.lock);
    _apply_slash_locked(target_str, target_uuid, floor, epoch);
    pthread_mutex_unlock(&rep_state.lock);
    /* Drive the tier/exclusion publication so a sub-cut-off floor excludes
     * the peer at the network layer immediately (mirrors Python's
     * pending_tiers -> _compute_reputation -> _publish_tier_change flow). */
    _publish_tier_change(proc, target_uuid, floor);
    _publish_reputation_change(target_uuid, floor);
    log_info(proc->logger, "Reputation: slash applied target=%s floor=%.2f\n",
             target_str, floor);
    json_decref(payload);
    return true;
}

/****************************
 * Phase 2: quorum-signed Merkle checkpoints
 *
 * Mirrors Python repprocess.handle_checkpoint_propose / _sign / _final +
 * _store_checkpoint. A member co-signs a proposed checkpoint only when its own
 * transaction_window_root matches the proposed root, so a finalized checkpoint
 * certifies that a quorum observed the same committed window. Wire payloads are
 * plain JSON objects (byte_pinning:false). As with slashing, C drives a single
 * rep_state per dispatcher, so the propose handler records the pending root that
 * the sign handler later finalizes.
 ****************************/

static bool handle_checkpoint_propose(const process_t *proc, directory_t *queues, generic_msg_t *msg)
{
    (void)queues;
    net_msg_t *nmsg = &msg->info.net_msg;
    if (!nmsg->verified)
    {
        log_warn(proc->logger,
                 "Reputation: rejecting unverified checkpoint_propose from %s\n",
                 nmsg->from_whom.nickname);
        return true;
    }
    json_t *payload = NULL;
    if (net_msg_unpack_json(nmsg, &payload) != 0 || payload == NULL)
        return false;
    const char *proposer_str =
        json_string_value(json_object_get(payload, "proposer_uuid"));
    const char *root =
        json_string_value(json_object_get(payload, "root"));
    int64_t epoch = json_integer_value(json_object_get(payload, "epoch"));
    int64_t first_index =
        json_integer_value(json_object_get(payload, "first_index"));
    int64_t count_covered =
        json_integer_value(json_object_get(payload, "count"));
    if (proposer_str == NULL || root == NULL)
    {
        json_decref(payload);
        return false;
    }
    char key[UUID_STRING_LEN + 32];
    snprintf(key, sizeof(key), "%s:%lld", proposer_str, (long long)epoch);

    /* Consensus check: co-sign ONLY if our own committed window produces the
     * same Merkle root. Record the proposed round as pending either way so the
     * sign handler (driven by other nodes' co-signs in conformance) can
     * finalize the agreed value. The record carries the window bounds as well
     * as the root because the designation covers them. */
    char mine[TX_HASH_HEX_LEN + 1];
    json_t *pending_rec = json_object();
    if (pending_rec != NULL)
    {
        json_object_set_new(pending_rec, "root", json_string(root));
        json_object_set_new(pending_rec, "first_index",
                            json_integer(first_index));
        json_object_set_new(pending_rec, "count", json_integer(count_covered));
    }
    /* Which chain the proposal names. Compare THAT chain's window, not always
     * the primary one: a gateway holds several, and comparing the wrong window
     * would decline every honest child-group proposal (§10.2). */
    const char *group_str = json_string_value(json_object_get(payload,
                                                             "group_uuid"));
    char chain_key[UUID_STRING_LEN + 1];
    _chain_key(proc, group_str, chain_key, sizeof(chain_key));
    if (pending_rec != NULL && chain_key[0] != '\0')
        json_object_set_new(pending_rec, "group_uuid", json_string(chain_key));
    pthread_mutex_lock(&rep_state.lock);
    transaction_window_root(_chain_for_key_locked(chain_key), mine);
    _store_pending_locked(&rep_state.checkpoint_pending, key, pending_rec);
    pthread_mutex_unlock(&rep_state.lock);
    json_decref(pending_rec);
    bool matches = (strncmp(mine, root, TX_HASH_HEX_LEN + 1) == 0);
    if (!matches)
    {
        log_debug(proc->logger,
                  "Reputation: checkpoint_propose window_root mismatch on "
                  "chain %s, declining\n",
                  chain_key[0] ? chain_key : "primary");
        json_decref(payload);
        return true;
    }

    /* Co-sign: sign the checkpoint designation with our own key and emit
     * checkpoint_sign back to the proposer, naming ourselves. */
    const identity_t *self = _resolve_self_identity(proc);
    uint8_t desig[REP_DESIG_MAX];
    size_t dlen = rep_checkpoint_designation(proposer_str, root, epoch,
                                            first_index, count_covered,
                                            chain_key, desig, sizeof(desig));
    char sig_hex[REP_SIG_HEX_LEN + 1] = {0};
    if (self == NULL || dlen == 0
        || _cosign_hex(proc, desig, dlen, sig_hex, sizeof(sig_hex)) != 0)
    {
        log_warn(proc->logger,
                 "Reputation: cannot sign checkpoint_propose; declining to co-sign\n");
        json_decref(payload);
        return true;
    }
    char self_str[UUID_STRING_LEN + 1];
    uuid_unparse_lower(self->uuid, self_str);
    json_t *sign_json = json_object();
    if (sign_json == NULL)
    {
        json_decref(payload);
        return true;
    }
    json_object_set_new(sign_json, "proposer_uuid", json_string(proposer_str));
    json_object_set_new(sign_json, "epoch", json_integer(epoch));
    json_object_set_new(sign_json, "signer_uuid", json_string(self_str));
    json_object_set_new(sign_json, "signature", json_string(sig_hex));
    json_decref(payload);

    generic_msg_t sign = {0};
    sign.type = NET_MESSAGE;
    strncpy(sign.info.net_msg.process, "reputation", PROC_NAME_LEN);
    sign.info.net_msg.function = REP_PROTO_CHECKPOINT_SIGN;
    sign.info.net_msg.encrypt = true;
    memcpy(&sign.info.net_msg.to_whom, &nmsg->from_whom,
           sizeof(public_identity_t));
    strncpy(sign.info.net_msg.return_to, "reputation", PROC_NAME_LEN);
    net_msg_pack_json(&sign.info.net_msg, sign_json);
    json_decref(sign_json);
    messaging_send("network", NET_MESSAGE, &sign, false);
    return true;
}

static bool handle_checkpoint_sign(const process_t *proc, directory_t *queues, generic_msg_t *msg)
{
    (void)queues;
    net_msg_t *nmsg = &msg->info.net_msg;
    if (!nmsg->verified)
        return true;
    json_t *payload = NULL;
    if (net_msg_unpack_json(nmsg, &payload) != 0 || payload == NULL)
        return false;
    const char *proposer_str =
        json_string_value(json_object_get(payload, "proposer_uuid"));
    int64_t epoch = json_integer_value(json_object_get(payload, "epoch"));
    const char *claimed =
        json_string_value(json_object_get(payload, "signer_uuid"));
    const char *ack_sig =
        json_string_value(json_object_get(payload, "signature"));
    if (proposer_str == NULL)
    {
        json_decref(payload);
        return false;
    }
    char key[UUID_STRING_LEN + 32];
    snprintf(key, sizeof(key), "%s:%lld", proposer_str, (long long)epoch);

    /* Credit the AUTHENTICATED sender, never the payload's claim. */
    char voter[UUID_STRING_LEN + 1];
    uuid_unparse_lower(nmsg->from_whom.uuid, voter);
    if (claimed != NULL && strncmp(claimed, voter, sizeof(voter)) != 0)
    {
        log_warn(proc->logger,
                 "Reputation: checkpoint_sign claims voter %s but was sent by %s; refused\n",
                 claimed, voter);
        json_decref(payload);
        return true;
    }

    pthread_mutex_lock(&rep_state.lock);
    json_t *pending = _load_pending_locked(&rep_state.checkpoint_pending, key);
    pthread_mutex_unlock(&rep_state.lock);
    if (pending == NULL)
    {
        json_decref(payload);
        return true;   /* not our round, or already finalized */
    }
    char root[TX_HASH_HEX_LEN + 1] = {0};
    const char *pending_root =
        json_string_value(json_object_get(pending, "root"));
    if (pending_root != NULL)
    {
        strncpy(root, pending_root, TX_HASH_HEX_LEN);
        root[TX_HASH_HEX_LEN] = '\0';
    }
    int64_t first_index =
        json_integer_value(json_object_get(pending, "first_index"));
    int64_t count_covered =
        json_integer_value(json_object_get(pending, "count"));
    /* The chain came with the round when it was recorded; the co-signature was
     * made over bytes that include it. */
    const char *pending_group =
        json_string_value(json_object_get(pending, "group_uuid"));
    uint8_t desig[REP_DESIG_MAX];
    size_t dlen = rep_checkpoint_designation(proposer_str, root, epoch,
                                            first_index, count_covered,
                                            pending_group, desig,
                                            sizeof(desig));
    if (dlen == 0 || !_verify_cosignature(proc, voter, desig, dlen, ack_sig))
    {
        log_warn(proc->logger,
                 "Reputation: checkpoint_sign co-signature from %s failed "
                 "verification; not counted\n", voter);
        json_decref(pending);
        json_decref(payload);
        return true;
    }

    pthread_mutex_lock(&rep_state.lock);
    _record_cosig_locked(&rep_state.checkpoint_sigs, key, voter, ack_sig);
    size_t count = 0;
    json_t *sigs = _cosigs_json_locked(&rep_state.checkpoint_sigs, key, &count);
    pthread_mutex_unlock(&rep_state.lock);
    peers_read_lock(proc);
    size_t quorum = proc->protocol.num_peers / 2;
    peers_read_unlock(proc);
    bool finalize = count > quorum;
    json_decref(pending);
    json_decref(payload);

    if (finalize)
    {
        json_t *final_json = json_object();
        if (final_json == NULL)
        {
            json_decref(sigs);
            return true;
        }
        json_object_set_new(final_json, "proposer_uuid",
                            json_string(proposer_str));
        json_object_set_new(final_json, "root", json_string(root));
        json_object_set_new(final_json, "epoch", json_integer(epoch));
        /* The window bounds travel so a receiver can re-derive the designation
         * the co-signatures were made over. */
        json_object_set_new(final_json, "first_index",
                            json_integer(first_index));
        json_object_set_new(final_json, "count", json_integer(count_covered));
        json_object_set(final_json, "sigs", sigs);
        /* Upgrade our own stored copy from the lone self-signature to the
         * quorum map, so the evidence WE persist is attested by the group
         * rather than only by us. The proposer never stored its own finalized
         * checkpoint before this, which left it the one node in the group with
         * no record of a checkpoint it had itself driven to quorum. */
        _store_checkpoint(proc, proposer_str, root, epoch, (int)first_index,
                          (int)count_covered,
                          pending_group == NULL ? "" : pending_group, sigs);
        generic_msg_t bcast = {0};
        bcast.type = NET_MESSAGE;
        strncpy(bcast.info.net_msg.process, "reputation", PROC_NAME_LEN);
        bcast.info.net_msg.function = REP_PROTO_CHECKPOINT_FINAL;
        bcast.info.net_msg.encrypt = true;
        net_msg_pack_json(&bcast.info.net_msg, final_json);
        json_decref(final_json);
        peers_read_lock(proc);
        for (size_t i = 0; i < proc->protocol.num_peers; i++)
        {
            generic_msg_t per = bcast;
            memcpy(&per.info.net_msg.to_whom, &proc->protocol.peers[i],
                   sizeof(public_identity_t));
            messaging_send("network", NET_MESSAGE, &per, false);
        }
        peers_read_unlock(proc);
    }
    json_decref(sigs);
    return true;
}


/* Defined with the rest of the evidence machinery below; deep resolution
 * needs it to describe a chain exactly as the persisted evidence does. */
static void _current_checkpoint_locked(const char *chain_key,
                                      rep_checkpoint_t *out);

/****************************
 * Deep resolution: one peer, on demand, at any depth (ISSUES.md 10.2)
 *
 * Mirrors Python repprocess handle_resolve / handle_resolved /
 * _forward_resolve / _accept_resolved and reputation.py's resolve helpers.
 * A node holds chains only for groups it belongs to, so a peer two levels
 * down is unscoreable locally. Rather than enumerate the subtree -- a cost
 * that grows with the TREE to answer about one PEER -- the query is relayed
 * toward the holder and the answer returns along the reverse path carrying
 * the quorum-signed window that backs it.
 *
 * The window travels whole, not as the peer's entries with inclusion proofs:
 * a proof shows an entry IS present and says nothing about entries withheld,
 * so a holder could answer with a peer's good transactions, omit the bad ones
 * and still verify. Recomputing the root from the entries closes that.
 ****************************/

/* Hops a resolve may travel, and the ceiling we refuse above. Must match
 * Python RESOLVE_TTL_DEFAULT / RESOLVE_TTL_MAX -- a runtime that forwarded one
 * hop further than its twin would answer queries the other dropped. */
#define REP_RESOLVE_TTL_DEFAULT 4
#define REP_RESOLVE_TTL_MAX     8
/* Seconds a relayed or outstanding query is retained. A garbage-collection
 * bound, not a latency target. */
#define REP_RESOLVE_TTL_SECS    30.0
/* Query-ids retained for loop detection, bounded like the other dedup rings. */
#define REP_RESOLVE_SEEN_MAX    256

typedef struct {
    char   answer_to[UUID_STRING_LEN + 1];  /* neighbour to hand the answer to */
    char   peer[UUID_STRING_LEN + 1];       /* only set for queries we originated */
    char   req_proc[PROC_NAME_LEN + 1];
    double deadline;
} rep_resolve_t;

static double _resolve_now(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    return (double)ts.tv_sec + (double)ts.tv_nsec / 1e9;
}

/* Record a query-id, returning false if it was already seen (caller drops the
 * query). FIFO-bounded: at the cap the whole ring is cleared rather than
 * evicted one by one, because map_t has no insertion order to evict by and a
 * cleared ring only costs the re-forwarding of a query old enough to have
 * fallen out of it. Caller holds the lock. */
static bool _mark_resolve_seen_locked(const char *query_id)
{
    data_t *unused = NULL;
    if (map_get(&rep_state.resolve_seen, (map_key_t)query_id, &unused) == 0)
        return false;
    if (map_size(&rep_state.resolve_seen) >= REP_RESOLVE_SEEN_MAX)
    {
        map_free(&rep_state.resolve_seen);
        map_init(&rep_state.resolve_seen);
    }
    map_set(&rep_state.resolve_seen, (map_key_t)query_id, integer_data(1));
    return true;
}

static int _resolve_track(map_t *table, const char *query_id,
                          const char *answer_to, const char *peer,
                          const char *req_proc)
{
    rep_resolve_t *ent = calloc(1, sizeof(rep_resolve_t));
    if (ent == NULL)
        return -1;
    if (answer_to != NULL)
        snprintf(ent->answer_to, sizeof(ent->answer_to), "%s", answer_to);
    if (peer != NULL)
        snprintf(ent->peer, sizeof(ent->peer), "%s", peer);
    if (req_proc != NULL)
        snprintf(ent->req_proc, sizeof(ent->req_proc), "%s", req_proc);
    ent->deadline = _resolve_now() + REP_RESOLVE_TTL_SECS;
    data_t *d = object_ptr_data(ent, sizeof(rep_resolve_t));
    if (d == NULL || map_set(table, (map_key_t)query_id, d) != 0)
    {
        free(ent);
        return -1;
    }
    return 0;
}

/* Take an entry out of a table, copying it out. Caller holds the lock. */
static bool _resolve_take_locked(map_t *table, const char *query_id,
                                 rep_resolve_t *out)
{
    data_t *d = NULL;
    if (map_get(table, (map_key_t)query_id, &d) != 0 || d == NULL)
        return false;
    void *ptr = NULL;
    if (data_object_ptr(d, &ptr) != 0 || ptr == NULL)
        return false;
    if (out != NULL)
        memcpy(out, ptr, sizeof(rep_resolve_t));
    map_remove(table, (map_key_t)query_id);
    free(ptr);
    return true;
}

/* Expire relayed and outstanding queries. A subtree that never answers is the
 * ordinary case, not an error, and nothing else would ever clear these.
 * Mirrors Python _prune_resolve_state. */
static void _prune_resolve_state(const process_t *proc)
{
    double stamp = _resolve_now();
    map_t *tables[2] = { &rep_state.resolve_pending,
                         &rep_state.resolve_outstanding };
    pthread_mutex_lock(&rep_state.lock);
    for (int t = 0; t < 2; t++)
    {
        array_t *keys = map_keys(tables[t]);
        size_t n = array_size(keys);
        for (size_t i = 0; i < n; i++)
        {
            data_t *kd = NULL;
            map_key_t key = NULL;
            if (array_get(keys, (int)i, &kd) != 0
                || data_string_ptr(kd, &key) != 0 || key == NULL)
                continue;
            data_t *d = NULL;
            if (map_get(tables[t], key, &d) != 0 || d == NULL)
                continue;
            void *ptr = NULL;
            if (data_object_ptr(d, &ptr) != 0 || ptr == NULL)
                continue;
            rep_resolve_t *ent = (rep_resolve_t *)ptr;
            if (ent->deadline > stamp)
                continue;
            if (t == 1 && proc != NULL)
                log_info(proc->logger,
                         "Reputation: deep resolve of %.8s timed out\n",
                         ent->peer);
            map_remove(tables[t], key);
            free(ent);
        }
        array_free(keys);
    }
    pthread_mutex_unlock(&rep_state.lock);
}

/* The key of the chain whose window holds committed bilateral entries for
 * `peer_str`, or false when no chain of ours does. Primary chain first, so a
 * peer we transact with directly is answered from the chain that actually
 * knows it. Caller holds the lock. Mirrors Python _chain_holding. */
static bool _chain_holding_locked(const char *peer_str, char *out, size_t cap)
{
    array_t *child_keys = map_keys(&rep_state.child_hist);
    size_t n_child = array_size(child_keys);
    bool found = false;
    for (size_t ci = 0; ci <= n_child && !found; ci++)
    {
        const char *chain_key = "";
        if (ci > 0)
        {
            data_t *kd = NULL;
            map_key_t k = NULL;
            if (array_get(child_keys, (int)(ci - 1), &kd) != 0
                || data_string_ptr(kd, &k) != 0 || k == NULL)
                continue;
            chain_key = k;
        }
        tx_history_t *chain = _chain_for_key_locked(chain_key);
        if (chain == NULL)
            continue;
        for (int i = 0; i < chain->chain_len; i++)
        {
            const transaction_t *tx = &chain->chain[i];
            if (tx->index < 0 || !tx->p1_set || !tx->p2_set)
                continue;
            char p1[UUID_STRING_LEN + 1], p2[UUID_STRING_LEN + 1];
            uuid_unparse_lower(tx->p1_uuid, p1);
            uuid_unparse_lower(tx->p2_uuid, p2);
            if (strcmp(p1, peer_str) == 0 || strcmp(p2, peer_str) == 0)
            {
                snprintf(out, cap, "%s", chain_key);
                found = true;
                break;
            }
        }
    }
    array_free(child_keys);
    return found;
}

/* The co-signer identities an answer carries, in the DRY canonical public form
 * (public_identity_to_json). Only signers we hold an identity for: a uuid we
 * cannot produce a key for would travel as an unverifiable name, which is
 * worse than absent. Mirrors Python _resolve_signers. */
static json_t *_resolve_signers(const process_t *proc, map_t *sigs)
{
    json_t *arr = json_array();
    if (arr == NULL || sigs == NULL)
        return arr;
    array_t *voters = map_keys(sigs);
    size_t n_voters = array_size(voters);
    for (size_t vi = 0; vi < n_voters; vi++)
    {
        data_t *vd = NULL;
        map_key_t voter = NULL;
        if (array_get(voters, (int)vi, &vd) != 0
            || data_string_ptr(vd, &voter) != 0 || voter == NULL)
            continue;
        peers_read_lock(proc);
        const public_identity_t *match = NULL;
        for (size_t i = 0; i < proc->protocol.num_peers; i++)
        {
            char uuid_str[UUID_STRING_LEN + 1];
            uuid_unparse_lower(proc->protocol.peers[i].uuid, uuid_str);
            if (strcmp(uuid_str, voter) == 0)
            {
                match = &proc->protocol.peers[i];
                break;
            }
        }
        json_t *obj = NULL;
        if (match != NULL && public_identity_to_json(match, &obj) == 0
            && obj != NULL)
            json_array_append_new(arr, obj);
        else if (obj != NULL)
            json_decref(obj);
        peers_read_unlock(proc);
    }
    array_free(voters);
    return arr;
}

/* Send an answer to one neighbour. */
static void _send_resolved(const process_t *proc,
                           const public_identity_t *to_whom, json_t *answer,
                           const char *req_proc)
{
    (void)proc;
    generic_msg_t out = {0};
    out.type = NET_MESSAGE;
    strncpy(out.info.net_msg.process,
            (req_proc != NULL && req_proc[0] != '\0') ? req_proc : "reputation",
            PROC_NAME_LEN);
    out.info.net_msg.function = REP_PROTO_REP_RESOLVED;
    out.info.net_msg.encrypt = true;
    memcpy(&out.info.net_msg.to_whom, to_whom, sizeof(public_identity_t));
    net_msg_pack_json(&out.info.net_msg, answer);
    messaging_send("network", NET_MESSAGE, &out, false);
}

/* Send a query one level DOWN, to every child group we gateway, with the TTL
 * decremented. Addressed to the child GROUP rather than a chosen child gateway:
 * the reputation process holds the child groups but not the rank data identity
 * picks a gateway with, and asking the group is the same answer without a
 * second, drifting copy of that derivation living here. Returns the number of
 * groups reached; 0 means this branch is a dead end. Mirrors Python
 * _forward_resolve. */
static size_t _forward_resolve(const process_t *proc, json_t *query)
{
    if (proc == NULL || proc->protocol.child_groups == NULL)
        return 0;
    int ttl = (int)json_integer_value(json_object_get(query, "ttl"));
    if (ttl <= 0)
        return 0;
    json_t *onward = json_deep_copy(query);
    if (onward == NULL)
        return 0;
    json_object_set_new(onward, "ttl", json_integer(ttl - 1));

    size_t sent = 0;
    array_t *groups = map_keys(proc->protocol.child_groups);
    size_t n_groups = array_size(groups);
    for (size_t gi = 0; gi < n_groups; gi++)
    {
        data_t *gk = NULL;
        map_key_t gkey = NULL;
        if (array_get(groups, (int)gi, &gk) != 0
            || data_string_ptr(gk, &gkey) != 0 || gkey == NULL)
            continue;
        /* Every member of that group: the holder answers, a member that is
         * itself a gateway relays deeper, and the query-id ring keeps a node
         * reached twice from acting twice. */
        peers_read_lock(proc);
        for (size_t i = 0; i < proc->protocol.num_peers; i++)
        {
            if (!_peer_in_group(proc, &proc->protocol.peers[i], gkey))
                continue;
            generic_msg_t per = {0};
            per.type = NET_MESSAGE;
            strncpy(per.info.net_msg.process, "reputation", PROC_NAME_LEN);
            per.info.net_msg.function = REP_PROTO_REP_RESOLVE;
            per.info.net_msg.encrypt = true;
            memcpy(&per.info.net_msg.to_whom, &proc->protocol.peers[i],
                   sizeof(public_identity_t));
            net_msg_pack_json(&per.info.net_msg, onward);
            messaging_send("network", NET_MESSAGE, &per, false);
            sent++;
        }
        peers_read_unlock(proc);
    }
    array_free(groups);
    json_decref(onward);
    return sent;
}

/* Build the answer for a peer we hold a chain for, or NULL when that chain has
 * no finalized checkpoint. No checkpoint means no answer, deliberately: the
 * window would still be true, but a receiver two hops away cannot tell an
 * unattested truth from a fabrication, so sending one would only teach
 * requestors to accept what they cannot check. Mirrors Python _resolve_answer.
 * Caller owns the result. */
static json_t *_resolve_answer(const process_t *proc, const char *query_id,
                               const char *peer_str, const char *chain_key)
{
    pthread_mutex_lock(&rep_state.lock);
    rep_chain_ckpt_t *slot = _ckpt_slot_locked(chain_key);
    if (slot == NULL || !slot->set)
    {
        pthread_mutex_unlock(&rep_state.lock);
        log_debug(proc->logger,
                  "Reputation: resolve %.8s: chain %s has no finalized "
                  "checkpoint; no answer\n", peer_str,
                  chain_key[0] ? chain_key : "primary");
        return NULL;
    }
    rep_checkpoint_t ckpt;
    if (rep_checkpoint_init(&ckpt) != 0)
    {
        pthread_mutex_unlock(&rep_state.lock);
        return NULL;
    }
    /* Same filler the persisted evidence uses, so an answer and the file on
     * disk describe the chain identically. */
    _current_checkpoint_locked(chain_key, &ckpt);

    tx_history_t *chain = _chain_for_key_locked(chain_key);
    json_t *doc = NULL;
    int err = reputation_evidence_to_json(chain, &ckpt, &doc);
    uuid_t peer_uu;
    double score = 0.0;
    bool have_score = (uuid_parse(peer_str, peer_uu) == 0);
    if (have_score)
        score = reputation_consensus(chain, peer_uu, &rep_state.task_weights);
    json_t *signers = _resolve_signers(proc, &ckpt.sigs);
    pthread_mutex_unlock(&rep_state.lock);
    rep_checkpoint_free(&ckpt);

    if (err != 0 || doc == NULL)
    {
        if (signers != NULL)
            json_decref(signers);
        return NULL;
    }
    json_object_set_new(doc, "query_id", json_string(query_id));
    json_object_set_new(doc, "peer_uuid", json_string(peer_str));
    json_object_set_new(doc, "score",
                        have_score ? json_real(score) : json_null());
    json_object_set_new(doc, "signers", signers);
    return doc;
}

/* One accepted or refused answer, keyed by peer uuid. `reason` sits beside the
 * boolean deliberately: an operator reading "unverified" needs to know WHICH
 * gate failed, and a caller may knowingly accept a weaker answer. Mirrors
 * Python resolved_reps. */
typedef struct {
    double score;
    bool   verified;
    bool   have_score;
    char   reason[192];
} rep_resolved_t;

static void _record_resolved(const char *peer_str, double score,
                             bool have_score, bool verified,
                             const char *reason)
{
    rep_resolved_t *rec = calloc(1, sizeof(rep_resolved_t));
    if (rec == NULL)
        return;
    rec->score = score;
    rec->have_score = have_score;
    rec->verified = verified;
    snprintf(rec->reason, sizeof(rec->reason), "%s", reason ? reason : "");
    data_t *d = object_ptr_data(rec, sizeof(rep_resolved_t));
    pthread_mutex_lock(&rep_state.lock);
    data_t *old = NULL;
    if (map_get(&rep_state.resolved_reps, (map_key_t)peer_str, &old) == 0
        && old != NULL)
    {
        void *op = NULL;
        if (data_object_ptr(old, &op) == 0 && op != NULL)
            free(op);
        map_remove(&rep_state.resolved_reps, (map_key_t)peer_str);
    }
    if (d == NULL || map_set(&rep_state.resolved_reps, (map_key_t)peer_str, d) != 0)
        free(rec);
    pthread_mutex_unlock(&rep_state.lock);
}

/* An anchor verifier built from the SAME policy the identity process admits
 * peers with, so "an anchor we accept" means one thing on this node. Built on
 * first use and kept: a deep answer is rare, but rebuilding an OpenSSL store
 * per co-signature would not be.
 *
 * Only the plain policy verifier, not the per-anchor fan-out id_proc does:
 * this gate asks "is this signer anchored at all", where admission asks the
 * harder question of WHICH agency vouches for a peer, and answering the
 * narrower question with the broader machinery would put a second copy of that
 * decision here to drift. */
#ifdef AT_ZTA_ENABLED
static zta_verifier_t *_resolve_zta_verifier(const process_t *proc)
{
    static zta_verifier_t *cached = NULL;
    static bool tried = false;
    if (tried)
        return cached;
    tried = true;
    if (proc == NULL || proc->configs == NULL)
        return NULL;
    data_t *zta_dat = NULL;
    config_t *zta_cfg = NULL;
    char zta_key[] = "zta_policy";
    if (map_get(proc->configs, zta_key, &zta_dat) != 0 || zta_dat == NULL
        || data_object_ptr(zta_dat, (void **)&zta_cfg) != 0
        || zta_cfg == NULL || zta_cfg->data_struct == NULL)
        return NULL;
    zta_policy_t *policy = (zta_policy_t *)zta_cfg->data_struct;
    if (zta_policy_create_verifier(policy, &cached) != 0)
        cached = NULL;
    return cached;
}
#endif  /* AT_ZTA_ENABLED */

/* Whether a co-signer may count toward an answer's evidence: a peer we already
 * hold cleared admission, otherwise the carried identity must present a
 * credential that chains to one of OUR anchors. Without this gate an answer
 * could ship its own freshly-minted signers and satisfy every signature check.
 * Mirrors Python _resolve_trust_signer. */
static bool _resolve_trust_signer(const process_t *proc, const char *voter,
                                  const public_identity_t *carried)
{
    peers_read_lock(proc);
    for (size_t i = 0; i < proc->protocol.num_peers; i++)
    {
        char uuid_str[UUID_STRING_LEN + 1];
        uuid_unparse_lower(proc->protocol.peers[i].uuid, uuid_str);
        if (strcmp(uuid_str, voter) == 0)
        {
            peers_read_unlock(proc);
            return true;
        }
    }
    peers_read_unlock(proc);
#ifdef AT_ZTA_ENABLED
    if (carried == NULL || carried->zta_credential_len == 0)
        return false;
    zta_verifier_t *verifier = _resolve_zta_verifier(proc);
    if (verifier == NULL || verifier->verify_credential == NULL)
        return false;
    zta_result_t result = {0};
    if (verifier->verify_credential(verifier, carried->zta_credential,
                                    carried->zta_credential_len, &result) != 0)
        return false;
    return result.status == ZTA_VERIFIED;
#else
    /* Without ZTA compiled in there is no anchor to chain a stranger's
     * credential to, so an unknown signer cannot be trusted at all. Refusing
     * is the fail-safe direction: a build with no way to check credentials
     * must not accept evidence from signers it has never admitted. */
    (void)carried;
    return false;
#endif
}

/* Verify an answer to a query we made and record the result.
 *
 * Three gates, in order of what they buy: the window must reproduce the signed
 * root (which is what makes OMISSION detectable, since any edit to the entry
 * list moves the root away from the bytes a quorum signed); the co-signatures
 * must verify; and each signer must be trusted. NOT checked, and it cannot be
 * from this side: whether the signers are a MAJORITY of the answering group.
 * Quorum sizing needs that group's membership, and an opaque subtree is
 * precisely what does not disclose it.
 *
 * The recorded score is the one WE compute from the attested window, not the
 * number the holder sent: the holder's EMA is weighted by per-capability
 * weights that live in a node-local cache and are part of no hashed entry, so
 * it cannot be re-derived here. Mirrors Python _accept_resolved. */
static void _accept_resolved(const process_t *proc, const char *peer_str,
                             json_t *doc)
{
    tx_history_t parsed;
    tx_history_init(&parsed);
    rep_checkpoint_t ckpt = {0};
    if (reputation_evidence_from_json(doc, &parsed, &ckpt) != 0)
    {
        _record_resolved(peer_str, 0.0, false, false,
                         "malformed or hash-broken evidence document");
        tx_history_free(&parsed);
        return;
    }
    if (!ckpt.present || ckpt.root[0] == '\0')
    {
        _record_resolved(peer_str, 0.0, false, false,
                         "no checkpoint: the window is unattested");
        tx_history_free(&parsed);
        rep_checkpoint_free(&ckpt);
        return;
    }
    char recomputed[TX_HASH_HEX_LEN + 1];
    transaction_window_root(&parsed, recomputed);
    if (strcmp(recomputed, ckpt.root) != 0)
    {
        _record_resolved(peer_str, 0.0, false, false,
                         "window does not reproduce the signed root "
                         "(entries added, altered or withheld)");
        tx_history_free(&parsed);
        rep_checkpoint_free(&ckpt);
        return;
    }
    uint8_t desig[REP_DESIG_MAX];
    size_t dlen = rep_checkpoint_designation(
        ckpt.proposer_uuid, ckpt.root, ckpt.epoch, ckpt.first_index,
        ckpt.count, ckpt.group_uuid, desig, sizeof(desig));

    /* Signers the answer carried, by uuid, so a requestor holding no identity
     * from the answering group can still check a signature. */
    json_t *signers = json_object_get(doc, "signers");
    size_t verified_count = 0;
    array_t *voters = map_keys(&ckpt.sigs);
    size_t n_voters = array_size(voters);
    for (size_t vi = 0; dlen > 0 && vi < n_voters; vi++)
    {
        data_t *vd = NULL;
        map_key_t voter = NULL;
        if (array_get(voters, (int)vi, &vd) != 0
            || data_string_ptr(vd, &voter) != 0 || voter == NULL)
            continue;
        {
            data_t *sd = NULL;
            string_t sig_str = NULL;
            if (map_get(&ckpt.sigs, voter, &sd) != 0 || sd == NULL
                || data_string_ptr(sd, &sig_str) != 0)
                continue;
            const char *sig_hex = sig_str;
            public_identity_t carried = {0};
            bool have_carried = false;
            if (signers != NULL && json_is_array(signers))
            {
                size_t si;
                json_t *sv = NULL;
                json_array_foreach(signers, si, sv)
                {
                    public_identity_t cand = {0};
                    if (public_identity_from_json(sv, &cand) != 0)
                        continue;
                    char cand_str[UUID_STRING_LEN + 1];
                    uuid_unparse_lower(cand.uuid, cand_str);
                    if (strcmp(cand_str, voter) == 0)
                    {
                        memcpy(&carried, &cand, sizeof(public_identity_t));
                        have_carried = true;
                        break;
                    }
                }
            }
            bool sig_ok = _verify_cosignature(proc, voter, desig, dlen, sig_hex);
            if (!sig_ok && have_carried && sig_hex != NULL
                && strnlen(sig_hex, REP_SIG_HEX_LEN + 2) == REP_SIG_HEX_LEN)
            {
                unsigned char raw[crypto_sign_BYTES];
                if (unhexlify((const unsigned char *)sig_hex, REP_SIG_HEX_LEN,
                              raw) == 0)
                    sig_ok = crypto_sign_verify_detached(
                        raw, desig, dlen, carried.signature.public) == 0;
            }
            if (!sig_ok)
                continue;
            if (!_resolve_trust_signer(proc, voter,
                                       have_carried ? &carried : NULL))
                continue;
            verified_count++;
        }
    }
    array_free(voters);
    rep_checkpoint_free(&ckpt);
    if (verified_count < 1)
    {
        _record_resolved(peer_str, 0.0, false, false,
                         "0 signer(s) verified and trusted, needed 1");
        tx_history_free(&parsed);
        return;
    }
    char reason[192];
    snprintf(reason, sizeof(reason),
             "root reproduced; %zu signer(s) verified and trusted "
             "(quorum size not checkable across a boundary)", verified_count);
    uuid_t peer_uu;
    if (uuid_parse(peer_str, peer_uu) != 0)
    {
        _record_resolved(peer_str, 0.0, false, true, reason);
        tx_history_free(&parsed);
        return;
    }
    /* NULL weights: weight 1 for everything, the unweighted consensus over the
     * same attested entries. */
    double score = reputation_consensus(&parsed, peer_uu, NULL);
    _record_resolved(peer_str, score, true, true, reason);
    log_info(proc->logger, "Reputation: deep resolve of %.8s = %.4f (%s)\n",
             peer_str, score, reason);
    tx_history_free(&parsed);
}

size_t reputation_deep_resolve(const process_t *proc, const char *query_id,
                               const char *peer_uuid, int ttl)
{
    _ensure_init();
    if (proc == NULL || peer_uuid == NULL)
        return 0;
    char qid[128];
    if (query_id != NULL && query_id[0] != '\0')
        snprintf(qid, sizeof(qid), "%s", query_id);
    else
        snprintf(qid, sizeof(qid), "%.8s-%lld", peer_uuid,
                 (long long)(_resolve_now() * 1000.0));
    json_t *query = json_object();
    if (query == NULL)
        return 0;
    json_object_set_new(query, "query_id", json_string(qid));
    json_object_set_new(query, "peer_uuid", json_string(peer_uuid));
    json_object_set_new(query, "ttl",
                        json_integer(ttl > 0 ? ttl : REP_RESOLVE_TTL_DEFAULT));
    json_object_set_new(query, "requesting_process", json_string("reputation"));
    pthread_mutex_lock(&rep_state.lock);
    _mark_resolve_seen_locked(qid);
    _resolve_track(&rep_state.resolve_outstanding, qid, NULL, peer_uuid,
                   "reputation");
    pthread_mutex_unlock(&rep_state.lock);
    size_t sent = _forward_resolve(proc, query);
    json_decref(query);
    return sent;
}

bool reputation_resolved_get(const char *peer_uuid, double *score_out,
                             bool *have_score_out, bool *verified_out,
                             char *reason_out, size_t reason_cap)
{
    _ensure_init();
    if (peer_uuid == NULL)
        return false;
    bool found = false;
    pthread_mutex_lock(&rep_state.lock);
    data_t *d = NULL;
    if (map_get(&rep_state.resolved_reps, (map_key_t)peer_uuid, &d) == 0
        && d != NULL)
    {
        void *ptr = NULL;
        if (data_object_ptr(d, &ptr) == 0 && ptr != NULL)
        {
            rep_resolved_t *rec = (rep_resolved_t *)ptr;
            if (score_out != NULL)
                *score_out = rec->score;
            if (have_score_out != NULL)
                *have_score_out = rec->have_score;
            if (verified_out != NULL)
                *verified_out = rec->verified;
            if (reason_out != NULL && reason_cap > 0)
                snprintf(reason_out, reason_cap, "%s", rec->reason);
            found = true;
        }
    }
    pthread_mutex_unlock(&rep_state.lock);
    return found;
}

size_t reputation_resolve_pending_count(void)
{
    _ensure_init();
    pthread_mutex_lock(&rep_state.lock);
    size_t n = map_size(&rep_state.resolve_pending);
    pthread_mutex_unlock(&rep_state.lock);
    return n;
}

size_t reputation_resolve_outstanding_count(void)
{
    _ensure_init();
    pthread_mutex_lock(&rep_state.lock);
    size_t n = map_size(&rep_state.resolve_outstanding);
    pthread_mutex_unlock(&rep_state.lock);
    return n;
}

/* Answer a deep query, or relay it one level down. Never blocks awaiting a
 * child: the relay records who to answer and returns, and the answer is an
 * independent message that arrives (or does not) later. Mirrors Python
 * handle_resolve. */
static bool handle_resolve(const process_t *proc, directory_t *queues, generic_msg_t *msg)
{
    (void)queues;
    net_msg_t *nmsg = &msg->info.net_msg;
    if (!nmsg->verified)
    {
        log_warn(proc->logger,
                 "Reputation: rejecting unverified rep_resolve from %s\n",
                 nmsg->from_whom.nickname);
        return true;
    }
    json_t *payload = NULL;
    if (net_msg_unpack_json(nmsg, &payload) != 0 || payload == NULL)
        return true;
    const char *qid = json_string_value(json_object_get(payload, "query_id"));
    const char *peer_str = json_string_value(json_object_get(payload, "peer_uuid"));
    json_t *ttl_j = json_object_get(payload, "ttl");
    int ttl = (int)json_integer_value(ttl_j);
    const char *req_proc =
        json_string_value(json_object_get(payload, "requesting_process"));
    /* Bounded, not clamped: TTL is attacker-controlled and an inflated one is
     * an amplification lever, so an out-of-range query is refused outright
     * (Python resolve_query_from_dict raises for the same reason). */
    if (qid == NULL || peer_str == NULL || !json_is_integer(ttl_j)
        || ttl < 0 || ttl > REP_RESOLVE_TTL_MAX)
    {
        log_warn(proc->logger, "Reputation: malformed rep_resolve; dropped\n");
        json_decref(payload);
        return true;
    }
    char sender[UUID_STRING_LEN + 1];
    uuid_unparse_lower(nmsg->from_whom.uuid, sender);

    pthread_mutex_lock(&rep_state.lock);
    bool fresh = _mark_resolve_seen_locked(qid);
    pthread_mutex_unlock(&rep_state.lock);
    if (!fresh)
    {
        json_decref(payload);
        return true;   /* already handled: a loop, or a duplicate leg */
    }

    char chain_key[UUID_STRING_LEN + 1] = {0};
    pthread_mutex_lock(&rep_state.lock);
    bool held = _chain_holding_locked(peer_str, chain_key, sizeof(chain_key));
    pthread_mutex_unlock(&rep_state.lock);
    if (held)
    {
        json_t *answer = _resolve_answer(proc, qid, peer_str, chain_key);
        if (answer != NULL)
        {
            _send_resolved(proc, &nmsg->from_whom, answer, req_proc);
            json_decref(answer);
            json_decref(payload);
            return true;
        }
        /* Held the chain but cannot attest it: fall through so a deeper node
         * that can answers instead. */
    }
    if (_forward_resolve(proc, payload) > 0)
    {
        pthread_mutex_lock(&rep_state.lock);
        _resolve_track(&rep_state.resolve_pending, qid, sender, peer_str,
                       req_proc);
        pthread_mutex_unlock(&rep_state.lock);
    }
    json_decref(payload);
    return true;
}

/* Take an answer: relay it back one hop, or accept it if it is ours. An answer
 * for a query-id we never relayed and never sent is dropped unread -- on a
 * relay path answers are unsolicited by construction, so the pending table is
 * the only thing distinguishing one we are carrying from one injected. Mirrors
 * Python handle_resolved. */
static bool handle_resolved(const process_t *proc, directory_t *queues, generic_msg_t *msg)
{
    (void)queues;
    net_msg_t *nmsg = &msg->info.net_msg;
    if (!nmsg->verified)
    {
        log_warn(proc->logger,
                 "Reputation: rejecting unverified rep_resolved from %s\n",
                 nmsg->from_whom.nickname);
        return true;
    }
    json_t *payload = NULL;
    if (net_msg_unpack_json(nmsg, &payload) != 0 || payload == NULL)
        return true;
    const char *qid = json_string_value(json_object_get(payload, "query_id"));
    const char *peer_str = json_string_value(json_object_get(payload, "peer_uuid"));
    if (qid == NULL || peer_str == NULL)
    {
        json_decref(payload);
        return true;
    }
    rep_resolve_t relay = {0};
    pthread_mutex_lock(&rep_state.lock);
    bool relaying = _resolve_take_locked(&rep_state.resolve_pending, qid, &relay);
    pthread_mutex_unlock(&rep_state.lock);
    if (relaying)
    {
        peers_read_lock(proc);
        const public_identity_t *dest = NULL;
        for (size_t i = 0; i < proc->protocol.num_peers; i++)
        {
            char uuid_str[UUID_STRING_LEN + 1];
            uuid_unparse_lower(proc->protocol.peers[i].uuid, uuid_str);
            if (strcmp(uuid_str, relay.answer_to) == 0)
            {
                dest = &proc->protocol.peers[i];
                break;
            }
        }
        /* Relayed VERBATIM: the signatures are over bytes, and a re-encode
         * that reordered a key or renormalized a float would invalidate
         * evidence this node has no business invalidating. Relays carry, they
         * do not curate. */
        if (dest != NULL)
            _send_resolved(proc, dest, payload, relay.req_proc);
        else
            log_warn(proc->logger,
                     "Reputation: cannot relay answer %.8s; %.8s no longer "
                     "known\n", qid, relay.answer_to);
        peers_read_unlock(proc);
        json_decref(payload);
        return true;
    }

    rep_resolve_t mine = {0};
    pthread_mutex_lock(&rep_state.lock);
    bool ours = _resolve_take_locked(&rep_state.resolve_outstanding, qid, &mine);
    pthread_mutex_unlock(&rep_state.lock);
    if (!ours)
    {
        log_debug(proc->logger,
                  "Reputation: unsolicited rep_resolved %.8s; dropped\n", qid);
        json_decref(payload);
        return true;
    }
    _accept_resolved(proc, peer_str, payload);
    json_decref(payload);
    return true;
}

static bool handle_checkpoint_final(const process_t *proc, directory_t *queues, generic_msg_t *msg)
{
    (void)queues;
    net_msg_t *nmsg = &msg->info.net_msg;
    if (!nmsg->verified)
    {
        log_warn(proc->logger,
                 "Reputation: rejecting unverified checkpoint_final from %s\n",
                 nmsg->from_whom.nickname);
        return true;
    }
    json_t *payload = NULL;
    if (net_msg_unpack_json(nmsg, &payload) != 0 || payload == NULL)
        return false;
    const char *root = json_string_value(json_object_get(payload, "root"));
    int64_t epoch = json_integer_value(json_object_get(payload, "epoch"));
    const char *proposer_str =
        json_string_value(json_object_get(payload, "proposer_uuid"));
    int64_t first_index =
        json_integer_value(json_object_get(payload, "first_index"));
    int64_t count_covered =
        json_integer_value(json_object_get(payload, "count"));
    if (root == NULL)
    {
        json_decref(payload);
        return false;
    }
    /* The chain this checkpoint covers, normalized through our own view (§10.2).
     * Both the signed designation and the quorum size depend on it. */
    char final_chain[UUID_STRING_LEN + 1];
    _chain_key(proc, json_string_value(json_object_get(payload, "group_uuid")),
               final_chain, sizeof(final_chain));
    /* Verify the retained co-signatures before storing the root. This root is
     * the anchor _verify_slash_evidence measures slash evidence against,
     * expressly so the root is "not chosen by the accuser" — which only holds
     * if a quorum is checked here. */
    {
        uint8_t desig[REP_DESIG_MAX];
        size_t dlen = (proposer_str != NULL)
            ? rep_checkpoint_designation(proposer_str, root, epoch, first_index,
                                         count_covered, final_chain, desig,
                                         sizeof(desig))
            : 0;
        json_t *sigs = json_object_get(payload, "sigs");
        if (dlen == 0 || !_quorum_met_for(proc, sigs, desig, dlen, final_chain))
        {
            log_warn(proc->logger,
                     "Reputation: rejecting checkpoint_final epoch=%lld: %zu "
                     "verified co-signature(s) do not meet quorum\n",
                     (long long)epoch,
                     dlen == 0 ? (size_t)0
                               : _verified_cosigners(proc, sigs, desig, dlen));
            json_decref(payload);
            return true;
        }
    }
    /* Stores the window bounds and the co-signatures alongside the root, and
     * persists the evidence: this is the instant at which the resident window
     * and an agreed root describe each other (ISSUES §10.3). */
    _store_checkpoint(proc, proposer_str, root, epoch, (int)first_index,
                      (int)count_covered, final_chain,
                      json_object_get(payload, "sigs"));
    log_info(proc->logger, "Reputation: checkpoint stored epoch=%lld root=%.12s\n",
             (long long)epoch, root);
    json_decref(payload);
    return true;
}

/****************************
 * Verifiable warm start (ISSUES.md §10.3)
 *
 * Mirrors Python repprocess._persist_history / _rebuild_from_evidence /
 * _attested_ceilings / _grade_restored_reputations / _maybe_checkpoint, and
 * reads and writes the SAME `reputation-history.cfg.json` document (plain JSON,
 * schema-pinned — see reputation.h REP_EVIDENCE_*).
 ****************************/

/* --- Operational snapshot (`reputation.cfg.json`) -------------------------
 *
 * C had no reputation persistence at all before this: nothing wrote the
 * snapshot and nothing read it, so a C node always cold-started and there was
 * no warm start for the evidence above to make verifiable.
 *
 * Written as plain JSON rather than through the config-registry framework, and
 * carrying Python's `__type__` tag rather than C's `typename`, for one reason:
 * warm-start state is the SAME state in both runtimes, so a node of either kind
 * should be able to resume from a snapshot the other wrote. That is the same
 * argument that keeps the wire protocol strings byte-identical to Python's enum
 * values — the identifier is a shared constant, not a language artifact. The
 * reader tolerates the tag being absent.
 *
 * Only peers strictly above the persist threshold survive a restart, mirroring
 * Python's two-sided filter (see doc/architecture/persistent-cohort.md). Self
 * is always kept. */
#define REP_PERSIST_THRESHOLD_DEFAULT 0.5
#define REP_PERSIST_THRESHOLD \
    (reputation_env_double("AT_REP_PERSIST_THRESHOLD", \
                           REP_PERSIST_THRESHOLD_DEFAULT))
#define REP_SNAPSHOT_TYPE \
    "autonomous_trust.core._python.reputation.reputation.Reputations"

static int _snapshot_path(char *out, size_t cap)
{
    char cfg_dir[CFG_PATH_LEN + 1] = {0};
    if (get_cfg_dir(cfg_dir, sizeof(cfg_dir)) < 0)
        return -1;
    int n = snprintf(out, cap, "%s/%s%s", cfg_dir, REP_SNAPSHOT_FILE,
                     CFG_FILE_EXT);
    if (n < 0 || (size_t)n >= cap)
        return -1;
    return 0;
}

/* Load the persisted operational snapshot into rep_state.reputations.
 * Absent/unreadable is a cold start, not an error. */
static void _load_reputations(const process_t *proc)
{
    char path[CFG_PATH_LEN + 64] = {0};
    if (_snapshot_path(path, sizeof(path)) != 0)
        return;
    json_error_t jerr;
    json_t *doc = json_load_file(path, 0, &jerr);
    if (doc == NULL)
        return;
    json_t *current = json_object_get(doc, "current");
    int loaded = 0;
    if (json_is_object(current))
    {
        const char *key;
        json_t *val;
        json_object_foreach(current, key, val)
        {
            if (!json_is_number(val))
                continue;
            uuid_t u;
            if (uuid_parse(key, u) != 0)
                continue;
            pthread_mutex_lock(&rep_state.lock);
            reputations_update(&rep_state.reputations, u,
                               json_number_value(val));
            pthread_mutex_unlock(&rep_state.lock);
            loaded++;
        }
    }
    json_decref(doc);
    if (loaded > 0)
        log_info(proc->logger,
                 "Reputation: warm start loaded %d persisted peer score(s)\n",
                 loaded);
}

/* Write the operational snapshot. Failure is logged and swallowed — a node that
 * cannot persist should keep running, it simply cold-starts next time. */
static void _persist_reputations(const process_t *proc)
{
    char path[CFG_PATH_LEN + 64] = {0};
    if (_snapshot_path(path, sizeof(path)) != 0)
        return;
    json_t *current = json_object();
    if (current == NULL)
        return;
    double threshold = REP_PERSIST_THRESHOLD;
    pthread_mutex_lock(&rep_state.lock);
    map_key_t key = NULL;
    data_t *val = NULL;
    map_entries_for_each(&rep_state.reputations.scores, key, val)
    {
        double score = 0.0;
        if (data_floating_pt_dbl(val, &score) != 0)
            continue;
        if (score <= threshold)
            continue;
        json_object_set_new(current, key, json_real(score));
    }
    map_end_for_each
    pthread_mutex_unlock(&rep_state.lock);
    json_t *doc = json_pack("{s:s, s:o}", "__type__", REP_SNAPSHOT_TYPE,
                            "current", current);
    if (doc == NULL)
    {
        json_decref(current);
        return;
    }
    if (json_dump_file(doc, path, JSON_INDENT(2)) != 0)
        log_warn(proc->logger,
                 "Reputation: could not persist snapshot to %s\n", path);
    json_decref(doc);
}

/* Path of one chain's evidence document, or -1 if it does not fit.
 *
 * One file per chain rather than one file holding every chain: it mirrors the
 * group_child_<name>.cfg.json convention already used for child groups, keeps
 * the primary file's shape byte-for-byte what it was, and means a corrupt or
 * stale child file costs that subtree its attestation and nothing else. */
static int _evidence_path(const char *chain_key, char *out, size_t cap)
{
    char cfg_dir[CFG_PATH_LEN + 1] = {0};
    if (get_cfg_dir(cfg_dir, sizeof(cfg_dir)) < 0)
        return -1;
    int n;
    if (chain_key != NULL && chain_key[0] != '\0')
        n = snprintf(out, cap, "%s/%s-%s%s", cfg_dir, REP_EVIDENCE_FILE,
                     chain_key, CFG_FILE_EXT);
    else
        n = snprintf(out, cap, "%s/%s%s", cfg_dir, REP_EVIDENCE_FILE,
                     CFG_FILE_EXT);
    if (n < 0 || (size_t)n >= cap)
        return -1;
    return 0;
}

/* Snapshot one chain's finalized checkpoint. Caller holds the lock. */
static void _current_checkpoint_locked(const char *chain_key,
                                       rep_checkpoint_t *out)
{
    rep_chain_ckpt_t *slot = _ckpt_slot_locked(chain_key);
    out->present = (slot != NULL && slot->set);
    if (!out->present)
        return;
    snprintf(out->proposer_uuid, sizeof(out->proposer_uuid), "%s",
             slot->proposer);
    snprintf(out->root, sizeof(out->root), "%s", slot->root);
    snprintf(out->group_uuid, sizeof(out->group_uuid), "%s",
             (chain_key == NULL) ? "" : chain_key);
    out->epoch = slot->epoch;
    out->first_index = slot->first_index;
    out->count = slot->count;
    map_key_t key = NULL;
    data_t *val = NULL;
    map_entries_for_each(&slot->sigs_final, key, val)
    {
        string_t sig = NULL;
        if (data_string_ptr(val, &sig) == 0 && sig != NULL)
            map_set(&out->sigs, key, string_data(sig, strlen(sig)));
    }
    map_end_for_each
}

/* Write the evidence behind the reputation snapshot: the resident hash-linked
 * window plus the quorum-signed checkpoint over it.
 *
 * Called from the checkpoint-store path, and deliberately only there: at that
 * instant the resident window and the agreed root describe each other. Writing
 * on every commit would be both hotter and LESS useful, since a chain that has
 * moved past its checkpoint is exactly a chain the rebuild cannot attest.
 *
 * Failure is logged and swallowed. The evidence is an optimization of trust —
 * its absence costs a warm start its elevated tiers and nothing else — so it
 * must never be able to take down the reputation process. */
static void _persist_history(const process_t *proc, const char *chain_key)
{
    char path[CFG_PATH_LEN + 64] = {0};
    if (_evidence_path(chain_key, path, sizeof(path)) != 0)
    {
        log_warn(proc->logger,
                 "Reputation: cannot build evidence path; not persisting\n");
        return;
    }
    rep_checkpoint_t ckpt;
    if (rep_checkpoint_init(&ckpt) != 0)
        return;
    json_t *doc = NULL;
    pthread_mutex_lock(&rep_state.lock);
    _current_checkpoint_locked(chain_key, &ckpt);
    int err = reputation_evidence_to_json(_chain_for_key_locked(chain_key),
                                          &ckpt, &doc);
    pthread_mutex_unlock(&rep_state.lock);
    rep_checkpoint_free(&ckpt);
    if (err != 0 || doc == NULL)
    {
        log_warn(proc->logger, "Reputation: could not build evidence doc\n");
        return;
    }
    if (json_dump_file(doc, path, JSON_INDENT(2)) != 0)
        log_warn(proc->logger,
                 "Reputation: could not persist evidence to %s\n", path);
    json_decref(doc);
}

/* Record a finalized checkpoint (root + window bounds + the co-signatures that
 * finalized it) and persist the evidence beside it.
 *
 * The co-signatures are retained past the live round on purpose: at boot the
 * rebuild has to verify the same quorum a live receiver does. A fuller
 * signature set for the checkpoint we already hold is an UPGRADE, not a
 * duplicate — the proposer self-stores holding only its own signature, and the
 * quorum map only exists a round later. */
static void _store_checkpoint(const process_t *proc, const char *proposer,
                              const char *root, int64_t epoch,
                              int first_index, int count,
                              const char *chain_key, json_t *sigs)
{
    if (proposer == NULL || root == NULL)
        return;
    size_t incoming = json_is_object(sigs) ? json_object_size(sigs) : 0;
    bool write = false;
    pthread_mutex_lock(&rep_state.lock);
    rep_chain_ckpt_t *slot = _ckpt_slot_locked(chain_key);
    if (slot == NULL)
    {
        pthread_mutex_unlock(&rep_state.lock);
        return;
    }
    bool same = slot->set && slot->epoch == epoch
        && strncmp(slot->proposer, proposer, UUID_STRING_LEN + 1) == 0;
    if (!same || incoming > map_size(&slot->sigs_final))
    {
        snprintf(slot->proposer, sizeof(slot->proposer), "%s", proposer);
        snprintf(slot->root, sizeof(slot->root), "%s", root);
        slot->epoch = epoch;
        slot->first_index = first_index;
        slot->count = count;
        slot->set = true;
        map_free(&slot->sigs_final);
        map_init(&slot->sigs_final);
        if (json_is_object(sigs))
        {
            const char *voter;
            json_t *sig;
            json_object_foreach(sigs, voter, sig)
            {
                const char *hex = json_string_value(sig);
                if (hex != NULL)
                    map_set(&slot->sigs_final, (map_key_t)voter,
                            string_data((string_t)hex, strlen(hex)));
            }
        }
        if (chain_key == NULL || chain_key[0] == '\0')
            _mirror_primary_ckpt_locked();
        write = true;
    }
    pthread_mutex_unlock(&rep_state.lock);
    if (write)
        _persist_history(proc, chain_key);
}

/* Clamp each restored score to what the evidence supports for that peer: its
 * `ceilings` entry, or — for a peer the evidence does not cover at all — the
 * ceiling of REP_UNVERIFIED_RESTORE_TIER.
 *
 * Self is never clamped (our own score is not a peer judgement). Clamping is
 * one-directional, so this can only withhold standing, never confer it, and it
 * composes with the staleness decay: decay is the time-out-of-contact axis,
 * this is the "nothing here shows you earned that" axis.
 *
 * There is no separate release step — the clamped value is where the peer
 * resumes climbing, so elevation is re-earned through the ordinary scoring
 * path. Mirrors Python _grade_restored_reputations. */
static void _grade_restored_reputations(const process_t *proc, map_t *ceilings,
                                        const char *self_uuid_str)
{
    double unverified = _tier_ceiling(REP_UNVERIFIED_RESTORE_TIER);
    int clamped = 0;
    pthread_mutex_lock(&rep_state.lock);
    map_key_t key = NULL;
    data_t *val = NULL;
    map_entries_for_each(&rep_state.reputations.scores, key, val)
    {
        if (self_uuid_str != NULL && strcmp(key, self_uuid_str) == 0)
            continue;
        double score = 0.0;
        if (data_floating_pt_dbl(val, &score) != 0)
            continue;
        double ceiling = unverified;
        data_t *cd = NULL;
        if (ceilings != NULL && map_get(ceilings, key, &cd) == 0 && cd != NULL)
            data_floating_pt_dbl(cd, &ceiling);
        if (score <= ceiling)
            continue;
        map_set(&rep_state.reputations.scores, key,
                floating_pt_dbl_data(ceiling));
        /* Remember what we clamped away from: it bounds any later lift from
         * child-group evidence (§10.2). */
        map_set(&rep_state.restore_clamped, key, floating_pt_dbl_data(score));
        clamped++;
    }
    map_end_for_each
    pthread_mutex_unlock(&rep_state.lock);
    if (clamped > 0)
        log_info(proc->logger,
                 "Reputation: warm start clamped %d peer score(s) to what the "
                 "evidence supports\n", clamped);
}

/* Treat the persisted snapshot's mtime as the instant of our last AT-bounded
 * activity: seed every warm-started peer's idle clock to it and apply the
 * offline-gap decay up front, so a long-dormant cohort comes up with faded —
 * not stale-inflated — trust. No-op when there is no snapshot on disk.
 * Mirrors Python _seed_idle_from_snapshot. */
static void _seed_idle_from_snapshot(const process_t *proc,
                                     const char *self_uuid_str)
{
    char cfg_dir[CFG_PATH_LEN + 1] = {0};
    if (get_cfg_dir(cfg_dir, sizeof(cfg_dir)) < 0)
        return;
    char path[CFG_PATH_LEN + 64] = {0};
    int n = snprintf(path, sizeof(path), "%s/%s%s", cfg_dir,
                     REP_SNAPSHOT_FILE, CFG_FILE_EXT);
    if (n < 0 || (size_t)n >= sizeof(path))
        return;
    struct stat st;
    if (stat(path, &st) != 0)
        return;
    double mtime = (double)st.st_mtime;
    double idle = (double)time(NULL) - mtime;
    if (idle < 0.0)
        idle = 0.0;
    int faded = 0;
    pthread_mutex_lock(&rep_state.lock);
    map_key_t key = NULL;
    data_t *val = NULL;
    map_entries_for_each(&rep_state.reputations.scores, key, val)
    {
        if (self_uuid_str != NULL && strcmp(key, self_uuid_str) == 0)
            continue;
        map_set(&rep_state.last_interaction, key, floating_pt_dbl_data(mtime));
        double score = 0.0;
        if (data_floating_pt_dbl(val, &score) != 0)
            continue;
        double decayed = reputation_decayed_score(score, idle);
        if (fabs(decayed - score) > 1e-12)
        {
            map_set(&rep_state.reputations.scores, key,
                    floating_pt_dbl_data(decayed));
            faded++;
        }
    }
    map_end_for_each
    pthread_mutex_unlock(&rep_state.lock);
    if (faded > 0)
        log_info(proc->logger,
                 "Reputation: warm start faded %d peer score(s) over a "
                 "%.0fs offline gap\n", faded, idle);
}

/* Relax idle peers' operational reputation toward almost-neutral. Throttled to
 * REP_DECAY_SWEEP_INTERVAL. A peer with no recorded interaction is stamped
 * rather than decayed, so its idle clock starts now instead of at the epoch.
 * Mirrors Python _decay_reputations. */
static void _decay_reputations(const process_t *proc, double present)
{
    pthread_mutex_lock(&rep_state.lock);
    if (rep_state.decay_swept
        && present - rep_state.last_decay_sweep < REP_DECAY_SWEEP_INTERVAL)
    {
        pthread_mutex_unlock(&rep_state.lock);
        return;
    }
    rep_state.last_decay_sweep = present;
    rep_state.decay_swept = true;
    /* Collect the changes under the lock, publish after releasing it: the
     * tier/exclusion publication sends IPC and must not hold rep_state. */
    char changed[MAX_CHAIN_LEN][UUID_STRING_LEN + 1];
    double changed_score[MAX_CHAIN_LEN];
    int n_changed = 0;
    map_key_t key = NULL;
    data_t *val = NULL;
    map_entries_for_each(&rep_state.reputations.scores, key, val)
    {
        double score = 0.0;
        if (data_floating_pt_dbl(val, &score) != 0)
            continue;
        /* A slashed peer's floor is authoritative; decay would drift the value
         * the slash pinned. Self is never decayed. */
        data_t *sl = NULL;
        if (map_get(&rep_state.slashed, key, &sl) == 0 && sl != NULL)
            continue;
        double last = 0.0;
        data_t *ld = NULL;
        bool have_last = (map_get(&rep_state.last_interaction, key, &ld) == 0
                          && ld != NULL
                          && data_floating_pt_dbl(ld, &last) == 0);
        if (!have_last)
        {
            /* First sight of this peer: start its idle clock now rather than
             * at the epoch, which would decay it as if absent since 1970. */
            map_set(&rep_state.last_interaction, key,
                    floating_pt_dbl_data(present));
            continue;
        }
        double decayed = reputation_decayed_score(score, present - last);
        if (fabs(decayed - score) < 1e-12)
            continue;
        map_set(&rep_state.reputations.scores, key,
                floating_pt_dbl_data(decayed));
        if (n_changed < MAX_CHAIN_LEN)
        {
            strncpy(changed[n_changed], key, UUID_STRING_LEN);
            changed[n_changed][UUID_STRING_LEN] = '\0';
            changed_score[n_changed] = decayed;
            n_changed++;
        }
    }
    map_end_for_each
    pthread_mutex_unlock(&rep_state.lock);
    for (int i = 0; i < n_changed; i++)
    {
        uuid_t u;
        if (uuid_parse(changed[i], u) != 0)
            continue;
        _publish_tier_change(proc, u, changed_score[i]);
        _publish_reputation_change(u, changed_score[i]);
    }
}

/* Stamp "we just transacted with this peer" — resets its idle clock so the
 * staleness sweep leaves an actively-interacting peer alone. */
static void _note_interaction(const uuid_t peer_uuid)
{
    char key[UUID_STRING_LEN + 1];
    uuid_unparse_lower(peer_uuid, key);
    pthread_mutex_lock(&rep_state.lock);
    map_set(&rep_state.last_interaction, (map_key_t)key,
            floating_pt_dbl_data((double)time(NULL)));
    pthread_mutex_unlock(&rep_state.lock);
}

/* At start-up, re-establish the committed history from the persisted evidence
 * and grade the restored reputations by whether that evidence VERIFIES.
 *
 * Three questions, in order, every negative answer degrading to the same safe
 * outcome rather than failing the process:
 *   1. Does the chain's hash-linkage hold? (checked inside
 *      reputation_evidence_from_json — a broken link means the file was
 *      altered or truncated.)
 *   2. Does the root recomputed over the checkpoint's window equal the root
 *      the checkpoint commits to? This is what ties the entries on disk to the
 *      thing that was signed.
 *   3. Does a quorum of co-signatures over that checkpoint verify against keys
 *      WE hold? The same test handle_checkpoint_final applies live, sized
 *      against our own roster so whoever wrote the file cannot also choose the
 *      bar it has to clear.
 *
 * Only if all three hold is the chain adopted. It is NOT adopted on failure,
 * and that is the load-bearing part: hash digests are public, so anyone can
 * produce a self-consistent chain, and adopting one would let the scoring path
 * re-derive the very elevated scores the clamp withholds. */
/* Verify and (only then) adopt ONE chain's persisted evidence, folding its
 * per-peer ceilings into @p ceilings. Returns true if the chain was adopted.
 *
 * Where two attested windows bound the same peer, the HIGHER bound wins: both
 * are quorum-attested statements about that peer and the restored score is a
 * single scalar, so letting one group's thin window suppress standing another
 * group's quorum actually witnessed would penalize the peer for our topology
 * rather than for its behaviour. */
static bool _rebuild_one_chain(const process_t *proc, const char *chain_key,
                               const char *self_uuid_str, map_t *ceilings)
{
    char path[CFG_PATH_LEN + 64] = {0};
    if (_evidence_path(chain_key, path, sizeof(path)) != 0)
        return false;
    json_error_t jerr;
    json_t *doc = json_load_file(path, 0, &jerr);
    if (doc == NULL)
    {
        /* No evidence on disk: a cold start, or a warm start from a snapshot
         * written before checkpointing ever ran. Persisted scores are
         * unattested, so they are clamped. */
        return false;
    }

    tx_history_t *loaded = NULL;
    rep_checkpoint_t ckpt;
    bool verified = false;
    if (tx_history_create(&loaded) == 0 && rep_checkpoint_init(&ckpt) == 0)
    {
        if (reputation_evidence_from_json(doc, loaded, &ckpt) != 0)
        {
            log_warn(proc->logger,
                     "Reputation: unusable warm-start evidence (bad schema, "
                     "malformed entry, or broken hash link); restoring at "
                     "tier %d\n", REP_UNVERIFIED_RESTORE_TIER);
        }
        else if (!ckpt.present)
        {
            log_info(proc->logger,
                     "Reputation: warm-start evidence carries no checkpoint; "
                     "restoring at tier %d\n", REP_UNVERIFIED_RESTORE_TIER);
        }
        else
        {
            char recomputed[TX_HASH_HEX_LEN + 1] = {0};
            if (reputation_checkpoint_window_root(loaded, &ckpt,
                                                  recomputed) != 0)
            {
                log_warn(proc->logger,
                         "Reputation: warm-start evidence does not cover "
                         "checkpoint window [%d, %d); restoring at tier %d\n",
                         ckpt.first_index, ckpt.first_index + ckpt.count,
                         REP_UNVERIFIED_RESTORE_TIER);
            }
            else if (strncmp(recomputed, ckpt.root, TX_HASH_HEX_LEN + 1) != 0)
            {
                log_warn(proc->logger,
                         "Reputation: warm-start evidence root mismatch "
                         "(checkpoint commits to %.12s, entries hash to "
                         "%.12s); restoring at tier %d\n", ckpt.root,
                         recomputed, REP_UNVERIFIED_RESTORE_TIER);
            }
            else
            {
                uint8_t desig[REP_DESIG_MAX];
                size_t dlen = rep_checkpoint_designation(
                    ckpt.proposer_uuid, ckpt.root, ckpt.epoch,
                    ckpt.first_index, ckpt.count, ckpt.group_uuid, desig,
                    sizeof(desig));
                /* Re-use the live path's quorum test verbatim, including its
                 * roster sizing. A roster we have not yet loaded resolves no
                 * co-signers, which fails CLOSED: capped, never forged. */
                json_t *sigs = json_object();
                map_key_t key = NULL;
                data_t *val = NULL;
                map_entries_for_each(&ckpt.sigs, key, val)
                {
                    string_t hex = NULL;
                    if (data_string_ptr(val, &hex) == 0 && hex != NULL)
                        json_object_set_new(sigs, key, json_string(hex));
                }
                map_end_for_each
                if (dlen == 0
                    || !_quorum_met_for(proc, sigs, desig, dlen, chain_key))
                {
                    log_warn(proc->logger,
                             "Reputation: warm-start evidence epoch=%lld has "
                             "%zu verified co-signature(s), short of quorum; "
                             "restoring at tier %d\n", (long long)ckpt.epoch,
                             dlen == 0 ? (size_t)0
                                 : _verified_cosigners(proc, sigs, desig, dlen),
                             REP_UNVERIFIED_RESTORE_TIER);
                }
                else
                {
                    verified = true;
                    reputation_evidence_ceilings(loaded, &ckpt, self_uuid_str,
                                                 ceilings);
                }
                json_decref(sigs);
            }
        }

        if (verified)
        {
            pthread_mutex_lock(&rep_state.lock);
            /* Adopt the attested history, and with it the checkpoint that
             * attests it, so this node resumes with a window a peer can audit
             * and an anchor slash evidence can be measured against. */
            tx_history_t *dest = _chain_for_key_locked(chain_key);
            tx_history_free(dest);
            *dest = *loaded;
            memset(loaded, 0, sizeof(*loaded));  /* ownership moved */
            rep_chain_ckpt_t *slot = _ckpt_slot_locked(chain_key);
            if (slot != NULL)
            {
                snprintf(slot->proposer, sizeof(slot->proposer), "%s",
                         ckpt.proposer_uuid);
                snprintf(slot->root, sizeof(slot->root), "%s", ckpt.root);
                slot->epoch = ckpt.epoch;
                slot->first_index = ckpt.first_index;
                slot->count = ckpt.count;
                slot->set = true;
                map_free(&slot->sigs_final);
                map_init(&slot->sigs_final);
                map_key_t key = NULL;
                data_t *val = NULL;
                map_entries_for_each(&ckpt.sigs, key, val)
                {
                    string_t hex = NULL;
                    if (data_string_ptr(val, &hex) == 0 && hex != NULL)
                        map_set(&slot->sigs_final, key,
                                string_data(hex, strlen(hex)));
                }
                map_end_for_each
                /* Resume our OWN epoch counter past the persisted checkpoint.
                 * Peers dedup on (proposer, epoch, chain) and their rings are
                 * not reset by our restart, so a restarted proposer beginning
                 * again at 1 would have its first proposals discarded as
                 * re-broadcasts. */
                if (self_uuid_str != NULL
                    && strcmp(ckpt.proposer_uuid, self_uuid_str) == 0
                    && ckpt.epoch > slot->own_epoch)
                    slot->own_epoch = ckpt.epoch;
            }
            if (chain_key == NULL || chain_key[0] == '\0')
                _mirror_primary_ckpt_locked();
            int adopted = dest->committed_count;
            pthread_mutex_unlock(&rep_state.lock);
            log_info(proc->logger,
                     "Reputation: warm start VERIFIED — chain=%s, %d committed "
                     "entries, checkpoint epoch=%lld, %zu evidence-backed "
                     "peer(s)\n",
                     (chain_key != NULL && chain_key[0]) ? chain_key : "primary",
                     adopted, (long long)ckpt.epoch, map_size(ceilings));
        }
        rep_checkpoint_free(&ckpt);
    }
    if (loaded != NULL)
        tx_history_destroy(loaded);
    json_decref(doc);
    return verified;
}

/* Boot-time restore: the PRIMARY chain only, then clamp.
 *
 * A gateway's child groups arrive over IPC (CHILD_GROUP from the identity
 * process) AFTER this runs, so at this point the node does not yet know which
 * subtrees are its own -- and reading a file for a group we may not gateway is
 * exactly what must not happen. The child chains are restored by
 * _restore_child_evidence once the group set lands. */
static void _rebuild_from_evidence(const process_t *proc,
                                   const char *self_uuid_str)
{
    map_t ceilings;
    map_init(&ceilings);
    _rebuild_one_chain(proc, "", self_uuid_str, &ceilings);
    _grade_restored_reputations(proc, &ceilings, self_uuid_str);
    map_free(&ceilings);
}

/* A document must cover the chain it is NAMED for. A child document claiming
 * the primary chain (or another group's) would otherwise be adopted as that
 * chain's history on the strength of signatures made over different bytes. */
static bool _evidence_names_chain(const char *path, const char *chain_key)
{
    json_error_t jerr;
    json_t *doc = json_load_file(path, 0, &jerr);
    if (doc == NULL)
        return false;
    json_t *ck = json_object_get(doc, "checkpoint");
    bool ok = true;
    if (json_is_object(ck))
    {
        const char *claimed = json_string_value(json_object_get(ck,
                                                               "group_uuid"));
        if (claimed == NULL)
            claimed = "";
        ok = (strncmp(claimed, chain_key, UUID_STRING_LEN + 1) == 0);
    }
    json_decref(doc);
    return ok;
}

/* Restore a gateway's child-group chains once the group set has arrived, one
 * attempt per group (ISSUES.md §10.2).
 *
 * This runs late by necessity, which shapes what it may do to a live score: it
 * only ever LIFTS, and never above what was persisted. A peer attested solely
 * in a child group was clamped at boot as uncovered, and this returns it to
 * what its subtree's evidence bears out. Lowering here would be wrong twice
 * over -- the peer may have earned standing since boot, and late-arriving
 * evidence is not a reason to discount it. Mirrors Python
 * _restore_child_evidence. */
static void _restore_child_evidence(const process_t *proc,
                                    const char *self_uuid_str)
{
    if (proc == NULL || proc->protocol.child_groups == NULL)
        return;
    /* Plain iteration over the key array rather than map_entries_for_each:
     * that macro declares its own locals, so nesting it around the per-peer
     * loop below shadows them (-Werror=shadow). */
    array_t *groups = map_keys(proc->protocol.child_groups);
    size_t n_groups = array_size(groups);
    for (size_t gi = 0; gi < n_groups; gi++)
    {
        data_t *gk_dat = NULL;
        if (array_get(groups, (int)gi, &gk_dat) != 0)
            continue;
        map_key_t gkey = NULL;
        if (data_string_ptr(gk_dat, &gkey) != 0 || gkey == NULL)
            continue;
        pthread_mutex_lock(&rep_state.lock);
        data_t *seen = NULL;
        bool tried = (map_get(&rep_state.child_evidence_tried, gkey, &seen) == 0);
        if (!tried)
            map_set(&rep_state.child_evidence_tried, gkey, integer_data(1));
        pthread_mutex_unlock(&rep_state.lock);
        if (tried)
            continue;
        char path[CFG_PATH_LEN + 64] = {0};
        if (_evidence_path(gkey, path, sizeof(path)) != 0)
            continue;
        if (!_evidence_names_chain(path, gkey))
        {
            log_warn(proc->logger,
                     "Reputation: evidence for chain %s names another chain; "
                     "refusing it\n", gkey);
            continue;
        }
        map_t ceilings;
        map_init(&ceilings);
        if (_rebuild_one_chain(proc, gkey, self_uuid_str, &ceilings))
        {
            map_key_t pkey = NULL;
            data_t *pval = NULL;
            map_entries_for_each(&ceilings, pkey, pval)
            {
                double ceiling = 0.0;
                if (data_floating_pt_dbl(pval, &ceiling) != 0)
                    continue;
                uuid_t peer;
                if (uuid_parse(pkey, peer) != 0)
                    continue;
                double current = 0.0;
                double bound = ceiling;
                pthread_mutex_lock(&rep_state.lock);
                bool have = (reputations_get(&rep_state.reputations, peer,
                                             &current) == 0);
                data_t *cd = NULL;
                if (have
                    && map_get(&rep_state.restore_clamped, pkey, &cd) == 0
                    && cd != NULL)
                {
                    double persisted = 0.0;
                    if (data_floating_pt_dbl(cd, &persisted) == 0
                        && persisted < bound)
                        bound = persisted;
                }
                bool lift = have && bound > current;
                if (lift)
                    reputations_update(&rep_state.reputations, peer, bound);
                pthread_mutex_unlock(&rep_state.lock);
                if (lift)
                {
                    log_info(proc->logger,
                             "Reputation: child-group evidence lifted %s "
                             "%.3f -> %.3f\n", pkey, current, bound);
                    _publish_tier_change(proc, peer, bound);
                    _publish_reputation_change(peer, bound);
                }
            }
            map_end_for_each
        }
        map_free(&ceilings);
    }
}

/* A per-node offset into the checkpoint interval, so members do not all
 * propose on the same tick: every member co-signs every proposal, so N nodes
 * proposing together cost N² messages in one burst. Derived from our own uuid
 * rather than drawn randomly, so the phase survives a restart. Mirrors Python
 * _checkpoint_phase. */
static double _checkpoint_phase(const char *self_uuid_str)
{
    if (self_uuid_str == NULL)
        return 0.0;
    uuid_t u;
    if (uuid_parse(self_uuid_str, u) != 0)
        return 0.0;
    /* Python takes UUID.int % interval; the low-order bytes of the same uuid
     * give an equally-uniform offset without 128-bit arithmetic. The phase is
     * a load-spreading device, not a protocol value, so the two runtimes need
     * not agree on it. */
    uint64_t lo = 0;
    for (int i = 8; i < 16; i++)
        lo = (lo << 8) | (uint64_t)u[i];
    int64_t interval = (int64_t)REP_CHECKPOINT_INTERVAL;
    if (interval < 1)
        interval = 1;
    return (double)(lo % (uint64_t)interval);
}

/* Originate a checkpoint over THIS node's committed window: stamp the epoch,
 * sign, seed our own co-signature, self-store, and broadcast
 * checkpoint_propose. Mirrors Python forward_checkpoint.
 *
 * The self-store matters as much as the broadcast: a single-node group needs
 * no round trip, and it is not special-cased — at boot the same quorum rule
 * applies, so a lone self-signature attests a genuinely single-node group and
 * nothing more. */
static void _originate_checkpoint(const process_t *proc,
                                  const char *self_uuid_str,
                                  const char *chain_key)
{
    if (self_uuid_str == NULL || self_uuid_str[0] == '\0')
        return;
    if (chain_key == NULL)
        chain_key = "";
    char root[TX_HASH_HEX_LEN + 1] = {0};
    int64_t epoch = 0;
    int first_index = 0, count = 0;
    pthread_mutex_lock(&rep_state.lock);
    rep_chain_ckpt_t *slot = _ckpt_slot_locked(chain_key);
    tx_history_t *chain = _chain_for_key_locked(chain_key);
    if (slot != NULL)
    {
        slot->own_epoch++;
        epoch = slot->own_epoch;
    }
    transaction_window_root(chain, root);
    count = chain->committed_count;
    first_index = (count > 0) ? chain->first_index : chain->next_index;
    pthread_mutex_unlock(&rep_state.lock);

    uint8_t desig[REP_DESIG_MAX];
    size_t dlen = rep_checkpoint_designation(self_uuid_str, root, epoch,
                                             first_index, count, chain_key,
                                             desig, sizeof(desig));
    char sig_hex[REP_SIG_HEX_LEN + 1] = {0};
    json_t *sigs = json_object();
    if (dlen > 0 && _cosign_hex(proc, desig, dlen, sig_hex,
                                sizeof(sig_hex)) == 0)
    {
        json_object_set_new(sigs, self_uuid_str, json_string(sig_hex));
    }
    else
    {
        log_error(proc->logger,
                  "Reputation: cannot sign own checkpoint; it cannot reach "
                  "quorum\n");
    }
    /* Record the round so our own handle_checkpoint_sign can tally acks
     * against it, exactly as if a peer had proposed to us. */
    /* The round key carries the chain too: a gateway's primary and child rounds
     * can otherwise collide at the same epoch number. */
    char key[UUID_STRING_LEN * 2 + 32];
    snprintf(key, sizeof(key), "%s:%lld:%s", self_uuid_str, (long long)epoch,
             chain_key);
    json_t *pending = json_pack("{s:s, s:i, s:i, s:s}", "root", root,
                                "first_index", first_index, "count", count,
                                "group_uuid", chain_key);
    if (pending != NULL)
    {
        pthread_mutex_lock(&rep_state.lock);
        _store_pending_locked(&rep_state.checkpoint_pending, key, pending);
        pthread_mutex_unlock(&rep_state.lock);
        json_decref(pending);
    }
    if (sig_hex[0] != '\0')
    {
        pthread_mutex_lock(&rep_state.lock);
        _record_cosig_locked(&rep_state.checkpoint_sigs, key, self_uuid_str,
                             sig_hex);
        pthread_mutex_unlock(&rep_state.lock);
    }
    _store_checkpoint(proc, self_uuid_str, root, epoch, first_index, count,
                      chain_key, sigs);

    json_t *payload = json_pack("{s:s, s:s, s:I, s:i, s:i, s:s}",
                                "proposer_uuid", self_uuid_str,
                                "root", root,
                                "epoch", (json_int_t)epoch,
                                "first_index", first_index,
                                "count", count,
                                "group_uuid", chain_key);
    if (payload != NULL)
    {
        generic_msg_t bcast = {0};
        bcast.type = NET_MESSAGE;
        strncpy(bcast.info.net_msg.process, "reputation", PROC_NAME_LEN);
        bcast.info.net_msg.function = REP_PROTO_CHECKPOINT_PROPOSE;
        bcast.info.net_msg.encrypt = true;
        net_msg_pack_json(&bcast.info.net_msg, payload);
        json_decref(payload);
        peers_read_lock(proc);
        for (size_t i = 0; i < proc->protocol.num_peers; i++)
        {
            generic_msg_t per = bcast;
            memcpy(&per.info.net_msg.to_whom, &proc->protocol.peers[i],
                   sizeof(public_identity_t));
            messaging_send("network", NET_MESSAGE, &per, false);
        }
        peers_read_unlock(proc);
    }
    json_decref(sigs);
    log_info(proc->logger,
             "Reputation: proposed checkpoint chain=%s epoch=%lld count=%d "
             "root=%.12s\n", chain_key[0] ? chain_key : "primary",
             (long long)epoch, count, root);
}

/* Originate a checkpoint on the interval, when the window has actually moved.
 *
 * Two guards, both about not spending the group's bandwidth for nothing. An
 * empty window has nothing to attest. A window whose head has not advanced
 * since the last checkpoint is already attested — re-signing it produces a new
 * epoch committing to the same root, which no verifier can use for anything
 * the previous one could not. Mirrors Python _maybe_checkpoint. */
static void _maybe_checkpoint(const process_t *proc, double present,
                              const char *self_uuid_str)
{
    if (REP_CHECKPOINT_INTERVAL <= 0)
        return;
    pthread_mutex_lock(&rep_state.lock);
    if (!rep_state.checkpoint_phase_taken)
    {
        rep_state.next_checkpoint_at = present + _checkpoint_phase(self_uuid_str);
        rep_state.checkpoint_phase_taken = true;
        pthread_mutex_unlock(&rep_state.lock);
        return;
    }
    if (present < rep_state.next_checkpoint_at)
    {
        pthread_mutex_unlock(&rep_state.lock);
        return;
    }
    rep_state.next_checkpoint_at = present + REP_CHECKPOINT_INTERVAL;

    /* Every chain, each on its own: an idle primary chain is skipped while a
     * busy child group is checkpointed, and each round is confined to the group
     * that can actually co-sign it (§10.2). Collect the due chains under the
     * lock, originate after releasing it -- origination signs and sends. */
    char due_keys[DEFAULT_MAX_PEERS + 1][UUID_STRING_LEN + 1];
    int n_due = 0;
    array_t *child_keys = map_keys(&rep_state.child_hist);
    size_t n_child = array_size(child_keys);
    for (size_t ci = 0; ci <= n_child && n_due <= DEFAULT_MAX_PEERS; ci++)
    {
        const char *chain_key = "";
        if (ci > 0)
        {
            data_t *kd = NULL;
            map_key_t k = NULL;
            if (array_get(child_keys, (int)(ci - 1), &kd) != 0
                || data_string_ptr(kd, &k) != 0 || k == NULL)
                continue;
            chain_key = k;
        }
        tx_history_t *chain = _chain_for_key_locked(chain_key);
        rep_chain_ckpt_t *slot = _ckpt_slot_locked(chain_key);
        if (chain == NULL || slot == NULL)
            continue;
        int head = -1;
        for (int i = chain->chain_len - 1; i >= 0; i--)
        {
            if (chain->chain[i].index >= 0)
            {
                head = chain->chain[i].index;
                break;
            }
        }
        if (head < 0 || head <= slot->last_head)
            continue;
        slot->last_head = head;
        snprintf(due_keys[n_due], sizeof(due_keys[0]), "%s", chain_key);
        n_due++;
    }
    pthread_mutex_unlock(&rep_state.lock);
    for (int i = 0; i < n_due; i++)
        _originate_checkpoint(proc, self_uuid_str, due_keys[i]);
}

int reputation_register_handlers(process_t *proc)
{
    if (proc == NULL) return -1;
    process_register_handler(proc, REP_PROTO_REQUEST,   (handler_ptr_t)handle_request);
    process_register_handler(proc, REP_PROTO_GRANT,     (handler_ptr_t)handle_grant);
    process_register_handler(proc, REP_PROTO_NACK,      (handler_ptr_t)handle_nack);
    process_register_handler(proc, REP_PROTO_BACKDATE,  (handler_ptr_t)handle_backdate);
    process_register_handler(proc, REP_PROTO_TX,        (handler_ptr_t)handle_transaction);
    process_register_handler(proc, REP_PROTO_ACCEPTED,  (handler_ptr_t)handle_accepted);
    process_register_handler(proc, REP_PROTO_COMMITTED, (handler_ptr_t)handle_committed);
    process_register_handler(proc, REP_PROTO_OUTDATED,  (handler_ptr_t)handle_outdated);
    process_register_handler(proc, REP_PROTO_UPDATE,    (handler_ptr_t)handle_update);
    process_register_handler(proc, REP_PROTO_REP_REQ,   (handler_ptr_t)handle_rep_request);
    process_register_handler(proc, REP_PROTO_REP_RESP,  (handler_ptr_t)handle_rep_response);
    process_register_handler(proc, REP_PROTO_CONSENSUS_REP_REQ,
                             (handler_ptr_t)handle_consensus_rep_request);
    process_register_handler(proc, REP_PROTO_LOCAL_QUERY, (handler_ptr_t)handle_local_rep_query);
    process_register_handler(proc, REP_PROTO_APP_ROSTER, (handler_ptr_t)handle_app_roster_request);
    process_register_handler(proc, REP_PROTO_SLASH_PROPOSE, (handler_ptr_t)handle_slash_propose);
    process_register_handler(proc, REP_PROTO_SLASH_SIGN,    (handler_ptr_t)handle_slash_sign);
    process_register_handler(proc, REP_PROTO_SLASH_FINAL,   (handler_ptr_t)handle_slash_final);
    process_register_handler(proc, REP_PROTO_CHECKPOINT_PROPOSE, (handler_ptr_t)handle_checkpoint_propose);
    process_register_handler(proc, REP_PROTO_CHECKPOINT_SIGN,    (handler_ptr_t)handle_checkpoint_sign);
    process_register_handler(proc, REP_PROTO_CHECKPOINT_FINAL,   (handler_ptr_t)handle_checkpoint_final);
    process_register_handler(proc, REP_PROTO_REP_RESOLVE,        (handler_ptr_t)handle_resolve);
    process_register_handler(proc, REP_PROTO_REP_RESOLVED,       (handler_ptr_t)handle_resolved);
    return 0;
}

/* ---- Conformance test hooks (see rep_proc_priv.h doc) ---------------------- */

void reputation_set_synchronous_dispatch(bool enabled)
{
    _ensure_init();
    pthread_mutex_lock(&rep_state.lock);
    rep_state.synchronous_dispatch = enabled;
    pthread_mutex_unlock(&rep_state.lock);
}

void reputation_reset_state(int num_peers)
{
    _ensure_init();
    pthread_mutex_lock(&rep_state.lock);
    /* Tear down + reinit. Preserve synchronous_dispatch so the harness
     * doesn't have to set it on every reset. */
    bool was_sync = rep_state.synchronous_dispatch;
    if (rep_state.paxos.initialized)
        paxos_destroy(&rep_state.paxos);
    /* Clear my_requests; entries are smrt_ptr-backed tx_score_t. */
    map_free(&rep_state.my_requests);
    map_init(&rep_state.my_requests);
    map_free(&rep_state.updates);
    map_init(&rep_state.updates);
    array_free(&rep_state.requested_reps);
    array_init(&rep_state.requested_reps);
    /* History reset: free contents + reinit. tx_history_destroy
     * additionally `free()`s the container, which would corrupt the
     * heap when the container is the embedded `rep_state.history`
     * member (never malloc'd). tx_history_free clears contents only. */
    tx_history_free(&rep_state.history);
    tx_history_init(&rep_state.history);
    /* Child chains are heap-allocated per group; free the histories before
     * dropping the map or their chains leak. */
    {
        map_key_t ck = NULL;
        data_t *cv = NULL;
        map_entries_for_each(&rep_state.child_hist, ck, cv)
        {
            void *hp = NULL;
            if (data_object_ptr(cv, &hp) == 0 && hp != NULL)
            {
                tx_history_free((tx_history_t *)hp);
                free(hp);
            }
        }
        map_end_for_each
    }
    map_free(&rep_state.child_hist);
    map_init(&rep_state.child_hist);
    {
        map_key_t sk = NULL;
        data_t *sv = NULL;
        map_entries_for_each(&rep_state.chain_ckpts, sk, sv)
        {
            void *sp = NULL;
            if (data_object_ptr(sv, &sp) == 0 && sp != NULL)
            {
                map_free(&((rep_chain_ckpt_t *)sp)->sigs_final);
                free(sp);
            }
        }
        map_end_for_each
    }
    map_free(&rep_state.chain_ckpts);
    map_init(&rep_state.chain_ckpts);
    map_free(&rep_state.round_group);
    map_init(&rep_state.round_group);
    map_free(&rep_state.peer_tiers);
    map_init(&rep_state.peer_tiers);
    map_free(&rep_state.committed_paxos_rounds);
    map_init(&rep_state.committed_paxos_rounds);
    rep_state.committed_paxos_ring_head = 0;
    rep_state.committed_paxos_ring_len = 0;
    map_free(&rep_state.coop_mode);
    map_init(&rep_state.coop_mode);
    map_free(&rep_state.task_weights);
    map_init(&rep_state.task_weights);
    rep_state.task_weights_ring_head = 0;
    rep_state.task_weights_ring_len = 0;
    memset(rep_state.task_weights_ring, 0, sizeof(rep_state.task_weights_ring));
    map_free(&rep_state.task_tiers);   /* lockstep with task_weights (§2.3) */
    map_init(&rep_state.task_tiers);
    map_free(&rep_state.slashed);
    map_init(&rep_state.slashed);
    map_free(&rep_state.slash_sigs);
    map_init(&rep_state.slash_sigs);
    map_free(&rep_state.slash_pending);
    map_init(&rep_state.slash_pending);
    rep_state.slash_epoch = 0;
    map_free(&rep_state.excluded);
    map_init(&rep_state.excluded);
    map_free(&rep_state.checkpoint_sigs);
    map_init(&rep_state.checkpoint_sigs);
    map_free(&rep_state.checkpoint_pending);
    map_init(&rep_state.checkpoint_pending);
    rep_state.checkpoint_root[0] = '\0';
    rep_state.checkpoint_epoch = 0;
    rep_state.checkpoint_set = false;
    map_free(&rep_state.checkpoint_sigs_final);
    map_init(&rep_state.checkpoint_sigs_final);
    rep_state.checkpoint_first_index = 0;
    rep_state.checkpoint_count = 0;
    rep_state.checkpoint_proposer[0] = '\0';
    rep_state.checkpoint_own_epoch = 0;
    rep_state.next_checkpoint_at = 0.0;
    rep_state.checkpoint_phase_taken = false;
    rep_state.last_checkpoint_head = -1;
    map_free(&rep_state.last_interaction);
    map_init(&rep_state.last_interaction);
    rep_state.last_decay_sweep = 0.0;
    rep_state.decay_swept = false;
    map_free(&rep_state.child_evidence_tried);
    map_init(&rep_state.child_evidence_tried);
    map_free(&rep_state.restore_clamped);
    map_init(&rep_state.restore_clamped);
    rep_state.num_updates = 3;  /* default; a fixture may lower it per step */
    rep_state.num_peers = num_peers;
    paxos_init(&rep_state.paxos, num_peers, NULL);
    rep_state.synchronous_dispatch = was_sync;
    pthread_mutex_unlock(&rep_state.lock);
}

void reputation_install_task_weight(const uuid_t task_uuid, int weight)
{
    _ensure_init();
    char task_str[UUID_STRING_LEN + 1] = {0};
    uuid_unparse_lower(task_uuid, task_str);
    pthread_mutex_lock(&rep_state.lock);
    _record_task_weight_locked(task_str, weight);
    pthread_mutex_unlock(&rep_state.lock);
}

void reputation_set_chain_len(int len)
{
    _ensure_init();
    pthread_mutex_lock(&rep_state.lock);
    rep_state.paxos.chain_len = len;
    pthread_mutex_unlock(&rep_state.lock);
}

void reputation_set_last_id(int64_t id)
{
    _ensure_init();
    pthread_mutex_lock(&rep_state.lock);
    rep_state.paxos.last_id = id;
    pthread_mutex_unlock(&rep_state.lock);
}

void reputation_set_num_updates(int n)
{
    _ensure_init();
    pthread_mutex_lock(&rep_state.lock);
    rep_state.num_updates = n;
    pthread_mutex_unlock(&rep_state.lock);
}

void reputation_install_my_request(int64_t id1, int64_t id2,
                                   const uuid_t proposer_uuid,
                                   double score,
                                   const uuid_t task_uuid)
{
    _ensure_init();
    /* Stage rep_state.my_requests[proposer_uuid_str] = tx_score_t{score, task_uuid}.
     * handle_grant looks this up by proposer uuid string to find the
     * pending round and broadcast a transaction on majority. */
    char proposer_str[UUID_STRING_LEN + 1];
    uuid_unparse_lower(proposer_uuid, proposer_str);

    tx_score_t *tx = smrt_create(sizeof(tx_score_t));
    if (tx == NULL) return;
    memset(tx, 0, sizeof(*tx));
    if (task_uuid != NULL)
        uuid_copy(tx->task_uuid, task_uuid);
    tx->score = score;

    pthread_mutex_lock(&rep_state.lock);
    data_t *tx_dat = object_ptr_data(tx, sizeof(tx_score_t));
    map_set(&rep_state.my_requests, proposer_str, tx_dat);

    /* Also stage paxos.proposals[id1:id2] = {score} so handle_accepted's
     * score lookup succeeds. paxos_record_grant does the right thing. */
    paxos_record_grant(&rep_state.paxos, id1, id2, score);
    pthread_mutex_unlock(&rep_state.lock);
}

void reputation_install_accepted(int64_t id1, int64_t id2)
{
    _ensure_init();
    pthread_mutex_lock(&rep_state.lock);
    /* paxos_has_granted_id(id2) walks paxos.granted_ids — populated only
     * by paxos_handle_request on the PAXOS_GRANT branch. To pretend a
     * round at (id1, id2) was granted, append id2 directly and also
     * stage a proposal so the score lookup in handle_accepted has
     * something to find. */
    data_t *id2_dat = integer_data((int)id2);
    if (id2_dat != NULL)
        array_append(&rep_state.paxos.granted_ids, id2_dat);
    if (id1 > rep_state.paxos.last_id)
        rep_state.paxos.last_id = id1;
    pthread_mutex_unlock(&rep_state.lock);
}

int reputation_get_chain_len(void)
{
    if (!rep_state.initialized) return -1;
    pthread_mutex_lock(&rep_state.lock);
    int len = rep_state.paxos.chain_len;
    pthread_mutex_unlock(&rep_state.lock);
    return len;
}

int reputation_get_committed_tx_count(void)
{
    if (!rep_state.initialized) return -1;
    pthread_mutex_lock(&rep_state.lock);
    int len = tx_history_len(&rep_state.history);
    pthread_mutex_unlock(&rep_state.lock);
    return len;
}

void reputation_get_window_root(char *out)
{
    if (!rep_state.initialized)
    {
        out[0] = '\0';
        return;
    }
    pthread_mutex_lock(&rep_state.lock);
    transaction_window_root(&rep_state.history, out);
    pthread_mutex_unlock(&rep_state.lock);
}

void reputation_get_checkpoint_root(char *out)
{
    if (!rep_state.initialized)
    {
        out[0] = '\0';
        return;
    }
    pthread_mutex_lock(&rep_state.lock);
    if (rep_state.checkpoint_set)
    {
        strncpy(out, rep_state.checkpoint_root, TX_HASH_HEX_LEN);
        out[TX_HASH_HEX_LEN] = '\0';
    }
    else
    {
        out[0] = '\0';
    }
    pthread_mutex_unlock(&rep_state.lock);
}

int reputation_get_evidence_doc(json_t **out)
{
    if (out == NULL) return -1;
    *out = NULL;
    if (!rep_state.initialized) return -1;
    rep_checkpoint_t ckpt;
    if (rep_checkpoint_init(&ckpt) != 0) return -1;
    pthread_mutex_lock(&rep_state.lock);
    /* The PRIMARY chain's document — what the corpus pins. A gateway's child
     * chains each have their own file; those are exercised by the unit tests
     * rather than the scenario snapshot. */
    _current_checkpoint_locked("", &ckpt);
    int err = reputation_evidence_to_json(&rep_state.history, &ckpt, out);
    pthread_mutex_unlock(&rep_state.lock);
    rep_checkpoint_free(&ckpt);
    return err;
}

int reputation_get_evidence_ceiling(const uuid_t self_uuid,
                                    const uuid_t peer_uuid, double *out)
{
    if (out == NULL || !rep_state.initialized) return -1;
    /* Self is excluded, as it is in production and in the Python twin: our own
     * score is not a peer judgement. */
    char self_key[UUID_STRING_LEN + 1];
    uuid_unparse_lower(self_uuid, self_key);
    /* Bound over the RESIDENT window, treating it as the attested one: the
     * assertion is about the arithmetic, and a scenario that has not run a
     * checkpoint round has no attested subrange to name. */
    rep_checkpoint_t ckpt;
    if (rep_checkpoint_init(&ckpt) != 0) return -1;
    map_t ceilings;
    if (map_init(&ceilings) != 0)
    {
        rep_checkpoint_free(&ckpt);
        return -1;
    }
    pthread_mutex_lock(&rep_state.lock);
    ckpt.present = true;
    ckpt.count = rep_state.history.committed_count;
    ckpt.first_index = (ckpt.count > 0) ? rep_state.history.first_index
                                        : rep_state.history.next_index;
    int err = reputation_evidence_ceilings(&rep_state.history, &ckpt, self_key,
                                           &ceilings);
    pthread_mutex_unlock(&rep_state.lock);
    if (err == 0)
    {
        char key[UUID_STRING_LEN + 1];
        uuid_unparse_lower(peer_uuid, key);
        data_t *d = NULL;
        if (map_get(&ceilings, (map_key_t)key, &d) == 0 && d != NULL)
            err = data_floating_pt_dbl(d, out);
        else
            err = -1;
    }
    map_free(&ceilings);
    rep_checkpoint_free(&ckpt);
    return err;
}

int reputation_get_request_count(void)
{
    if (!rep_state.initialized) return -1;
    pthread_mutex_lock(&rep_state.lock);
    int count = (int)array_size(&rep_state.paxos.granted_ids);
    pthread_mutex_unlock(&rep_state.lock);
    return count;
}

int64_t reputation_get_last_id(void)
{
    if (!rep_state.initialized) return 0;
    pthread_mutex_lock(&rep_state.lock);
    int64_t id = rep_state.paxos.last_id;
    pthread_mutex_unlock(&rep_state.lock);
    return id;
}

void reputation_install_tx_pair(const uuid_t task_uuid,
                                const uuid_t p1_uuid, double p1_score,
                                const uuid_t p2_uuid, double p2_score)
{
    _ensure_init();
    pthread_mutex_lock(&rep_state.lock);
    tx_history_update(&rep_state.history, task_uuid, p1_uuid, p1_score);
    tx_history_update(&rep_state.history, task_uuid, p2_uuid, p2_score);
    pthread_mutex_unlock(&rep_state.lock);
}

void reputation_install_peer_reputation(const uuid_t peer_uuid, double score)
{
    _ensure_init();
    pthread_mutex_lock(&rep_state.lock);
    reputations_update(&rep_state.reputations, peer_uuid, score);
    pthread_mutex_unlock(&rep_state.lock);
}

void reputation_install_coop_mode(const uuid_t peer_uuid, bool in_coop)
{
    _ensure_init();
    char key[UUID_STRING_LEN + 1] = {0};
    uuid_unparse_lower(peer_uuid, key);
    pthread_mutex_lock(&rep_state.lock);
    map_set(&rep_state.coop_mode, key, integer_data(in_coop ? 1 : 0));
    pthread_mutex_unlock(&rep_state.lock);
}

void reputation_install_checkpoint(const char *root, int64_t epoch)
{
    _ensure_init();
    pthread_mutex_lock(&rep_state.lock);
    if (root != NULL && root[0] != '\0')
    {
        /* Seed the PRIMARY chain's slot, not just the flat mirror: slash
         * evidence is verified against the finalized slots (any chain's root
         * may anchor it since §10.2), so a fixture that only wrote the mirror
         * would leave the evidence unverifiable. */
        rep_chain_ckpt_t *slot = _ckpt_slot_locked("");
        if (slot != NULL)
        {
            snprintf(slot->root, sizeof(slot->root), "%s", root);
            slot->epoch = epoch;
            slot->set = true;
        }
        _mirror_primary_ckpt_locked();
    }
    pthread_mutex_unlock(&rep_state.lock);
}

int reputation_get_peer_reputation(const uuid_t peer_uuid, double *out)
{
    if (!rep_state.initialized || out == NULL) return -1;
    pthread_mutex_lock(&rep_state.lock);
    int rc = reputations_get(&rep_state.reputations, peer_uuid, out);
    pthread_mutex_unlock(&rep_state.lock);
    return rc == 0 ? 0 : -1;
}

/* Frama-C: skipped — [solver-timeout] state-cascade through paxos_init +
 * process_register_handler stubs prevents WP from discharging
 * valid_rw(proc) and valid_rd(signal) at downstream call sites */
/* Resolve this node's own identity UUID from the loaded "identity" config.
 * Same access path net_proc.c:1495 and zta_process.c:750 use — proc->configs
 * carries the identity config for every process, so the long-standing
 * "process doesn't carry self identity" comments above are obsolete. Returns
 * true and fills out_uuid on success; false if identity isn't resolvable yet. */
static bool _resolve_self_uuid(const process_t *proc, uuid_t out_uuid)
{
    if (proc == NULL || proc->configs == NULL)
        return false;
    data_t *id_dat = NULL;
    char id_key[] = "identity";
    if (map_get(proc->configs, id_key, &id_dat) != 0 || id_dat == NULL)
        return false;
    config_t *id_cfg = NULL;
    if (data_object_ptr(id_dat, (void **)&id_cfg) != 0 || id_cfg == NULL
        || id_cfg->data_struct == NULL)
        return false;
    const identity_t *self = (const identity_t *)id_cfg->data_struct;
    uuid_copy(out_uuid, self->uuid);
    return true;
}

/* Handle a locally-submitted TransactionScore. Another process on this node
 * (e.g. the data-source's producer-side dod.sensor-report score) posts a
 * TRANSACTION_SCORE generic message to our queue; we are the proposer, so we
 * start a Paxos round under our own identity. Mirrors Python automate.py
 * putting a TransactionScore on the reputation queue → repprocess._start_paxos.
 *
 * The generic run_message_handlers cannot dispatch this — it only routes
 * net_msg payloads by function name — which is why such messages were silently
 * dropped before (and _forward_transaction was dead code).
 *
 * Only real (non-zero task_uuid) scores are forwarded. A zero task_uuid is the
 * legacy ZTA/config "system score" sentinel (zta_process.c:124) whose bilateral
 * semantics are out of scope here; it stays a no-op, unchanged from before. */
static void _handle_local_tx_score(const process_t *proc,
                                   const generic_msg_t *msg,
                                   const uuid_t self_uuid, bool have_self)
{
    const tx_score_msg_t *ts = &msg->info.tx_score;
    uuid_t zero;
    uuid_clear(zero);
    if (uuid_compare(ts->task_uuid, zero) == 0)
    {
        log_debug(proc->logger,
                  "Reputation: ignoring system TRANSACTION_SCORE (zero task)\n");
        return;
    }
    if (!have_self)
    {
        log_warn(proc->logger,
                 "Reputation: dropping local score — self identity unavailable\n");
        return;
    }
    /* §11.2: a LOCAL submitter off the scale is a bug in that submitter, so it is
     * refused here too rather than forwarded into a Paxos round. The Python twin
     * raises ValueError at this point (TransactionScore's constructor); C has no
     * exception to raise into an app, so it logs and drops. */
    if (!tx_score_in_range(ts->score))
    {
        log_warn(proc->logger,
                 "Reputation: dropping local TRANSACTION_SCORE: score %f is off "
                 "the [%g, %g] scale\n", ts->score, TX_SCORE_MIN, TX_SCORE_MAX);
        return;
    }
    _forward_transaction(proc, ts->task_uuid, self_uuid, ts->score,
                         ts->capability_name);
}

int reputation_run(process_t *proc, directory_t *queues, queue_id_t signal, logger_t *logger)
{
    _ensure_init();

    peers_read_lock(proc);
    rep_state.num_peers = (int)proc->protocol.num_peers;
    peers_read_unlock(proc);
    paxos_init(&rep_state.paxos, rep_state.num_peers, logger);

    reputation_register_handlers(proc);
    proc->protocol.phase = 1;

    /* Custom loop (mirrors data_source_run): intercept locally-submitted
     * TRANSACTION_SCORE messages and start a Paxos round for them; everything
     * else flows through the registered net_msg handlers exactly as
     * process_loop would. Without this, a node could only participate in
     * transactions other peers initiate, never propose its own. */
    process_ctx_t ctx = {0};
    int err = process_setup(proc, signal, logger, &ctx);
    if (err != 0)
        return err;

    uuid_t self_uuid;
    bool have_self = _resolve_self_uuid(proc, self_uuid);
    char self_str[UUID_STRING_LEN + 1] = {0};
    if (have_self)
        uuid_unparse_lower(self_uuid, self_str);

    /* Warm start, in the order the pieces depend on each other: load the
     * persisted operational snapshot, fade it by the gap we spent out of
     * contact, then adopt the persisted history if its checkpoint verifies and
     * clamp every score the evidence does not bear out. See ISSUES.md §10.3 and
     * doc/architecture/reputation.md. */
    _load_reputations(proc);
    _seed_idle_from_snapshot(proc, have_self ? self_str : NULL);
    _rebuild_from_evidence(proc, have_self ? self_str : NULL);

    while (keep_running(proc, &ctx.sig_q, logger))
    {
        sleep_until(proc, cadence);

        /* Periodic work, throttled internally: relax idle peers toward
         * almost-neutral, commit to our own window so the persisted evidence
         * carries a quorum-signed root, and keep the snapshot current. */
        double present = (double)time(NULL);
        /* Expire deep-resolution state. A relayed query whose subtree never
         * answers is the ordinary case, not an error, and this is the only
         * thing that clears it. Mirrors Python's call in process(). */
        _prune_resolve_state(proc);
        _decay_reputations(proc, present);
        if (!have_self)
        {
            have_self = _resolve_self_uuid(proc, self_uuid);
            if (have_self)
                uuid_unparse_lower(self_uuid, self_str);
        }
        _maybe_checkpoint(proc, present, have_self ? self_str : NULL);
        /* A gateway's child groups arrive over IPC (CHILD_GROUP) after this
         * process was constructed, so their persisted evidence is restored
         * here rather than at boot. Idempotent per group. */
        if (proc->protocol.child_groups != NULL)
            _restore_child_evidence(proc, have_self ? self_str : NULL);

        generic_msg_t buf = {0};
        int rerr = messaging_recv(&buf);
        if (rerr == -1 || rerr == ENOMSG)
            continue;

        if (buf.type == TRANSACTION_SCORE)
        {
            /* Self identity may not have been loaded at startup; resolve
             * lazily on first use so an early submission isn't lost. */
            if (!have_self)
                have_self = _resolve_self_uuid(proc, self_uuid);
            _handle_local_tx_score(proc, &buf, self_uuid, have_self);
        }
        else
        {
            run_message_handlers(proc, queues, buf.type, &buf);
        }
    }

    /* Final flush on the way out, so a clean shutdown leaves a snapshot the
     * next start can warm-start from (mirrors Python's SIGTERM flush). The
     * evidence file is already current — it is rewritten at every checkpoint
     * store — so only the operational scores need saving here. */
    _persist_reputations(proc);

    array_free(queues);
    if (ctx.fd1 > 0)
        close(ctx.fd1);
    if (ctx.fd2 > 0)
        close(ctx.fd2);
    return 0;
}
DECLARE_PROCESS(reputation, rep_proc, reputation_run);
