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

/* Slash "reason" that lifts (rather than floors) a target: releases the
 * slash floor, restores the score to PREREP_NEUTRAL, and re-admits it.
 * Recovery is explicit-only. Mirror: Python SlashAttestation.REASON_REHABILITATE. */
#define REP_SLASH_REASON_REHABILITATE "rehabilitate"

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
char REP_PROTO_SLASH_PROPOSE[] = "slash propose";
char REP_PROTO_SLASH_SIGN[]    = "slash sign";
char REP_PROTO_SLASH_FINAL[]   = "slash final";
char REP_PROTO_CHECKPOINT_PROPOSE[] = "checkpoint propose";
char REP_PROTO_CHECKPOINT_SIGN[]    = "checkpoint sign";
char REP_PROTO_CHECKPOINT_FINAL[]   = "checkpoint final";

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
    map_t slash_sigs;     /* "target:epoch" -> integer_data(signer count) */
    map_t slash_pending;  /* "target:epoch" -> integer_data(floor x1000) */
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
    map_t checkpoint_sigs;     /* "proposer:epoch" -> integer_data(signer count) */
    map_t checkpoint_pending;  /* "proposer:epoch" -> string_data(root hex) */
    char  checkpoint_root[TX_HASH_HEX_LEN + 1];  /* latest finalized root */
    int64_t checkpoint_epoch;  /* epoch of the latest finalized checkpoint */
    bool  checkpoint_set;      /* a checkpoint has been finalized/stored */
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
        rep_state.num_updates = 3;  /* catch-up quorum; mirrors Python default */
        /* paxos_init is called in reputation_run after num_peers is known */
        rep_state.num_peers = 0;
        pthread_mutex_init(&rep_state.lock, NULL);
        rep_state.initialized = true;
    }
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
    const char *peer_uuid_str = json_string_value(j_peer_uuid);

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
    const char *peer_uuid_str = json_string_value(j_peer_uuid);
    const char *task_uuid_str = json_string_value(json_object_get(payload, "task_uuid"));
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
        if (have_task_uuid)
        {
            tx_history_update(&rep_state.history, task_uuid, peer_uuid, score);
        }
        else
        {
            tx_history_update(&rep_state.history, peer_uuid, peer_uuid, score);
        }
        paxos_advance_chain(&rep_state.paxos);
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
    if (task_uuid_str && uuid_parse(task_uuid_str, task_uuid) == 0)
    {
        tx_history_update(&rep_state.history, task_uuid, peer_uuid, score);
    }
    else
    {
        /* Same fallback handle_accepted uses when task_uuid is
         * missing: key the entry by peer_uuid. */
        tx_history_update(&rep_state.history, peer_uuid, peer_uuid, score);
    }
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
    pthread_mutex_lock(&rep_state.lock);
    bool root_ok = rep_state.checkpoint_set
        && (strncmp(root, rep_state.checkpoint_root, TX_HASH_HEX_LEN + 1) == 0);
    pthread_mutex_unlock(&rep_state.lock);
    if (!root_ok)
        return false;
    return tx_merkle_verify(leaf, steps, (int)n, root);
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
    pthread_mutex_lock(&rep_state.lock);
    map_set(&rep_state.slash_pending, (map_key_t)key,
            integer_data((int)(floor * 1000.0)));
    pthread_mutex_unlock(&rep_state.lock);

    /* Co-sign: emit slash_sign back to the proposer. */
    char self_str[UUID_STRING_LEN + 1];
    uuid_t self_uuid;
    uuid_clear(self_uuid);
    uuid_unparse_lower(self_uuid, self_str);
    json_t *sign_json = json_object();
    if (sign_json == NULL)
    {
        json_decref(payload);
        return true;
    }
    json_object_set_new(sign_json, "target_uuid", json_string(target_str));
    json_object_set_new(sign_json, "epoch", json_integer(epoch));
    json_object_set_new(sign_json, "signer_uuid", json_string(self_str));
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
    if (target_str == NULL)
    {
        json_decref(payload);
        return false;
    }
    char key[UUID_STRING_LEN + 32];
    snprintf(key, sizeof(key), "%s:%lld", target_str, (long long)epoch);

    pthread_mutex_lock(&rep_state.lock);
    int count = 0;
    data_t *cnt_d = NULL;
    if (map_get(&rep_state.slash_sigs, (map_key_t)key, &cnt_d) == 0
        && cnt_d != NULL)
        data_integer(cnt_d, &count);
    count += 1;
    map_set(&rep_state.slash_sigs, (map_key_t)key, integer_data(count));
    double floor = 0.0;
    int floor_milli = 0;
    data_t *fl_d = NULL;
    bool have_floor = (map_get(&rep_state.slash_pending, (map_key_t)key,
                               &fl_d) == 0 && fl_d != NULL);
    if (have_floor)
    {
        data_integer(fl_d, &floor_milli);
        floor = ((double)floor_milli) / 1000.0;
    }
    int quorum = rep_state.num_peers / 2;
    bool finalize = have_floor && count > quorum;
    pthread_mutex_unlock(&rep_state.lock);
    json_decref(payload);

    if (finalize)
    {
        json_t *final_json = json_object();
        if (final_json == NULL)
            return true;
        json_object_set_new(final_json, "target_uuid",
                            json_string(target_str));
        json_object_set_new(final_json, "floor_score", json_real(floor));
        json_object_set_new(final_json, "epoch", json_integer(epoch));
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
    if (proposer_str == NULL || root == NULL)
    {
        json_decref(payload);
        return false;
    }
    char key[UUID_STRING_LEN + 32];
    snprintf(key, sizeof(key), "%s:%lld", proposer_str, (long long)epoch);

    /* Consensus check: co-sign ONLY if our own committed window produces the
     * same Merkle root. Record the proposed root as pending either way so the
     * sign handler (driven by other nodes' co-signs in conformance) can
     * finalize the agreed value. */
    char mine[TX_HASH_HEX_LEN + 1];
    pthread_mutex_lock(&rep_state.lock);
    transaction_window_root(&rep_state.history, mine);
    map_set(&rep_state.checkpoint_pending, (map_key_t)key,
            string_data((string_t)root, strlen(root) + 1));
    pthread_mutex_unlock(&rep_state.lock);
    bool matches = (strncmp(mine, root, TX_HASH_HEX_LEN + 1) == 0);
    if (!matches)
    {
        log_debug(proc->logger,
                  "Reputation: checkpoint_propose window_root mismatch, declining\n");
        json_decref(payload);
        return true;
    }

    /* Co-sign: emit checkpoint_sign back to the proposer. */
    char self_str[UUID_STRING_LEN + 1];
    uuid_t self_uuid;
    uuid_clear(self_uuid);
    uuid_unparse_lower(self_uuid, self_str);
    json_t *sign_json = json_object();
    if (sign_json == NULL)
    {
        json_decref(payload);
        return true;
    }
    json_object_set_new(sign_json, "proposer_uuid", json_string(proposer_str));
    json_object_set_new(sign_json, "epoch", json_integer(epoch));
    json_object_set_new(sign_json, "signer_uuid", json_string(self_str));
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
    if (proposer_str == NULL)
    {
        json_decref(payload);
        return false;
    }
    char key[UUID_STRING_LEN + 32];
    snprintf(key, sizeof(key), "%s:%lld", proposer_str, (long long)epoch);

    pthread_mutex_lock(&rep_state.lock);
    int count = 0;
    data_t *cnt_d = NULL;
    if (map_get(&rep_state.checkpoint_sigs, (map_key_t)key, &cnt_d) == 0
        && cnt_d != NULL)
        data_integer(cnt_d, &count);
    count += 1;
    map_set(&rep_state.checkpoint_sigs, (map_key_t)key, integer_data(count));
    char root[TX_HASH_HEX_LEN + 1] = {0};
    data_t *root_d = NULL;
    bool have_root = (map_get(&rep_state.checkpoint_pending, (map_key_t)key,
                              &root_d) == 0 && root_d != NULL);
    if (have_root)
        data_string(root_d, root, sizeof(root));
    int quorum = rep_state.num_peers / 2;
    bool finalize = have_root && count > quorum;
    pthread_mutex_unlock(&rep_state.lock);
    json_decref(payload);

    if (finalize)
    {
        json_t *final_json = json_object();
        if (final_json == NULL)
            return true;
        json_object_set_new(final_json, "proposer_uuid",
                            json_string(proposer_str));
        json_object_set_new(final_json, "root", json_string(root));
        json_object_set_new(final_json, "epoch", json_integer(epoch));
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
    if (root == NULL)
    {
        json_decref(payload);
        return false;
    }
    pthread_mutex_lock(&rep_state.lock);
    strncpy(rep_state.checkpoint_root, root, TX_HASH_HEX_LEN);
    rep_state.checkpoint_root[TX_HASH_HEX_LEN] = '\0';
    rep_state.checkpoint_epoch = epoch;
    rep_state.checkpoint_set = true;
    pthread_mutex_unlock(&rep_state.lock);
    log_info(proc->logger, "Reputation: checkpoint stored epoch=%lld root=%.12s\n",
             (long long)epoch, root);
    json_decref(payload);
    return true;
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
    process_register_handler(proc, REP_PROTO_SLASH_PROPOSE, (handler_ptr_t)handle_slash_propose);
    process_register_handler(proc, REP_PROTO_SLASH_SIGN,    (handler_ptr_t)handle_slash_sign);
    process_register_handler(proc, REP_PROTO_SLASH_FINAL,   (handler_ptr_t)handle_slash_final);
    process_register_handler(proc, REP_PROTO_CHECKPOINT_PROPOSE, (handler_ptr_t)handle_checkpoint_propose);
    process_register_handler(proc, REP_PROTO_CHECKPOINT_SIGN,    (handler_ptr_t)handle_checkpoint_sign);
    process_register_handler(proc, REP_PROTO_CHECKPOINT_FINAL,   (handler_ptr_t)handle_checkpoint_final);
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
        strncpy(rep_state.checkpoint_root, root, TX_HASH_HEX_LEN);
        rep_state.checkpoint_root[TX_HASH_HEX_LEN] = '\0';
        rep_state.checkpoint_epoch = epoch;
        rep_state.checkpoint_set = true;
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

    while (keep_running(proc, &ctx.sig_q, logger))
    {
        sleep_until(proc, cadence);

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

    array_free(queues);
    if (ctx.fd1 > 0)
        close(ctx.fd1);
    if (ctx.fd2 > 0)
        close(ctx.fd2);
    return 0;
}
DECLARE_PROCESS(reputation, rep_proc, reputation_run);
