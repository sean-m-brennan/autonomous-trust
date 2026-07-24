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

#define _GNU_SOURCE
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <dirent.h>
#include <pthread.h>
#include <sodium.h>

#include "processes/processes.h"
#include "structures/map.h"
#include "utilities/message.h"
#include "utilities/msg_types_priv.h"
#include "utilities/exception.h"
#include "utilities/probes.h"
#include "utilities/timeout.h"
#include "structures/data.h"
#include "network/net_message.h"
#include "config/configuration.h"
#include "peers.h"
#include "history.h"
#include "identity_priv.h"
#include "id_proc_priv.h"
#include "utilities/b64.h"

#ifdef AT_ZTA_ENABLED
#include "zta/zta_policy.h"
#include "zta/zta_verifier.h"
#include "zta/zta_audit.h"
#endif

/* Operator-attended signal helpers (ethne D8/Q9); defined below _build_announcement
 * but used earlier in handle_welcoming_committee. */
static json_t *_operator_attestation_json(const public_identity_t *pub);
static void _apply_operator_attestation_json(const json_t *att, public_identity_t *pub);
#ifdef AT_ZTA_ENABLED
static bool _is_operator_credential(const zta_policy_t *policy,
                                    const uint8_t *cred, size_t cred_len,
                                    const uint8_t *advertised_hash);
#endif

DEFINE_ERROR(EID_NOQ, "Required process queue missing");

#define MAJORITY(n) (((n) / 2) + 1)

/****************************
 * Protocol function names (must match Python IdentityProtocol)
 ****************************/

static char ID_ANNOUNCE[]    = "request_access";
static char ID_ACCEPT[]      = "access_granted";
static char ID_HISTORY[]     = "full_history";
static char ID_DIFF[]        = "history_diff";
static char ID_PROPOSE[]     = "propose_peer";
static char ID_VOTE[]        = "vote_on_peer";
static char ID_CONFIRM[]     = "peer_accepted";
static char ID_UPDATE[]      = "group_key_update";
static char ID_CAPS_QUERY[]  = "peer_caps_query";
static char ID_CAPS_RESPONSE[] = "peer_caps_response";
/* Identity backfill for a cold/late joiner that holds a group member's
 * address but never received its full Identity (merge/partition path fills
 * group.address_map but peers[] stays sparse). See identity_periodic_identity
 * _resync + dod-coordinator-partition-nonconvergence.md (layer 3). */
static char ID_IDENTITY_QUERY[]    = "peer_identity_query";
static char ID_IDENTITY_RESPONSE[] = "peer_identity_response";
/* Local-only IPC from ReputationProcess (no wire egress). Payload is a
 * 2-element JSON array `[peer_uuid_str, new_tier_int]`. Mirrors
 * Python IdentityProtocol.tier_update. */
static char ID_TIER[]        = "tier_update";
/* Group partition recovery (doc/architecture/partition-recovery.md).
 *   ID_PARTITION_SIGNAL: local-only IPC from NetProcess when group-channel
 *                        traffic is rejected (no wire egress). Payload is
 *                        the from_addr string.
 *   ID_PARTITION_PROBE / ID_PARTITION_RESPONSE: wire-facing, sent on the
 *                        unsecured-broadcast channel. Encrypt=false in
 *                        the outbound Message; receivers verify the
 *                        embedded identity signature themselves.
 * Mirrors Python IdentityProtocol.partition_{signal,probe,response}. */
static char ID_PARTITION_SIGNAL[]   = "partition_signal";
static char ID_PARTITION_PROBE[]    = "group_partition_probe";
static char ID_PARTITION_RESPONSE[] = "group_partition_response";
/* Subtree member-roster enumeration (hierarchy-aware membership). A node asks
 * a gateway to enumerate its subtree; the gateway replies with its LOCAL
 * members plus the child gateways to recurse into, and the requestor
 * aggregates breadth-first (identity_aggregate_subtree_roster). Mirrors
 * Python IdentityProtocol.roster_req / roster_resp. See
 * doc/architecture/gateway-reputation-tree.md. */
static char ID_ROSTER_QUERY[]    = "subtree_roster_query";
static char ID_ROSTER_RESPONSE[] = "subtree_roster_response";

/****************************
 * Process state (file-scope static, thread-safe via mutex)
 ****************************/

static struct {
    array_t histories;
    map_t peer_potentials;
    map_t vote_collection;
    bool choosing_group;
    /* Group-merge tracking — mirrors Python's self.self_bootstrapped
     * and self.merging in idprocess.py:126-127. Set when choose_group's
     * self-bootstrap fallback fires (no histories arrived in time);
     * cleared after _merge_to_mesh adopts a real mesh. `merging` is
     * the re-entry guard for the merge helper. See BUGS.md §P1. */
    bool self_bootstrapped;
    bool merging;
    pthread_mutex_t lock;
    bool initialized;
    /* Test-only: when true, paths that would normally defer work to
     * background threads (vote-collection finalize, choose_group) run
     * inline so the conformance harness can observe a deterministic
     * cascade. Mirrors Python's IdentityProcess.synchronous_dispatch.
     * In this mode the protocol also emits propose_peer / peer_accepted
     * as a single broadcast (zero-to_whom) instead of per-peer fanout
     * so that bg-only scenarios still see one outbound for each. */
    bool synchronous_dispatch;
    /* Test-installed per-process own-capability allowlist used by
     * handle_caps_query to populate its outgoing caps_response payload.
     * Keyed by process_t* (formatted "%p"); values are array_t* of
     * heap-dup'd capability-name strings. Mirrors neg_state.own_caps_by_proc.
     * Production code MUST NOT touch this. */
    map_t own_caps_by_proc;
    /* Peer capabilities recorded by handle_caps_response. Keyed by
     * lowercased uuid string; values are array_t* of cap-name strings.
     * Conformance assertion surface via identity_get_peer_caps_count. */
    map_t peer_caps_map;
    /* Optional per-capability descriptors learned from the descriptor form
     * of caps_response (PIV_MFA_OPERATOR_ACCESS_PLAN.md §3.5). Keyed by
     * capability NAME (not peer uuid — a descriptor is a property of the
     * capability); values are JSON-string data of the size-bounded
     * descriptor object {required_tier, description, kind, arg_schema}
     * (name excluded; caller keys by it). Mirrors Python's runtime-only
     * PeerCapabilities.descriptors. Conformance assertion surface via
     * identity_get_peer_cap_descriptor. */
    map_t peer_cap_descriptors_map;
    /* Reputation-derived per-peer trust tier. Keyed by lowercased uuid
     * string; values are int data. Written by handle_tier_update on
     * local IPC from ReputationProcess. Mirrors Python's per-peer
     * `peer._tier` mutation in idprocess.py. Distinct from topology
     * rank (agreement_voter_t::rank / identity_t::rank) which is
     * loaded statically from identity.json — see
     * doc/architecture/trust-tiers.md §1 for the disambiguation. */
    map_t peer_tiers;
    /* Self trust-tier mirror updated when handle_tier_update's payload
     * targets the local identity uuid. Default 0; reads are unlocked
     * since the field is a single int and writes are mutex-guarded. */
    int self_tier;
    /* Per-process identity history (Python's `self._history`). Lazy-
     * initialized by _ensure_history(proc) the first time a path needs
     * the local DAG — _peer_accepted's `steps` slot in the wire
     * payload, _merge_to_mesh's ingest of inbound steps, etc. Selection
     * mirrors Python's idprocess.py:100-110: read `identity.block` and
     * call the matching `identity_history_by_*_create`. NULL until
     * first use. */
    identity_history_t *history;
    /* Group partition recovery state (doc/architecture/partition-recovery.md).
     * Mirrors Python's idprocess.py:_partition_probe_cooldown /
     * _partition_response_cooldown / _partition_recovery_in_progress.
     *   partition_probe_cooldown:   key=from_addr string,
     *                                val=int64_t epoch_us (CLOCK_MONOTONIC)
     *   partition_response_cooldown: key=probing peer uuid hex,
     *                                val=int64_t epoch_us
     *   partition_recovery_target:   the foreign group_uuid we asked
     *                                request_access from; empty when no
     *                                recovery is in flight.
     *   partition_recovery_started_us: monotonic-epoch timestamp; 0 when
     *                                no recovery is in flight. The 15s
     *                                lockout window is enforced
     *                                independently in the handlers. */
    map_t partition_probe_cooldown;
    map_t partition_response_cooldown;
    /* Two-phase admission (ISSUES.md §3.1-a). Key "<proc>|<peer_uuid>",
     * value array_t* of DISTINCT confirmer uuid strings. A peer stays
     * PROVISIONAL (group key withheld in _add_peer) until the entry reaches
     * proc->protocol.admission_quorum, then handle_confirm_peer promotes it
     * and clears the entry. Mirrors Python's _provisional_confirmations. */
    map_t provisional_confirmations;
    char partition_recovery_target[64];
    int64_t partition_recovery_started_us;
} id_state;

static void _ensure_id_init(void)
{
    if (!id_state.initialized)
    {
        array_init(&id_state.histories);
        map_init(&id_state.peer_potentials);
        map_init(&id_state.vote_collection);
        map_init(&id_state.own_caps_by_proc);
        map_init(&id_state.peer_caps_map);
        map_init(&id_state.peer_cap_descriptors_map);
        map_init(&id_state.peer_tiers);
        map_init(&id_state.partition_probe_cooldown);
        map_init(&id_state.partition_response_cooldown);
        map_init(&id_state.provisional_confirmations);
        id_state.partition_recovery_target[0] = '\0';
        id_state.partition_recovery_started_us = 0;
        id_state.self_tier = 0;
        id_state.choosing_group = false;
        id_state.self_bootstrapped = false;
        id_state.merging = false;
        pthread_mutex_init(&id_state.lock, NULL);
        id_state.initialized = true;
    }
}

/* Resolve the configured identity from proc->configs and call the
 * matching identity_history_by_*_create. Caller must hold id_state.lock.
 * Returns the cached history if already built, NULL on failure to
 * resolve config or construct. Mirrors Python's idprocess.py:100-110
 * (the `_history` field selection in IdentityProcess.__init__).
 *
 * peers_t* is passed as NULL — the local process peer list lives in
 * proc->protocol.peers (a flat array), and identity_history_t's peers
 * field is only consulted by verify_object's voter lookup; the wire-
 * payload paths (recite, ingest, merge) don't touch it. */
static identity_history_t *_ensure_history_locked(const process_t *proc)
{
    if (id_state.history != NULL)
        return id_state.history;
    if (proc == NULL || proc->configs == NULL)
        return NULL;

    data_t *id_dat = NULL;
    char id_key[] = "identity";
    if (map_get(proc->configs, id_key, &id_dat) != 0 || id_dat == NULL)
        return NULL;
    config_t *id_cfg = NULL;
    if (data_object_ptr(id_dat, (void **)&id_cfg) != 0 ||
        id_cfg == NULL || id_cfg->data_struct == NULL)
        return NULL;
    identity_t *self_id = (identity_t *)id_cfg->data_struct;
    public_identity_t *self_pub = NULL;
    if (identity_publish(self_id, &self_pub) != 0 || self_pub == NULL)
        return NULL;

    /* Construct history matching self_id->block. The threshold/
     * difficulty arguments use the cross-impl defaults — POA threshold
     * derives at vote-time (sentinel -1), POW uses POW_DEFAULT_DIFFICULTY.
     * Stake doesn't get a reputation_fn here; the C identity_history
     * stake path doesn't yet read one. */
    identity_history_t *h = NULL;
    int err = -1;
    switch (self_id->block) {
        case POA:
            err = identity_history_by_authority_create(self_pub, NULL,
                                                       proc->logger, 0,
                                                       AUTHORITY_THRESHOLD_DERIVE,
                                                       &h);
            break;
        case POS:
            err = identity_history_by_stake_create(self_pub, NULL,
                                                   proc->logger, 0,
                                                   NULL, &h);
            break;
        case POW:
        default:
            err = identity_history_by_work_create(self_pub, NULL,
                                                  proc->logger, 0,
                                                  POW_DEFAULT_DIFFICULTY, &h);
            break;
    }
    smrt_deref(self_pub);

    if (err != 0 || h == NULL)
        return NULL;
    id_state.history = h;
    return h;
}

static void _id_proc_key(const process_t *proc, char *out, size_t n)
{
    snprintf(out, n, "%p", (const void *)proc);
}

/* Look up the test-installed own-caps array for a process. Returns the
 * array_t* of heap-dup'd cap-name strings, or NULL if no override is
 * installed. Caller does NOT hold id_state.lock; this function acquires
 * it for the lookup and releases before returning the pointer. The
 * array contents are stable for the lifetime of the install (the test
 * harness owns lifecycle). */
static array_t *_id_own_caps_for(const process_t *proc)
{
    if (proc == NULL) return NULL;
    char key[32]; _id_proc_key(proc, key, sizeof(key));
    pthread_mutex_lock(&id_state.lock);
    data_t *dat = NULL;
    array_t *arr = NULL;
    if (map_get(&id_state.own_caps_by_proc, key, &dat) == 0 && dat != NULL)
        data_object_ptr(dat, (ptr_t *)&arr);
    pthread_mutex_unlock(&id_state.lock);
    return arr;
}

void identity_set_own_capabilities(const process_t *proc,
                                   const char *const *cap_names,
                                   size_t n_caps)
{
    _ensure_id_init();
    char key[32]; _id_proc_key(proc, key, sizeof(key));
    pthread_mutex_lock(&id_state.lock);
    if (cap_names == NULL || n_caps == 0)
    {
        map_remove(&id_state.own_caps_by_proc, key);
        pthread_mutex_unlock(&id_state.lock);
        return;
    }
    array_t *arr = NULL;
    if (array_create(&arr) != 0 || arr == NULL)
    {
        pthread_mutex_unlock(&id_state.lock);
        return;
    }
    for (size_t i = 0; i < n_caps; i++)
    {
        if (cap_names[i] == NULL) continue;
        size_t len = strlen(cap_names[i]);
        char *dup = smrt_create(len + 1);
        if (dup == NULL) continue;
        memcpy(dup, cap_names[i], len + 1);
        data_t *str_dat = string_data(dup, len + 1);
        if (str_dat == NULL) { smrt_deref(dup); continue; }
        array_append(arr, str_dat);
    }
    data_t *arr_dat = object_ptr_data(arr, sizeof(array_t));
    map_set(&id_state.own_caps_by_proc, key, arr_dat);
    pthread_mutex_unlock(&id_state.lock);
}

int identity_get_peer_caps_count(const uuid_t uuid)
{
    if (!id_state.initialized) return 0;
    char uuid_str[UUID_STRING_LEN + 1];
    uuid_unparse_lower(uuid, uuid_str);
    pthread_mutex_lock(&id_state.lock);
    data_t *dat = NULL;
    array_t *arr = NULL;
    if (map_get(&id_state.peer_caps_map, uuid_str, &dat) == 0 && dat != NULL)
        data_object_ptr(dat, (ptr_t *)&arr);
    int n = (arr != NULL) ? (int)array_size(arr) : 0;
    pthread_mutex_unlock(&id_state.lock);
    return n;
}

size_t identity_provisional_count(const process_t *proc)
{
    /* Two-phase admission observable (ISSUES.md §3.1-a): number of peers this
     * process is holding PROVISIONAL (confirm seen, quorum not yet met, group
     * key withheld). Counts provisional_confirmations keys prefixed "<proc>|".
     * Mirrors the Python adapter's provisional_peer_count. */
    if (!id_state.initialized || proc == NULL) return 0;
    char prefix[64];
    int plen = snprintf(prefix, sizeof(prefix), "%p|", (const void *)proc);
    if (plen <= 0) return 0;
    size_t n = 0;
    pthread_mutex_lock(&id_state.lock);
    array_t *keys = map_keys(&id_state.provisional_confirmations);  /* map-owned */
    if (keys != NULL) {
        for (size_t i = 0; i < array_size(keys); i++) {
            data_t *kd = NULL; char *k = NULL;
            if (array_get(keys, (int)i, &kd) == 0 && kd != NULL
                && data_string_ptr(kd, &k) == 0 && k != NULL
                && strncmp(k, prefix, (size_t)plen) == 0)
                n++;
        }
    }
    pthread_mutex_unlock(&id_state.lock);
    return n;
}

int identity_get_peer_cap_descriptor(const char *cap_name, char *buf, size_t buflen)
{
    if (!id_state.initialized || cap_name == NULL || buf == NULL || buflen == 0)
        return -1;
    pthread_mutex_lock(&id_state.lock);
    data_t *dat = NULL;
    int rc = -1;
    if (map_get(&id_state.peer_cap_descriptors_map, (map_key_t)cap_name, &dat) == 0
        && dat != NULL)
    {
        char *s = NULL;
        if (data_string_ptr(dat, &s) == 0 && s != NULL)
        {
            strncpy(buf, s, buflen - 1);
            buf[buflen - 1] = '\0';
            rc = 0;
        }
    }
    pthread_mutex_unlock(&id_state.lock);
    return rc;
}

void identity_install_peer_caps(const uuid_t uuid,
                                const char *const *caps, size_t n_caps)
{
    _ensure_id_init();
    array_t *arr = NULL;
    if (array_create(&arr) != 0 || arr == NULL)
        return;
    for (size_t i = 0; i < n_caps; i++) {
        if (caps[i] == NULL) continue;
        data_t *str_dat = string_data((char *)caps[i], strlen(caps[i]));
        if (str_dat != NULL)
            array_append(arr, str_dat);
    }
    char uuid_str[UUID_STRING_LEN + 1];
    uuid_unparse_lower(uuid, uuid_str);
    data_t *arr_dat = object_ptr_data(arr, sizeof(array_t));
    pthread_mutex_lock(&id_state.lock);
    map_set(&id_state.peer_caps_map, uuid_str, arr_dat);
    pthread_mutex_unlock(&id_state.lock);
}

/****************************
 * Internal helpers
 ****************************/

/* Frama-C: skipped — [solver-timeout] logging/map preconditions */
static int _remember_activity(const process_t *proc, directory_t *queues, generic_msg_t *msg)
{
    /* Update proc configs with latest data; broadcast to all other processes */
    size_t qsize = array_size(queues);
    for (size_t i = 0; i < qsize; i++)
    {
        data_t *name_val = NULL;
        if (array_get(queues, (int)i, &name_val) != 0)
            continue;
        char *qname = NULL;
        if (data_string_ptr(name_val, &qname) != 0)
            continue;
        if (strcmp(qname, proc->name) == 0)
            continue;
        messaging_send(qname, msg->type, msg, false);
    }
    return 0;
}

/****************************
 * Helper: _update_group
 * Phase-3 group churn — broadcast the current group state to all peers so
 * they converge on our address_map / group key. Mirrors Python's
 * `_update_group` (idprocess.py:598).
 *
 * Two emit modes (same shape as _peer_accepted's ID_CONFIRM fanout):
 *   - production: per-peer encrypted unicast.
 *   - synchronous_dispatch: a single broadcast (to_whom zeroed) so a
 *     bg-only conformance scenario sees one outbound regardless of
 *     peer count.
 *
 * The receive-side (handle_group_update) MUST apply the uuid tiebreaker
 * on equal-size address lists to prevent an ID_UPDATE ping-pong flood —
 * see the constraint block above handle_group_update and memory entry
 * `feedback_group_update_flood.md`.
 ****************************/

/* Frama-C: skipped — [solver-timeout] identity/peers/JSON preconditions */
static int _update_group(const process_t *proc, directory_t *queues)
{
    (void)queues; /* network emission uses messaging_send by queue name */

    if (id_state.synchronous_dispatch)
    {
        generic_msg_t update = {0};
        update.type = NET_MESSAGE;
        strncpy(update.info.net_msg.process, "identity", PROC_NAME_LEN);
        update.info.net_msg.function = ID_UPDATE;
        update.info.net_msg.encrypt = false;
        /* to_whom left zeroed → network layer broadcast */
        json_t *grp_json = NULL;
        if (group_to_json(&proc->protocol.group, &grp_json) != 0 || grp_json == NULL)
        {
            log_error(proc->logger, "Identity: group_to_json failed (update broadcast)\n");
            if (grp_json != NULL) json_decref(grp_json);
            return EXCEPTION(ENOMEM);
        }
        net_msg_pack_json(&update.info.net_msg, grp_json);
        json_decref(grp_json);
        messaging_send("network", NET_MESSAGE, &update, false);
        return 0;
    }

    peers_read_lock(proc);
    for (size_t i = 0; i < proc->protocol.num_peers; i++)
    {
        generic_msg_t update = {0};
        update.type = NET_MESSAGE;
        strncpy(update.info.net_msg.process, "identity", PROC_NAME_LEN);
        update.info.net_msg.function = ID_UPDATE;
        update.info.net_msg.encrypt = true;
        memcpy(&update.info.net_msg.to_whom, &proc->protocol.peers[i],
               sizeof(public_identity_t));
        json_t *grp_json = NULL;
        if (group_to_json(&proc->protocol.group, &grp_json) != 0 || grp_json == NULL)
        {
            log_error(proc->logger, "Identity: group_to_json failed (update fanout)\n");
            if (grp_json != NULL) json_decref(grp_json);
            continue;
        }
        net_msg_pack_json(&update.info.net_msg, grp_json);
        json_decref(grp_json);
        messaging_send("network", NET_MESSAGE, &update, false);
    }
    peers_read_unlock(proc);
    return 0;
}

/****************************
 * Helper: _add_peer
 * Adds a new peer to the process's peer list and broadcasts to local processes.
 * Then mirrors Python's `_add_peer` (idprocess.py:701) by recording the new
 * peer's address in the group map and emitting ID_UPDATE to existing peers.
 ****************************/

/* Helper: _confirm_group_membership — the CONFIRMED half of two-phase
 * admission (ISSUES.md §3.1-a). Records the peer's address in our group's
 * address_map and propagates the updated group (which carries the shared
 * private key) to existing peers. Split out of _add_peer so a PROVISIONAL
 * member can be tracked without the group key ever leaving this node until
 * the admission quorum is met. Mirrors Python _confirm_group_membership. */
/* Frama-C: skipped — [solver-timeout] group/messaging preconditions */
static void _confirm_group_membership(process_t *proc, directory_t *queues,
                                      const public_identity_t *new_peer)
{
    /* Phase-3 group churn — parity with Python's _add_peer (idprocess.py:705).
     * Record the new peer's address in our group's address_map, then broadcast
     * the updated group to existing peers via _update_group. The receive-side
     * tiebreaker prevents an ID_UPDATE ping-pong flood. */
    if (proc->protocol.group.address_map.items == NULL)
        map_init(&proc->protocol.group.address_map);
    char new_uuid_str[UUID_STRING_LEN + 1];
    uuid_unparse_lower(new_peer->uuid, new_uuid_str);
    if (group_add_address(&proc->protocol.group, new_uuid_str, (char *)new_peer->address) == 0)
    {
        /* Local-process broadcast of the updated group (Python: _record_group). */
        generic_msg_t group_msg = {0};
        group_msg.type = GROUP;
        memcpy(&group_msg.info.group, &proc->protocol.group, sizeof(group_t));
        _remember_activity(proc, queues, &group_msg);
        /* Push the updated group to our peers. */
        _update_group(proc, queues);
    }
}

/* Frama-C: skipped — [solver-timeout] logging/identity/peers preconditions */
static int _add_peer(process_t *proc, directory_t *queues,
                     const public_identity_t *new_peer, bool confirmed)
{
    peers_write_lock(proc);
    /* Idempotency: an amnesia path may revisit a peer already in the list
     * (Python's _peer_accepted threads an explicit amnesia flag to skip
     * the add; we instead detect duplicate UUIDs here). Without this guard
     * the list grows linearly on every re-admission. */
    for (size_t i = 0; i < proc->protocol.num_peers; i++) {
        if (uuid_compare(proc->protocol.peers[i].uuid, new_peer->uuid) == 0) {
            peers_write_unlock(proc);
            return 0;
        }
    }
    if (proc->protocol.num_peers >= MAX_PEERS)
    {
        peers_write_unlock(proc);
        return -1;
    }
    memcpy(&proc->protocol.peers[proc->protocol.num_peers],
           new_peer, sizeof(public_identity_t));
    proc->protocol.num_peers++;
    peers_write_unlock(proc);
    generic_msg_t peer_msg = {0};
    peer_msg.type = PEER;
    memcpy(&peer_msg.info.peer, new_peer, sizeof(public_identity_t));
    _remember_activity(proc, queues, &peer_msg);

    /* Two-phase admission (§3.1-a): propagate the group key only for a
     * CONFIRMED peer. A provisional add records the peer above (visibility /
     * reputation) but withholds the group key until the quorum is met. */
    if (confirmed)
        _confirm_group_membership(proc, queues, new_peer);
    return 0;
}

/****************************
 * Helper: _send_caps_query
 * Directed UDP-loss recovery — sends ID_CAPS_QUERY to a specific peer over
 * the network. Mirrors Python's `_send_caps_query` (idprocess.py:870).
 *
 * Used by `handle_confirm_peer` when the incoming peer's UUID is missing
 * from `id_state.peer_potentials` — i.e. their `announce` (UDP broadcast)
 * was lost, so we never populated their cap potentials, but the confirm
 * (group/TCP) arrived and we're about to admit them. Without this query,
 * the late joiner ends up in `peers[]` but absent from `peer_capabilities`,
 * invisible to cap-driven discovery (see memory feedback_late_joiner_caps).
 *
 * Encrypt=false: when the announce is lost we typically lack the peer's
 * crypto material, so we can't authenticated-encrypt to them. The peer's
 * `handle_caps_query` doesn't gate on encryption; the response back to us
 * (which has the encryptor key needed) is the encrypted leg. The caller
 * must populate `peer->address` for routing.
 ****************************/

/* Frama-C: skipped — [solver-timeout] identity/messaging preconditions */
static int _send_caps_query(const process_t *proc, const public_identity_t *peer)
{
    generic_msg_t query = {0};
    query.type = NET_MESSAGE;
    strncpy(query.info.net_msg.process, "identity", PROC_NAME_LEN);
    query.info.net_msg.function = ID_CAPS_QUERY;
    query.info.net_msg.encrypt = false;
    memcpy(&query.info.net_msg.to_whom, peer, sizeof(public_identity_t));
    strncpy(query.info.net_msg.return_to, "identity", PROC_NAME_LEN);
    messaging_send("network", NET_MESSAGE, &query, false);
    log_info(proc->logger,
             "Identity: sent caps_query to %s (UDP-loss recovery)\n",
             peer->nickname);
    return 0;
}

/****************************
 * Helper: _peer_accepted
 * Sends ID_CONFIRM to existing group members and ID_ACCEPT to the new peer,
 * then adds the peer to our list (which also triggers Phase-3 group churn
 * inside `_add_peer` — see the constraint block above `handle_group_update`
 * for the tiebreaker rule that prevents an ID_UPDATE flood).
 *
 * Confirm payload carries `{uuid, nickname, address}` so the receiver can
 * route a directed `caps_query` back to the new peer if its announce was
 * lost (UDP-loss recovery — see _send_caps_query).
 *
 * @p amnesia mirrors Python's `_peer_accepted(amnesia=True)` flag
 * (idprocess.py:488,515-522): when true, the peer is already in our
 * peers list (returned-peer / confirm-before-announce recovery case),
 * so we re-emit the confirm + accept + history broadcasts to refresh
 * the peer's view but skip the _add_peer call to avoid no-op churn
 * (and, more importantly, to avoid emitting a duplicate group update).
 ****************************/

/* Frama-C: skipped — [solver-timeout] identity/peers preconditions */
static int _peer_accepted(process_t *proc, directory_t *queues,
                          const public_identity_t *new_peer, int rank,
                          bool amnesia)
{
    /* Record the peer's topology rank (carried on the message envelope) for
     * rank-based child-gateway discovery — the live source that replaces the
     * rank C peers drop (public_identity_t has none). Kept current even on the
     * amnesia path. Only a known (non-zero) rank is stored; an absent/unknown
     * rank (0) reads back as the default and must not clobber a prior value.
     * Mirrors Python, whose peers carry _rank off the same envelope. */
    if (new_peer != NULL && rank != 0) {
        char ru[UUID_STRING_LEN + 1];
        uuid_unparse_lower(new_peer->uuid, ru);
        identity_set_peer_rank(proc, ru, rank);
    }

    /* Send ID_CONFIRM to existing group members with new_peer identity in JSON payload.
     *
     * Two modes:
     *  - production: per-peer encrypted unicast (C lacks the group-key
     *    broadcast Python uses, so the fanout is open-coded);
     *  - synchronous_dispatch: a single broadcast send (to_whom zeroed)
     *    so a bg-only conformance scenario sees one outbound regardless
     *    of peer count. Mirrors Python's `to_whom=self.group` semantics.
     */
    if (id_state.synchronous_dispatch)
    {
        generic_msg_t confirm = {0};
        confirm.type = NET_MESSAGE;
        strncpy(confirm.info.net_msg.process, "identity", PROC_NAME_LEN);
        confirm.info.net_msg.function = ID_CONFIRM;
        confirm.info.net_msg.encrypt = false;
        /* to_whom left zeroed → network layer broadcast */
        /* DRY canonical: full public-identity payload (incl. sig/enc pubkeys),
         * shared byte-shape with Python public_identity_to_canonical, so a
         * Python member can parse the confirm announcement. (Was a
         * {uuid,nickname,address} subset that dropped the public keys.) */
        json_t *peer_json = NULL;
        if (public_identity_to_json(new_peer, &peer_json) != 0 || peer_json == NULL) {
            log_error(proc->logger, "Identity: public_identity_to_json failed (confirm broadcast)\n");
            return EXCEPTION(ENOMEM);
        }
        net_msg_pack_json(&confirm.info.net_msg, peer_json);
        json_decref(peer_json);
        messaging_send("network", NET_MESSAGE, &confirm, false);
    }
    else
    {
        peers_read_lock(proc);
        for (size_t i = 0; i < proc->protocol.num_peers; i++)
        {
            generic_msg_t confirm = {0};
            confirm.type = NET_MESSAGE;
            strncpy(confirm.info.net_msg.process, "identity", PROC_NAME_LEN);
            confirm.info.net_msg.function = ID_CONFIRM;
            confirm.info.net_msg.encrypt = true;
            memcpy(&confirm.info.net_msg.to_whom, &proc->protocol.peers[i], sizeof(public_identity_t));
            /* DRY canonical full public-identity payload (see the broadcast
             * arm above) so a Python member can parse the confirm fanout. */
            json_t *peer_json = NULL;
            if (public_identity_to_json(new_peer, &peer_json) != 0 || peer_json == NULL) {
                log_error(proc->logger, "Identity: public_identity_to_json failed (confirm fanout)\n");
                continue;
            }
            net_msg_pack_json(&confirm.info.net_msg, peer_json);
            json_decref(peer_json);
            messaging_send("network", NET_MESSAGE, &confirm, false);
        }
        peers_read_unlock(proc);
    }
    /* Send ID_ACCEPT to the new peer */
    generic_msg_t accept = {0};
    accept.type = NET_MESSAGE;
    strncpy(accept.info.net_msg.process, "identity", PROC_NAME_LEN);
    accept.info.net_msg.function = ID_ACCEPT;
    accept.info.net_msg.encrypt = false;
    memcpy(&accept.info.net_msg.to_whom, new_peer, sizeof(public_identity_t));
    messaging_send("network", NET_MESSAGE, &accept, false);

    /* Send ID_HISTORY to the new peer so they can decrypt subsequent
     * group-encrypted traffic AND populate their peer list with our
     * existing admissions. The payload is a 3-element JSON array
     * [group_obj, [steps...], [peer_idents...]] matching Python's
     * `to_json_string((self.group, self._history.recite(),
     * [p.publish() for p in self.peers.all]))` (idprocess.py:507-510).
     *
     * The C identity process doesn't yet hold a per-process
     * identity_history_t (Python's `self._history` field), so the
     * `steps` slot ships as an empty array for now. The receive-side
     * (handle_receive_history → choose_group → _populate_peers_from_history)
     * tolerates that — the peers slot is what late-joiner sync
     * actually needs to work. When per-process identity_history_t
     * gets wired up, call dag_recite + linked_step_to_json here and
     * replace the empty array. */
    json_t *hist_arr = json_array();
    if (hist_arr != NULL)
    {
        /* Slot 0: group. */
        json_t *group_json = NULL;
        if (group_to_json(&proc->protocol.group, &group_json) == 0 &&
            group_json != NULL) {
            json_array_append_new(hist_arr, group_json);
        } else {
            json_array_append_new(hist_arr, json_null());
        }
        /* Slot 1: steps from the per-process identity history DAG.
         * dag_recite walks from the head of the main branch back to
         * root and yields the steps in insert order; each one becomes
         * a `{uuid, timestamp, payload(hex)}` JSON object via
         * linked_step_to_json. Mirrors Python's `self._history.recite()`
         * in idprocess.py:508. */
        json_t *steps_json = json_array();
        if (steps_json != NULL)
        {
            pthread_mutex_lock(&id_state.lock);
            identity_history_t *h = _ensure_history_locked(proc);
            if (h != NULL) {
                array_t *steps_arr = NULL;
                if (dag_recite(&h->dag, NULL, NULL, &steps_arr) == 0 &&
                    steps_arr != NULL) {
                    size_t n = array_size(steps_arr);
                    for (size_t i = 0; i < n; i++) {
                        data_t *s_dat = NULL;
                        if (array_get(steps_arr, (int)i, &s_dat) != 0 ||
                            s_dat == NULL)
                            continue;
                        ptr_t sptr = NULL;
                        if (data_object_ptr(s_dat, &sptr) != 0 || sptr == NULL)
                            continue;
                        json_t *step_json =
                            linked_step_to_json((const linked_step_t *)sptr);
                        if (step_json != NULL)
                            json_array_append_new(steps_json, step_json);
                    }
                    array_free(steps_arr);
                }
            }
            pthread_mutex_unlock(&id_state.lock);
            json_array_append_new(hist_arr, steps_json);
        } else {
            json_array_append_new(hist_arr, json_array());
        }
        /* Slot 2: peer-bundle. Iterate proc->protocol.peers[] and
         * publish each as a public-identity JSON object. */
        json_t *peers_json = json_array();
        if (peers_json != NULL)
        {
            peers_read_lock(proc);
            for (size_t i = 0; i < proc->protocol.num_peers; i++)
            {
                json_t *p_json = NULL;
                if (public_identity_to_json(&proc->protocol.peers[i], &p_json) == 0 &&
                    p_json != NULL)
                    json_array_append_new(peers_json, p_json);
            }
            peers_read_unlock(proc);
            json_array_append_new(hist_arr, peers_json);
        } else {
            json_array_append_new(hist_arr, json_array());
        }
    }

    generic_msg_t hist = {0};
    hist.type = NET_MESSAGE;
    strncpy(hist.info.net_msg.process, "identity", PROC_NAME_LEN);
    hist.info.net_msg.function = ID_HISTORY;
    hist.info.net_msg.encrypt = true;
    memcpy(&hist.info.net_msg.to_whom, new_peer, sizeof(public_identity_t));
    if (hist_arr != NULL)
    {
        net_msg_pack_json(&hist.info.net_msg, hist_arr);
        json_decref(hist_arr);
    }
    messaging_send("network", NET_MESSAGE, &hist, false);

    /* Skip _add_peer in the amnesia case — the peer is already in our
     * list and re-adding would emit a redundant group update. */
    if (amnesia)
        return 0;
    /* Welcomer path — post-finalize, so this admission is CONFIRMED. */
    return _add_peer(proc, queues, new_peer, true);
}

/****************************
 * Handler: welcoming_committee (request_access)
 * Phase 3 only. Receives broadcast from new peer wanting to join.
 ****************************/

/* Frama-C: skipped —
 * identity_run + all handlers + helpers: [solver-timeout] every function copies
 * public_identity_t structs (memcpy of struct→struct triggers WP "Hide sub-term
 * definition" cast warning that blocks discharge of valid_dest/valid_src/separation).
 * Helpers also touch filesystem/network/identity stubs.
 */
/*@
  requires \valid(proc);
  requires \valid(queues);
  requires \valid(msg);
  requires proc->logger == \null || \valid(proc->logger);
*/
static bool handle_welcoming_committee(const process_t *proc, directory_t *queues, generic_msg_t *msg)
{
    if (proc->protocol.phase != 3)
        return false;

    net_msg_t *nmsg = &msg->info.net_msg;
    log_info(proc->logger, "Identity: received access request from %s\n",
             nmsg->from_whom.nickname);

    /* Validate the new identity */
    if (nmsg->from_whom.nickname[0] == '\0')
    {
        log_warn(proc->logger, "Identity: rejecting empty identity\n");
        return true;
    }

    /* Check if already a peer.  If so, re-send access_granted in case the
     * peer restarted and lost its in-memory peer list (it still holds the
     * same identity/keys, but needs us to re-acknowledge it). */
    peers_read_lock(proc);
    bool already_known = false;
    for (size_t i = 0; i < proc->protocol.num_peers; i++)
    {
        if (uuid_compare(proc->protocol.peers[i].uuid, nmsg->from_whom.uuid) == 0)
        {
            already_known = true;
            break;
        }
    }
    peers_read_unlock(proc);
    if (already_known)
    {
        /* Amnesiac peer: re-run the full admission emission cycle
         * (peer_accepted to group + access_granted to peer + full_history)
         * so the returning peer recovers the same state it had before any
         * restart. Matches Python's _peer_accepted(amnesia=True). */
        log_info(proc->logger,
                 "Identity: peer %s already known (amnesia path)\n",
                 nmsg->from_whom.nickname);
        _peer_accepted((process_t *)proc, queues, &nmsg->from_whom,
                       nmsg->from_rank, true);
        return true;
    }

    /* Operator-attended signal (ethne D8/Q9): deliver any wire-carried
     * attestation (payload slot 2) onto from_whom — the ZTA credential is NOT
     * on the envelope, so this is what makes a real-wire credential available
     * to the gate below (the conformance harness attaches from_whom in-process,
     * so a missing payload is fine). Then neutralize the advertised
     * operator_bound: it is earned only by operator-anchor verification in the
     * ZTA block, never trusted from the wire. Mirrors Python
     * welcoming_committee's _apply_operator_attestation + _zta_admit entry. */
    {
        json_t *apayload = NULL;
        if (net_msg_unpack_json(nmsg, &apayload) == 0 && apayload != NULL) {
            if (json_is_array(apayload) && json_array_size(apayload) > 2)
                _apply_operator_attestation_json(json_array_get(apayload, 2),
                                                 &nmsg->from_whom);
            json_decref(apayload);
        }
        nmsg->from_whom.operator_bound = false;
    }

#ifdef AT_ZTA_ENABLED
    /* ZTA credential verification at admission */
    {
        /* Look up ZTA policy from configs. Values are object_ptr_data(config_t)
         * (load_all_configs), so unwrap data_t -> config_t -> data_struct,
         * exactly as the "identity" config is read above. (A prior direct
         * cast of the data_t wrapper to zta_policy_t* read garbage — the
         * policy fields landed on the data_t header.) */
        data_t *zta_dat = NULL;
        config_t *zta_cfg = NULL;
        zta_policy_t *zta_policy = NULL;
        char zta_key[] = "zta_policy";
        if (map_get(proc->configs, zta_key, &zta_dat) == 0 && zta_dat
            && data_object_ptr(zta_dat, (void **)&zta_cfg) == 0
            && zta_cfg != NULL && zta_cfg->data_struct != NULL)
            zta_policy = (zta_policy_t *)zta_cfg->data_struct;

        if (zta_policy && zta_policy->enabled && zta_policy->require_at_admission) {
            zta_verifier_t *verifier = NULL;
            int zrc = zta_policy_create_verifier(zta_policy, &verifier);
            if (zrc == 0 && verifier) {
                zta_result_t zta_result;
                /* Size guard BEFORE verify: an oversized credential is almost
                 * certainly hostile/corrupt and would let a remote cause an OOM
                 * / parse-time DoS. public_identity_sync_in already rejects this
                 * at protobuf deserialization (identity.c:ZTA_CRED_MAX), but the
                 * conformance harness attaches a live from_whom (no wire round-
                 * trip), so the bound is enforced here at the admission gate too,
                 * mirroring Python idprocess._zta_admit. Pinned by conformance
                 * zta-x509-reject-oversized-credential. Keep ZTA_CRED_MAX in
                 * lockstep with Python (identity/zta/zta_verifier.py). */
                if (nmsg->from_whom.zta_credential_len > ZTA_CRED_MAX) {
                    log_warn(proc->logger,
                             "Identity: ZTA credential too large for %s "
                             "(%zu > %u)\n", nmsg->from_whom.nickname,
                             nmsg->from_whom.zta_credential_len,
                             (unsigned)ZTA_CRED_MAX);
                    verifier->destroy(verifier);
                    return true; /* reject */
                }
                verifier->verify_credential(
                    verifier,
                    nmsg->from_whom.zta_credential,
                    nmsg->from_whom.zta_credential_len,
                    &zta_result);

                if (zta_result.status == ZTA_REJECTED || zta_result.status == ZTA_EXPIRED) {
                    log_warn(proc->logger,
                             "Identity: ZTA credential %s for %s: %s\n",
                             zta_status_str(zta_result.status),
                             nmsg->from_whom.nickname, zta_result.reason);
                    verifier->destroy(verifier);
                    return true; /* reject */
                }
                if (zta_result.status == ZTA_VERIFIED && verifier->check_revocation) {
                    /* A chain-valid certificate may nonetheless have been
                     * revoked. verify_credential only walks the chain + expiry
                     * (x509_verify_credential), so the admission gate must check
                     * revocation explicitly before admitting. Only an
                     * affirmative ZTA_REVOKED blocks: ZTA_UNAVAILABLE — the
                     * default when no CRL/OCSP source is configured — keeps the
                     * peer admitted, so deployments without a revocation source
                     * are unchanged. Mirrors Python idprocess._zta_admit; pinned
                     * by conformance zta-x509-reject-revoked-credential. */
                    zta_result_t rev_result;
                    verifier->check_revocation(verifier,
                                               zta_result.credential_hash,
                                               &rev_result);
                    if (rev_result.status == ZTA_REVOKED) {
                        log_warn(proc->logger,
                                 "Identity: ZTA credential %s for %s: %s\n",
                                 zta_status_str(rev_result.status),
                                 nmsg->from_whom.nickname, rev_result.reason);
                        verifier->destroy(verifier);
                        return true; /* reject */
                    }
                }
                if (zta_result.status == ZTA_VERIFIED) {
                    /* Peer credential verified against the mission anchor. Now
                     * classify operator-class against the DISTINCT operator
                     * anchor (ethne D8/Q9): only a credential that also
                     * chain-verifies there marks a human guardian. Overwrites
                     * the (neutralized) operator_bound with the verified truth,
                     * so a lying node's advertised claim never survives. */
                    if (_is_operator_credential(zta_policy,
                                                nmsg->from_whom.zta_credential,
                                                nmsg->from_whom.zta_credential_len,
                                                nmsg->from_whom.zta_credential_hash)) {
                        nmsg->from_whom.operator_bound = true;
                        log_info(proc->logger,
                                 "Identity: %s is operator-attended (human guardian)\n",
                                 nmsg->from_whom.nickname);
                    }
                }
                if (zta_result.status == ZTA_UNAVAILABLE || zta_result.status == ZTA_DEFERRED) {
                    if (!zta_policy->allow_ddil_fallback) {
                        log_warn(proc->logger,
                                 "Identity: ZTA unavailable, DDIL fallback disabled; rejecting %s\n",
                                 nmsg->from_whom.nickname);
                        verifier->destroy(verifier);
                        return true; /* reject */
                    }
                    log_info(proc->logger,
                             "Identity: ZTA verification deferred (DDIL) for %s\n",
                             nmsg->from_whom.nickname);
                }
                verifier->destroy(verifier);
            }
        }
    }
#endif

    /* Bootstrap: auto-accept when no existing peers (no one to vote).
     * Skipped in synchronous_dispatch (conformance) mode so the harness
     * still sees the canonical propose + vote + accept cascade — Python's
     * test path always proposes regardless of peer count. */
    peers_read_lock(proc);
    bool bootstrap = (proc->protocol.num_peers == 0);
    size_t snapshot_num_peers = proc->protocol.num_peers;
    peers_read_unlock(proc);
    if (bootstrap && !id_state.synchronous_dispatch)
    {
        log_info(proc->logger, "Identity: bootstrap — auto-accepting first peer %s\n",
                 nmsg->from_whom.nickname);
        _peer_accepted((process_t *)proc, queues, &nmsg->from_whom,
                       nmsg->from_rank, false);
        return true;
    }

    /* Store proposed peer in potentials and self-vote before sending proposals */
    char uuid_str[UUID_STRING_LEN + 1];
    uuid_unparse_lower(nmsg->from_whom.uuid, uuid_str);
    /* Capture the announced rank now, so a later majority-vote admission
     * (handle_count_vote, which adds from peer_potentials without a fresh
     * envelope) already has it for rank-based child-gateway discovery. Only a
     * known (non-zero) rank is stored (see _peer_accepted). */
    if (nmsg->from_rank != 0)
        identity_set_peer_rank((process_t *)proc, uuid_str, nmsg->from_rank);

    pthread_mutex_lock(&id_state.lock);
    public_identity_t *potential = smrt_create(sizeof(public_identity_t));
    if (potential != NULL)
    {
        memcpy(potential, &nmsg->from_whom, sizeof(public_identity_t));
        data_t *pot_dat = object_ptr_data(potential, sizeof(public_identity_t));
        map_set(&id_state.peer_potentials, uuid_str, pot_dat);
    }
    /* Proposer self-vote: count as 1 */
    data_t *self_vote = integer_data(1);
    map_set(&id_state.vote_collection, uuid_str, self_vote);
    pthread_mutex_unlock(&id_state.lock);

    /* Propose this peer to existing group members for voting.
     * Carry proposed peer identity in JSON payload (not from_whom)
     * because encrypted messages overwrite from_whom with the sender.
     *
     * synchronous_dispatch: emit ONE broadcast (zero to_whom) so the
     * harness sees a single propose_peer outbound regardless of peer
     * count. Production fans out one encrypted unicast per peer. */
    json_t *proposal_json = json_object();
    if (proposal_json == NULL) {
        log_error(proc->logger, "Identity: json_object OOM (propose_peer)\n");
        return true;
    }
    json_object_set_new(proposal_json, "uuid", json_string(uuid_str));
    json_object_set_new(proposal_json, "nickname", json_string(nmsg->from_whom.nickname));
    json_object_set_new(proposal_json, "address", json_string(nmsg->from_whom.address));
    /* Carry the candidate's signature/encryptor public keys so voters can
     * run the full Sybil collision check (uuid OR signature OR encryptor),
     * matching Python idprocess._process_id. The nested {"hex_seed": ...}
     * shape mirrors public_identity_to_json's wire format. */
    unsigned char *cand_sig_hex = signature_publish(&nmsg->from_whom.signature);
    if (cand_sig_hex != NULL) {
        json_t *cand_sig = json_object();
        if (cand_sig != NULL) {
            json_object_set_new(cand_sig, "hex_seed", json_string((char *)cand_sig_hex));
            json_object_set_new(proposal_json, "signature", cand_sig);
        }
        free(cand_sig_hex);
    }
    unsigned char *cand_enc_hex = encryptor_publish(&nmsg->from_whom.encryptor);
    if (cand_enc_hex != NULL) {
        json_t *cand_enc = json_object();
        if (cand_enc != NULL) {
            json_object_set_new(cand_enc, "hex_seed", json_string((char *)cand_enc_hex));
            json_object_set_new(proposal_json, "encryptor", cand_enc);
        }
        free(cand_enc_hex);
    }

    if (id_state.synchronous_dispatch)
    {
        generic_msg_t propose_msg = {0};
        propose_msg.type = NET_MESSAGE;
        strncpy(propose_msg.info.net_msg.process, "identity", PROC_NAME_LEN);
        propose_msg.info.net_msg.function = ID_PROPOSE;
        propose_msg.info.net_msg.encrypt = false;
        /* to_whom zeroed → broadcast */
        net_msg_pack_json(&propose_msg.info.net_msg, proposal_json);
        messaging_send("network", NET_MESSAGE, &propose_msg, false);
    }
    else
    {
        peers_read_lock(proc);
        for (size_t i = 0; i < proc->protocol.num_peers; i++)
        {
            generic_msg_t propose_msg = {0};
            propose_msg.type = NET_MESSAGE;
            strncpy(propose_msg.info.net_msg.process, "identity", PROC_NAME_LEN);
            propose_msg.info.net_msg.function = ID_PROPOSE;
            propose_msg.info.net_msg.encrypt = true;
            memcpy(&propose_msg.info.net_msg.to_whom, &proc->protocol.peers[i],
                   sizeof(public_identity_t));
            net_msg_pack_json(&propose_msg.info.net_msg, proposal_json);
            messaging_send("network", NET_MESSAGE, &propose_msg, false);
        }
        peers_read_unlock(proc);
    }
    json_decref(proposal_json);

    log_info(proc->logger, "Identity: proposed peer %s for voting\n",
             nmsg->from_whom.nickname);

    /* synchronous_dispatch: inline-finalize. Production waits for inbound
     * vote messages to drive handle_count_vote → _peer_accepted; in test
     * mode no real votes will arrive, so check whether the self-vote
     * alone meets the majority (it does whenever num_peers == 0, and
     * scenarios that need >1 voter pre-stage extra peers). Mirrors what
     * Python's _vote_collection thread does after the timeout. */
    if (id_state.synchronous_dispatch
        && 1 >= MAJORITY(snapshot_num_peers))
    {
        log_info(proc->logger,
                 "Identity: synchronous_dispatch — self-vote majority for %s\n",
                 nmsg->from_whom.nickname);
        _peer_accepted((process_t *)proc, queues, &nmsg->from_whom,
                       nmsg->from_rank, false);
    }
    return true;
}

/****************************
 * Handler: handle_acceptance (access_granted)
 * Phase 2+. Receives acceptance from an existing peer.
 ****************************/

/* Frama-C: skipped —
 * identity_run + all handlers + helpers: [solver-timeout] every function copies
 * public_identity_t structs (memcpy of struct→struct triggers WP "Hide sub-term
 * definition" cast warning that blocks discharge of valid_dest/valid_src/separation).
 * Helpers also touch filesystem/network/identity stubs.
 */
/*@
  requires \valid(proc);
  requires \valid(queues);
  requires \valid(msg);
  requires proc->logger == \null || \valid(proc->logger);
*/
static bool handle_acceptance(const process_t *proc, directory_t *queues, generic_msg_t *msg)
{
    if (proc->protocol.phase < 2)
        return false;

    net_msg_t *nmsg = &msg->info.net_msg;
    log_info(proc->logger, "Identity: access granted by %s\n",
             nmsg->from_whom.nickname);

    /* Dedup + append under the write lock */
    peers_write_lock((process_t *)proc);
    bool duplicate = false;
    for (size_t i = 0; i < proc->protocol.num_peers; i++)
    {
        if (uuid_compare(proc->protocol.peers[i].uuid, nmsg->from_whom.uuid) == 0)
        {
            duplicate = true;
            break;
        }
    }
    bool appended = false;
    if (!duplicate && proc->protocol.num_peers < MAX_PEERS)
    {
        memcpy(&((process_t *)proc)->protocol.peers[proc->protocol.num_peers],
               &nmsg->from_whom, sizeof(public_identity_t));
        ((process_t *)proc)->protocol.num_peers++;
        appended = true;
    }
    peers_write_unlock((process_t *)proc);

    if (duplicate)
    {
        log_debug(proc->logger, "Identity: peer already known, skipping duplicate add\n");
    }
    else if (appended)
    {
        /* Broadcast peer update to all local processes */
        generic_msg_t peer_msg = {0};
        peer_msg.type = PEER;
        memcpy(&peer_msg.info.peer, &nmsg->from_whom, sizeof(public_identity_t));
        _remember_activity(proc, queues, &peer_msg);
    }

    return true;
}

/* Forward declaration — definition is in the pre-loop block lower in
 * this file. _merge_to_mesh / _announce_self_to_bundled_peers reuse the
 * same announcement build + retry-on-network-busy logic. */
static int _announce_identity(const process_t *proc, directory_t *queues);

/****************************
 * Helper: _announce_self_to_bundled_peers
 *
 * Mirrors Python's `_announce_self_to_bundled_peers` (idprocess.py:659-699).
 * Sends an ID_ACCEPT (carrying self identity, package_hash, capabilities)
 * to each peer in the bundle so the receivers' `handle_acceptance` adds
 * us to their peer list. Without this, only welcomers (the few peers
 * that voted on us at announce time) ever add us; everyone else stays
 * in the unknown-sender path for our encrypted traffic and silently
 * defers/drops it via the mystery-handler.
 *
 * The bundle list is the union of peer identities pulled out of inbound
 * full_history payloads (Python's choose_group / _merge_to_mesh stash
 * those into a `unioned_peers` dict before calling). The C history
 * wire-format currently ships an empty payload (see _peer_accepted
 * note above), so this helper is wired but quiescent until the wire
 * format catches up. Once it does, no further wiring will be needed
 * here.
 ****************************/
static int _announce_self_to_bundled_peers(const process_t *proc,
                                           directory_t *queues,
                                           const public_identity_t *peers,
                                           size_t n_peers)
{
    (void)queues;
    if (proc == NULL || peers == NULL || n_peers == 0)
        return 0;

    /* Build the accept payload once — same shape as the welcomer's
     * ID_ACCEPT in _peer_accepted: identity in `from_whom`, no body. */
    generic_msg_t accept_template = {0};
    accept_template.type = NET_MESSAGE;
    strncpy(accept_template.info.net_msg.process, "identity", PROC_NAME_LEN);
    accept_template.info.net_msg.function = ID_ACCEPT;
    accept_template.info.net_msg.encrypt = false;
    strncpy(accept_template.info.net_msg.return_to, "identity", PROC_NAME_LEN);

    /* Populate from_whom with our published identity, same way as
     * _build_announcement does it. */
    data_t *id_dat = NULL;
    char id_key[] = "identity";
    if (map_get(proc->configs, id_key, &id_dat) == 0 && id_dat != NULL)
    {
        config_t *id_cfg = NULL;
        if (data_object_ptr(id_dat, (void **)&id_cfg) == 0 &&
            id_cfg != NULL && id_cfg->data_struct != NULL)
        {
            public_identity_t *pub = NULL;
            identity_publish((const identity_t *)id_cfg->data_struct, &pub);
            if (pub != NULL) {
                memcpy(&accept_template.info.net_msg.from_whom, pub,
                       sizeof(public_identity_t));
                smrt_deref(pub);
            }
        }
    }

    size_t sent = 0;
    for (size_t i = 0; i < n_peers; i++)
    {
        generic_msg_t accept = accept_template;
        memcpy(&accept.info.net_msg.to_whom, &peers[i],
               sizeof(public_identity_t));
        if (messaging_send("network", NET_MESSAGE, &accept, false) == 0) {
            sent++;
            probes_counter("peer.set", "self_announce", "sent");
        } else {
            probes_counter("peer.set", "self_announce", "queue_full");
        }
    }
    if (sent > 0)
        log_debug(proc->logger,
                  "Identity: announced self to %zu bundled peer(s)\n", sent);
    return 0;
}

/****************************
 * Helper: _populate_peers_from_history
 *
 * Mirrors Python's `_populate_peers_from_history` (idprocess.py:605-657).
 * Seeds proc->protocol.peers from a welcomer's bundled peer list. Late
 * joiners never receive the confirm broadcasts for peers admitted
 * before they joined — admit-time `_peer_accepted` targets the
 * welcomer's group at that moment.
 *
 * We deliberately do NOT call _add_peer here because the history bundle
 * we just adopted already contains an admission step for each of these
 * peers; _add_peer would double-emit group churn. We append directly to
 * proc->protocol.peers (skipping self / already-known entries) and
 * follow up with _announce_self_to_bundled_peers so the bundled peers
 * learn about us — without that, the symmetry breaks and encrypted
 * traffic to them fails the unknown-sender decrypt path.
 ****************************/
static int _populate_peers_from_history(process_t *proc,
                                        directory_t *queues,
                                        const public_identity_t *peer_idents,
                                        size_t n)
{
    if (proc == NULL || peer_idents == NULL || n == 0)
        return 0;

    /* Resolve self uuid for the dedup check. */
    uuid_t self_uuid;
    uuid_clear(self_uuid);
    data_t *id_dat = NULL;
    char id_key[] = "identity";
    if (map_get(proc->configs, id_key, &id_dat) == 0 && id_dat != NULL) {
        config_t *id_cfg = NULL;
        if (data_object_ptr(id_dat, (void **)&id_cfg) == 0 &&
            id_cfg != NULL && id_cfg->data_struct != NULL) {
            const public_identity_t *me =
                (const public_identity_t *)id_cfg->data_struct;
            uuid_copy(self_uuid, (unsigned char *)me->uuid);
        }
    }

    /* Append new peers. peers_write_lock guards the array; the
     * uniqueness check is similar to _add_peer's idempotent guard. */
    size_t added = 0;
    peers_write_lock(proc);
    for (size_t i = 0; i < n; i++) {
        const public_identity_t *p = &peer_idents[i];
        if (uuid_compare((unsigned char *)p->uuid, self_uuid) == 0)
            continue;
        bool dup = false;
        for (size_t k = 0; k < proc->protocol.num_peers; k++) {
            if (uuid_compare(proc->protocol.peers[k].uuid,
                             (unsigned char *)p->uuid) == 0) {
                dup = true;
                break;
            }
        }
        if (dup)
            continue;
        if (proc->protocol.num_peers >= MAX_PEERS)
            break;
        memcpy(&proc->protocol.peers[proc->protocol.num_peers],
               p, sizeof(public_identity_t));
        proc->protocol.num_peers++;
        added++;
    }
    peers_write_unlock(proc);

    if (added > 0) {
        log_debug(proc->logger,
                  "Identity: history bundle added %zu previously unknown peer(s)\n",
                  added);
        /* Bundled peers don't know about us yet — fix the asymmetry. */
        _announce_self_to_bundled_peers(proc, queues, peer_idents, n);
    }
    return 0;
}

/****************************
 * Helper: _union_peers_from_histories
 *
 * Walk every stashed history JSON in @p id_state.histories, pull the
 * `peers` slot (index 2 of the 3-tuple) out of each, parse entries
 * into public_identity_t records, and dedup by uuid. Mirrors Python's
 * choose_group / _merge_to_mesh `unioned_peers` collection
 * (idprocess.py:278-296, 397-409). The caller owns the returned heap
 * array and must free() it; @p *out_count receives the entry count.
 *
 * Returns 0 on success (even if zero peers found); non-zero on
 * allocation failure.
 ****************************/
static int _union_peers_from_histories(public_identity_t **out, size_t *out_count)
{
    if (out == NULL || out_count == NULL)
        return EINVAL;
    *out = NULL;
    *out_count = 0;

    /* First pass: count entries to bound the alloc; cap at MAX_PEERS to
     * keep the working set small. */
    size_t cap = 0;
    size_t n_hist = array_size(&id_state.histories);
    for (size_t i = 0; i < n_hist; i++) {
        data_t *h_dat = NULL;
        if (array_get(&id_state.histories, (int)i, &h_dat) != 0 || h_dat == NULL)
            continue;
        ptr_t ptr = NULL;
        if (data_object_ptr(h_dat, &ptr) != 0 || ptr == NULL)
            continue;
        const json_t *root = (const json_t *)ptr;
        if (!json_is_array(root) || json_array_size(root) < 3)
            continue;
        const json_t *peers_arr = json_array_get(root, 2);
        if (peers_arr && json_is_array(peers_arr))
            cap += json_array_size(peers_arr);
    }
    if (cap == 0)
        return 0;
    if (cap > MAX_PEERS)
        cap = MAX_PEERS;

    public_identity_t *buf = calloc(cap, sizeof(public_identity_t));
    if (buf == NULL)
        return ENOMEM;

    size_t n = 0;
    for (size_t i = 0; i < n_hist && n < cap; i++) {
        data_t *h_dat = NULL;
        if (array_get(&id_state.histories, (int)i, &h_dat) != 0 || h_dat == NULL)
            continue;
        ptr_t ptr = NULL;
        if (data_object_ptr(h_dat, &ptr) != 0 || ptr == NULL)
            continue;
        const json_t *root = (const json_t *)ptr;
        if (!json_is_array(root) || json_array_size(root) < 3)
            continue;
        const json_t *peers_arr = json_array_get(root, 2);
        if (!peers_arr || !json_is_array(peers_arr))
            continue;
        size_t m = json_array_size(peers_arr);
        for (size_t k = 0; k < m && n < cap; k++) {
            const json_t *p_obj = json_array_get(peers_arr, k);
            if (!p_obj || !json_is_object(p_obj))
                continue;
            public_identity_t parsed = {0};
            if (public_identity_from_json(p_obj, &parsed) != 0)
                continue;
            /* Dedup by uuid against entries already in buf. */
            bool dup = false;
            for (size_t j = 0; j < n; j++) {
                if (uuid_compare((unsigned char *)buf[j].uuid,
                                 (unsigned char *)parsed.uuid) == 0) {
                    dup = true;
                    break;
                }
            }
            if (!dup) {
                buf[n] = parsed;
                n++;
            }
        }
    }

    if (n == 0) {
        free(buf);
        return 0;
    }
    *out = buf;
    *out_count = n;
    return 0;
}

/****************************
 * Helper: _merge_to_mesh
 *
 * Mirrors Python's `_merge_to_mesh` (idprocess.py:383-441). Called when
 * a full_history arrives AFTER choose_group's self-bootstrap fallback
 * already ran. Adopts the mesh's group + history, then re-broadcasts
 * request_access on the open channel so a BG admits us through the
 * normal welcoming-committee flow. The eventual access_granted +
 * full_history round-trip routes back through handle_receive_history
 * with self_bootstrapped now clear — no re-entry.
 *
 * The merging flag is the re-entry guard; caller is responsible for
 * setting it and this helper clears it on exit (success or failure).
 ****************************/
static int _merge_to_mesh(process_t *proc, directory_t *queues)
{
    if (proc == NULL)
        return EINVAL;

    /* TODO (divergence.md C14 follow-up): Python's `_merge_to_mesh` and
     * sibling history-merge paths emit `id.receive_history/arrived` and
     * related counters via `_probes.counter`. Mirror those here so
     * cross-impl dashboards (probes JSONL ➜ tail tool) line up. The
     * framework is wired — just add `probes_counter("id.receive_history",
     * "arrived", shape)` and friends at the matching call sites. */
    log_info(proc->logger,
             "Identity: merging self-bootstrap into mesh (re-announcing)\n");

    /* Walk the stashed histories under the id_state lock to pull
     * three things out: (1) the bundled peer list, (2) the group from
     * the longest-history welcomer, (3) that same welcomer's steps
     * array. Mirrors Python choose_group / _merge_to_mesh which sort
     * `accepted` by `len(steps) > len(accepted[1])` so the most
     * complete view wins (idprocess.py:305-306, 412). Releasing the
     * lock before calling _populate_peers_from_history (which takes
     * its own locks). */
    public_identity_t *peer_bundle = NULL;
    size_t bundle_n = 0;
    group_t adopted_group = {0};
    bool have_group = false;
    json_t *steps_ref = NULL;     /* borrowed; alive while histories holds it */
    size_t best_steps_len = 0;    /* highest json_array_size(steps) seen */

    pthread_mutex_lock(&id_state.lock);
    _union_peers_from_histories(&peer_bundle, &bundle_n);

    size_t n_hist = array_size(&id_state.histories);
    for (size_t i = 0; i < n_hist; i++) {
        data_t *h_dat = NULL;
        if (array_get(&id_state.histories, (int)i, &h_dat) != 0 || h_dat == NULL)
            continue;
        ptr_t hptr = NULL;
        if (data_object_ptr(h_dat, &hptr) != 0 || hptr == NULL)
            continue;
        json_t *root = (json_t *)hptr;
        if (!json_is_array(root) || json_array_size(root) < 2)
            continue;
        json_t *s_json = json_array_get(root, 1);
        size_t this_steps_len =
            (s_json && json_is_array(s_json)) ? json_array_size(s_json) : 0;

        /* Pick this entry only if it has strictly more steps than the
         * best seen so far. The first entry always replaces the
         * zero-initialized baseline (`have_group=false` ensures
         * even an empty-steps entry can seed adoption when no other
         * choice exists). Strict > on ties matches Python's behavior:
         * the first welcomer at a given length wins, later ties keep
         * the earlier pick. */
        bool pick = false;
        if (!have_group && this_steps_len == 0) {
            pick = true;
        } else if (this_steps_len > best_steps_len) {
            pick = true;
        }
        if (!pick)
            continue;

        json_t *g_json = json_array_get(root, 0);
        if (g_json && json_is_object(g_json)) {
            group_t parsed = {0};
            if (group_from_json(g_json, &parsed) == 0) {
                adopted_group = parsed;
                have_group = true;
            }
        }
        steps_ref = (this_steps_len > 0) ? s_json : NULL;
        best_steps_len = this_steps_len;
    }

    /* Ingest the inbound steps into our DAG before releasing the lock —
     * _ensure_history_locked requires it. */
    if (steps_ref != NULL) {
        identity_history_t *h = _ensure_history_locked(proc);
        if (h != NULL) {
            size_t m = json_array_size(steps_ref);
            linked_step_t **steps = calloc(m, sizeof(linked_step_t *));
            size_t parsed_n = 0;
            if (steps != NULL) {
                for (size_t k = 0; k < m; k++) {
                    json_t *sj = json_array_get(steps_ref, k);
                    if (sj == NULL || !json_is_object(sj))
                        continue;
                    linked_step_t *step = NULL;
                    if (linked_step_from_json(sj, &step) == 0 && step != NULL)
                        steps[parsed_n++] = step;
                }
                if (parsed_n > 0) {
                    /* C12 parity: dag_catch_up does the full ingest +
                     * diff + recite + validate + merge sequence that
                     * mirrors Python StepDAG.catch_up
                     * (dag.py:287-297). The validator installed by
                     * identity_history_create vetoes the merge on
                     * timestamp backdating; on rejection the branch
                     * remains in the DAG but unmerged. We discard the
                     * branch_diff — id_proc has no consumer for it. */
                    dag_catch_up(&h->dag, steps, parsed_n, NULL);
                }
                /* dag_ingest_branch retains owning refs on success; on
                 * failure we leak the unowned ones intentionally rather
                 * than guess at the ownership boundary mid-stream. */
                free(steps);
            }
        }
    }
    pthread_mutex_unlock(&id_state.lock);

    /* Adopt the mesh's group key under peers_write_lock (the
     * proc->protocol.group field is covered by the same lock as
     * proc->protocol.peers in the existing code). Mirrors Python's
     * `self.group = accepted_group` in idprocess.py:420. */
    if (have_group) {
        char gid_str[UUID_STRING_LEN + 1];
        uuid_unparse_lower(adopted_group.uuid, gid_str);
        peers_write_lock(proc);
        memcpy(&proc->protocol.group, &adopted_group, sizeof(group_t));
        peers_write_unlock(proc);
        log_info(proc->logger,
                 "Identity: adopted mesh group %s during merge\n", gid_str);
    }

    _populate_peers_from_history(proc, queues, peer_bundle, bundle_n);
    free(peer_bundle);

    int rc = _announce_identity(proc, queues);

    pthread_mutex_lock(&id_state.lock);
    id_state.self_bootstrapped = false;
    id_state.merging = false;
    pthread_mutex_unlock(&id_state.lock);

    return rc;
}

/****************************
 * Handler: receive_history (full_history)
 * Receives full history + group from established peer.
 ****************************/

/*@
  requires \valid(proc);
  requires \valid(queues);
  requires \valid(msg);
  requires proc->logger == \null || \valid(proc->logger);
*/
static bool handle_receive_history(const process_t *proc, directory_t *queues, generic_msg_t *msg)
{
    (void)queues;
    net_msg_t *nmsg = &msg->info.net_msg;
    log_info(proc->logger, "Identity: received history from %s\n",
             nmsg->from_whom.nickname);

    /* Unpack JSON payload and store for group selection */
    json_t *payload = NULL;
    if (net_msg_unpack_json(nmsg, &payload) != 0 || payload == NULL)
    {
        log_warn(proc->logger, "Identity: handle_receive_history: no JSON payload\n");
        return true;
    }

    pthread_mutex_lock(&id_state.lock);
    /* Store the history JSON blob in the histories array for later processing */
    data_t *hist_dat = object_ptr_data(payload, sizeof(json_t));
    array_append(&id_state.histories, hist_dat);
    /* Late-history merge trigger — mirrors Python's idprocess.py:367-377.
     * If choose_group's self-bootstrap fallback already fired and a real
     * mesh's history just arrived, fan out to _merge_to_mesh so we can
     * re-broadcast request_access and be admitted normally. The merging
     * flag guards against re-entry while the helper is running. */
    bool should_merge = (id_state.self_bootstrapped
                         && !id_state.merging
                         && !id_state.choosing_group);
    if (should_merge)
        id_state.merging = true;
    pthread_mutex_unlock(&id_state.lock);

    log_debug(proc->logger, "Identity: stored history from %s\n", nmsg->from_whom.nickname);

    if (should_merge)
        _merge_to_mesh((process_t *)proc, queues);
    return true;
}

/****************************
 * Handler: handle_vote_on_peer (propose_peer)
 * Phase 3 only. Receives a peer proposal for voting.
 ****************************/

/* Worker arguments for async vote dispatch. Owned by the worker; freed
 * after the messaging_send call returns. Carries only the small inputs
 * the send path needs so the proc/queues structures don't escape the
 * handler scope. */
typedef struct {
    char              proposed_uuid[UUID_STRING_LEN + 1];
    public_identity_t to_whom;
    logger_t         *logger;
} vote_on_peer_args_t;

static void _vote_on_peer_send(vote_on_peer_args_t *args)
{
    json_t *vote_json = json_object();
    if (vote_json == NULL) {
        log_error(args->logger, "Identity: json_object OOM (vote)\n");
        return;
    }
    json_object_set_new(vote_json, "uuid", json_string(args->proposed_uuid));
    json_object_set_new(vote_json, "approved", json_true());

    generic_msg_t vote_msg = {0};
    vote_msg.type = NET_MESSAGE;
    strncpy(vote_msg.info.net_msg.process, "identity", PROC_NAME_LEN);
    vote_msg.info.net_msg.function = ID_VOTE;
    memcpy(&vote_msg.info.net_msg.to_whom, &args->to_whom, sizeof(public_identity_t));
    vote_msg.info.net_msg.encrypt = true;
    net_msg_pack_json(&vote_msg.info.net_msg, vote_json);
    json_decref(vote_json);

    messaging_send("network", NET_MESSAGE, &vote_msg, false);
    log_debug(args->logger, "Identity: sent approval vote for %s\n", args->proposed_uuid);
}

static void *vote_on_peer_worker(void *arg)
{
    vote_on_peer_args_t *args = (vote_on_peer_args_t *)arg;
    _vote_on_peer_send(args);
    free(args);
    return NULL;
}

/* Frama-C: skipped —
 * identity_run + all handlers + helpers: [solver-timeout] every function copies
 * public_identity_t structs (memcpy of struct→struct triggers WP "Hide sub-term
 * definition" cast warning that blocks discharge of valid_dest/valid_src/separation).
 * Helpers also touch filesystem/network/identity stubs.
 */
/*@
  requires \valid(proc);
  requires \valid(queues);
  requires \valid(msg);
  requires proc->logger == \null || \valid(proc->logger);
*/
static bool handle_vote_on_peer(const process_t *proc, directory_t *queues, generic_msg_t *msg)
{
    (void)queues;
    if (proc->protocol.phase != 3)
        return false;

    /* Policy B — border-guards-only voting (ISSUES.md §3.1-c). Mirrors the
     * Python handle_vote_on_peer gate: a non-border-guard consumes the
     * proposal but abstains rather than voting on a candidate it has no
     * welcoming-committee validation context for. Default is border-guard
     * (set in identity_register_handlers), so this is a no-op unless a
     * deployment/harness designates a non-guard. */
    if (!proc->protocol.border_guard_mode) {
        log_debug(proc->logger, "Identity: not a border guard; abstaining from vote\n");
        return true;
    }

    net_msg_t *nmsg = &msg->info.net_msg;

    /* Extract proposed peer identity from JSON payload (not from_whom,
     * which gets overwritten by decryption with the sender's identity) */
    json_t *payload = NULL;
    if (net_msg_unpack_json(nmsg, &payload) != 0 || payload == NULL)
    {
        log_warn(proc->logger, "Identity: handle_vote_on_peer: no JSON payload\n");
        return true;
    }

    const char *proposed_uuid_raw = json_string_value(json_object_get(payload, "uuid"));
    if (proposed_uuid_raw == NULL)
    {
        json_decref(payload);
        log_warn(proc->logger, "Identity: handle_vote_on_peer: missing uuid\n");
        return true;
    }

    /* Sybil guard — parity with Python idprocess._process_id (the
     * collision check at the top): refuse to vote for a candidate that
     * collides with an existing peer on UUID, signature public key, OR
     * encryptor public key. A forged peer claiming any facet of a known
     * identity is dropped here, so no approval vote is emitted; a genuinely
     * new candidate falls through to the normal vote. The signature/
     * encryptor hex are carried in the propose payload (see the enriched
     * payload build above). Peers are read lock-free, matching the other
     * handler-side reads in this file (the identity message loop is
     * single-threaded). */
    {
        const char *proposed_sig = NULL;
        const char *proposed_enc = NULL;
        json_t *sig_obj = json_object_get(payload, "signature");
        if (json_is_object(sig_obj))
            proposed_sig = json_string_value(json_object_get(sig_obj, "hex_seed"));
        json_t *enc_obj = json_object_get(payload, "encryptor");
        if (json_is_object(enc_obj))
            proposed_enc = json_string_value(json_object_get(enc_obj, "hex_seed"));

        uuid_t proposed_uuid;
        bool have_uuid = (uuid_parse(proposed_uuid_raw, proposed_uuid) == 0);
        for (size_t i = 0; i < proc->protocol.num_peers; i++) {
            const public_identity_t *peer = &proc->protocol.peers[i];
            const char *reason = NULL;
            if (have_uuid && memcmp(peer->uuid, proposed_uuid,
                                    sizeof(uuid_t)) == 0) {
                reason = "uuid";
            }
            if (reason == NULL && proposed_sig != NULL) {
                unsigned char *peer_sig = signature_publish(&peer->signature);
                if (peer_sig != NULL) {
                    if (strcmp((char *)peer_sig, proposed_sig) == 0)
                        reason = "signature";
                    free(peer_sig);
                }
            }
            if (reason == NULL && proposed_enc != NULL) {
                unsigned char *peer_enc = encryptor_publish(&peer->encryptor);
                if (peer_enc != NULL) {
                    if (strcmp((char *)peer_enc, proposed_enc) == 0)
                        reason = "encryptor";
                    free(peer_enc);
                }
            }
            if (reason != NULL) {
                log_warn(proc->logger,
                         "Identity: refusing vote — candidate %s collides "
                         "with an existing peer on %s (sybil)\n",
                         proposed_uuid_raw, reason);
                json_decref(payload);
                return true;
            }
        }
    }

    /* Prove-parity — Python idprocess._process_id votes only after
     * self._history.prove(blob) succeeds; the PoA/PoS prove() override
     * (poa.py:37-42, pos.py:35-40) returns None for a candidate whose UUID
     * OR address is blacklisted, so no proof is produced and no approval
     * vote is appended. Mirror that here by consulting the per-process
     * identity-history blacklist (identity_history_is_blacklisted, which
     * backs identity_history_prove) and dropping the vote on a match. The
     * collision/sybil facet of prove() is handled by the guard above. The
     * history is reached under id_state.lock via the same lazy initializer
     * the other handler paths use. */
    {
        const char *proposed_addr =
            json_string_value(json_object_get(payload, "address"));
        uuid_t bl_uuid;
        const unsigned char *bl_uuid_ptr = NULL;
        if (uuid_parse(proposed_uuid_raw, bl_uuid) == 0)
            bl_uuid_ptr = bl_uuid;
        pthread_mutex_lock(&id_state.lock);
        identity_history_t *hist = _ensure_history_locked(proc);
        bool blacklisted = (hist != NULL) &&
            identity_history_is_blacklisted(hist, bl_uuid_ptr, proposed_addr);
        pthread_mutex_unlock(&id_state.lock);
        if (blacklisted) {
            log_warn(proc->logger,
                     "Identity: refusing vote — candidate %s is blacklisted "
                     "(prove rejected)\n",
                     proposed_uuid_raw);
            json_decref(payload);
            return true;
        }
    }

    vote_on_peer_args_t *args = calloc(1, sizeof(*args));
    if (args == NULL) {
        json_decref(payload);
        log_error(proc->logger, "Identity: vote_on_peer alloc failed\n");
        return true;
    }
    strncpy(args->proposed_uuid, proposed_uuid_raw, UUID_STRING_LEN);
    args->proposed_uuid[UUID_STRING_LEN] = '\0';
    json_decref(payload);
    memcpy(&args->to_whom, &nmsg->from_whom, sizeof(public_identity_t));
    args->logger = proc->logger;

    log_info(proc->logger, "Identity: received peer proposal for %s\n",
             args->proposed_uuid);

    /* Async unless conformance/sync mode is active. Mirrors Python
     * idprocess.py:749-769 which spawns `_process_id` via _spawn (which
     * respects `synchronous_dispatch`). In sync mode we run inline so
     * scenario steps stay deterministic. See [[synchronous-dispatch-hooks]]. */
    pthread_mutex_lock(&id_state.lock);
    bool sync = id_state.synchronous_dispatch;
    pthread_mutex_unlock(&id_state.lock);

    if (sync) {
        _vote_on_peer_send(args);
        free(args);
        return true;
    }

    pthread_t tid;
    pthread_attr_t attr;
    pthread_attr_init(&attr);
    pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
    int rc = pthread_create(&tid, &attr, vote_on_peer_worker, args);
    pthread_attr_destroy(&attr);
    if (rc != 0) {
        log_warn(proc->logger,
                 "Identity: vote_on_peer pthread_create failed (rc=%d) — falling back to inline\n",
                 rc);
        _vote_on_peer_send(args);
        free(args);
    }
    return true;
}

/****************************
 * Vote-collection helpers (exposed via id_proc_priv.h for concurrency tests)
 *
 * These own the id_state.lock critical section for the vote_collection map,
 * so callers (including handle_count_vote) never need to touch the mutex
 * directly.  Prior to their extraction the critical section inside the
 * handler was incorrectly left unguarded — see BUGS.md C6.
 ****************************/

int vote_collection_increment(const char *uuid_key)
{
    _ensure_id_init();
    pthread_mutex_lock(&id_state.lock);

    data_t *count_dat = NULL;
    int count = 0;
    if (map_get(&id_state.vote_collection, (map_key_t)uuid_key, &count_dat) == 0)
        data_integer(count_dat, &count);
    count += 1;
    data_t *new_count_dat = integer_data(count);
    map_set(&id_state.vote_collection, (map_key_t)uuid_key, new_count_dat);

    pthread_mutex_unlock(&id_state.lock);
    return count;
}

int vote_collection_get(const char *uuid_key, int *out_count)
{
    if (out_count == NULL)
        return -1;
    _ensure_id_init();
    pthread_mutex_lock(&id_state.lock);

    data_t *count_dat = NULL;
    int rc = -1;
    if (map_get(&id_state.vote_collection, (map_key_t)uuid_key, &count_dat) == 0)
    {
        int count = 0;
        data_integer(count_dat, &count);
        *out_count = count;
        rc = 0;
    }

    pthread_mutex_unlock(&id_state.lock);
    return rc;
}

void identity_set_synchronous_dispatch(bool enabled)
{
    _ensure_id_init();
    pthread_mutex_lock(&id_state.lock);
    id_state.synchronous_dispatch = enabled;
    pthread_mutex_unlock(&id_state.lock);
}

void identity_set_border_guard_mode(process_t *proc, bool enabled)
{
    /* Per-process (not global id_state) — mirrors Python's per-instance
     * IdentityProcess.border_guard_mode. See ISSUES.md §3.1-c. */
    if (proc != NULL)
        proc->protocol.border_guard_mode = enabled;
}

void identity_set_admission_quorum(process_t *proc, int quorum)
{
    /* Per-process two-phase admission quorum (ISSUES.md §3.1-a). Mirrors
     * Python's per-instance IdentityProcess._admission_quorum. */
    if (proc != NULL)
        proc->protocol.admission_quorum = quorum > 0 ? quorum : 1;
}

void identity_reset_state(void)
{
    _ensure_id_init();
    pthread_mutex_lock(&id_state.lock);
    /* Preserve synchronous_dispatch across reset so the harness can set
     * it once at adapter init rather than on every scenario. Matches
     * reputation_reset_state's preservation semantics. */
    bool was_sync = id_state.synchronous_dispatch;
    array_free(&id_state.histories);
    array_init(&id_state.histories);
    map_free(&id_state.peer_potentials);
    map_init(&id_state.peer_potentials);
    map_free(&id_state.vote_collection);
    map_init(&id_state.vote_collection);
    map_free(&id_state.own_caps_by_proc);
    map_init(&id_state.own_caps_by_proc);
    map_free(&id_state.peer_caps_map);
    map_init(&id_state.peer_caps_map);
    map_free(&id_state.peer_cap_descriptors_map);
    map_init(&id_state.peer_cap_descriptors_map);
    map_free(&id_state.peer_tiers);
    map_init(&id_state.peer_tiers);
    map_free(&id_state.partition_probe_cooldown);
    map_init(&id_state.partition_probe_cooldown);
    map_free(&id_state.partition_response_cooldown);
    map_init(&id_state.partition_response_cooldown);
    map_free(&id_state.provisional_confirmations);
    map_init(&id_state.provisional_confirmations);
    id_state.partition_recovery_target[0] = '\0';
    id_state.partition_recovery_started_us = 0;
    id_state.self_tier = 0;
    id_state.choosing_group = false;
    id_state.self_bootstrapped = false;
    id_state.merging = false;
    id_state.synchronous_dispatch = was_sync;
    pthread_mutex_unlock(&id_state.lock);
}

/****************************
 * Handler: count_vote (vote_on_peer)
 * Phase 3 only. Receives and counts votes on proposed peers.
 ****************************/

/*@
  requires \valid(proc);
  requires \valid(queues);
  requires \valid(msg);
  requires proc->logger == \null || \valid(proc->logger);
*/
static bool handle_count_vote(process_t *proc, directory_t *queues, generic_msg_t *msg)
{
    if (proc->protocol.phase != 3)
        return false;

    net_msg_t *nmsg = &msg->info.net_msg;
    log_debug(proc->logger, "Identity: received vote from %s\n",
              nmsg->from_whom.nickname);

    /* Unpack JSON payload to get the proposed peer UUID and approval flag */
    json_t *payload = NULL;
    if (net_msg_unpack_json(nmsg, &payload) != 0 || payload == NULL)
    {
        log_warn(proc->logger, "Identity: handle_count_vote: no JSON payload\n");
        return true;
    }

    json_t *j_uuid     = json_object_get(payload, "uuid");
    json_t *j_approved = json_object_get(payload, "approved");

    if (!j_uuid || !j_approved)
    {
        json_decref(payload);
        log_warn(proc->logger, "Identity: handle_count_vote: missing JSON fields\n");
        return true;
    }

    const char *peer_uuid_raw = json_string_value(j_uuid);
    bool approved = json_is_true(j_approved);

    if (!approved || peer_uuid_raw == NULL)
    {
        json_decref(payload);
        log_debug(proc->logger, "Identity: vote not approved, skipping\n");
        return true;
    }

    /* Copy UUID before freeing JSON payload */
    char uuid_key[UUID_STRING_LEN + 2];
    strncpy(uuid_key, peer_uuid_raw, sizeof(uuid_key) - 1);
    uuid_key[sizeof(uuid_key) - 1] = '\0';
    json_decref(payload);

    /* Atomically read-modify-write the vote count under id_state.lock.
     * Formerly this was open-coded here and the lock was never acquired,
     * with a stray unlock at the tail — see BUGS.md C6. */
    int count = vote_collection_increment(uuid_key);

    peers_read_lock(proc);
    size_t num_peers = proc->protocol.num_peers;
    peers_read_unlock(proc);

    log_debug(proc->logger, "Identity: vote count for %s: %d (need %d)\n",
              uuid_key, count, MAJORITY(num_peers));

    /* If majority reached, accept the peer */
    if (count >= MAJORITY(num_peers))
    {
        /* Find the proposed peer in peer_potentials */
        pthread_mutex_lock(&id_state.lock);
        data_t *peer_dat = NULL;
        map_get(&id_state.peer_potentials, uuid_key, &peer_dat);
        public_identity_t *new_peer = NULL;
        if (peer_dat != NULL)
            data_object_ptr(peer_dat, (void **)&new_peer);
        pthread_mutex_unlock(&id_state.lock);

        if (new_peer != NULL)
        {
            log_info(proc->logger, "Identity: majority vote reached for %s, accepting peer\n",
                     uuid_key);
            /* Rank was captured at the potential-store (handle_welcoming_
             * committee); pass 0 so _peer_accepted's non-zero gate leaves it. */
            _peer_accepted(proc, queues, new_peer, 0, false);
        }
        else
        {
            log_warn(proc->logger, "Identity: majority reached but peer %s not in potentials\n",
                     uuid_key);
        }
    }

    return true;
}

/****************************
 * Handler: handle_confirm_peer (peer_accepted)
 * Phase 3 only. Receives confirmation that a peer was accepted.
 ****************************/

/*@
  requires \valid(proc);
  requires \valid(queues);
  requires \valid(msg);
  requires proc->logger == \null || \valid(proc->logger);
*/
/* Two-phase admission bookkeeping (ISSUES.md §3.1-a). Record `confirmer_uuid`
 * as having confirmed `peer_uuid` for `proc`; return the count of DISTINCT
 * confirmers so far. Keyed "<proc>|<peer_uuid>" in id_state so per-participant
 * conformance runs don't collide. A NULL confirmer is stored as a distinct
 * anonymous token so single-confirm (quorum 1) admission still promotes.
 * Mirrors Python IdentityProcess._provisional_confirmations. */
static size_t _record_confirmation(const process_t *proc, const char *peer_uuid,
                                   const char *confirmer_uuid)
{
    char key[128];
    snprintf(key, sizeof(key), "%p|%s", (const void *)proc, peer_uuid);
    pthread_mutex_lock(&id_state.lock);
    data_t *dat = NULL;
    array_t *confirmers = NULL;
    if (map_get(&id_state.provisional_confirmations, (map_key_t)key, &dat) == 0
        && dat != NULL) {
        data_object_ptr(dat, (ptr_t *)&confirmers);
    } else {
        if (array_create(&confirmers) != 0 || confirmers == NULL) {
            pthread_mutex_unlock(&id_state.lock);
            return 0;
        }
        data_t *arr_dat = object_ptr_data(confirmers, sizeof(array_t));
        map_set(&id_state.provisional_confirmations, (map_key_t)key, arr_dat);
    }
    const char *cid = (confirmer_uuid != NULL && confirmer_uuid[0] != '\0')
                      ? confirmer_uuid : NULL;
    bool present = false;
    if (cid != NULL) {
        for (size_t i = 0; i < array_size(confirmers); i++) {
            data_t *e = NULL; char *s = NULL;
            if (array_get(confirmers, (int)i, &e) == 0 && e != NULL
                && data_string_ptr(e, &s) == 0 && s != NULL
                && strcmp(s, cid) == 0) { present = true; break; }
        }
    }
    if (!present) {
        char anon[32];
        if (cid == NULL) {
            snprintf(anon, sizeof(anon), "<anon:%zu>", array_size(confirmers));
            cid = anon;
        }
        data_t *sd = string_data((char *)cid, strlen(cid) + 1);
        if (sd != NULL) array_append(confirmers, sd);
    }
    size_t count = array_size(confirmers);
    pthread_mutex_unlock(&id_state.lock);
    return count;
}

static void _clear_confirmations(const process_t *proc, const char *peer_uuid)
{
    char key[128];
    snprintf(key, sizeof(key), "%p|%s", (const void *)proc, peer_uuid);
    pthread_mutex_lock(&id_state.lock);
    map_remove(&id_state.provisional_confirmations, (map_key_t)key);
    pthread_mutex_unlock(&id_state.lock);
}

static bool handle_confirm_peer(process_t *proc, directory_t *queues, generic_msg_t *msg)
{
    if (proc->protocol.phase != 3)
        return false;

    net_msg_t *nmsg = &msg->info.net_msg;
    log_info(proc->logger, "Identity: peer acceptance confirmed from %s\n",
             nmsg->from_whom.nickname);

    /* Unpack the new-peer identity from the JSON payload. DRY canonical: the
     * full public-identity form (shared byte-shape with Python
     * public_identity_to_canonical, incl. sig/enc pubkeys);
     * public_identity_from_json also tolerates the legacy {uuid,nickname,
     * address} subset (sig/enc optional). */
    json_t *payload = NULL;
    if (net_msg_unpack_json(nmsg, &payload) != 0 || payload == NULL)
    {
        log_warn(proc->logger, "Identity: handle_confirm_peer: no JSON payload\n");
        return true;
    }

    public_identity_t new_peer;
    if (public_identity_from_json(payload, &new_peer) != 0)
    {
        json_decref(payload);
        log_warn(proc->logger, "Identity: handle_confirm_peer: malformed peer identity\n");
        return true;
    }
    json_decref(payload);

    char uuid_str_buf[UUID_STRING_LEN + 1];
    uuid_unparse_lower(new_peer.uuid, uuid_str_buf);
    const char *uuid_str = uuid_str_buf;
    const char *nickname = new_peer.nickname;
    const char *address  = (new_peer.address[0] != '\0') ? (const char *)new_peer.address : NULL;

    log_info(proc->logger, "Identity: confirmed peer %s (%s)\n", nickname, uuid_str);

    /* UDP-loss recovery: if the new peer's announce never reached us, their
     * UUID is absent from id_state.peer_potentials. The confirm broadcast is
     * still reliable (group/TCP), so the peer is in `peers[]` but has no
     * registered capabilities — invisible to cap-driven discovery. Mirrors
     * Python's handle_confirm_peer (idprocess.py:847). Requires `address`
     * from the confirm payload to route the query. See memory entry
     * feedback_late_joiner_caps.md. */
    if (uuid_str != NULL && address != NULL && address[0] != '\0')
    {
        pthread_mutex_lock(&id_state.lock);
        data_t *pot_dat = NULL;
        bool has_potential = (map_get(&id_state.peer_potentials,
                                      (map_key_t)uuid_str, &pot_dat) == 0
                              && pot_dat != NULL);
        pthread_mutex_unlock(&id_state.lock);
        if (!has_potential)
        {
            log_info(proc->logger,
                     "Identity: no prior caps potential for %s (%s) — "
                     "querying directly (announce likely lost)\n",
                     nickname, uuid_str);
            _send_caps_query(proc, &new_peer);
        }
    }

    /* Two-phase admission (ISSUES.md §3.1-a). Count DISTINCT confirmers; the
     * group key is propagated only once the quorum is met. The confirmer is
     * the message sender (nmsg->from_whom, populated on receive / auto-stamped
     * by the net layer). Quorum 1 (default) promotes on the first confirm =
     * historical single-welcomer behavior. Mirrors Python handle_confirm_peer. */
    char confirmer_uuid[UUID_STRING_LEN + 1] = "";
    if (nmsg->from_whom.nickname[0] != '\0')
        uuid_unparse_lower(nmsg->from_whom.uuid, confirmer_uuid);
    size_t count = _record_confirmation(proc, uuid_str,
                                        confirmer_uuid[0] ? confirmer_uuid : NULL);
    int quorum = proc->protocol.admission_quorum > 0
                 ? proc->protocol.admission_quorum : 1;
    bool reached = count >= (size_t)quorum;

    bool already = false;
    peers_read_lock(proc);
    for (size_t i = 0; i < proc->protocol.num_peers; i++) {
        if (uuid_compare(proc->protocol.peers[i].uuid, new_peer.uuid) == 0) {
            already = true;
            break;
        }
    }
    peers_read_unlock(proc);

    if (!already) {
        /* First time we hear of this peer via confirm: record it
         * (peers/activity), propagating the group key only if the quorum is
         * already satisfied (PROVISIONAL when it is not). */
        _add_peer(proc, queues, &new_peer, reached);
    } else if (reached) {
        /* Already provisionally known; the quorum is now met — promote. */
        _confirm_group_membership(proc, queues, &new_peer);
    }
    if (reached) {
        _clear_confirmations(proc, uuid_str);
    } else {
        log_debug(proc->logger, "Identity: peer %s provisional: %zu/%d confirms\n",
                  nickname, count, quorum);
    }

    return true;
}

/****************************
 * Handler: handle_history_diff (history_diff)
 * Phase 3 only. Receives and logs history diffs.
 ****************************/

/*@
  requires \valid(proc);
  requires \valid(queues);
  requires \valid(msg);
  requires proc->logger == \null || \valid(proc->logger);
*/
static bool handle_history_diff(const process_t *proc, directory_t *queues, generic_msg_t *msg)
{
    (void)queues;
    if (proc->protocol.phase != 3)
        return false;

    net_msg_t *nmsg = &msg->info.net_msg;
    log_debug(proc->logger, "Identity: received history diff from %s\n",
              nmsg->from_whom.nickname);

    /* Unpack JSON step list from payload */
    json_t *payload = NULL;
    if (net_msg_unpack_json(nmsg, &payload) != 0 || payload == NULL)
    {
        log_warn(proc->logger, "Identity: handle_history_diff: no JSON payload\n");
        return true;
    }

    /* Log what was received — DAG merge requires DAG infrastructure */
    size_t step_count = 0;
    if (json_is_array(payload))
        step_count = json_array_size(payload);
    else if (json_is_object(payload))
        step_count = 1;

    log_info(proc->logger,
             "Identity: received %zu history diff step(s) from %s (DAG merge pending infrastructure)\n",
             step_count, nmsg->from_whom.nickname);

    json_decref(payload);
    return true;
}

/****************************
 * Handler: handle_group_update (group_key_update)
 * Phase 3 only. Receives group address list updates and either adopts the
 * incoming group or, when we are the canonical winner, pushes our group to
 * peers via `_update_group` so the network converges.
 *
 * !!! TIEBREAKER CONSTRAINT — DO NOT REMOVE !!!
 *
 * Mirrors Python's idprocess.py::handle_group_update. Equal-size address
 * lists with differing uuids MUST be broken deterministically by uuid (the
 * smaller-uuid peer wins). The loser silently adopts; only the winner
 * re-broadcasts. Symmetric reflection on equality is the predicate that
 * produces a network-wide ID_UPDATE flood (~10k msgs/sec) — observed in a
 * civilian-demo run; see memory entry `feedback_group_update_flood.md`.
 *
 * Decision matrix:
 *   same uuid:
 *     theirs > mine  → adopt (replace map)
 *     theirs <= mine → silent no-op (NEVER echo)
 *   different uuid:
 *     theirs > mine  → adopt
 *     theirs < mine  → push our group (we are larger; canonical winner)
 *     equal size     → older group wins (ISSUES.md §3.1-b): adopt iff
 *                      theirs.created < mine.created when both ages known
 *                      and differ; else adopt iff strcmp(theirs.uuid,
 *                      mine.uuid) < 0. Otherwise push our group (we win).
 *
 * The emit-side is in _update_group; the natural call site is _add_peer
 * (via _peer_accepted) on every new admission. That path also exercises
 * this tiebreaker on the receive side.
 ****************************/

/* Frama-C: skipped —
 * identity_run + all handlers + helpers: [solver-timeout] every function copies
 * public_identity_t structs (memcpy of struct→struct triggers WP "Hide sub-term
 * definition" cast warning that blocks discharge of valid_dest/valid_src/separation).
 * Helpers also touch filesystem/network/identity stubs.
 */
/*@
  requires \valid(proc);
  requires \valid(queues);
  requires \valid(msg);
  requires proc->logger == \null || \valid(proc->logger);
*/
static bool handle_group_update(const process_t *proc, directory_t *queues, generic_msg_t *msg)
{
    if (proc->protocol.phase != 3)
        return false;

    net_msg_t *nmsg = &msg->info.net_msg;
    log_info(proc->logger, "Identity: received group update from %s\n",
             nmsg->from_whom.nickname);

    json_t *payload = NULL;
    if (net_msg_unpack_json(nmsg, &payload) != 0 || payload == NULL)
        return true; /* malformed payload — discard, do not echo */

    /* Incoming group uuid + address_map size. */
    json_t *j_uuid = json_object_get(payload, "uuid");
    const char *theirs_uuid_str = j_uuid ? json_string_value(j_uuid) : NULL;
    uuid_t theirs_uuid = {0};
    bool theirs_uuid_valid = (theirs_uuid_str != NULL
                              && uuid_parse(theirs_uuid_str, theirs_uuid) == 0);

    json_t *j_addr_map = json_object_get(payload, "address_map");
    size_t theirs_size = (j_addr_map != NULL && json_is_object(j_addr_map))
                         ? json_object_size(j_addr_map) : 0;

    /* Group age (ISSUES.md §3.1-b): the size-tie tiebreaker. Absent/non-
     * numeric defaults to 0 (unknown → uuid tiebreak). Mirrors Python
     * from_canonical's "created" default. */
    json_t *j_created = json_object_get(payload, "created");
    double theirs_created = (j_created != NULL && json_is_number(j_created))
                            ? json_number_value(j_created) : 0.0;

    /* Cross-runtime proof point: the incoming canonical group payload parsed
     * (Python's to_canonical / C's group_to_json flat form, shared field
     * names uuid/address/address_map). Logged BEFORE the adopt/no-op decision
     * so a same-group equal-size no-op (returned silently below) is still
     * observable -- otherwise a successful parse is indistinguishable from a
     * parse-failed-and-discarded one. A real uuid + nonzero address count here
     * means Python's group_key_update was canonical and C ingested it; the
     * pre-canonical ConfigJSONEncoder form would log "uuid ?, addresses 0".
     * Asserted by embedded/test-interop-cpython.sh; see project_group_key_sync. */
    log_info(proc->logger,
             "Identity: parsed incoming group update (uuid %s, addresses %zu)\n",
             theirs_uuid_str ? theirs_uuid_str : "?", theirs_size);

    /* Mine: snapshot uuid + address_map size. */
    size_t mine_size = map_size(&((process_t *)proc)->protocol.group.address_map);
    char mine_uuid_str[UUID_STRING_LEN + 1];
    uuid_unparse_lower(proc->protocol.group.uuid, mine_uuid_str);

    bool same_group = theirs_uuid_valid
                      && uuid_compare(theirs_uuid, proc->protocol.group.uuid) == 0;

    bool adopt = false;
    if (same_group)
    {
        /* Same group: adopt strictly larger membership, else silent no-op. */
        if (theirs_size > mine_size)
            adopt = true;
        else
        {
            json_decref(payload);
            return true; /* never echo on equal/smaller */
        }
    }
    else
    {
        /* Different groups: adopt strictly larger; tiebreak on uuid (smaller
         * wins). Symmetric reflection on equal size + different uuid is the
         * predicate that produces the ID_UPDATE flood — see constraint block
         * above and memory entry feedback_group_update_flood.md. */
        if (theirs_size > mine_size)
            adopt = true;
        else if (theirs_size < mine_size)
            adopt = false;
        else if (theirs_uuid_valid)
        {
            /* Size tie (ISSUES.md §3.1-b): the OLDER group wins — the more-
             * established group absorbs the younger one — so adopt theirs iff
             * it is older. Only when both carry a known age (created > 0) that
             * differs; otherwise fall back to the deterministic uuid tiebreak
             * (historical behavior, which prevents the equal-size ID_UPDATE
             * flood). "Adopt the older/larger group": larger is primary above,
             * older breaks the tie here. Mirrors Python handle_group_update. */
            double mine_created = proc->protocol.group.created;
            bool both_aged = (theirs_created > 0.0 && mine_created > 0.0);
            if (both_aged && theirs_created < mine_created)
                adopt = true; /* theirs is older -> it absorbs us */
            else if (both_aged && theirs_created > mine_created)
                adopt = false; /* theirs is younger -> we keep ours */
            else
                /* equal age or age unknown: deterministic uuid tiebreak */
                adopt = (strcmp(theirs_uuid_str, mine_uuid_str) < 0);
        }
        else
        {
            /* No comparable uuid — cannot tiebreak deterministically. Treat
             * as no-op rather than risk a flood. */
            json_decref(payload);
            return true;
        }
    }

    if (adopt)
    {
        /* Conform to Python handle_group_update's refuse branch
         * (idprocess.py): never abandon a group we can DECRYPT for a
         * DIFFERENT, public-only group we cannot. A group_key_update carries
         * the shared private key only when the sender owns it (group_to_json
         * emits public_only=false + the raw key); a public-only update for a
         * foreign uuid would leave us holding that uuid with no usable key, so
         * keep our keyed group and wait for a private-bearing full_history to
         * converge. Same-uuid public-only updates are NOT refused — those keep
         * our key while adopting the larger membership (we already retain our
         * encryptor below). See [[dod-microdrone-targets-live-vs-playback]]. */
        json_t *j_encr = json_object_get(payload, "encryptor");
        json_t *j_po = j_encr ? json_object_get(j_encr, "public_only") : NULL;
        bool theirs_public_only = (j_po == NULL) ? true : json_boolean_value(j_po);
        bool mine_owns_private = !sodium_is_zero(
            proc->protocol.group.encryptor.private, crypto_box_SECRETKEYBYTES);
        if (!same_group && theirs_public_only && mine_owns_private)
        {
            log_info(proc->logger,
                     "Identity: refusing public-only group %s over our keyed "
                     "group %s\n",
                     theirs_uuid_str ? theirs_uuid_str : "?", mine_uuid_str);
            json_decref(payload);
            return true; /* quiet no-op; keep our decryptable group, no echo */
        }

        log_info(proc->logger,
                 "Identity: adopting incoming group (uuid %s, addresses %zu)\n",
                 theirs_uuid_str ? theirs_uuid_str : "?", theirs_size);
        if (theirs_uuid_valid)
            memcpy(((process_t *)proc)->protocol.group.uuid,
                   theirs_uuid, sizeof(uuid_t));
        json_t *j_address = json_object_get(payload, "address");
        const char *incoming_addr = j_address ? json_string_value(j_address) : NULL;
        if (incoming_addr != NULL && incoming_addr[0] != '\0')
        {
            strncpy(((process_t *)proc)->protocol.group.address,
                    incoming_addr, ADDR_LEN);
            ((process_t *)proc)->protocol.group.address[ADDR_LEN] = '\0';
        }
        /* Inherit the adopted group's age (ISSUES.md §3.1-b) when known, so
         * subsequent merges compare against the established group's creation
         * epoch, not ours. Mirrors Python Group.update_from. */
        if (theirs_created > 0.0)
            ((process_t *)proc)->protocol.group.created = theirs_created;
        /* Replace address_map: free any existing entries, then ingest theirs
         * by walking the JSON object so we never need map_priv.h here. */
        if (((process_t *)proc)->protocol.group.address_map.items != NULL)
            map_free(&((process_t *)proc)->protocol.group.address_map);
        map_init(&((process_t *)proc)->protocol.group.address_map);
        if (j_addr_map != NULL && json_is_object(j_addr_map))
        {
            const char *k;
            json_t *v;
            json_object_foreach(j_addr_map, k, v)
            {
                const char *addr = json_string_value(v);
                if (k != NULL && addr != NULL)
                    group_add_address(&((process_t *)proc)->protocol.group,
                                      k, addr);
            }
        }
        /* Conform to Python branch 1 (`self.group = theirs`): when theirs
         * carries a usable key (public_only=false) OR we held no key of our
         * own, INSTALL theirs' encryptor so we end with theirs' uuid AND
         * theirs' key — not theirs' uuid paired with our stale key. The
         * remaining adopt case (same-uuid public-only update while we own the
         * key) falls through and KEEPS our encryptor — Python's
         * adopt_membership. Mirrors group_from_json's encryptor reconstruction
         * (group.c:204-225). See [[dod-microdrone-targets-live-vs-playback]]. */
        if (!theirs_public_only || !mine_owns_private)
        {
            json_t *encr_obj = json_object_get(payload, "encryptor");
            const char *seed_hex = encr_obj
                ? json_string_value(json_object_get(encr_obj, "hex_seed"))
                : NULL;
            if (seed_hex != NULL)
            {
                if (theirs_public_only)
                    public_encryptor_init(
                        &((process_t *)proc)->protocol.group.encryptor,
                        (const unsigned char *)seed_hex, strlen(seed_hex));
                else
                    encryptor_init_from_private(
                        &((process_t *)proc)->protocol.group.encryptor,
                        (const unsigned char *)seed_hex, strlen(seed_hex));
            }
        }
        /* Mirror Python's _record_group: push GROUP state to local processes. */
        generic_msg_t group_msg = {0};
        group_msg.type = GROUP;
        memcpy(&group_msg.info.group, &proc->protocol.group, sizeof(group_t));
        _remember_activity(proc, queues, &group_msg);
        json_decref(payload);
        return true;
    }

    /* We are the canonical winner — push our group to peers so they converge.
     * Never reached on same-uuid equal-size (returned silent no-op above), so
     * cannot participate in the flood. */
    json_decref(payload);
    _update_group(proc, queues);
    return true;
}

/****************************
 * Handler: handle_caps_query (peer_caps_query)
 *
 * Look up the test-installed own-capability allowlist for this
 * process and emit it as a JSON array in a caps_response back to
 * the sender. Mirrors Python's handle_caps_query (idprocess.py:798
 * — reads `self.capabilities.to_list()`, emits as JSON-array
 * payload). When no allowlist is installed, emits an empty array;
 * the receiver's handle_caps_response treats that as a no-op.
 ****************************/

/* Frama-C: skipped — JSON + messaging stubs. */
static bool handle_caps_query(const process_t *proc, directory_t *queues, generic_msg_t *msg)
{
    (void)queues;
    net_msg_t *nmsg = &msg->info.net_msg;
    log_debug(proc->logger, "Identity: caps_query from %s\n",
              nmsg->from_whom.nickname);

    /* Build a JSON array of own capability names from the test-installed
     * allowlist for this process (NULL → empty array). */
    json_t *caps_arr = json_array();
    array_t *own = _id_own_caps_for(proc);
    if (own != NULL)
    {
        pthread_mutex_lock(&id_state.lock);
        for (size_t i = 0; i < array_size(own); i++)
        {
            data_t *str_dat = NULL;
            if (array_get(own, i, &str_dat) != 0 || str_dat == NULL) continue;
            char *cap_name = NULL;
            if (data_string_ptr(str_dat, &cap_name) != 0 || cap_name == NULL)
                continue;
            json_array_append_new(caps_arr, json_string(cap_name));
        }
        pthread_mutex_unlock(&id_state.lock);
    }

    generic_msg_t response = {0};
    response.type = NET_MESSAGE;
    strncpy(response.info.net_msg.process, "identity", PROC_NAME_LEN);
    response.info.net_msg.function = ID_CAPS_RESPONSE;
    response.info.net_msg.encrypt = true;
    memcpy(&response.info.net_msg.to_whom, &nmsg->from_whom,
           sizeof(public_identity_t));
    strncpy(response.info.net_msg.return_to, "identity", PROC_NAME_LEN);
    net_msg_pack_json(&response.info.net_msg, caps_arr);
    json_decref(caps_arr);
    messaging_send("network", NET_MESSAGE, &response, false);
    return true;
}

/* Strict bounds on capability-descriptor fields received over the wire.
 * A descriptor is untrusted peer input, so cap every string/collection to
 * keep a malicious or buggy peer from inflating memory / slowing parsing.
 * Oversized values are truncated/dropped, not rejected. MUST stay in lockstep
 * with Python capabilities.sanitize_descriptor (MAX_DESCRIPTION_LEN etc.). */
#define AT_DESC_MAX_DESCRIPTION_LEN  256
#define AT_DESC_MAX_KIND_LEN          32
#define AT_DESC_MAX_ARG_SCHEMA_ENTRIES 32
#define AT_DESC_MAX_ARG_KEY_LEN       64
#define AT_DESC_MAX_ARG_VALUE_LEN     64

/* Build a size-bounded descriptor object from an untrusted caps_response item.
 * Returns a NEW json reference (caller decrefs) holding only the recognized,
 * clamped keys (required_tier/description/kind/arg_schema) — `name` is excluded
 * (the caller keys the map by it). Returns NULL if nothing worth storing.
 * Mirrors Python capabilities.sanitize_descriptor. */
/* Frama-C: skipped — JSON sanitation. */
static json_t *_sanitize_descriptor(json_t *item)
{
    if (!json_is_object(item)) return NULL;
    json_t *clean = json_object();
    if (clean == NULL) return NULL;

    /* required_tier: int only. jansson json_is_integer() is false for
     * booleans, so this naturally rejects bool-as-int like Python does. */
    json_t *rt = json_object_get(item, "required_tier");
    if (json_is_integer(rt))
        json_object_set_new(clean, "required_tier",
                            json_integer(json_integer_value(rt)));

    json_t *desc = json_object_get(item, "description");
    if (json_is_string(desc))
    {
        const char *s = json_string_value(desc);
        if (s != NULL && s[0] != '\0')
        {
            char b[AT_DESC_MAX_DESCRIPTION_LEN + 1];
            strncpy(b, s, AT_DESC_MAX_DESCRIPTION_LEN);
            b[AT_DESC_MAX_DESCRIPTION_LEN] = '\0';
            json_object_set_new(clean, "description", json_string(b));
        }
    }

    json_t *kind = json_object_get(item, "kind");
    if (json_is_string(kind))
    {
        const char *s = json_string_value(kind);
        if (s != NULL && s[0] != '\0')
        {
            char b[AT_DESC_MAX_KIND_LEN + 1];
            strncpy(b, s, AT_DESC_MAX_KIND_LEN);
            b[AT_DESC_MAX_KIND_LEN] = '\0';
            json_object_set_new(clean, "kind", json_string(b));
        }
    }

    json_t *schema = json_object_get(item, "arg_schema");
    if (json_is_object(schema) && json_object_size(schema) > 0)
    {
        json_t *bounded = json_object();
        if (bounded != NULL)
        {
            const char *k = NULL;
            json_t *v = NULL;
            size_t cnt = 0;
            json_object_foreach(schema, k, v)
            {
                if (cnt >= AT_DESC_MAX_ARG_SCHEMA_ENTRIES) break;
                char kb[AT_DESC_MAX_ARG_KEY_LEN + 1];
                strncpy(kb, k, AT_DESC_MAX_ARG_KEY_LEN);
                kb[AT_DESC_MAX_ARG_KEY_LEN] = '\0';
                if (json_is_string(v))
                {
                    const char *vs = json_string_value(v);
                    char vb[AT_DESC_MAX_ARG_VALUE_LEN + 1];
                    strncpy(vb, vs != NULL ? vs : "", AT_DESC_MAX_ARG_VALUE_LEN);
                    vb[AT_DESC_MAX_ARG_VALUE_LEN] = '\0';
                    json_object_set_new(bounded, kb, json_string(vb));
                }
                else
                {
                    /* non-string value: keep as-is (Python passes it through) */
                    json_object_set(bounded, kb, v);
                }
                cnt++;
            }
            if (json_object_size(bounded) > 0)
                json_object_set_new(clean, "arg_schema", bounded);
            else
                json_decref(bounded);
        }
    }

    if (json_object_size(clean) == 0)
    {
        json_decref(clean);
        return NULL;
    }
    return clean;
}

/****************************
 * Handler: handle_caps_response (peer_caps_response)
 *
 * Tolerant parse: each array item is either a legacy bare capability NAME
 * (JSON string) or a descriptor OBJECT {name, required_tier, description,
 * kind, arg_schema} (PIV_MFA_OPERATOR_ACCESS_PLAN.md §3.5). Names register
 * under the sender's uuid in id_state.peer_caps_map (per-cap count observed
 * via identity_get_peer_caps_count); descriptors are size-bounded
 * (_sanitize_descriptor) and stored by cap name in peer_cap_descriptors_map
 * (observed via identity_get_peer_cap_descriptor). Mirrors Python's
 * handle_caps_response (idprocess.py — tolerant item parse + descriptor
 * registration). A receiver MUST accept both forms; a bare string carries
 * only the name.
 ****************************/

/* Frama-C: skipped — JSON parsing + map mutation. */
static bool handle_caps_response(const process_t *proc, directory_t *queues, generic_msg_t *msg)
{
    (void)queues;
    net_msg_t *nmsg = &msg->info.net_msg;
    log_debug(proc->logger, "Identity: caps_response from %s\n",
              nmsg->from_whom.nickname);

    json_t *payload = NULL;
    if (net_msg_unpack_json(nmsg, &payload) != 0 || payload == NULL)
    {
        log_warn(proc->logger,
                 "Identity: handle_caps_response: no JSON payload\n");
        return true;
    }
    if (!json_is_array(payload))
    {
        json_decref(payload);
        log_warn(proc->logger,
                 "Identity: handle_caps_response: payload not a JSON array\n");
        return true;
    }

    array_t *arr = NULL;
    if (array_create(&arr) != 0 || arr == NULL)
    {
        json_decref(payload);
        return true;
    }
    size_t n = json_array_size(payload);
    for (size_t i = 0; i < n; i++)
    {
        json_t *item = json_array_get(payload, i);
        const char *name = NULL;
        json_t *desc_src = NULL;   /* non-NULL only for the object form */
        if (json_is_string(item))
        {
            name = json_string_value(item);
        }
        else if (json_is_object(item))
        {
            json_t *nm = json_object_get(item, "name");
            if (json_is_string(nm))
            {
                name = json_string_value(nm);
                desc_src = item;
            }
        }
        if (name == NULL) continue;   /* malformed item: skip */

        size_t len = strlen(name);
        char *dup = smrt_create(len + 1);
        if (dup == NULL) continue;
        memcpy(dup, name, len + 1);
        data_t *str_dat = string_data(dup, len + 1);
        if (str_dat == NULL) { smrt_deref(dup); continue; }
        array_append(arr, str_dat);

        /* Object form: record the size-bounded descriptor keyed by cap name.
         * An empty/None descriptor is ignored so a legacy name-only item never
         * clobbers a known descriptor (Python register_descriptor semantics). */
        if (desc_src != NULL)
        {
            json_t *clean = _sanitize_descriptor(desc_src);
            if (clean != NULL)
            {
                char *djson = json_dumps(clean, JSON_COMPACT | JSON_SORT_KEYS);
                json_decref(clean);
                if (djson != NULL)
                {
                    size_t dl = strlen(djson);
                    char *ddup = smrt_create(dl + 1);
                    if (ddup != NULL)
                    {
                        memcpy(ddup, djson, dl + 1);
                        data_t *ddat = string_data(ddup, dl + 1);
                        if (ddat != NULL)
                        {
                            pthread_mutex_lock(&id_state.lock);
                            map_set(&id_state.peer_cap_descriptors_map,
                                    (map_key_t)name, ddat);
                            pthread_mutex_unlock(&id_state.lock);
                        }
                        else
                        {
                            smrt_deref(ddup);
                        }
                    }
                    free(djson);   /* jansson json_dumps() uses malloc */
                }
            }
        }
    }
    json_decref(payload);

    char uuid_str[UUID_STRING_LEN + 1];
    uuid_unparse_lower(nmsg->from_whom.uuid, uuid_str);
    data_t *arr_dat = object_ptr_data(arr, sizeof(array_t));
    pthread_mutex_lock(&id_state.lock);
    map_set(&id_state.peer_caps_map, uuid_str, arr_dat);
    pthread_mutex_unlock(&id_state.lock);

    log_debug(proc->logger,
              "Identity: registered %zu cap(s) for peer %s\n",
              array_size(arr), uuid_str);
    return true;
}

/****************************
 * Handler: tier_update
 * Local-only IPC from ReputationProcess. Payload is a 2-element JSON
 * array `[peer_uuid_str, new_tier_int]`. Mirrors Python's
 * handle_tier_update (idprocess.py). Updates the peer_tiers map (or
 * self_tier if the payload targets us); negotiation's tier-gate then
 * consults these for capability access decisions.
 ****************************/

/*@
  requires \valid(proc);
  requires \valid(queues);
  requires \valid(msg);
  requires proc->logger == \null || \valid(proc->logger);
*/
static bool handle_tier_update(const process_t *proc, directory_t *queues, generic_msg_t *msg)
{
    (void)queues;
    net_msg_t *nmsg = &msg->info.net_msg;

    json_t *payload = NULL;
    if (net_msg_unpack_json(nmsg, &payload) != 0 || payload == NULL)
    {
        log_warn(proc->logger, "Identity: handle_tier_update: no JSON payload\n");
        return true;
    }
    if (!json_is_array(payload) || json_array_size(payload) < 2)
    {
        json_decref(payload);
        log_warn(proc->logger, "Identity: handle_tier_update: bad payload shape\n");
        return true;
    }
    const char *peer_uuid_str = json_string_value(json_array_get(payload, 0));
    json_t *j_tier = json_array_get(payload, 1);
    if (peer_uuid_str == NULL || !json_is_integer(j_tier))
    {
        json_decref(payload);
        log_warn(proc->logger, "Identity: handle_tier_update: bad field types\n");
        return true;
    }
    int new_tier = (int)json_integer_value(j_tier);

    /* Detect self-target by comparing against our own identity uuid from
     * proc->configs["identity"]. Mirrors Python idprocess.py. */
    bool is_self = false;
    char self_str[UUID_STRING_LEN + 1] = {0};
    data_t *id_dat = NULL;
    char id_key[] = "identity";
    if (map_get(proc->configs, id_key, &id_dat) == 0 && id_dat != NULL)
    {
        config_t *id_cfg = NULL;
        if (data_object_ptr(id_dat, (void **)&id_cfg) == 0 &&
            id_cfg != NULL && id_cfg->data_struct != NULL)
        {
            const public_identity_t *me =
                (const public_identity_t *)id_cfg->data_struct;
            uuid_unparse_lower(me->uuid, self_str);
            if (strncmp(self_str, peer_uuid_str, UUID_STRING_LEN) == 0)
                is_self = true;
        }
    }

    /* map_set takes `char *const` for the key; copy into a writable
     * local before insertion. The map dups the key internally so the
     * stack-local is safe to drop afterward. */
    char key_buf[UUID_STRING_LEN + 1];
    strncpy(key_buf, peer_uuid_str, UUID_STRING_LEN);
    key_buf[UUID_STRING_LEN] = '\0';

    pthread_mutex_lock(&id_state.lock);
    if (is_self) {
        id_state.self_tier = new_tier;
    } else {
        data_t *tier_dat = integer_data(new_tier);
        if (tier_dat != NULL)
            map_set(&id_state.peer_tiers, key_buf, tier_dat);
    }
    pthread_mutex_unlock(&id_state.lock);

    log_debug(proc->logger, "Identity: tier update for %s -> %d%s\n",
              key_buf, new_tier, is_self ? " (self)" : "");
    json_decref(payload);
    return true;
}

int identity_get_peer_tier(const uuid_t uuid)
{
    if (!id_state.initialized) return 0;
    char uuid_str[UUID_STRING_LEN + 1];
    uuid_unparse_lower(uuid, uuid_str);
    pthread_mutex_lock(&id_state.lock);
    int tier = 0;
    data_t *dat = NULL;
    if (map_get(&id_state.peer_tiers, uuid_str, &dat) == 0 && dat != NULL)
        data_integer(dat, &tier);
    pthread_mutex_unlock(&id_state.lock);
    return tier;
}

int identity_get_self_tier(void)
{
    if (!id_state.initialized) return 0;
    pthread_mutex_lock(&id_state.lock);
    int r = id_state.self_tier;
    pthread_mutex_unlock(&id_state.lock);
    return r;
}

size_t identity_get_partition_recovery_target(char *out, size_t out_len)
{
    if (out == NULL || out_len == 0) return 0;
    if (!id_state.initialized) {
        out[0] = '\0';
        return 0;
    }
    pthread_mutex_lock(&id_state.lock);
    size_t n = strnlen(id_state.partition_recovery_target,
                       sizeof(id_state.partition_recovery_target));
    if (n >= out_len) n = out_len - 1;
    memcpy(out, id_state.partition_recovery_target, n);
    out[n] = '\0';
    pthread_mutex_unlock(&id_state.lock);
    return n;
}

int identity_partition_canonical_probe(const char *group_uuid,
                                       int group_size,
                                       char *out, size_t out_len)
{
    if (group_uuid == NULL || out == NULL || out_len == 0) return -1;
    int n = snprintf(out, out_len, "%s|%d", group_uuid, group_size);
    if (n < 0 || (size_t)n >= out_len) return -1;
    return n;
}

int identity_partition_canonical_response(const char *group_uuid,
                                          int group_size,
                                          const char *in_response_to,
                                          char *out, size_t out_len)
{
    if (group_uuid == NULL || in_response_to == NULL
        || out == NULL || out_len == 0) return -1;
    int n = snprintf(out, out_len, "%s|%d|%s", group_uuid, group_size,
                     in_response_to);
    if (n < 0 || (size_t)n >= out_len) return -1;
    return n;
}

/****************************
 * Pre-loop: acquire capabilities and announce
 ****************************/

static int _acquire_capabilities(const process_t *proc, directory_t *queues)
{
    /* Scale the base 10s wait by the slowest peer's RTT so nodes reachable
     * only via DTN (multi-minute bundle RTTs) still complete capability
     * exchange without tripping this deadline. See utilities/timeout.h. */
    int timeout_ms = at_timeout_scale_ms(10000, proc);
    int elapsed = 0;
    while (elapsed < timeout_ms)
    {
        generic_msg_t buf = {0};
        int err = messaging_recv(&buf);
        if (err == 0)
            run_message_handlers((process_t *)proc, queues, buf.type, &buf);
        if (proc->protocol.peer_capabilities != NULL)
            break;
        usleep(100000);
        elapsed += 100;
    }
    return 0;
}

/* Frama-C: skipped — [solver-timeout] JSON + identity preconditions */
/* Build the operator-attended attestation for the request_access DATA payload
 * (ethne D8/Q9), mirroring Python IdentityProcess._operator_attestation: emit
 * only the non-default fields (a plain node contributes an empty {} so the
 * payload stays backward-compatible). The ZTA binding rides here because it is
 * NOT on the envelope — this payload is also what delivers the verifiable
 * credential to the welcoming committee. Bytes are base64 (VARIANT_ORIGINAL ==
 * Python base64.b64encode). Returns a new json object (never NULL on success). */
static json_t *_operator_attestation_json(const public_identity_t *pub)
{
    json_t *att = json_object();
    if (att == NULL || pub == NULL)
        return att;
    if (pub->operator_bound)
        json_object_set_new(att, "operator_bound", json_true());
    if (pub->operator_attested_at > 0.0)
        json_object_set_new(att, "operator_attested_at",
                            json_real(pub->operator_attested_at));
#ifdef AT_ZTA_ENABLED
    if (pub->zta_issuer[0] != '\0')
        json_object_set_new(att, "zta_issuer", json_string(pub->zta_issuer));
    if (pub->zta_credential_len > 0 && pub->zta_credential != NULL) {
        size_t hlen = b64_encoded_len(sizeof(pub->zta_credential_hash));
        char *hb64 = malloc(hlen);
        if (hb64 != NULL) {
            base64_encode(pub->zta_credential_hash, sizeof(pub->zta_credential_hash),
                          hb64, hlen);
            json_object_set_new(att, "zta_credential_hash", json_string(hb64));
            free(hb64);
        }
        size_t clen = b64_encoded_len(pub->zta_credential_len);
        char *cb64 = malloc(clen);
        if (cb64 != NULL) {
            base64_encode(pub->zta_credential, pub->zta_credential_len, cb64, clen);
            json_object_set_new(att, "zta_credential", json_string(cb64));
            free(cb64);
        }
    }
#endif
    return att;
}

/* Copy the request_access attestation dict onto a newly-announced peer identity
 * (inverse of _operator_attestation_json; mirror of Python
 * _apply_operator_attestation). The advertised operator_bound is copied only as
 * a claim — the welcoming committee overwrites it with the verified result. */
static void _apply_operator_attestation_json(const json_t *att, public_identity_t *pub)
{
    if (att == NULL || pub == NULL || !json_is_object(att))
        return;
    pub->operator_bound = json_is_true(json_object_get(att, "operator_bound"));
    json_t *oa = json_object_get(att, "operator_attested_at");
    pub->operator_attested_at = json_is_number(oa) ? json_number_value(oa) : 0.0;
#ifdef AT_ZTA_ENABLED
    const char *iss = json_string_value(json_object_get(att, "zta_issuer"));
    if (iss != NULL)
        snprintf(pub->zta_issuer, sizeof(pub->zta_issuer), "%s", iss);
    const char *hb64 = json_string_value(json_object_get(att, "zta_credential_hash"));
    if (hb64 != NULL)
        base64_decode(hb64, strlen(hb64),
                      pub->zta_credential_hash, sizeof(pub->zta_credential_hash));
    const char *cb64 = json_string_value(json_object_get(att, "zta_credential"));
    if (cb64 != NULL) {
        size_t declen = b64_decoded_len_s(strlen(cb64), cb64);
        if (declen > 0 && declen <= ZTA_CRED_MAX) {
            if (pub->zta_credential != NULL) {  /* free prior to avoid a leak */
                free(pub->zta_credential);
                pub->zta_credential = NULL;
                pub->zta_credential_len = 0;
            }
            pub->zta_credential = malloc(declen);
            if (pub->zta_credential != NULL) {
                base64_decode(cb64, strlen(cb64), pub->zta_credential, declen);
                pub->zta_credential_len = declen;
            }
        }
    }
#endif
}

#ifdef AT_ZTA_ENABLED
/* True iff the credential is operator-class: it chain-verifies against the
 * DISTINCT operator trust anchor AND its sha256 matches the advertised hash
 * (ethne D8/Q9). Non-forgeable (derived from verification, never the advertised
 * bool) and fail-safe (no anchor / no match / not verified -> false). Mirror of
 * Python IdentityProcess._is_operator_credential. Issuer-based markers are NOT
 * used (a distinct anchor is the agreed discriminator). */
static bool _is_operator_credential(const zta_policy_t *policy,
                                    const uint8_t *cred, size_t cred_len,
                                    const uint8_t *advertised_hash)
{
    if (cred == NULL || cred_len == 0)
        return false;
    uint8_t actual[crypto_hash_sha256_BYTES];
    crypto_hash_sha256(actual, cred, cred_len);
    bool adv_present = false;
    for (size_t i = 0; i < sizeof(actual); i++)
        if (advertised_hash[i] != 0) { adv_present = true; break; }
    if (adv_present && sodium_memcmp(actual, advertised_hash, sizeof(actual)) != 0)
        return false;
    zta_verifier_t *op = NULL;
    if (zta_policy_create_operator_verifier(policy, &op) != 0 || op == NULL)
        return false;
    zta_result_t r;
    memset(&r, 0, sizeof(r));
    op->verify_credential(op, cred, cred_len, &r);
    bool ok = (r.status == ZTA_VERIFIED);
    op->destroy(op);
    return ok;
}
#endif

static int _build_announcement(const process_t *proc, generic_msg_t *buf)
{
    memset(buf, 0, sizeof(generic_msg_t));
    buf->type = NET_MESSAGE;
    strncpy(buf->info.net_msg.process, "identity", PROC_NAME_LEN);
    buf->info.net_msg.function = ID_ANNOUNCE;
    buf->info.net_msg.encrypt = false; /* Broadcast is unencrypted */

    /* Get own identity from config */
    data_t *id_dat = NULL;
    char id_key[] = "identity";
    if (map_get(proc->configs, id_key, &id_dat) == 0)
    {
        config_t *id_cfg = NULL;
        if (data_object_ptr(id_dat, (void **)&id_cfg) == 0 && id_cfg->data_struct != NULL)
        {
            public_identity_t *pub = NULL;
            identity_publish((const identity_t *)id_cfg->data_struct, &pub);
            if (pub != NULL)
            {
                memcpy(&buf->info.net_msg.from_whom, pub, sizeof(public_identity_t));
                smrt_deref(pub);
            }
        }
    }

    /* DRY request_access payload: identity rides the envelope from_*
     * fields (stamped above + by net_proc on outbound) — the canonical,
     * cross-runtime identity representation. The payload carries only the
     * request-specific extras [package_hash, capabilities], matching
     * Python's _broadcast_request_access (idprocess.py). Without a payload
     * Python's welcoming_committee (which does `ph, caps =
     * from_json_string(obj)`) would choke; emit the 2-element array so the
     * two runtimes parse identically. The C node has no package-hash
     * concept, so slot 0 is the empty string (Python treats an empty peer
     * hash as "unknown" and skips its counterfeit check — see
     * welcoming_committee). Slot 1 is this node's own capability names. */
    json_t *payload = json_array();
    if (payload != NULL) {
        json_array_append_new(payload, json_string(""));  /* package_hash */
        json_t *caps_arr = json_array();
        array_t *own = _id_own_caps_for(proc);
        if (own != NULL) {
            pthread_mutex_lock(&id_state.lock);
            for (size_t i = 0; i < array_size(own); i++) {
                data_t *str_dat = NULL;
                if (array_get(own, i, &str_dat) != 0 || str_dat == NULL) continue;
                char *cap_name = NULL;
                if (data_string_ptr(str_dat, &cap_name) != 0 || cap_name == NULL)
                    continue;
                json_array_append_new(caps_arr, json_string(cap_name));
            }
            pthread_mutex_unlock(&id_state.lock);
        }
        json_array_append_new(payload, caps_arr);
        /* Slot 2 (optional): operator-attended attestation (ethne D8/Q9),
         * built from this node's own identity (already in from_whom above). A
         * plain node emits an empty {} so Python's arity-tolerant unpack still
         * reads [package_hash, capabilities]. Mirrors Python
         * _broadcast_request_access appending _operator_attestation(). */
        json_array_append_new(payload,
                              _operator_attestation_json(&buf->info.net_msg.from_whom));
        net_msg_pack_json(&buf->info.net_msg, payload);
        json_decref(payload);
    }

    /* Set broadcast recipient (to_whom empty = broadcast) */
    strncpy(buf->info.net_msg.return_to, "identity", PROC_NAME_LEN);
    return 0;
}

/* Parity wrapper for Python's `_broadcast_request_access`
 * (idprocess.py:219-227). Builds and emits the request_access envelope
 * on the open channel — used both by the Phase 1→2 initial announce
 * AND by the group-merge recovery path in `_merge_to_mesh` to
 * re-broadcast without a phase change. */
/* Frama-C: skipped — [solver-timeout] logging/snprintf/json preconditions */
static int _announce_identity(const process_t *proc, directory_t *queues)
{
    data_t net = STRING_DATA("network");
    if (!array_contains(queues, &net))
        return EXCEPTION(EID_NOQ);

    generic_msg_t buf = {0};
    _build_announcement(proc, &buf);

    /* Retry until network process IPC socket is ready */
    int ret = -1;
    for (int attempt = 0; attempt < 20; attempt++)
    {
        ret = messaging_send("network", NET_MESSAGE, &buf, false);
        if (ret == 0)
            break;
        log_debug(proc->logger, "Identity: network not ready, retrying (%d)...\n", attempt);
        usleep(100000); /* 100ms */
    }

    if (ret != 0)
    {
        log_error(proc->logger, "Identity: failed to send announcement to network\n");
        return ret;
    }

    log_info(proc->logger, "Identity: announced self to network\n");
    return 0;
}

/****************************
 * Identity process main entry
 ****************************/

/* Frama-C: skipped —
 * identity_run + all handlers + helpers: [solver-timeout] every function copies
 * public_identity_t structs (memcpy of struct→struct triggers WP "Hide sub-term
 * definition" cast warning that blocks discharge of valid_dest/valid_src/separation).
 */
/****************************
 * Partition recovery (doc/architecture/partition-recovery.md).
 *
 * Cross-impl parity notes (read first if touching either side):
 *
 * 1. The signature wire format is hex-encoded raw Ed25519
 *    (`crypto_sign_detached` → 64 bytes → hexlify → 128 ASCII chars).
 *    Python's `signed.signature` already produces this hex form via
 *    nacl's HexEncoder; both sides put the same ASCII string in the
 *    `signature` field of the JSON payload.
 *
 * 2. The canonical signature inputs MUST byte-match Python's
 *    `IdentityProcess._partition_probe_canonical` /
 *    `_partition_response_canonical`. Python format:
 *      probe:    "{group_uuid}|{group_size}"           (no spaces)
 *      response: "{group_uuid}|{group_size}|{in_response_to}"
 *    Use `snprintf` with `"%s|%d"` / `"%s|%d|%s"` exactly.
 *
 * 3. Cooldown timestamps use `CLOCK_MONOTONIC` microseconds — not
 *    wall-clock — so NTP / DST adjustments don't invalidate them.
 *
 * 4. The Python side accepts size-tie merges using lexicographic uuid
 *    comparison (smaller uuid wins). C must use the same: `strcmp`
 *    on the uuid hex strings.
 ****************************/

/* Cooldown window constants (seconds → microseconds for the map). */
#define PARTITION_PROBE_COOLDOWN_US      (10LL * 1000LL * 1000LL)
#define PARTITION_RESPONSE_COOLDOWN_US   (30LL * 1000LL * 1000LL)
#define PARTITION_RECOVERY_TIMEOUT_US    (15LL * 1000LL * 1000LL)

static int64_t _partition_now_us(void)
{
    struct timespec ts;
    if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0) return 0;
    return (int64_t)ts.tv_sec * 1000000LL + (int64_t)ts.tv_nsec / 1000LL;
}

/* Check cooldown map for `key`; return true (and update the stamp) if
 * the call is permitted, false if still within `threshold_us`. Caller
 * must hold id_state.lock. */
static bool _partition_cooldown_check(map_t *cooldown_map, const char *key,
                                      int64_t threshold_us)
{
    int64_t now_us = _partition_now_us();
    data_t *prev = NULL;
    if (map_get(cooldown_map, (map_key_t)key, &prev) == 0 && prev != NULL) {
        int prev_int = 0;
        /* We store seconds-truncated ints to fit the existing
         * integer_data() helper; that gives ~2s granularity in the
         * worst case, which is well below the 5s/10s/30s thresholds. */
        if (data_integer(prev, &prev_int) == 0) {
            int64_t prev_us = (int64_t)prev_int * 1000000LL;
            if (now_us - prev_us < threshold_us)
                return false;
        }
    }
    char key_buf[128];
    snprintf(key_buf, sizeof(key_buf), "%s", key);
    data_t *now_dat = integer_data((int)(now_us / 1000000LL));
    if (now_dat != NULL)
        map_set(cooldown_map, key_buf, now_dat);
    return true;
}

/* Returns true iff a recovery is currently in flight and not yet
 * timed out. Auto-clears stale state. Caller must hold id_state.lock. */
static bool _partition_recovery_active_locked(void)
{
    if (id_state.partition_recovery_target[0] == '\0')
        return false;
    int64_t now_us = _partition_now_us();
    if (now_us - id_state.partition_recovery_started_us
            >= PARTITION_RECOVERY_TIMEOUT_US) {
        id_state.partition_recovery_target[0] = '\0';
        id_state.partition_recovery_started_us = 0;
        return false;
    }
    return true;
}

/* Resolve our local identity from proc->configs. Returns NULL on
 * failure (which the handlers treat as bootstrap-incomplete and
 * silently skip — same as Python's `self.identity is None` guard
 * implicit in choose_group). */
static const identity_t *_partition_self_identity(const process_t *proc)
{
    if (proc == NULL || proc->configs == NULL) return NULL;
    data_t *id_dat = NULL;
    char id_key[] = "identity";
    if (map_get(proc->configs, id_key, &id_dat) != 0 || id_dat == NULL)
        return NULL;
    config_t *id_cfg = NULL;
    if (data_object_ptr(id_dat, (void **)&id_cfg) != 0 || id_cfg == NULL)
        return NULL;
    return (const identity_t *)id_cfg->data_struct;
}

/* Sign `canonical[0..clen)` with our identity's private key, write the
 * hex-encoded 64-byte signature to `hex_out` (must be >= 129 bytes).
 * Returns 0 on success, -1 on failure. */
static int _partition_sign_hex(const identity_t *ident,
                               const unsigned char *canonical, size_t clen,
                               char hex_out[129])
{
    if (ident == NULL || canonical == NULL || hex_out == NULL) return -1;
    unsigned char sig[crypto_sign_BYTES];
    if (crypto_sign_detached(sig, NULL, canonical, clen,
                             ident->signature.private) != 0)
        return -1;
    hexlify(sig, crypto_sign_BYTES, (unsigned char *)hex_out);
    return 0;
}

/* Hex-decode `hex_in` (128 chars) into a 64-byte signature buffer and
 * verify it against `canonical[0..clen)` using the embedded public
 * signing key in `pub`. Returns 0 on valid signature, -1 otherwise. */
static int _partition_verify_hex(const public_identity_t *pub,
                                 const unsigned char *canonical, size_t clen,
                                 const char *hex_in)
{
    if (pub == NULL || canonical == NULL || hex_in == NULL) return -1;
    size_t hlen = strnlen(hex_in, 130);
    if (hlen != crypto_sign_BYTES * 2) return -1;
    unsigned char sig[crypto_sign_BYTES];
    if (unhexlify((const unsigned char *)hex_in, hlen, sig) != 0)
        return -1;
    if (crypto_sign_verify_detached(sig, canonical, clen,
                                    pub->signature.public) != 0)
        return -1;
    return 0;
}

/* Local helper to emit a fully-built net_msg via the network process.
 * Returns 0 on success. Mirrors the messaging_send pattern used by
 * _announce_identity. */
static int _partition_broadcast(const process_t *proc, generic_msg_t *buf)
{
    int ret = messaging_send("network", NET_MESSAGE, buf, false);
    if (ret != 0) {
        log_error(proc->logger,
                  "Identity: partition-recovery: messaging_send failed (%d)\n",
                  ret);
    }
    return ret;
}

/****************************
 * Helper: _periodic_caps_resync
 *
 * Periodic backstop for the late-joiner capability-loss UDP case. Mirrors
 * Python's IdentityProcess._periodic_caps_resync (idprocess.py) — see
 * memory feedback_late_joiner_caps, layer 7.
 *
 * The confirm-time directed caps_query (handle_confirm_peer →
 * _send_caps_query) recovers a peer whose announce was lost, but it is a
 * ONE-SHOT; if that query OR its caps_response is also dropped over UDP,
 * the peer stays in proc->protocol.peers[] yet absent from
 * id_state.peer_caps_map — invisible to cap-driven discovery. This sweep
 * re-sends caps_query to every admitted peer with ZERO registered caps.
 *
 * Self-limiting: a peer with any cap is skipped, so a converged group
 * emits nothing. Reuses the existing reliable directed query/response —
 * NO new wire message, so Python/C wire parity (conformance corpus) is
 * unaffected. Bounded at CAPS_RESYNC_MAX_PER_SWEEP so a large degraded
 * group can't burst the network queue. Cap-less peers are snapshotted
 * under the peers read-lock (cap-count check nests id_state.lock, which
 * is safe: no path holds id_state.lock then takes the peers write-lock),
 * then queried after the lock is released.
 ****************************/
void identity_periodic_caps_resync(const process_t *proc)
{
    if (proc == NULL) return;
    /* Only when operational and actually in a group (mirror Python's
     * `phase == 3 and group is not None and not choosing`). */
    if (proc->protocol.phase != 3) return;
    if (proc->protocol.group.uuid[0] == 0
        && map_size(&((process_t *)proc)->protocol.group.address_map) == 0)
        return;
    pthread_mutex_lock(&id_state.lock);
    bool choosing = id_state.choosing_group;
    pthread_mutex_unlock(&id_state.lock);
    if (choosing) return;

    const identity_t *self = _partition_self_identity(proc);

    public_identity_t capless[CAPS_RESYNC_MAX_PER_SWEEP];
    size_t cnt = 0;
    peers_read_lock(proc);
    size_t n = proc->protocol.num_peers;
    for (size_t i = 0; i < n && cnt < CAPS_RESYNC_MAX_PER_SWEEP; i++) {
        const public_identity_t *peer = &proc->protocol.peers[i];
        if (self != NULL && uuid_compare(peer->uuid, self->uuid) == 0)
            continue;
        if (identity_get_peer_caps_count(peer->uuid) > 0)
            continue;
        memcpy(&capless[cnt++], peer, sizeof(public_identity_t));
    }
    peers_read_unlock(proc);

    for (size_t i = 0; i < cnt; i++)
        _send_caps_query(proc, &capless[i]);
    if (cnt > 0) {
        char cnt_str[16];
        snprintf(cnt_str, sizeof(cnt_str), "%zu", cnt);
        probes_counter("peer.set", "caps_resync_query", cnt_str);
        log_debug(proc->logger,
                  "Identity: caps resync re-queried %zu cap-less peer(s)\n",
                  cnt);
    }
}

/****************************
 * Helper: _group_has_address
 * True iff @p addr appears as a value in the group's address_map. Used by
 * handle_identity_response to gate backfilled identities to actual group
 * members (a stray broadcaster's response can't inject itself into peers[]).
 * Mirrors Python's `addr in list(self.group.addresses)` test.
 ****************************/
static bool _group_has_address(group_t *group, const char *addr)
{
    if (group == NULL || addr == NULL || addr[0] == '\0') return false;
    bool found = false;
    map_key_t key;
    data_t *value;
    map_entries_for_each(&group->address_map, key, value)
        string_t a = NULL;
        if (data_string_ptr(value, &a) == 0 && a != NULL && strcmp(a, addr) == 0)
            found = true;
    map_end_for_each
    return found;
}

/****************************
 * Periodic: identity_periodic_identity_resync
 *
 * Cold/late-joiner identity-loss backstop. A node that adopted a group via
 * the merge/partition path holds the members' ADDRESSES (group.address_map)
 * but not their full Identities (peers[] stays sparse — only the welcomer's
 * bundled identities ever landed). Without the identities it can't name
 * consensus reputations for those members. Broadcasts a peer_identity_query
 * listing our group uuid + the uuids we already hold; same-group members not
 * in that have-list reply with their published identity (handle_identity_query)
 * which we add to peers[] (handle_identity_response).
 *
 * Mirrors Python's IdentityProcess._periodic_identity_resync (idprocess.py)
 * and rides the same caps-resync cadence in identity_run's main loop. See
 * dod-coordinator-partition-nonconvergence.md (layer 3).
 ****************************/
/* Frama-C: skipped — JSON + messaging stubs. */
void identity_periodic_identity_resync(const process_t *proc)
{
    if (proc == NULL) return;
    /* Only when operational and actually in a group (mirror Python's
     * `phase == 3 and group is not None and not choosing`). */
    if (proc->protocol.phase != 3) return;
    if (proc->protocol.group.uuid[0] == 0
        && map_size(&((process_t *)proc)->protocol.group.address_map) == 0)
        return;
    pthread_mutex_lock(&id_state.lock);
    bool choosing = id_state.choosing_group;
    pthread_mutex_unlock(&id_state.lock);
    if (choosing) return;

    int group_size = (int)map_size(&((process_t *)proc)->protocol.group.address_map);
    const identity_t *self = _partition_self_identity(proc);

    /* `have` = the uuids we hold an Identity for = our peers + self. */
    json_t *have = json_array();
    if (have == NULL) return;
    if (self != NULL) {
        char self_uuid_str[UUID_STRING_LEN + 1];
        uuid_unparse_lower(self->uuid, self_uuid_str);
        json_array_append_new(have, json_string(self_uuid_str));
    }
    peers_read_lock(proc);
    for (size_t i = 0; i < proc->protocol.num_peers; i++) {
        char u[UUID_STRING_LEN + 1];
        uuid_unparse_lower(proc->protocol.peers[i].uuid, u);
        json_array_append_new(have, json_string(u));
    }
    peers_read_unlock(proc);

    /* We hold an Identity for (at least) every group member -> nothing to do.
     * uuid-count vs address-count is 1:1 per member; an occasional over-query
     * is harmless (responders skip via the have-list). */
    int have_count = (int)json_array_size(have);
    if (have_count >= group_size) {
        json_decref(have);
        return;
    }

    char group_uuid_str[UUID_STRING_LEN + 1];
    uuid_unparse_lower(proc->protocol.group.uuid, group_uuid_str);
    json_t *payload = json_object();
    if (payload == NULL) { json_decref(have); return; }
    json_object_set_new(payload, "group_uuid", json_string(group_uuid_str));
    json_object_set_new(payload, "have", have);  /* steals the reference */

    generic_msg_t query = {0};
    query.type = NET_MESSAGE;
    strncpy(query.info.net_msg.process, "identity", PROC_NAME_LEN);
    query.info.net_msg.function = ID_IDENTITY_QUERY;
    query.info.net_msg.encrypt = false;       /* may lack peer crypto material */
    /* to_whom left zeroed → network-layer broadcast */
    strncpy(query.info.net_msg.return_to, "identity", PROC_NAME_LEN);
    net_msg_pack_json(&query.info.net_msg, payload);
    json_decref(payload);
    messaging_send("network", NET_MESSAGE, &query, false);

    char miss_str[16];
    snprintf(miss_str, sizeof(miss_str), "%d", group_size - have_count);
    probes_counter("peer.set", "identity_resync_query", miss_str);
    log_debug(proc->logger,
              "Identity resync: querying group for %d missing member "
              "identity/ies\n", group_size - have_count);
}

/****************************
 * Handler: handle_identity_query (peer_identity_query)
 *
 * A same-group peer that holds our address but not our Identity asks for it
 * (payload: its group uuid + the uuids it already has). If we're in that
 * group and not in its have-list, reply with our published identity so it can
 * populate peers[]. Mirrors Python's handle_identity_query (idprocess.py).
 ****************************/
/* Frama-C: skipped — JSON + messaging stubs. */
static bool handle_identity_query(const process_t *proc, directory_t *queues, generic_msg_t *msg)
{
    (void)queues;
    if (proc == NULL || msg == NULL) return true;
    net_msg_t *nmsg = &msg->info.net_msg;
    if (proc->protocol.group.uuid[0] == 0
        && map_size(&((process_t *)proc)->protocol.group.address_map) == 0)
        return true;

    json_t *payload = NULL;
    if (net_msg_unpack_json(nmsg, &payload) != 0 || payload == NULL)
        return true;
    if (!json_is_object(payload)) { json_decref(payload); return true; }

    /* Different group — not our concern. */
    char our_group_uuid_str[UUID_STRING_LEN + 1];
    uuid_unparse_lower(proc->protocol.group.uuid, our_group_uuid_str);
    const char *asked_group =
        json_string_value(json_object_get(payload, "group_uuid"));
    if (asked_group == NULL || strcmp(asked_group, our_group_uuid_str) != 0) {
        json_decref(payload);
        return true;
    }

    /* If the asker already has us, stay silent. */
    const identity_t *self = _partition_self_identity(proc);
    if (self == NULL) { json_decref(payload); return true; }
    char self_uuid_str[UUID_STRING_LEN + 1];
    uuid_unparse_lower(self->uuid, self_uuid_str);
    json_t *have = json_object_get(payload, "have");
    if (have != NULL && json_is_array(have)) {
        size_t hn = json_array_size(have);
        for (size_t i = 0; i < hn; i++) {
            const char *h = json_string_value(json_array_get(have, i));
            if (h != NULL && strcmp(h, self_uuid_str) == 0) {
                json_decref(payload);
                return true;  /* asker already has us */
            }
        }
    }
    json_decref(payload);

    /* Reply with our published identity + address. */
    public_identity_t *self_pub = NULL;
    if (identity_publish(self, &self_pub) != 0 || self_pub == NULL)
        return true;
    json_t *from_id_json = NULL;
    if (public_identity_to_json(self_pub, &from_id_json) != 0
        || from_id_json == NULL) {
        smrt_deref(self_pub);
        return true;
    }
    smrt_deref(self_pub);
    json_t *out = json_object();
    if (out == NULL) { json_decref(from_id_json); return true; }
    json_object_set_new(out, "from_identity", from_id_json);
    json_object_set_new(out, "from_address", json_string(self->address));

    generic_msg_t reply = {0};
    reply.type = NET_MESSAGE;
    strncpy(reply.info.net_msg.process, "identity", PROC_NAME_LEN);
    reply.info.net_msg.function = ID_IDENTITY_RESPONSE;
    reply.info.net_msg.encrypt = false;
    /* to_whom left zeroed → broadcast (mirrors Python's to_whom=broadcast) */
    strncpy(reply.info.net_msg.return_to, "identity", PROC_NAME_LEN);
    net_msg_pack_json(&reply.info.net_msg, out);
    json_decref(out);
    messaging_send("network", NET_MESSAGE, &reply, false);
    probes_counter("peer.set", "identity_response_sent", "1");
    log_debug(proc->logger,
              "Identity resync: replied to identity_query from %s\n",
              nmsg->from_whom.nickname);
    return true;
}

/****************************
 * Handler: handle_identity_response (peer_identity_response)
 *
 * Receive a group member's published identity (reply to our identity_query)
 * and add it to peers[]. Gated to peers whose advertised address is actually
 * in our group's address_map, so a stray broadcaster can't inject itself.
 * Mirrors Python's handle_identity_response (idprocess.py).
 ****************************/
/* Frama-C: skipped — JSON parsing + peers mutation. */
static bool handle_identity_response(const process_t *proc, directory_t *queues, generic_msg_t *msg)
{
    (void)queues;
    if (proc == NULL || msg == NULL) return true;
    net_msg_t *nmsg = &msg->info.net_msg;
    if (proc->protocol.group.uuid[0] == 0
        && map_size(&((process_t *)proc)->protocol.group.address_map) == 0)
        return true;

    json_t *payload = NULL;
    if (net_msg_unpack_json(nmsg, &payload) != 0 || payload == NULL)
        return true;
    if (!json_is_object(payload)) { json_decref(payload); return true; }

    json_t *ident_json = json_object_get(payload, "from_identity");
    if (ident_json == NULL || !json_is_object(ident_json)) {
        probes_counter("peer.set", "identity_response_no_identity", "1");
        json_decref(payload);
        return true;
    }
    public_identity_t parsed = {0};
    if (public_identity_from_json(ident_json, &parsed) != 0) {
        probes_counter("peer.set", "identity_response_no_identity", "1");
        json_decref(payload);
        return true;
    }

    /* Address: prefer the identity's own, else the explicit field. */
    const char *addr = (parsed.address[0] != '\0')
        ? parsed.address
        : json_string_value(json_object_get(payload, "from_address"));

    /* Only backfill identities for actual group members. */
    if (!_group_has_address(&((process_t *)proc)->protocol.group, addr)) {
        probes_counter("peer.set", "identity_response_not_in_group", "1");
        json_decref(payload);
        return true;
    }

    /* Never add self. */
    const identity_t *self = _partition_self_identity(proc);
    if (self != NULL && uuid_compare(parsed.uuid, self->uuid) == 0) {
        json_decref(payload);
        return true;
    }
    json_decref(payload);

    /* Add to peers if not already present. Mirrors
     * _populate_peers_from_history's append-under-write-lock. Unlike Python
     * there is no separate `main` peer copy to fan out to (the layer-3a
     * reliable-put fix is Python-specific) — peers[] is the shared struct. */
    bool added = false;
    peers_write_lock((process_t *)proc);
    bool dup = false;
    for (size_t i = 0; i < proc->protocol.num_peers; i++) {
        if (uuid_compare(proc->protocol.peers[i].uuid, parsed.uuid) == 0) {
            dup = true;
            break;
        }
    }
    if (!dup && proc->protocol.num_peers < MAX_PEERS) {
        memcpy(&((process_t *)proc)->protocol.peers[proc->protocol.num_peers],
               &parsed, sizeof(public_identity_t));
        ((process_t *)proc)->protocol.num_peers++;
        added = true;
    }
    peers_write_unlock((process_t *)proc);

    if (added) {
        probes_counter("peer.set", "identity_response_added", "1");
        char u[UUID_STRING_LEN + 1];
        uuid_unparse_lower(parsed.uuid, u);
        log_debug(proc->logger,
                  "Identity resync: backfilled identity for group member %s\n",
                  u);
    } else {
        probes_counter("peer.set", "identity_response_redundant", "1");
    }
    return true;
}

static bool handle_partition_signal(const process_t *proc, directory_t *queues, generic_msg_t *msg)
{
    (void)queues;
    if (proc == NULL || msg == NULL) return true;
    /* Suppress while we have no group yet — the normal bootstrap flow
     * (choose_group) will catch up. Mirrors Python's `self.group is
     * None or self.choosing` guard. */
    if (proc->protocol.group.uuid[0] == 0
        && map_size(&((process_t *)proc)->protocol.group.address_map) == 0)
        return true;
    pthread_mutex_lock(&id_state.lock);
    bool active = _partition_recovery_active_locked();
    pthread_mutex_unlock(&id_state.lock);
    if (active) return true;

    /* Payload is the raw from_addr string the NetProcess detected the
     * out-of-group traffic from. Stored in msg.info.net_msg via
     * net_msg_pack_string upstream. */
    json_t *payload = NULL;
    if (net_msg_unpack_json(&msg->info.net_msg, &payload) != 0
        || payload == NULL || !json_is_string(payload)) {
        if (payload != NULL) json_decref(payload);
        log_debug(proc->logger,
                  "Identity: partition_signal: malformed payload\n");
        return true;
    }
    const char *from_addr = json_string_value(payload);
    if (from_addr == NULL || from_addr[0] == '\0') {
        json_decref(payload);
        return true;
    }

    pthread_mutex_lock(&id_state.lock);
    bool may_send = _partition_cooldown_check(
        &id_state.partition_probe_cooldown, from_addr,
        PARTITION_PROBE_COOLDOWN_US);
    pthread_mutex_unlock(&id_state.lock);
    if (!may_send) {
        json_decref(payload);
        return true;
    }

    /* Build canonical signing input: "{group_uuid_str}|{group_size}". */
    char group_uuid_str[UUID_STRING_LEN + 1];
    uuid_unparse_lower(proc->protocol.group.uuid, group_uuid_str);
    int group_size = (int)map_size(&((process_t *)proc)->protocol.group.address_map);
    char canonical[UUID_STRING_LEN + 32];
    int clen = snprintf(canonical, sizeof(canonical), "%s|%d",
                        group_uuid_str, group_size);
    if (clen < 0 || (size_t)clen >= sizeof(canonical)) {
        json_decref(payload);
        return true;
    }

    const identity_t *self = _partition_self_identity(proc);
    if (self == NULL) {
        json_decref(payload);
        return true;
    }
    char sig_hex[129];
    if (_partition_sign_hex(self, (const unsigned char *)canonical,
                            (size_t)clen, sig_hex) != 0) {
        json_decref(payload);
        return true;
    }

    /* Construct JSON payload: from_identity (public), my_group_uuid,
     * my_group_size, signature. */
    public_identity_t *self_pub = NULL;
    if (identity_publish(self, &self_pub) != 0 || self_pub == NULL) {
        json_decref(payload);
        return true;
    }
    json_t *from_id_json = NULL;
    if (public_identity_to_json(self_pub, &from_id_json) != 0
        || from_id_json == NULL) {
        smrt_deref(self_pub);
        json_decref(payload);
        return true;
    }
    smrt_deref(self_pub);

    json_t *probe_json = json_object();
    json_object_set_new(probe_json, "from_identity", from_id_json);
    json_object_set_new(probe_json, "from_address",
                        json_string(self->address));
    json_object_set_new(probe_json, "my_group_uuid",
                        json_string(group_uuid_str));
    json_object_set_new(probe_json, "my_group_size",
                        json_integer(group_size));
    json_object_set_new(probe_json, "signature",
                        json_string(sig_hex));

    generic_msg_t out = {0};
    out.type = NET_MESSAGE;
    strncpy(out.info.net_msg.process, "identity", PROC_NAME_LEN);
    out.info.net_msg.function = ID_PARTITION_PROBE;
    out.info.net_msg.encrypt = false;  /* unsecured broadcast */
    memcpy(&out.info.net_msg.from_whom, _partition_self_identity(proc),
           sizeof(public_identity_t));
    net_msg_pack_json(&out.info.net_msg, probe_json);
    json_decref(probe_json);

    _partition_broadcast(proc, &out);
    log_debug(proc->logger,
              "Identity: partition_probe broadcast (group=%s size=%d trigger=%s)\n",
              group_uuid_str, group_size, from_addr);
    json_decref(payload);
    return true;
}

static bool handle_partition_probe(const process_t *proc, directory_t *queues, generic_msg_t *msg)
{
    if (proc == NULL || msg == NULL) return true;
    /* Skip if we have no group yet. */
    if (proc->protocol.group.uuid[0] == 0
        && map_size(&((process_t *)proc)->protocol.group.address_map) == 0)
        return true;

    json_t *payload = NULL;
    if (net_msg_unpack_json(&msg->info.net_msg, &payload) != 0
        || payload == NULL || !json_is_object(payload)) {
        if (payload != NULL) json_decref(payload);
        return true;
    }

    json_t *j_from_id    = json_object_get(payload, "from_identity");
    json_t *j_group_uuid = json_object_get(payload, "my_group_uuid");
    json_t *j_group_size = json_object_get(payload, "my_group_size");
    json_t *j_signature  = json_object_get(payload, "signature");
    if (!json_is_object(j_from_id) || !json_is_string(j_group_uuid)
        || !json_is_integer(j_group_size) || !json_is_string(j_signature)) {
        json_decref(payload);
        return true;
    }
    const char *sender_group_uuid = json_string_value(j_group_uuid);
    int sender_group_size = (int)json_integer_value(j_group_size);
    const char *sig_hex = json_string_value(j_signature);

    /* Decode the sender's public identity. */
    public_identity_t sender_pub;
    memset(&sender_pub, 0, sizeof(sender_pub));
    if (public_identity_from_json(j_from_id, &sender_pub) != 0) {
        json_decref(payload);
        return true;
    }

    /* Verify signature. */
    char canonical[UUID_STRING_LEN + 32];
    int clen = snprintf(canonical, sizeof(canonical), "%s|%d",
                        sender_group_uuid, sender_group_size);
    if (clen < 0 || (size_t)clen >= sizeof(canonical)) {
        json_decref(payload);
        return true;
    }
    if (_partition_verify_hex(&sender_pub,
                              (const unsigned char *)canonical,
                              (size_t)clen, sig_hex) != 0) {
        log_debug(proc->logger,
                  "Identity: partition_probe: bad signature, dropping\n");
        json_decref(payload);
        return true;
    }

    char sender_uuid_str[UUID_STRING_LEN + 1];
    uuid_unparse_lower(sender_pub.uuid, sender_uuid_str);

    pthread_mutex_lock(&id_state.lock);
    bool may_send = _partition_cooldown_check(
        &id_state.partition_response_cooldown, sender_uuid_str,
        PARTITION_RESPONSE_COOLDOWN_US);
    pthread_mutex_unlock(&id_state.lock);
    if (!may_send) {
        json_decref(payload);
        return true;
    }

    /* Build response: same shape as probe + in_response_to + group leader.
     * Leader heuristic: prefer a known peer; fall back to ourselves.
     * Mirrors Python's `_select_partition_leader` simplification path. */
    const identity_t *self = _partition_self_identity(proc);
    if (self == NULL) {
        json_decref(payload);
        return true;
    }
    char our_group_uuid_str[UUID_STRING_LEN + 1];
    uuid_unparse_lower(proc->protocol.group.uuid, our_group_uuid_str);
    int our_group_size = (int)map_size(&((process_t *)proc)->protocol.group.address_map);
    char leader_uuid_str[UUID_STRING_LEN + 1];
    uuid_unparse_lower(self->uuid, leader_uuid_str);
    const char *leader_address = self->address;
    if (proc->protocol.num_peers > 0) {
        /* Use the most-recently-added peer's identity as leader
         * (Python sorts by _admitted_at desc; we lack that field in C,
         * so use the last peer added — same effect in the common case
         * where peers are appended in admission order). */
        size_t idx = proc->protocol.num_peers - 1;
        uuid_unparse_lower(proc->protocol.peers[idx].uuid, leader_uuid_str);
        leader_address = proc->protocol.peers[idx].address;
    }

    char resp_canonical[UUID_STRING_LEN * 2 + 64];
    int rclen = snprintf(resp_canonical, sizeof(resp_canonical),
                         "%s|%d|%s", our_group_uuid_str, our_group_size,
                         sender_uuid_str);
    if (rclen < 0 || (size_t)rclen >= sizeof(resp_canonical)) {
        json_decref(payload);
        return true;
    }
    char resp_sig_hex[129];
    if (_partition_sign_hex(self,
                            (const unsigned char *)resp_canonical,
                            (size_t)rclen, resp_sig_hex) != 0) {
        json_decref(payload);
        return true;
    }
    public_identity_t *self_pub = NULL;
    if (identity_publish(self, &self_pub) != 0 || self_pub == NULL) {
        json_decref(payload);
        return true;
    }
    json_t *from_id_json = NULL;
    if (public_identity_to_json(self_pub, &from_id_json) != 0
        || from_id_json == NULL) {
        smrt_deref(self_pub);
        json_decref(payload);
        return true;
    }
    smrt_deref(self_pub);

    json_t *resp_json = json_object();
    json_object_set_new(resp_json, "from_identity", from_id_json);
    json_object_set_new(resp_json, "from_address",
                        json_string(self->address));
    json_object_set_new(resp_json, "in_response_to",
                        json_string(sender_uuid_str));
    json_object_set_new(resp_json, "my_group_uuid",
                        json_string(our_group_uuid_str));
    json_object_set_new(resp_json, "my_group_size",
                        json_integer(our_group_size));
    json_object_set_new(resp_json, "my_group_leader",
                        json_string(leader_uuid_str));
    json_object_set_new(resp_json, "my_group_leader_address",
                        json_string(leader_address));
    json_object_set_new(resp_json, "signature",
                        json_string(resp_sig_hex));

    generic_msg_t out = {0};
    out.type = NET_MESSAGE;
    strncpy(out.info.net_msg.process, "identity", PROC_NAME_LEN);
    out.info.net_msg.function = ID_PARTITION_RESPONSE;
    out.info.net_msg.encrypt = false;
    memcpy(&out.info.net_msg.from_whom, _partition_self_identity(proc),
           sizeof(public_identity_t));
    net_msg_pack_json(&out.info.net_msg, resp_json);
    json_decref(resp_json);

    _partition_broadcast(proc, &out);
    log_debug(proc->logger,
              "Identity: partition_response broadcast (to=%s our_group=%s/%d)\n",
              sender_uuid_str, our_group_uuid_str, our_group_size);

    /* Symmetric adoption: the probe already advertises the prober's group
     * size, so decide adoption HERE too — not only in
     * handle_partition_response. Without this a node that never receives a
     * foreign GROUP-channel message (the dod_mission coordinator, in no
     * other group's address map) only ever RESPONDS to probes and can never
     * initiate a merge into a larger group, leaving a size-1/2 group wedged
     * on the losing side of every comparison. Mirrors
     * handle_partition_response's adopt decision (strictly larger, or equal
     * size with smaller uuid), guarded by the in-flight lock so exactly one
     * side adopts. See dod-coordinator-partition-nonconvergence.md (layer 2). */
    pthread_mutex_lock(&id_state.lock);
    bool recovery_active = _partition_recovery_active_locked();
    pthread_mutex_unlock(&id_state.lock);
    if (!recovery_active) {
        bool adopt = (sender_group_size > our_group_size)
            || (sender_group_size == our_group_size
                && strcmp(sender_group_uuid, our_group_uuid_str) < 0);
        if (adopt) {
            pthread_mutex_lock(&id_state.lock);
            snprintf(id_state.partition_recovery_target,
                     sizeof(id_state.partition_recovery_target), "%s",
                     sender_group_uuid);
            id_state.partition_recovery_started_us = _partition_now_us();
            pthread_mutex_unlock(&id_state.lock);
            int rc = _announce_identity(proc, queues);
            if (rc != 0)
                log_error(proc->logger,
                          "Identity: partition_probe adopt: _announce_identity "
                          "failed (%d)\n", rc);
            log_info(proc->logger,
                     "Identity: partition recovery (from probe) -> group=%s "
                     "(size=%d vs our %d)\n",
                     sender_group_uuid, sender_group_size, our_group_size);
        }
    }
    json_decref(payload);
    return true;
}

static bool handle_partition_response(const process_t *proc, directory_t *queues, generic_msg_t *msg)
{
    if (proc == NULL || msg == NULL) return true;
    if (proc->protocol.group.uuid[0] == 0
        && map_size(&((process_t *)proc)->protocol.group.address_map) == 0)
        return true;
    pthread_mutex_lock(&id_state.lock);
    bool active = _partition_recovery_active_locked();
    pthread_mutex_unlock(&id_state.lock);
    if (active) return true;

    json_t *payload = NULL;
    if (net_msg_unpack_json(&msg->info.net_msg, &payload) != 0
        || payload == NULL || !json_is_object(payload)) {
        if (payload != NULL) json_decref(payload);
        return true;
    }

    json_t *j_from_id     = json_object_get(payload, "from_identity");
    json_t *j_in_resp     = json_object_get(payload, "in_response_to");
    json_t *j_group_uuid  = json_object_get(payload, "my_group_uuid");
    json_t *j_group_size  = json_object_get(payload, "my_group_size");
    json_t *j_leader_addr = json_object_get(payload, "my_group_leader_address");
    json_t *j_signature   = json_object_get(payload, "signature");
    if (!json_is_object(j_from_id) || !json_is_string(j_in_resp)
        || !json_is_string(j_group_uuid) || !json_is_integer(j_group_size)
        || !json_is_string(j_leader_addr) || !json_is_string(j_signature)) {
        json_decref(payload);
        return true;
    }

    /* Filter responses addressed to other peers' probes. */
    const identity_t *self = _partition_self_identity(proc);
    if (self == NULL) {
        json_decref(payload);
        return true;
    }
    char self_uuid_str[UUID_STRING_LEN + 1];
    uuid_unparse_lower(self->uuid, self_uuid_str);
    if (strncmp(json_string_value(j_in_resp), self_uuid_str,
                UUID_STRING_LEN) != 0) {
        json_decref(payload);
        return true;
    }

    public_identity_t sender_pub;
    memset(&sender_pub, 0, sizeof(sender_pub));
    if (public_identity_from_json(j_from_id, &sender_pub) != 0) {
        json_decref(payload);
        return true;
    }
    const char *their_group_uuid = json_string_value(j_group_uuid);
    int their_size = (int)json_integer_value(j_group_size);
    const char *sig_hex = json_string_value(j_signature);

    char canonical[UUID_STRING_LEN * 2 + 64];
    int clen = snprintf(canonical, sizeof(canonical), "%s|%d|%s",
                        their_group_uuid, their_size, self_uuid_str);
    if (clen < 0 || (size_t)clen >= sizeof(canonical)) {
        json_decref(payload);
        return true;
    }
    if (_partition_verify_hex(&sender_pub,
                              (const unsigned char *)canonical,
                              (size_t)clen, sig_hex) != 0) {
        log_debug(proc->logger,
                  "Identity: partition_response: bad signature, dropping\n");
        json_decref(payload);
        return true;
    }

    char our_group_uuid_str[UUID_STRING_LEN + 1];
    uuid_unparse_lower(proc->protocol.group.uuid, our_group_uuid_str);
    int our_size = (int)map_size(&((process_t *)proc)->protocol.group.address_map);
    bool adopt = (their_size > our_size)
        || (their_size == our_size
            && strcmp(their_group_uuid, our_group_uuid_str) < 0);
    if (!adopt) {
        log_debug(proc->logger,
                  "Identity: partition_response: we_win (ours=%d theirs=%d)\n",
                  our_size, their_size);
        json_decref(payload);
        return true;
    }

    /* Mark recovery in flight and re-broadcast request_access. The
     * target group's welcoming-committee will admit us through the
     * normal POA voting; the subsequent full_history delivery feeds
     * _merge_to_mesh which adopts their group. */
    pthread_mutex_lock(&id_state.lock);
    snprintf(id_state.partition_recovery_target,
             sizeof(id_state.partition_recovery_target), "%s",
             their_group_uuid);
    id_state.partition_recovery_started_us = _partition_now_us();
    pthread_mutex_unlock(&id_state.lock);

    /* Re-broadcast request_access on the open channel. */
    int rc = _announce_identity(proc, queues);
    if (rc != 0) {
        log_error(proc->logger,
                  "Identity: partition_response: _announce_identity failed (%d)\n",
                  rc);
    }
    log_info(proc->logger,
             "Identity: partition recovery initiated -> group=%s (size=%d > our %d)\n",
             their_group_uuid, their_size, our_size);
    json_decref(payload);
    return true;
}

/****************************
 * Subtree member-roster enumeration (requestor-side BFS + opt-out)
 *
 * The C twin of Python's idprocess enumerate_local_members /
 * handle_roster_request / aggregate_subtree_roster. Each gateway answers
 * ONLY about itself (local members + child-gateway uuids) and stays
 * stateless/non-blocking; the requestor walks the tree. A node that opted
 * out (AT_ROSTER_PRIVATE) replies with a `private` marker and discloses
 * nothing. See doc/architecture/gateway-reputation-tree.md.
 ****************************/

/* Fan-out / cycle backstop for the recursive aggregation (mirrors Python's
 * SUBTREE_ROSTER_MAX_NODES). Far above any real cohort tree. */
#define ROSTER_MAX_NODES 4096

static bool _roster_env_private(void)
{
    const char *v = getenv("AT_ROSTER_PRIVATE");
    if (v == NULL || v[0] == '\0') return false;
    return strcmp(v, "1") == 0 || strcasecmp(v, "true") == 0
        || strcasecmp(v, "yes") == 0 || strcasecmp(v, "on") == 0;
}

static int _roster_key_cmp(const void *a, const void *b)
{
    return strcmp(*(const char *const *)a, *(const char *const *)b);
}

/* Add (or enrich) a member into the by-uuid accumulator object. Missing
 * nickname/address on an existing entry are filled; uuid is the key. */
static void _roster_add_member(json_t *by_uuid, const char *uuid,
                               const char *nickname, const char *address)
{
    if (by_uuid == NULL || uuid == NULL || uuid[0] == '\0') return;
    json_t *entry = json_object_get(by_uuid, uuid);  /* borrowed */
    if (entry == NULL) {
        entry = json_object();
        json_object_set_new(entry, "uuid", json_string(uuid));
        json_object_set_new(entry, "nickname",
                            (nickname && nickname[0]) ? json_string(nickname)
                                                      : json_null());
        json_object_set_new(entry, "address",
                            (address && address[0]) ? json_string(address)
                                                    : json_null());
        json_object_set_new(by_uuid, uuid, entry);  /* steals entry */
        return;
    }
    if (nickname && nickname[0]) {
        json_t *n = json_object_get(entry, "nickname");
        if (n == NULL || json_is_null(n))
            json_object_set_new(entry, "nickname", json_string(nickname));
    }
    if (address && address[0]) {
        json_t *a = json_object_get(entry, "address");
        if (a == NULL || json_is_null(a))
            json_object_set_new(entry, "address", json_string(address));
    }
}

/* Flatten a by-uuid accumulator into a NEW json array sorted by uuid — the
 * canonical member ordering shared with Python (sort by uuid on both sides). */
static json_t *_roster_sorted_members(json_t *by_uuid)
{
    json_t *arr = json_array();
    size_t n = json_object_size(by_uuid);
    if (n == 0) return arr;
    const char **keys = calloc(n, sizeof(*keys));
    if (keys == NULL) return arr;
    size_t i = 0;
    const char *k; json_t *v;
    json_object_foreach(by_uuid, k, v) { keys[i++] = k; }
    qsort(keys, n, sizeof(*keys), _roster_key_cmp);
    for (i = 0; i < n; i++)
        json_array_append(arr, json_object_get(by_uuid, keys[i]));  /* incref */
    free(keys);
    return arr;
}

/* Add every member of a group's address_map (uuid -> address) to by_uuid. */
static void _roster_add_group_members(group_t *group, json_t *by_uuid)
{
    if (group == NULL) return;
    map_key_t key;
    data_t *value;
    map_entries_for_each(&group->address_map, key, value)
        string_t addr = NULL;
        data_string_ptr(value, &addr);
        _roster_add_member(by_uuid, key, NULL, addr);
    map_end_for_each
}

/* This node's own membership contribution: itself + primary group + each
 * gatewayed child group, deduped and sorted by uuid. Pure and local — no
 * network, no reputation. Caller owns the returned array (json_decref).
 * Stays PURE regardless of roster_private; privacy is enforced only at the
 * disclosure boundary (handle_roster_request). */
json_t *identity_enumerate_local_members(const process_t *proc)
{
    json_t *by_uuid = json_object();
    if (proc != NULL) {
        const identity_t *self = _partition_self_identity(proc);
        if (self != NULL) {
            char su[UUID_STRING_LEN + 1];
            uuid_unparse_lower(self->uuid, su);
            _roster_add_member(by_uuid, su, self->nickname, self->address);
        }
        _roster_add_group_members(&((process_t *)proc)->protocol.group, by_uuid);
        if (proc->protocol.child_groups != NULL) {
            map_key_t key;
            data_t *value;
            map_entries_for_each(proc->protocol.child_groups, key, value)
                group_t *cg = NULL;
                if (data_object_ptr(value, (ptr_t *)&cg) == 0 && cg != NULL)
                    _roster_add_group_members(cg, by_uuid);
            map_end_for_each
        }
    }
    json_t *out = _roster_sorted_members(by_uuid);
    json_decref(by_uuid);
    return out;
}

/* A peer's rank for child-gateway discovery, read from the peer_ranks seam
 * (default 0/unknown). C peers are public_identity_t, which drops rank, so the
 * map is the rank source rather than the peer table. Mirrors Python's
 * IdentityProcess._member_rank. */
static int _roster_member_rank(const process_t *proc, const char *uuid)
{
    if (proc == NULL || proc->protocol.peer_ranks == NULL || uuid == NULL)
        return 0;
    data_t *rd = NULL;
    int r = 0;
    if (map_get(proc->protocol.peer_ranks, (map_key_t)uuid, &rd) == 0
        && rd != NULL && data_integer(rd, &r) == 0)
        return r;
    return 0;
}

/* Discover the recursion target for one child group = its highest-rank member
 * (excluding self), ties broken by the lexicographically greater uuid so the
 * choice is deterministic and identical in Python. Writes the winning uuid
 * into @p out (UUID_STRING_LEN+1) and returns true, or returns false for an
 * empty / self-only group. Mirrors Python's _discover_child_gateway. */
static bool _roster_discover_child_gateway(const process_t *proc,
                                           group_t *group, const char *self_uuid,
                                           char *out)
{
    if (group == NULL) return false;
    bool have = false;
    int best_rank = 0;
    char best_uuid[UUID_STRING_LEN + 1] = {0};
    map_key_t key;
    data_t *value;
    map_entries_for_each(&group->address_map, key, value)
        (void)value;  /* discovery keys on member uuid, not address */
        const char *u = (const char *)key;
        if (u == NULL || u[0] == '\0') continue;
        if (self_uuid != NULL && strcmp(u, self_uuid) == 0) continue;
        int rank = _roster_member_rank(proc, u);
        /* key = (rank, uuid); greater wins (uuid tiebreak = strcmp > 0). */
        if (!have || rank > best_rank
            || (rank == best_rank && strcmp(u, best_uuid) > 0)) {
            have = true;
            best_rank = rank;
            strncpy(best_uuid, u, UUID_STRING_LEN);
            best_uuid[UUID_STRING_LEN] = '\0';
        }
    map_end_for_each
    if (have)
        memcpy(out, best_uuid, UUID_STRING_LEN + 1);  /* incl. NUL */
    return have;
}

/* The child gateways a full-subtree roster recurses into (deduped,
 * order-stable) as a NEW json array of node-uuid strings — one per gatewayed
 * child group, DISCOVERED by rank (highest-rank member excluding self), with an
 * explicit child_gateways[cg] entry overriding discovery. Empty when this node
 * gateways no deeper gateways — a roster query is then purely local. Mirrors
 * Python's _child_gateway_uuids. */
static json_t *_roster_child_gateway_array(const process_t *proc)
{
    json_t *arr = json_array();
    if (proc == NULL || proc->protocol.child_groups == NULL) return arr;
    const identity_t *self = _partition_self_identity(proc);
    char self_uuid[UUID_STRING_LEN + 1] = {0};
    if (self != NULL) uuid_unparse_lower(self->uuid, self_uuid);
    const char *self_p = self != NULL ? self_uuid : NULL;
    json_t *seen = json_object();
    map_key_t key;
    data_t *value;
    map_entries_for_each(proc->protocol.child_groups, key, value)
        const char *cg_uuid = (const char *)key;
        char gw[UUID_STRING_LEN + 1] = {0};
        const char *gw_p = NULL;
        data_t *ov = NULL;
        if (proc->protocol.child_gateways != NULL)
            map_get(proc->protocol.child_gateways, (map_key_t)cg_uuid, &ov);
        string_t ov_s = NULL;
        if (ov != NULL && data_string_ptr(ov, &ov_s) == 0
            && ov_s != NULL && ov_s[0] != '\0') {
            gw_p = ov_s;  /* explicit override */
        } else {
            group_t *cg = NULL;
            if (data_object_ptr(value, (ptr_t *)&cg) == 0 && cg != NULL
                && _roster_discover_child_gateway(proc, cg, self_p, gw))
                gw_p = gw;
        }
        if (gw_p != NULL && gw_p[0] != '\0'
            && json_object_get(seen, gw_p) == NULL) {
            json_object_set_new(seen, gw_p, json_true());
            json_array_append_new(arr, json_string(gw_p));
        }
    map_end_for_each
    json_decref(seen);
    return arr;
}

/* This node's roster-query answer as a NEW json object {members,
 * child_gateways, private} (caller owns). A node that opted out discloses
 * nothing. Shared by handle_roster_request (the wire path) and the
 * requestor-side aggregation's fetch (tests / conformance), so both see
 * identical content. See gateway-reputation-tree.md. */
json_t *identity_roster_response(const process_t *proc)
{
    json_t *out = json_object();
    if (out == NULL) return NULL;
    if (proc != NULL && proc->protocol.roster_private) {
        json_object_set_new(out, "members", json_array());
        json_object_set_new(out, "child_gateways", json_array());
        json_object_set_new(out, "private", json_true());
    } else {
        json_object_set_new(out, "members",
                            identity_enumerate_local_members(proc));
        json_object_set_new(out, "child_gateways",
                            _roster_child_gateway_array(proc));
        json_object_set_new(out, "private", json_false());
    }
    return out;
}

/* Handler: answer a subtree-roster query with this node's LOCAL members and
 * the child gateways to recurse into (the requestor does the BFS). A node
 * that opted out replies with an empty `private` marker. Never blocks
 * awaiting children — matches the async, no-blocking-handler model. */
bool handle_roster_request(const process_t *proc, directory_t *queues,
                           generic_msg_t *msg)
{
    (void)queues;
    if (proc == NULL || msg == NULL) return true;
    net_msg_t *nmsg = &msg->info.net_msg;

    json_t *out = identity_roster_response(proc);
    if (out == NULL) return true;

    generic_msg_t reply = {0};
    reply.type = NET_MESSAGE;
    strncpy(reply.info.net_msg.process, "identity", PROC_NAME_LEN);
    reply.info.net_msg.function = ID_ROSTER_RESPONSE;
    reply.info.net_msg.encrypt = false;
    /* Route the reply back to the requestor (mirrors rep_proc grant). */
    memcpy(&reply.info.net_msg.to_whom, &nmsg->from_whom,
           sizeof(public_identity_t));
    strncpy(reply.info.net_msg.return_to, "identity", PROC_NAME_LEN);
    net_msg_pack_json(&reply.info.net_msg, out);
    json_decref(out);
    messaging_send("network", NET_MESSAGE, &reply, false);
    return true;
}

/* Requestor-side breadth-first flatten of a gateway's subtree into a deduped,
 * uuid-sorted member roster. `fetch(ctx, gateway_uuid)` returns a NEW response
 * object {members, child_gateways, private} (the aggregator decrefs it) or
 * NULL on failure. On return *out_members (always set, caller owns) is the
 * sorted roster, *out_complete is false only on a fetch failure or the node
 * cap (unreachability, NOT privacy), and *out_private (if non-NULL, caller
 * owns) lists the gateways that opted out. */
int identity_aggregate_subtree_roster(const char *top_uuid,
                                      roster_fetch_fn fetch, void *ctx,
                                      json_t **out_members, bool *out_complete,
                                      json_t **out_private)
{
    if (top_uuid == NULL || fetch == NULL || out_members == NULL) return -1;
    json_t *by_uuid = json_object();
    json_t *privates = json_array();
    json_t *seen = json_object();
    json_t *q = json_array();
    bool complete = true;
    json_array_append_new(q, json_string(top_uuid));
    json_object_set_new(seen, top_uuid, json_true());
    size_t qi = 0, guard = 0;
    while (qi < json_array_size(q)) {
        if (guard++ >= ROSTER_MAX_NODES) { complete = false; break; }
        const char *gw = json_string_value(json_array_get(q, qi++));
        if (gw == NULL) { complete = false; continue; }
        json_t *resp = fetch(ctx, gw);
        if (resp == NULL) { complete = false; continue; }
        json_t *priv = json_object_get(resp, "private");
        if (priv != NULL && json_is_true(priv)) {
            json_array_append_new(privates, json_string(gw));
            json_decref(resp);
            continue;
        }
        json_t *members = json_object_get(resp, "members");
        if (json_is_array(members)) {
            size_t i, n = json_array_size(members);
            for (i = 0; i < n; i++) {
                json_t *m = json_array_get(members, i);  /* borrowed */
                const char *mu = json_string_value(json_object_get(m, "uuid"));
                if (mu != NULL && mu[0] != '\0'
                    && json_object_get(by_uuid, mu) == NULL)
                    json_object_set(by_uuid, mu, m);  /* incref */
            }
        }
        json_t *children = json_object_get(resp, "child_gateways");
        if (json_is_array(children)) {
            size_t i, n = json_array_size(children);
            for (i = 0; i < n; i++) {
                const char *cu = json_string_value(json_array_get(children, i));
                if (cu != NULL && cu[0] != '\0'
                    && json_object_get(seen, cu) == NULL) {
                    json_object_set_new(seen, cu, json_true());
                    json_array_append_new(q, json_string(cu));
                }
            }
        }
        json_decref(resp);
    }
    *out_members = _roster_sorted_members(by_uuid);
    if (out_complete) *out_complete = complete;
    if (out_private) *out_private = privates; else json_decref(privates);
    json_decref(by_uuid);
    json_decref(seen);
    json_decref(q);
    return 0;
}

/* Seed a child cohort this node gateways (the C twin of Python's child_groups
 * seeding). `gateway_uuid` names the deeper gateway node to recurse into for
 * that child group (may be NULL for a 2-level gateway). Test/harness surface;
 * the live app path would populate these from group_child_*.cfg.json. */
int identity_add_child_group(process_t *proc, group_t *group,
                             const char *gateway_uuid)
{
    if (proc == NULL || group == NULL) return -1;
    if (proc->protocol.child_groups == NULL
        && map_create(&proc->protocol.child_groups) != 0)
        return -1;
    char cg_uuid[UUID_STRING_LEN + 1];
    uuid_unparse_lower(group->uuid, cg_uuid);
    data_t *gd = object_ptr_data(group, sizeof(group_t));
    if (gd == NULL || map_set(proc->protocol.child_groups, cg_uuid, gd) != 0)
        return -1;
    if (gateway_uuid != NULL && gateway_uuid[0] != '\0') {
        if (proc->protocol.child_gateways == NULL
            && map_create(&proc->protocol.child_gateways) != 0)
            return -1;
        data_t *gwd = string_data((string_t)gateway_uuid,
                                  strlen(gateway_uuid));
        if (gwd == NULL
            || map_set(proc->protocol.child_gateways, cg_uuid, gwd) != 0)
            return -1;
    }
    return 0;
}

void identity_set_roster_private(process_t *proc, bool enabled)
{
    if (proc == NULL) return;
    proc->protocol.roster_private = enabled;
}

/* Record a peer's rank for rank-based child-gateway discovery — the seam that
 * stands in for the rank C peers drop (public_identity_t carries no rank). The
 * live app path would populate this from the rank on full identity_t blocks
 * received via the history/chain path. Mirrors the fact that Python peers
 * already carry _rank/effective_rank. */
int identity_set_peer_rank(process_t *proc, const char *uuid, int rank)
{
    if (proc == NULL || uuid == NULL || uuid[0] == '\0') return -1;
    if (proc->protocol.peer_ranks == NULL
        && map_create(&proc->protocol.peer_ranks) != 0)
        return -1;
    data_t *rd = integer_data(rank);
    if (rd == NULL || map_set(proc->protocol.peer_ranks, (map_key_t)uuid, rd) != 0)
        return -1;
    return 0;
}

/* Parse ONE group_child_*.cfg.json into a heap group_t (member enumeration
 * only: uuid + address_map). The on-disk files are the Python `Group` schema
 * (top-level array [group, hist]; group carries `_uuid` / `_address_map`),
 * which the flat C group_from_json does not read — so this bridges it, and
 * also tolerates the flat `uuid`/`address_map` shape. Encryptor/nickname are
 * intentionally NOT parsed: the roster capability reads only address_map.
 * Returns a heap group_t* (caller/child_groups owns it) or NULL. */
static group_t *_load_child_group_file(const char *path)
{
    json_error_t jerr;
    json_t *root = json_load_file(path, 0, &jerr);
    if (root == NULL) return NULL;
    json_t *gj = root;
    if (json_is_array(root)) {
        if (json_array_size(root) == 0) { json_decref(root); return NULL; }
        gj = json_array_get(root, 0);  /* borrowed */
    }
    if (!json_is_object(gj)) { json_decref(root); return NULL; }
    const char *uuid_str = json_string_value(json_object_get(gj, "_uuid"));
    if (uuid_str == NULL)
        uuid_str = json_string_value(json_object_get(gj, "uuid"));
    json_t *amap = json_object_get(gj, "_address_map");
    if (amap == NULL) amap = json_object_get(gj, "address_map");
    uuid_t guuid;
    if (uuid_str == NULL || !json_is_object(amap)
        || uuid_parse(uuid_str, guuid) != 0) {
        json_decref(root);
        return NULL;
    }
    group_t *g = calloc(1, sizeof(group_t));
    if (g == NULL) { json_decref(root); return NULL; }
    char no_addr[1] = {0};
    group_init(&guuid, no_addr, g);
    const char *mk;
    json_t *mv;
    json_object_foreach(amap, mk, mv) {
        const char *addr = json_string_value(mv);
        if (mk != NULL && addr != NULL)
            group_add_address(g, mk, addr);
    }
    json_decref(root);
    return g;
}

/* Seed child groups from group_child_*.cfg.json under @p cfg_dir — the C twin
 * of Python's IdentityProcess._load_child_groups. A gateway is seeded with one
 * such file per cohort it gateways; each becomes a child_groups entry so a
 * subtree-roster query enumerates those members. Matches the Python live path:
 * child_groups only (NOT child_gateways — deeper-recursion seeding is an
 * unspecified shared design question in both languages). Returns the count
 * adopted. See doc/architecture/gateway-reputation-tree.md. */
int identity_load_child_groups(process_t *proc, const char *cfg_dir)
{
    if (proc == NULL || cfg_dir == NULL) return 0;
    DIR *d = opendir(cfg_dir);
    if (d == NULL) return 0;
    static const char prefix[] = "group_child";
    static const char ext[] = ".cfg.json";
    const size_t plen = sizeof(prefix) - 1;
    const size_t elen = sizeof(ext) - 1;
    int loaded = 0;
    struct dirent *ent;
    while ((ent = readdir(d)) != NULL) {
        const char *name = ent->d_name;
        size_t nlen = strlen(name);
        if (strncmp(name, prefix, plen) != 0) continue;
        if (nlen < elen || strcmp(name + nlen - elen, ext) != 0) continue;
        char full[CFG_PATH_LEN + 1];
        if ((size_t)snprintf(full, sizeof(full), "%s/%s", cfg_dir, name)
            >= sizeof(full))
            continue;  /* path too long; skip rather than truncate */
        group_t *g = _load_child_group_file(full);
        if (g == NULL) continue;
        if (identity_add_child_group(proc, g, NULL) == 0) {
            loaded++;
        } else {
            group_free(g);
            free(g);
        }
    }
    closedir(d);
    return loaded;
}

int identity_register_handlers(process_t *proc)
{
    if (proc == NULL) return -1;
    /* Default to border-guard (mirrors Python IdentityProcess.border_guard_mode
     * = True). A deployment/harness may clear it via
     * identity_set_border_guard_mode to make this peer abstain from voting
     * (Policy B, ISSUES.md §3.1-c). */
    proc->protocol.border_guard_mode = true;
    /* Two-phase admission quorum (ISSUES.md §3.1-a). Default 1 = promote on
     * the first confirm (historical behavior); a deployment/harness sets it
     * higher via identity_set_admission_quorum for corroborated key handover. */
    proc->protocol.admission_quorum = 1;
    process_register_handler(proc, ID_ANNOUNCE, (handler_ptr_t)handle_welcoming_committee);
    process_register_handler(proc, ID_ACCEPT,   (handler_ptr_t)handle_acceptance);
    process_register_handler(proc, ID_HISTORY,  (handler_ptr_t)handle_receive_history);
    process_register_handler(proc, ID_DIFF,     (handler_ptr_t)handle_history_diff);
    process_register_handler(proc, ID_PROPOSE,  (handler_ptr_t)handle_vote_on_peer);
    process_register_handler(proc, ID_VOTE,     (handler_ptr_t)handle_count_vote);
    process_register_handler(proc, ID_CONFIRM,  (handler_ptr_t)handle_confirm_peer);
    process_register_handler(proc, ID_UPDATE,   (handler_ptr_t)handle_group_update);
    process_register_handler(proc, ID_CAPS_QUERY,    (handler_ptr_t)handle_caps_query);
    process_register_handler(proc, ID_CAPS_RESPONSE, (handler_ptr_t)handle_caps_response);
    process_register_handler(proc, ID_IDENTITY_QUERY,
                             (handler_ptr_t)handle_identity_query);
    process_register_handler(proc, ID_IDENTITY_RESPONSE,
                             (handler_ptr_t)handle_identity_response);
    process_register_handler(proc, ID_TIER,          (handler_ptr_t)handle_tier_update);
    process_register_handler(proc, ID_PARTITION_SIGNAL,
                             (handler_ptr_t)handle_partition_signal);
    process_register_handler(proc, ID_PARTITION_PROBE,
                             (handler_ptr_t)handle_partition_probe);
    process_register_handler(proc, ID_PARTITION_RESPONSE,
                             (handler_ptr_t)handle_partition_response);
    process_register_handler(proc, ID_ROSTER_QUERY,
                             (handler_ptr_t)handle_roster_request);
    /* Roster-privacy opt-out (AT config AT_ROSTER_PRIVATE). Read once here,
     * mirroring Python's _env_bool init. child_groups/child_gateways stay NULL
     * (empty) until seeded — a leaf node then answers a roster query purely
     * locally, identical to today. See gateway-reputation-tree.md. */
    proc->protocol.roster_private = _roster_env_private();
    return 0;
}

int identity_run(process_t *proc, directory_t *queues, queue_id_t signal, logger_t *logger)
{
    _ensure_id_init();

    /* Daemonize first so messaging is available for pre-loop activity */
    process_ctx_t pctx = {0};
    int err = process_setup(proc, signal, logger, &pctx);
    if (err != 0)
        return err;

    identity_register_handlers(proc);

    /* Seed-assisted dual membership: adopt any group_child_*.cfg.json cohorts
     * this gateway holds (C twin of Python's _load_child_groups). A leaf with
     * no such files is unchanged. See gateway-reputation-tree.md. */
    {
        char cfg_dir[CFG_PATH_LEN + 1];
        if (get_cfg_dir(cfg_dir) > 0) {
            int adopted = identity_load_child_groups(proc, cfg_dir);
            if (adopted > 0)
                log_info(proc->logger,
                         "Identity: seeded %d child group(s) from config\n",
                         adopted);
        }
    }

    /* Phase 0→1: Acquire capabilities */
    _acquire_capabilities(proc, queues);
    proc->protocol.phase = 1;

    /* Phase 1→2: Announce identity */
    _announce_identity(proc, queues);
    proc->protocol.phase = 2;

    /* Phase 2→3: choose_group — wait adaptively for histories from existing
     * peers, then either adopt one or self-bootstrap a fresh group. Mirrors
     * Python's choose_group (idprocess.py:248). Runs inline here and pumps
     * inbound messages during the wait so handle_receive_history can deposit
     * histories into id_state.histories. The conformance harness uses
     * at_identity_run (not this entry point), so blocking in the wait does
     * not affect synchronous_dispatch tests. */
    {
        /* AT_INIT_TIMEOUT_SEC env-var override — mirrors Python's
         * idprocess.py:87-92. The default 5 s is fine for a bootstrap
         * node, but late joiners that need an existing mesh's history
         * to arrive over UDP broadcast (e.g. an observer container
         * coming up beside an already-running peer mesh) routinely
         * lose the race and self-bootstrap. Set this env var on those
         * containers to extend the wait. */
        long INIT_TIMEOUT_US = 5L * 1000000L;  /* Python init_timeout=5s */
        const char *init_override = getenv("AT_INIT_TIMEOUT_SEC");
        if (init_override != NULL && init_override[0] != '\0') {
            double secs = strtod(init_override, NULL);
            if (secs > 0)
                INIT_TIMEOUT_US = (long)(secs * 1000000.0);
        }
        const long GRACE_US        = 1L * 1000000L;  /* Python grace=1s */
        struct timeval start_tv, now_tv;
        gettimeofday(&start_tv, NULL);
        long first_seen_us = -1;

        pthread_mutex_lock(&id_state.lock);
        id_state.choosing_group = true;
        pthread_mutex_unlock(&id_state.lock);

        while (keep_running(proc, &pctx.sig_q, logger))
        {
            gettimeofday(&now_tv, NULL);
            long elapsed_us = (now_tv.tv_sec - start_tv.tv_sec) * 1000000L
                            + (now_tv.tv_usec - start_tv.tv_usec);
            if (elapsed_us > INIT_TIMEOUT_US)
                break;

            pthread_mutex_lock(&id_state.lock);
            size_t hcount = array_size(&id_state.histories);
            pthread_mutex_unlock(&id_state.lock);
            if (hcount > 0)
            {
                if (first_seen_us < 0)
                    first_seen_us = elapsed_us;
                else if (elapsed_us - first_seen_us >= GRACE_US)
                    break;
            }

            /* Pump inbound messages so handle_receive_history can run. */
            generic_msg_t pump = {0};
            int rc = messaging_recv(&pump);
            if (rc == 0)
                run_message_handlers(proc, queues, pump.type, &pump);
            else
                sleep_until(proc, cadence);
        }

        /* Selection / self-bootstrap. The C history wire form is still a stub
         * (see _peer_accepted), so full history-parse + peer-union selection
         * isn't wired up here yet — when histories arrived we just log and
         * transition; the group address_map converges through subsequent
         * ID_UPDATE traffic. The self-bootstrap path matches Python's
         * Group.initialize({self.identity.uuid: self.identity.address}, ...). */
        pthread_mutex_lock(&id_state.lock);
        size_t final_hcount = array_size(&id_state.histories);
        pthread_mutex_unlock(&id_state.lock);

        if (final_hcount > 0)
        {
            log_info(logger, "Identity: choose_group: %zu histor%s received; "
                     "selecting mesh group\n",
                     final_hcount, final_hcount == 1 ? "y" : "ies");

            /* Parse + adopt the shared group key from the welcomer's
             * full_history (slot 0 = the DRY canonical group). Mirrors the
             * selection in _merge_to_mesh: the entry with the most steps wins
             * (most complete view), else the first entry seeds adoption.
             * Without this the C node kept its own self-seeded group and never
             * obtained the mesh key — full_history that arrives DURING the
             * choose_group wait (the common case once box-decrypt works) hit a
             * stub that only logged. Python's choose_group adopts here too
             * (idprocess.py:248+). See [[project_group_key_sync]]. */
            group_t adopted_group = {0};
            bool have_group = false;
            size_t best_steps_len = 0;
            pthread_mutex_lock(&id_state.lock);
            size_t n_hist = array_size(&id_state.histories);
            for (size_t i = 0; i < n_hist; i++) {
                data_t *h_dat = NULL;
                if (array_get(&id_state.histories, (int)i, &h_dat) != 0 || h_dat == NULL)
                    continue;
                ptr_t hptr = NULL;
                if (data_object_ptr(h_dat, &hptr) != 0 || hptr == NULL)
                    continue;
                json_t *root = (json_t *)hptr;
                if (!json_is_array(root) || json_array_size(root) < 2)
                    continue;
                json_t *s_json = json_array_get(root, 1);
                size_t this_steps_len =
                    (s_json && json_is_array(s_json)) ? json_array_size(s_json) : 0;
                bool pick = (!have_group && this_steps_len == 0)
                            || (this_steps_len > best_steps_len);
                if (!pick)
                    continue;
                json_t *g_json = json_array_get(root, 0);
                if (g_json && json_is_object(g_json)) {
                    group_t parsed = {0};
                    if (group_from_json(g_json, &parsed) == 0) {
                        adopted_group = parsed;
                        have_group = true;
                        best_steps_len = this_steps_len;
                    }
                }
            }
            pthread_mutex_unlock(&id_state.lock);

            if (have_group) {
                char gid_str[UUID_STRING_LEN + 1];
                uuid_unparse_lower(adopted_group.uuid, gid_str);
                peers_write_lock(proc);
                memcpy(&proc->protocol.group, &adopted_group, sizeof(group_t));
                peers_write_unlock(proc);
                log_info(logger,
                         "Identity: adopted mesh group %s during merge\n", gid_str);
            } else {
                log_warn(logger, "Identity: choose_group: histories present but "
                         "no parseable group; keeping self-seeded group\n");
            }
        }
        else
        {
            log_info(logger, "Identity: choose_group: no histories received; "
                     "self-bootstrapping a fresh group\n");
            public_identity_t *pub = NULL;
            data_t *id_dat = NULL;
            char id_key[] = "identity";
            if (map_get(proc->configs, id_key, &id_dat) == 0)
            {
                config_t *id_cfg = NULL;
                if (data_object_ptr(id_dat, (void **)&id_cfg) == 0
                    && id_cfg->data_struct != NULL)
                    identity_publish((const identity_t *)id_cfg->data_struct, &pub);
            }
            char empty_addr[1] = {0};
            char *seed_addr = (pub != NULL) ? pub->address : empty_addr;
            if (group_init(NULL, seed_addr, &proc->protocol.group) == 0 && pub != NULL)
            {
                char uuid_str[UUID_STRING_LEN + 1];
                uuid_unparse_lower(pub->uuid, uuid_str);
                group_add_address(&proc->protocol.group, uuid_str, pub->address);
                /* Stamp a real creation epoch (ISSUES.md §3.1-b) so a group
                 * minted at genesis carries a comparable age for the merge
                 * size-tie tiebreaker. Unix epoch seconds, directly
                 * comparable to Python initialize's now().timestamp() on the
                 * wire. group_init leaves created=0 (its callers include the
                 * conformance adapter, which must stay age-agnostic → uuid
                 * tiebreak), so the stamp lives here at the runtime genesis
                 * mint only. Mirrors Python Group.initialize. */
                proc->protocol.group.created = (double)time(NULL);
            }
            if (pub != NULL)
                smrt_deref(pub);
            /* Mark self-bootstrap so a late-arriving full_history triggers
             * the merge path in handle_receive_history → _merge_to_mesh.
             * Cleared once the merge completes. Mirrors Python's
             * `self.self_bootstrapped = True` (idprocess.py:342). */
            pthread_mutex_lock(&id_state.lock);
            id_state.self_bootstrapped = true;
            pthread_mutex_unlock(&id_state.lock);
        }

        pthread_mutex_lock(&id_state.lock);
        id_state.choosing_group = false;
        pthread_mutex_unlock(&id_state.lock);
    }
    proc->protocol.phase = 3;

    /* Identity-specific loop: re-announce periodically until peers found */
    generic_msg_t announce_buf = {0};
    _build_announcement(proc, &announce_buf);
    int announce_interval = 10; /* re-announce every 10 cadence cycles (~5s) */
    int cycle = 0;
    /* Late-joiner cap-loss backstop: re-query cap-less peers every
     * ~20s (≈40 cadence cycles), matching Python's
     * _CAPS_RESYNC_INTERVAL_SEC=20. See _periodic_caps_resync. */
    int caps_resync_interval = 40;
    int caps_cycle = 0;

    while (keep_running(proc, &pctx.sig_q, logger))
    {
        sleep_until(proc, cadence);

        /* Periodic re-announcement until we have peers */
        peers_read_lock(proc);
        bool no_peers = (proc->protocol.num_peers == 0);
        peers_read_unlock(proc);
        if (no_peers && ++cycle >= announce_interval)
        {
            cycle = 0;
            messaging_send("network", NET_MESSAGE, &announce_buf, false);
            log_debug(logger, "Identity: re-announcing (no peers yet)\n");
        }

        /* Periodic late-joiner cap-loss backstop (interval-gated so the
         * fast loop doesn't sweep every iteration; a converged group
         * emits no queries). */
        if (++caps_cycle >= caps_resync_interval)
        {
            caps_cycle = 0;
            identity_periodic_caps_resync(proc);
            /* Same cadence as caps-resync (Python rides the same interval):
             * a cold/late joiner holding only member addresses backfills the
             * missing Identities so consensus reputations can be named. A
             * converged node emits no query (have_count >= group_size). */
            identity_periodic_identity_resync(proc);
        }

        generic_msg_t buf = {0};
        err = messaging_recv(&buf);
        if (err == -1 || err == ENOMSG)
            continue;
        if (!run_message_handlers(proc, queues, buf.type, &buf))
        {
            log_debug(logger, "Identity: unhandled message type %ld\n", buf.type);
        }
    }

    if (pctx.fd1 > 0)
        close(pctx.fd1);
    if (pctx.fd2 > 0)
        close(pctx.fd2);
    return 0;
}
DECLARE_PROCESS(identity, id_proc, identity_run);
