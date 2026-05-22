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

#define _GNU_SOURCE
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
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
#include "peers.h"
#include "history.h"
#include "identity_priv.h"
#include "id_proc_priv.h"

#ifdef AT_ZTA_ENABLED
#include "zta/zta_policy.h"
#include "zta/zta_verifier.h"
#include "zta/zta_audit.h"
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
        map_init(&id_state.peer_tiers);
        map_init(&id_state.partition_probe_cooldown);
        map_init(&id_state.partition_response_cooldown);
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

/* Frama-C: skipped — [solver-timeout] logging/identity/peers preconditions */
static int _add_peer(process_t *proc, directory_t *queues, const public_identity_t *new_peer)
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
             peer->fullname);
    return 0;
}

/****************************
 * Helper: _peer_accepted
 * Sends ID_CONFIRM to existing group members and ID_ACCEPT to the new peer,
 * then adds the peer to our list (which also triggers Phase-3 group churn
 * inside `_add_peer` — see the constraint block above `handle_group_update`
 * for the tiebreaker rule that prevents an ID_UPDATE flood).
 *
 * Confirm payload carries `{uuid, fullname, address}` so the receiver can
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
                          const public_identity_t *new_peer, bool amnesia)
{
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
        json_t *peer_json = json_object();
        if (peer_json == NULL) {
            log_error(proc->logger, "Identity: json_object OOM (confirm broadcast)\n");
            return EXCEPTION(ENOMEM);
        }
        char uuid_str[UUID_STRING_LEN + 1];
        uuid_unparse_lower(new_peer->uuid, uuid_str);
        json_object_set_new(peer_json, "uuid", json_string(uuid_str));
        json_object_set_new(peer_json, "fullname", json_string(new_peer->fullname));
        json_object_set_new(peer_json, "address", json_string(new_peer->address));
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
            json_t *peer_json = json_object();
            if (peer_json == NULL) {
                log_error(proc->logger, "Identity: json_object OOM (confirm fanout)\n");
                continue;
            }
            char uuid_str[UUID_STRING_LEN + 1];
            uuid_unparse_lower(new_peer->uuid, uuid_str);
            json_object_set_new(peer_json, "uuid", json_string(uuid_str));
            json_object_set_new(peer_json, "fullname", json_string(new_peer->fullname));
            json_object_set_new(peer_json, "address", json_string(new_peer->address));
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
    return _add_peer(proc, queues, new_peer);
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
             nmsg->from_whom.fullname);

    /* Validate the new identity */
    if (nmsg->from_whom.fullname[0] == '\0')
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
                 nmsg->from_whom.fullname);
        _peer_accepted((process_t *)proc, queues, &nmsg->from_whom, true);
        return true;
    }

#ifdef AT_ZTA_ENABLED
    /* ZTA credential verification at admission */
    {
        /* Look up ZTA policy from configs */
        data_t *zta_cfg = NULL;
        zta_policy_t *zta_policy = NULL;
        char zta_key[] = "zta_policy";
        if (map_get(proc->configs, zta_key, &zta_cfg) == 0 && zta_cfg)
            zta_policy = (zta_policy_t *)zta_cfg;

        if (zta_policy && zta_policy->enabled && zta_policy->require_at_admission) {
            zta_verifier_t *verifier = NULL;
            int zrc = zta_policy_create_verifier(zta_policy, &verifier);
            if (zrc == 0 && verifier) {
                zta_result_t zta_result;
                verifier->verify_credential(
                    verifier,
                    nmsg->from_whom.zta_credential,
                    nmsg->from_whom.zta_credential_len,
                    &zta_result);

                if (zta_result.status == ZTA_REJECTED || zta_result.status == ZTA_EXPIRED) {
                    log_warn(proc->logger,
                             "Identity: ZTA credential %s for %s: %s\n",
                             zta_status_str(zta_result.status),
                             nmsg->from_whom.fullname, zta_result.reason);
                    verifier->destroy(verifier);
                    return true; /* reject */
                }
                if (zta_result.status == ZTA_UNAVAILABLE || zta_result.status == ZTA_DEFERRED) {
                    if (!zta_policy->allow_ddil_fallback) {
                        log_warn(proc->logger,
                                 "Identity: ZTA unavailable, DDIL fallback disabled; rejecting %s\n",
                                 nmsg->from_whom.fullname);
                        verifier->destroy(verifier);
                        return true; /* reject */
                    }
                    log_info(proc->logger,
                             "Identity: ZTA verification deferred (DDIL) for %s\n",
                             nmsg->from_whom.fullname);
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
                 nmsg->from_whom.fullname);
        _peer_accepted((process_t *)proc, queues, &nmsg->from_whom, false);
        return true;
    }

    /* Store proposed peer in potentials and self-vote before sending proposals */
    char uuid_str[UUID_STRING_LEN + 1];
    uuid_unparse_lower(nmsg->from_whom.uuid, uuid_str);

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
    json_object_set_new(proposal_json, "fullname", json_string(nmsg->from_whom.fullname));
    json_object_set_new(proposal_json, "address", json_string(nmsg->from_whom.address));

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
             nmsg->from_whom.fullname);

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
                 nmsg->from_whom.fullname);
        _peer_accepted((process_t *)proc, queues, &nmsg->from_whom, false);
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
             nmsg->from_whom.fullname);

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
             nmsg->from_whom.fullname);

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

    log_debug(proc->logger, "Identity: stored history from %s\n", nmsg->from_whom.fullname);

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
    map_free(&id_state.peer_tiers);
    map_init(&id_state.peer_tiers);
    map_free(&id_state.partition_probe_cooldown);
    map_init(&id_state.partition_probe_cooldown);
    map_free(&id_state.partition_response_cooldown);
    map_init(&id_state.partition_response_cooldown);
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
              nmsg->from_whom.fullname);

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
            _peer_accepted(proc, queues, new_peer, false);
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
static bool handle_confirm_peer(process_t *proc, directory_t *queues, generic_msg_t *msg)
{
    if (proc->protocol.phase != 3)
        return false;

    net_msg_t *nmsg = &msg->info.net_msg;
    log_info(proc->logger, "Identity: peer acceptance confirmed from %s\n",
             nmsg->from_whom.fullname);

    /* Unpack peer identity from JSON payload (uuid + fullname) */
    json_t *payload = NULL;
    if (net_msg_unpack_json(nmsg, &payload) != 0 || payload == NULL)
    {
        log_warn(proc->logger, "Identity: handle_confirm_peer: no JSON payload\n");
        return true;
    }

    json_t *j_uuid     = json_object_get(payload, "uuid");
    json_t *j_fullname = json_object_get(payload, "fullname");
    json_t *j_address  = json_object_get(payload, "address");

    if (!j_uuid || !j_fullname)
    {
        json_decref(payload);
        log_warn(proc->logger, "Identity: handle_confirm_peer: missing JSON fields\n");
        return true;
    }

    const char *uuid_str  = json_string_value(j_uuid);
    const char *fullname  = json_string_value(j_fullname);
    const char *address   = j_address ? json_string_value(j_address) : NULL;

    /* Reconstruct public_identity_t from JSON fields */
    public_identity_t new_peer;
    memset(&new_peer, 0, sizeof(public_identity_t));
    if (uuid_str != NULL)
        uuid_parse(uuid_str, new_peer.uuid);
    if (fullname != NULL)
        strncpy(new_peer.fullname, fullname, NAME_LEN);
    if (address != NULL)
        strncpy(new_peer.address, address, ADDR_LEN);

    json_decref(payload);

    log_info(proc->logger, "Identity: confirmed peer %s (%s)\n", fullname, uuid_str);

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
                     fullname, uuid_str);
            _send_caps_query(proc, &new_peer);
        }
    }

    _add_peer(proc, queues, &new_peer);

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
              nmsg->from_whom.fullname);

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
             step_count, nmsg->from_whom.fullname);

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
 *     equal size     → adopt iff strcmp(theirs.uuid, mine.uuid) < 0;
 *                      otherwise push our group (we are uuid-tiebreak winner)
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
             nmsg->from_whom.fullname);

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
            adopt = (strcmp(theirs_uuid_str, mine_uuid_str) < 0);
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
              nmsg->from_whom.fullname);

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

/****************************
 * Handler: handle_caps_response (peer_caps_response)
 *
 * Parse a JSON array of capability names and store under the sender's
 * uuid in id_state.peer_caps_map. Mirrors Python's
 * handle_caps_response (idprocess.py:832 — registers received caps
 * under sender.uuid in self.peer_capabilities, with per-cap dedup;
 * this C analog stores the full set verbatim, dedup with subsequent
 * responses by replacement). Conformance scenarios observe via
 * identity_get_peer_caps_count.
 ****************************/

/* Frama-C: skipped — JSON parsing + map mutation. */
static bool handle_caps_response(const process_t *proc, directory_t *queues, generic_msg_t *msg)
{
    (void)queues;
    net_msg_t *nmsg = &msg->info.net_msg;
    log_debug(proc->logger, "Identity: caps_response from %s\n",
              nmsg->from_whom.fullname);

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
        const char *name = json_string_value(json_array_get(payload, i));
        if (name == NULL) continue;
        size_t len = strlen(name);
        char *dup = smrt_create(len + 1);
        if (dup == NULL) continue;
        memcpy(dup, name, len + 1);
        data_t *str_dat = string_data(dup, len + 1);
        if (str_dat == NULL) { smrt_deref(dup); continue; }
        array_append(arr, str_dat);
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
    (void)queues;
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

int identity_register_handlers(process_t *proc)
{
    if (proc == NULL) return -1;
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
    process_register_handler(proc, ID_TIER,          (handler_ptr_t)handle_tier_update);
    process_register_handler(proc, ID_PARTITION_SIGNAL,
                             (handler_ptr_t)handle_partition_signal);
    process_register_handler(proc, ID_PARTITION_PROBE,
                             (handler_ptr_t)handle_partition_probe);
    process_register_handler(proc, ID_PARTITION_RESPONSE,
                             (handler_ptr_t)handle_partition_response);
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
                     "transitioning to phase 3 (selection pending full history parse)\n",
                     final_hcount, final_hcount == 1 ? "y" : "ies");
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
