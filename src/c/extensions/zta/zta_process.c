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

#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <jansson.h>
#include <sodium.h>

#include "processes/processes.h"
#include "processes/process_tracker.h"
#include "utilities/message.h"
#include "utilities/msg_types.h"
#include "utilities/util.h"
#include "utilities/msg_types_priv.h"
#include "config/configuration.h"

#include "identity/identity.h"
#include "identity/id_proc_priv.h"   /* identity_self_identity */
#include "reputation/reputation.h"

#include "zta_process.h"
#include "zta_policy.h"
#include "zta_verifier.h"
#include "zta_audit.h"
#include "zta_protocol.h"
#include "zta_msg_types.h"
#include "zta_delegation.h"
#include "network/net_message.h"
#include "utilities/send_retry.h"   /* at_send: keep a refused frame */

/* Protocol-string definitions (declared `extern char[]` in
 * zta_protocol.h). Writable arrays so they're directly assignable to
 * `char *` fields. */
char ZTA_PROTO_REVOCATION_ALERT[] = "zta_revoked";
char ZTA_PROTO_VERIFICATION[]     = "zta_verified";
char ZTA_PROTO_REVERIFY_REQ[]     = "zta_reverify";


/****************************
 * Process state
 ****************************/

#define MAX_REP_CACHE 128
#define MAX_PENDING_FINDINGS 32
#define REP_CACHE_TTL_SEC 600   /* Cache entries expire after 10 minutes */

/**
 * @brief Cached reputation score for a peer, obtained via local IPC query
 *        to the reputation process.
 */
typedef struct {
    uuid_t uuid;
    double score;
    struct timeval fetched_at;
    bool valid;
} rep_cache_entry_t;

/**
 * @brief A member's finding (a vouch or an alert) that arrived before we had
 *        the sender's reputation. Offered again when the reputation arrives.
 */
typedef struct {
    zta_deleg_kind_t kind;
    char from[ZTA_DELEG_UUID_LEN + 1];
    char peer[ZTA_DELEG_UUID_LEN + 1];
    uint8_t hash[ZTA_HASH_LEN];
    zta_status_t status;
    bool active;
} pending_finding_t;

static struct {
    zta_policy_t *policy;
    zta_verifier_t *verifier;
    zta_audit_log_t audit;
    uuid_t self_uuid;               /* Our own identity UUID */
    /* What members told us about peers (zta_delegation.h). */
    zta_deleg_t deleg;
    /* Reputation cache: local view of peer reputations for the bar */
    rep_cache_entry_t rep_cache[MAX_REP_CACHE];
    int rep_cache_count;
    /* Findings waiting for a reputation lookup to complete */
    pending_finding_t pending[MAX_PENDING_FINDINGS];
    int pending_count;
    bool initialized;
} zta_state;

/****************************
 * Internal helpers
 ****************************/

/**
 * @brief Tell the reputation process what ZTA now knows about a peer.
 *
 * doc/architecture/zta-integration.md. This replaces `_send_reputation_penalty`, which did
 * nothing: it stamped a zero `task_uuid`, which the reputation process
 * discards by design as the "system score" sentinel
 * (`rep_proc.c::_handle_local_tx_score`), AND it sent `score = -penalty`,
 * which `tx_score_in_range` has rejected since fixed the scale at
 * [0, 1] with no negatives. A revoked credential therefore produced two log
 * lines and cost the peer nothing at all, in the fielded runtime, with no test
 * covering it.
 *
 * A ZTA verdict is an authority finding about whether an identity is who it
 * claims -- not the outcome of an interaction with it -- so it is carried as a
 * standing (a bound, plus for a failure an unwind) rather than as a score that
 * the reputation scale has no room to express.
 */
/* Frama-C: skipped — [solver-timeout] logging/network preconditions */
static void _send_zta_standing(process_t *proc, const uuid_t peer_uuid,
                               peer_standing_t standing, double ceiling,
                               const char *reason, logger_t *logger)
{
    (void)proc;
    generic_msg_t msg;
    memset(&msg, 0, sizeof(msg));
    msg.type = PEER_STANDING;
    msg.size = sizeof(peer_standing_msg_t);
    memcpy(msg.info.peer_standing.peer_uuid, peer_uuid, sizeof(uuid_t));
    msg.info.peer_standing.standing = (int32_t)standing;
    msg.info.peer_standing.ceiling = ceiling;
    at_strlcpy(msg.info.peer_standing.reason, reason ? reason : "",
               sizeof(msg.info.peer_standing.reason));
    /* Name the authority. Ceilings are kept per (peer, source) and reduced by
     * minimum, so a ZTA verdict bounds a peer WITHOUT lifting a bound some
     * other authority placed on the same peer. */
    at_strlcpy(msg.info.peer_standing.source, PEER_STANDING_SOURCE_ZTA,
               sizeof(msg.info.peer_standing.source));

    /* A standing bounds what a peer may hold; from admission or a deferred
     * resolution nothing re-sends it, so a full reputation queue keeps it for
     * this process's tick (ISSUES §2.14). */
    (void)at_send(proc, "reputation", &msg, "a ZTA standing", "reputation", 0,
                  NULL, NULL, 0);

    char uuid_str[37];
    uuid_unparse_lower(peer_uuid, uuid_str);
    log_info(logger, "ZTA: standing %d (ceiling %.2f) for peer %s: %s\n",
             (int)standing, ceiling, uuid_str, reason ? reason : "");
}

/** A post-admission verification failure: unwind and demote (doc/architecture/zta-integration.md). The peer
 *  also stays bounded going forward -- unwinding once is not enough when the
 *  peer keeps transacting. */
static void _send_reputation_penalty(process_t *proc, const uuid_t peer_uuid,
                                     double penalty, logger_t *logger)
{
    /* The configured penalty is repurposed as the ceiling a failed peer is
     * held under: `revocation_reputation_penalty` is expressed as "how much
     * standing this costs", so what remains available is its complement. It
     * keeps one knob meaning one thing for an operator who has already tuned
     * it. */
    double ceiling = 1.0 - penalty;
    if (ceiling < 0.0) ceiling = 0.0;
    if (ceiling > 1.0) ceiling = 1.0;
    _send_zta_standing(proc, peer_uuid, PEER_STANDING_FAILED, ceiling,
                       "credential verification failed", logger);
}

/**
 * @brief Look up a peer's reputation in the local cache.
 * @return true if found and not expired, with score written to *score_out
 */
/* Frama-C: skipped —
 * zta_process_run + all helpers: [solver-timeout] memcpy of public_identity_t/uuid_t (19
 * sites) + reputation cache + delegated vouch lifecycle + peer iteration + json/network
 * cascades.
 */
/*@
  requires \valid(score_out);
  requires zta_state.rep_cache_count >= 0;
  requires zta_state.rep_cache_count <= MAX_REP_CACHE;
  assigns *score_out, zta_state.rep_cache[0 .. MAX_REP_CACHE - 1].valid;
*/
static bool _rep_cache_lookup(const uuid_t peer_uuid, double *score_out)
{
    struct timeval now;
    gettimeofday(&now, NULL);
    for (int i = 0; i < zta_state.rep_cache_count; i++) {
        rep_cache_entry_t *e = &zta_state.rep_cache[i];
        if (!e->valid)
            continue;
        if (uuid_compare(e->uuid, peer_uuid) != 0)
            continue;
        /* Check TTL — microsecond precision matters during sub-second bursts */
        long age_us = (now.tv_sec - e->fetched_at.tv_sec) * 1000000L +
                      (now.tv_usec - e->fetched_at.tv_usec);
        if (age_us > REP_CACHE_TTL_SEC * 1000000L) {
            e->valid = false;
            return false;
        }
        *score_out = e->score;
        return true;
    }
    return false;
}

/**
 * @brief Insert or update a reputation cache entry.
 */
/* Frama-C: skipped —
 * zta_process_run + all helpers: [solver-timeout] memcpy of public_identity_t/uuid_t (19
 * sites) + reputation cache + delegated vouch lifecycle + peer iteration + json/network
 * cascades.
 */
/*@
  requires zta_state.rep_cache_count >= 0;
  requires zta_state.rep_cache_count <= MAX_REP_CACHE;
  assigns zta_state.rep_cache_count,
          zta_state.rep_cache[0 .. MAX_REP_CACHE - 1];
*/
static void _rep_cache_update(const uuid_t peer_uuid, double score)
{
    /* Update existing entry if present */
    for (int i = 0; i < zta_state.rep_cache_count; i++) {
        if (zta_state.rep_cache[i].valid &&
            uuid_compare(zta_state.rep_cache[i].uuid, peer_uuid) == 0) {
            zta_state.rep_cache[i].score = score;
            gettimeofday(&zta_state.rep_cache[i].fetched_at, NULL);
            return;
        }
    }
    /* Find an empty slot or evict the oldest */
    int slot = -1;
    for (int i = 0; i < zta_state.rep_cache_count; i++) {
        if (!zta_state.rep_cache[i].valid) {
            slot = i;
            break;
        }
    }
    if (slot < 0) {
        if (zta_state.rep_cache_count < MAX_REP_CACHE) {
            slot = zta_state.rep_cache_count++;
        } else {
            /* Evict oldest entry */
            slot = 0;
            for (int i = 1; i < MAX_REP_CACHE; i++) {
                if (zta_state.rep_cache[i].fetched_at.tv_sec <
                    zta_state.rep_cache[slot].fetched_at.tv_sec)
                    slot = i;
            }
        }
    }
    rep_cache_entry_t *e = &zta_state.rep_cache[slot];
    memcpy(e->uuid, peer_uuid, sizeof(uuid_t));
    e->score = score;
    gettimeofday(&e->fetched_at, NULL);
    e->valid = true;
}

/**
 * @brief Send a local IPC query to the reputation process for a peer's score.
 */
/* Frama-C: skipped — [solver-timeout] logging/network preconditions */
static void _request_reputation(process_t *proc, const uuid_t peer_uuid,
                                logger_t *logger)
{
    char uuid_str[37];
    uuid_unparse_lower(peer_uuid, uuid_str);

    json_t *query = json_object();
    if (query == NULL) {
        log_error(logger, "ZTA: json_object OOM (rep query)\n");
        return;
    }
    json_object_set_new(query, "peer_uuid", json_string(uuid_str));
    json_object_set_new(query, "return_process", json_string(proc->name));

    generic_msg_t msg = {0};
    msg.type = NET_MESSAGE;
    strncpy(msg.info.net_msg.process, "reputation", PROC_NAME_LEN);
    msg.info.net_msg.function = REP_PROTO_LOCAL_QUERY;
    net_msg_pack_json(&msg.info.net_msg, query);
    json_decref(query);

    /* The vouch waits on the reply and is re-asked only if another vouch
     * arrives, so the query is kept on a full queue (ISSUES §2.14). */
    (void)at_send(proc, "reputation", &msg, "a reputation query", "reputation",
                  0, NULL, NULL, 0);
    net_msg_free_obj(&msg.info.net_msg);

    log_debug(logger, "ZTA: requested reputation for voucher %s\n", uuid_str);
}

/****************************
 * Delegated verification (zta_delegation.h)
 ****************************/

/* The decisions' view of this process. */

static bool _ctx_is_member(void *user, const char *uuid)
{
    const process_t *proc = (const process_t *)user;
    if (proc->protocol.group.address_map.items == NULL)
        return false;
    char key[UUID_STRING_LEN + 1];
    at_strlcpy(key, uuid, sizeof(key));
    data_t *value = NULL;
    return map_get((map_t *)&proc->protocol.group.address_map, key, &value) == 0;
}

/* The peers[] record for @p uuid_str, copied out; false when absent. */
static bool _peer_record(const process_t *proc, const char *uuid_str,
                         public_identity_t *out)
{
    uuid_t u;
    if (uuid_parse(uuid_str, u) != 0)
        return false;
    bool found = false;
    peers_read_lock(proc);
    for (size_t i = 0; i < proc->protocol.num_peers && !found; i++) {
        if (uuid_compare(proc->protocol.peers[i].uuid, u) == 0) {
            memcpy(out, &proc->protocol.peers[i], sizeof(*out));
            found = true;
        }
    }
    peers_read_unlock(proc);
    return found;
}

static bool _has_hash(const uint8_t hash[ZTA_HASH_LEN])
{
    for (int i = 0; i < ZTA_HASH_LEN; i++)
        if (hash[i] != 0)
            return true;
    return false;
}

static bool _ctx_recorded_hash(void *user, const char *peer, uint8_t out[ZTA_HASH_LEN])
{
    public_identity_t *rec = malloc(sizeof(*rec));
    if (rec == NULL)
        return false;
    bool ok = _peer_record((const process_t *)user, peer, rec)
              && _has_hash(rec->zta_credential_hash);
    if (ok)
        memcpy(out, rec->zta_credential_hash, ZTA_HASH_LEN);
    free(rec);
    return ok;
}

static int _ctx_reputation(void *user, const char *uuid, double *score)
{
    uuid_t u;
    if (uuid_parse(uuid, u) != 0)
        return 0;
    if (_rep_cache_lookup(u, score))
        return 1;
    _request_reputation((process_t *)user, u, ((process_t *)user)->logger);
    return 0;
}

/* This node's own answer for one peer's credential: the check the sweep runs. */
static zta_status_t _check_one(const uint8_t hash[ZTA_HASH_LEN], zta_result_t *result)
{
    zta_state.verifier->check_revocation(zta_state.verifier, hash, result);
    return result->status;
}

static zta_status_t _ctx_own_check(void *user, const char *peer)
{
    uint8_t hash[ZTA_HASH_LEN];
    if (!_ctx_recorded_hash(user, peer, hash))
        return ZTA_UNAVAILABLE;
    zta_result_t result;
    zta_status_t status = _check_one(hash, &result);
    log_info(((process_t *)user)->logger, "ZTA: re-checked %s on an alert: %s\n",
             peer, zta_status_str(status));
    return status;
}

static void _ctx_standing(void *user, const char *peer, peer_standing_t standing,
                          double ceiling, const char *reason)
{
    uuid_t u;
    if (uuid_parse(peer, u) != 0)
        return;
    _send_zta_standing((process_t *)user, u, standing,
                       ceiling < 0.0 ? PEER_NO_CEILING : ceiling, reason,
                       ((process_t *)user)->logger);
}

static zta_deleg_ctx_t _ctx(process_t *proc)
{
    zta_deleg_ctx_t ctx = {
        .user = proc,
        .is_member = _ctx_is_member,
        .recorded_hash = _ctx_recorded_hash,
        .reputation = _ctx_reputation,
        .own_check = _ctx_own_check,
        .standing = _ctx_standing,
        .min_reputation = zta_state.policy->delegated_verification_min_reputation,
        .quorum = zta_state.policy->delegated_verification_quorum,
        .ddil_cap = zta_state.policy->ddil_fallback_reputation_cap,
        .revocation_penalty = zta_state.policy->revocation_reputation_penalty,
    };
    return ctx;
}

/**
 * @brief Tell every other member of our group what our own check found.
 *
 * Wire form, both verbs: {"credential_hash": hex, "peer_uuid", "reason",
 * "status": "VERIFIED"|"REVOKED"}, sent to process "zta_verify" (the Python
 * runtime's network maps that name to its identity process). The sender is
 * the transport's, never a payload field.
 */
/* Frama-C: skipped — [solver-timeout] logging/network preconditions */
static void _send_finding(process_t *proc, char *verb, const char *peer_str,
                          const uint8_t hash[ZTA_HASH_LEN], zta_status_t status,
                          const char *reason)
{
    char hex[ZTA_HASH_LEN * 2 + 1];
    sodium_bin2hex(hex, sizeof(hex), hash, ZTA_HASH_LEN);
    json_t *body = json_pack("{s:s, s:s, s:s, s:s}", "credential_hash", hex,
                             "peer_uuid", peer_str, "reason", reason ? reason : "",
                             "status", zta_status_str(status));
    if (body == NULL) {
        log_error(proc->logger, "ZTA: json_pack OOM (%s)\n", verb);
        return;
    }
    public_identity_t *members = calloc(proc->protocol.num_peers + 1, sizeof(*members));
    size_t n = 0;
    if (members != NULL) {
        peers_read_lock(proc);
        for (size_t i = 0; i < proc->protocol.num_peers; i++) {
            char u[UUID_STRING_LEN + 1];
            uuid_unparse_lower(proc->protocol.peers[i].uuid, u);
            if (uuid_compare(proc->protocol.peers[i].uuid, zta_state.self_uuid) != 0
                && strcmp(u, peer_str) != 0 && _ctx_is_member(proc, u))
                memcpy(&members[n++], &proc->protocol.peers[i], sizeof(*members));
        }
        peers_read_unlock(proc);
    }
    for (size_t i = 0; i < n; i++) {
        generic_msg_t msg = {0};
        msg.type = NET_MESSAGE;
        strncpy(msg.info.net_msg.process, "zta_verify", PROC_NAME_LEN);
        msg.info.net_msg.function = verb;
        msg.info.net_msg.encrypt = true;
        memcpy(&msg.info.net_msg.to_whom, &members[i], sizeof(public_identity_t));
        strncpy(msg.info.net_msg.return_to, "zta_verify", PROC_NAME_LEN);
        net_msg_pack_json(&msg.info.net_msg, body);
        (void)at_send(proc, "network", &msg, "a ZTA finding", "network",
                      0, NULL, NULL, 0);
        net_msg_free_obj(&msg.info.net_msg);
    }
    free(members);
    json_decref(body);
    log_debug(proc->logger, "ZTA: sent %s for %s to %zu member(s)\n", verb, peer_str, n);
}

static void _hold(zta_deleg_kind_t kind, const char *from, const char *peer,
                  const uint8_t hash[ZTA_HASH_LEN], zta_status_t status, logger_t *logger)
{
    for (int i = 0; i < zta_state.pending_count; i++) {
        pending_finding_t *pf = &zta_state.pending[i];
        if (pf->active && pf->kind == kind && strcmp(pf->from, from) == 0
            && strcmp(pf->peer, peer) == 0)
            return;   /* already held */
    }
    if (zta_state.pending_count >= MAX_PENDING_FINDINGS) {
        log_warn(logger, "ZTA: pending finding queue full, dropping one from %s\n", from);
        return;
    }
    pending_finding_t *pf = &zta_state.pending[zta_state.pending_count++];
    pf->kind = kind;
    at_strlcpy(pf->from, from, sizeof(pf->from));
    at_strlcpy(pf->peer, peer, sizeof(pf->peer));
    memcpy(pf->hash, hash, ZTA_HASH_LEN);
    pf->status = status;
    pf->active = true;
}

/** One member's finding, decided and logged. */
static void _decide(process_t *proc, zta_deleg_kind_t kind, const char *from,
                    const char *peer, const uint8_t hash[ZTA_HASH_LEN], zta_status_t status)
{
    zta_deleg_ctx_t ctx = _ctx(proc);
    zta_deleg_verdict_t v = zta_deleg_event(&zta_state.deleg, &ctx, kind, from, peer,
                                            hash, status);
    const char *what = kind == ZTA_DELEG_VOUCH ? "vouch" : "revocation alert";
    if (v == ZTA_DELEG_PENDING) {
        _hold(kind, from, peer, hash, status, proc->logger);
        log_debug(proc->logger, "ZTA: %s from %s for %s held: reputation not known yet\n",
                  what, from, peer);
    } else if (v == ZTA_DELEG_COUNTED || v == ZTA_DELEG_QUORUM
               || v == ZTA_DELEG_OWN_FAILED || v == ZTA_DELEG_OWN_VERIFIED) {
        log_info(proc->logger, "ZTA: %s from %s for %s: %s\n", what, from, peer,
                 zta_deleg_verdict_str(v));
    } else {
        log_warn(proc->logger, "ZTA: %s from %s for %s ignored: %s\n", what, from, peer,
                 zta_deleg_verdict_str(v));
    }
}

/* Offer each held finding whose sender's reputation is now cached. */
/* Frama-C: skipped — [solver-timeout] array lifecycle preconditions */
static void _process_pending(process_t *proc, logger_t *logger)
{
    (void)logger;
    for (int i = zta_state.pending_count - 1; i >= 0; i--) {
        pending_finding_t pf = zta_state.pending[i];
        uuid_t u;
        double score = 0.0;
        if (!pf.active || uuid_parse(pf.from, u) != 0 || !_rep_cache_lookup(u, &score))
            continue;
        /* Out of the list first: deciding it may hold it again. */
        zta_state.pending[i] = zta_state.pending[--zta_state.pending_count];
        _decide(proc, pf.kind, pf.from, pf.peer, pf.hash, pf.status);
    }
}

/* A member's `zta_verified` / `zta_revoked`. */
/* Frama-C: skipped — [solver-timeout] logging/json handler */
static bool _handle_finding(const process_t *cproc, generic_msg_t *msg, zta_deleg_kind_t kind)
{
    process_t *proc = (process_t *)cproc;
    net_msg_t *nmsg = &msg->info.net_msg;
    if (!zta_state.initialized)
        return true;
    if (uuid_is_null(nmsg->from_whom.uuid)) {
        log_warn(proc->logger, "ZTA: %s with no sender refused\n", nmsg->function);
        return true;
    }
    char from[UUID_STRING_LEN + 1];
    uuid_unparse_lower(nmsg->from_whom.uuid, from);
    json_t *body = NULL;
    if (net_msg_unpack_json(nmsg, &body) != 0 || !json_is_object(body)) {
        json_decref(body);
        log_warn(proc->logger, "ZTA: %s from %s: unreadable body\n", nmsg->function, from);
        return true;
    }
    const char *peer = json_string_value(json_object_get(body, "peer_uuid"));
    const char *hex = json_string_value(json_object_get(body, "credential_hash"));
    const char *status_s = json_string_value(json_object_get(body, "status"));
    uuid_t pu;
    uint8_t hash[ZTA_HASH_LEN];
    size_t hlen = 0;
    if (peer == NULL || uuid_parse(peer, pu) != 0 || hex == NULL || status_s == NULL
        || sodium_hex2bin(hash, sizeof(hash), hex, strlen(hex), NULL, &hlen, NULL) != 0
        || hlen != ZTA_HASH_LEN) {
        json_decref(body);
        log_warn(proc->logger, "ZTA: %s from %s: malformed\n", nmsg->function, from);
        return true;
    }
    char peer_str[UUID_STRING_LEN + 1];
    uuid_unparse_lower(pu, peer_str);
    zta_status_t status = strcmp(status_s, "VERIFIED") == 0 ? ZTA_VERIFIED
                        : strcmp(status_s, "REVOKED") == 0 ? ZTA_REVOKED
                        : ZTA_REJECTED;   /* anything else: neither finding */
    json_decref(body);
    _decide(proc, kind, from, peer_str, hash, status);
    return true;
}

static bool _handle_vouch(const process_t *proc, directory_t *queues, generic_msg_t *msg)
{
    (void)queues;
    return _handle_finding(proc, msg, ZTA_DELEG_VOUCH);
}

static bool _handle_alert(const process_t *proc, directory_t *queues, generic_msg_t *msg)
{
    (void)queues;
    return _handle_finding(proc, msg, ZTA_DELEG_ALERT);
}

/**
 * @brief Re-verify all known peers with ZTA credentials
 */
/* Frama-C: skipped — [solver-timeout] peer iteration preconditions */
static void _reverify_peers(process_t *proc, logger_t *logger)
{
    /* Snapshot (uuid, credential hash) and act with the lock released: acting
     * walks the peer list again to reach the members. */
    size_t cap = proc->protocol.num_peers;
    uuid_t *uuids = calloc(cap + 1, sizeof(uuid_t));
    uint8_t (*hashes)[ZTA_HASH_LEN] = calloc(cap + 1, ZTA_HASH_LEN);
    size_t n = 0;
    if (uuids == NULL || hashes == NULL) {
        free(uuids);
        free(hashes);
        return;
    }
    peers_read_lock(proc);
    for (size_t i = 0; i < proc->protocol.num_peers && n < cap; i++) {
        public_identity_t *peer = &proc->protocol.peers[i];
        if (!_has_hash(peer->zta_credential_hash))
            continue;   /* Skip peers without ZTA credentials */
        memcpy(uuids[n], peer->uuid, sizeof(uuid_t));
        memcpy(hashes[n], peer->zta_credential_hash, ZTA_HASH_LEN);
        n++;
    }
    peers_read_unlock(proc);

    for (size_t i = 0; i < n; i++) {
        zta_result_t result;
        _check_one(hashes[i], &result);

        /* Record audit entry */
        if (zta_state.policy->audit_deferred_verifications) {
            zta_audit_entry_t entry;
            memset(&entry, 0, sizeof(entry));
            gettimeofday(&entry.timestamp, NULL);
            memcpy(entry.peer_uuid, uuids[i], sizeof(uuid_t));
            snprintf(entry.action, ZTA_ACTION_LEN, "periodic_reverify");
            memcpy(&entry.result, &result, sizeof(zta_result_t));
            entry.deferred = (result.status == ZTA_UNAVAILABLE ||
                              result.status == ZTA_DEFERRED);
            zta_audit_record(&zta_state.audit, &entry);
        }

        char uuid_str[37];
        uuid_unparse_lower(uuids[i], uuid_str);
        zta_deleg_own_result(&zta_state.deleg, uuid_str, result.status);

        switch (result.status) {
        case ZTA_REVOKED:
            log_warn(logger, "ZTA: peer %s credential REVOKED: %s\n",
                     uuid_str, result.reason);
            _send_reputation_penalty(proc, uuids[i],
                                     zta_state.policy->revocation_reputation_penalty,
                                     logger);
            /* Tell the group; each member re-checks before it acts. */
            _send_finding(proc, ZTA_PROTO_REVOCATION_ALERT, uuid_str, hashes[i],
                          ZTA_REVOKED, "credential revoked");
            break;

        case ZTA_EXPIRED:
            log_warn(logger, "ZTA: peer %s credential EXPIRED: %s\n",
                     uuid_str, result.reason);
            _send_reputation_penalty(proc, uuids[i],
                                     zta_state.policy->revocation_reputation_penalty * 0.5,
                                     logger);
            break;

        case ZTA_UNAVAILABLE:
        case ZTA_DEFERRED:
            log_debug(logger, "ZTA: reverification deferred for peer %s: %s\n",
                      uuid_str, result.reason);
            break;

        case ZTA_VERIFIED:
            log_debug(logger, "ZTA: peer %s credential still valid\n", uuid_str);
            /* Re-anchor the unwind (doc/architecture/zta-integration.md): everything committed up to now was
             * observed while this credential verified, so a LATER failure must
             * not reach back past this point. Also lifts any ceiling the peer
             * was under, which is what lets a DDIL admission recover once the
             * infrastructure returns. Mirrors the Python sweep. */
            _send_zta_standing(proc, uuids[i], PEER_STANDING_PROVED,
                               PEER_NO_CEILING, "re-verified", logger);
            /* Vouch, so a member that cannot reach the verifier can lift its cap */
            _send_finding(proc, ZTA_PROTO_VERIFICATION, uuid_str, hashes[i],
                          ZTA_VERIFIED, "re-verified");
            break;

        case ZTA_REJECTED:
            log_warn(logger, "ZTA: peer %s credential REJECTED: %s\n",
                     uuid_str, result.reason);
            _send_reputation_penalty(proc, uuids[i],
                                     zta_state.policy->revocation_reputation_penalty,
                                     logger);
            break;
        }
    }
    free(uuids);
    free(hashes);
}


/**
 * @brief Attempt to resolve deferred verifications
 */
/* Frama-C: skipped — [solver-timeout] array iteration preconditions */
static void _resolve_deferred(process_t *proc, logger_t *logger)
{
    if (!zta_state.verifier->is_available(zta_state.verifier))
        return;

    int count = zta_audit_deferred_count(&zta_state.audit);
    for (int i = count - 1; i >= 0; i--) {
        zta_audit_entry_t entry;
        if (zta_audit_get_deferred(&zta_state.audit, i, &entry) != 0)
            continue;

        /* Find the peer and snapshot the credential bytes we need — avoid
         * holding peers_rwlock across the external verifier call. */
        uint8_t *cred = NULL;
        size_t cred_len = 0;
        uint8_t cred_hash[32];
        bool have_peer = false;
        peers_read_lock(proc);
        for (size_t p = 0; p < proc->protocol.num_peers; p++) {
            if (uuid_compare(proc->protocol.peers[p].uuid, entry.peer_uuid) == 0) {
                public_identity_t *peer = &proc->protocol.peers[p];
                cred = peer->zta_credential;
                cred_len = peer->zta_credential_len;
                memcpy(cred_hash, peer->zta_credential_hash, sizeof(cred_hash));
                have_peer = true;
                break;
            }
        }
        peers_read_unlock(proc);
        if (!have_peer)
            continue;

        zta_result_t result;
        if (cred && cred_len > 0) {
            zta_state.verifier->verify_credential(
                zta_state.verifier,
                cred, cred_len,
                &result);
        } else {
            zta_state.verifier->check_revocation(
                zta_state.verifier, cred_hash, &result);
        }

        if (result.status == ZTA_UNAVAILABLE || result.status == ZTA_DEFERRED)
            continue; /* still can't resolve */

        zta_audit_resolve(&zta_state.audit, entry.peer_uuid, &result);
        {
            char peer_str[37];
            uuid_unparse_lower(entry.peer_uuid, peer_str);
            zta_deleg_own_result(&zta_state.deleg, peer_str, result.status);
        }

        char uuid_str[37];
        uuid_unparse_lower(entry.peer_uuid, uuid_str);

        if (result.status == ZTA_VERIFIED) {
            log_info(logger, "ZTA: deferred verification resolved for peer %s: VERIFIED\n",
                     uuid_str);
            /* The DDIL condition has cleared: lift the ceiling this peer was
             * admitted under and anchor the unwind here (doc/architecture/zta-integration.md). Until the cap
             * was actually enforced there was nothing for this branch to lift,
             * which is why it only logged. */
            _send_zta_standing(proc, entry.peer_uuid, PEER_STANDING_PROVED,
                               PEER_NO_CEILING, "deferred verification resolved",
                               logger);
        } else {
            log_warn(logger, "ZTA: deferred verification resolved for peer %s: %s - %s\n",
                     uuid_str, zta_status_str(result.status), result.reason);
            _send_reputation_penalty(proc, entry.peer_uuid,
                                     zta_state.policy->revocation_reputation_penalty,
                                     logger);
        }
    }
}

/**
 * @brief Handler for local_rep_response messages from the reputation process.
 *
 * Updates the reputation cache and triggers pending vouch processing.
 */
/* Frama-C: skipped — [solver-timeout] logging/json handler */
static bool _handle_rep_response(const process_t *proc, directory_t *queues,
                                 generic_msg_t *msg)
{
    (void)queues;
    net_msg_t *nmsg = &msg->info.net_msg;

    /* Local only: a member forging one would set its own score past the bar.
     * The rule of identity_is_local_app_verb (no sender, or ourselves). */
    if (!uuid_is_null(nmsg->from_whom.uuid)
        && uuid_compare(nmsg->from_whom.uuid, zta_state.self_uuid) != 0) {
        char who[UUID_STRING_LEN + 1];
        uuid_unparse_lower(nmsg->from_whom.uuid, who);
        log_warn(proc->logger, "ZTA: refusing %s from the wire (peer %s)\n",
                 nmsg->function, who);
        return true;
    }

    json_t *payload = NULL;
    if (net_msg_unpack_json(nmsg, &payload) != 0 || payload == NULL) {
        log_error(proc->logger, "ZTA: failed to unpack rep response\n");
        return false;
    }

    json_t *j_uuid  = json_object_get(payload, "peer_uuid");
    json_t *j_score  = json_object_get(payload, "score");
    json_t *j_found  = json_object_get(payload, "found");

    if (!j_uuid || !j_score) {
        json_decref(payload);
        return false;
    }

    const char *uuid_str = json_string_value(j_uuid);
    double score = json_real_value(j_score);
    bool found = j_found ? json_boolean_value(j_found) : false;

    uuid_t peer_uuid;
    if (uuid_parse(uuid_str, peer_uuid) != 0) {
        json_decref(payload);
        return false;
    }

    json_decref(payload);

    if (found) {
        _rep_cache_update(peer_uuid, score);
        log_debug(proc->logger, "ZTA: cached reputation %.2f for peer %s\n",
                  score, uuid_str);
    } else {
        /* Peer not known to reputation process — use 0.0 (will fail threshold) */
        _rep_cache_update(peer_uuid, 0.0);
        log_debug(proc->logger, "ZTA: peer %s unknown to reputation process, caching 0.0\n",
                  uuid_str);
    }

    /* Offer the held findings again now that we have new cache data */
    _process_pending((process_t *)proc, proc->logger);
    return true;
}
/****************************
 * Process runner
 ****************************/

/* Frama-C: skipped — [solver-timeout] logging/snprintf/process preconditions */
int zta_process_run(process_t *proc, directory_t *queues,
                    queue_id_t signal, logger_t *logger)
{
    at_zta_msg_types_link();
    /* Look up ZTA policy from configs. Values are object_ptr_data(config_t)
     * (load_all_configs), so unwrap data_t -> config_t -> data_struct rather
     * than casting the data_t wrapper directly to the policy struct. */
    data_t *policy_data = NULL;
    config_t *policy_cfg = NULL;
    char zta_key[] = "zta_policy";
    if (map_get(proc->configs, zta_key, &policy_data) != 0 || !policy_data
        || data_object_ptr(policy_data, (void **)&policy_cfg) != 0
        || policy_cfg == NULL || policy_cfg->data_struct == NULL) {
        log_info(logger, "ZTA: no policy configured, process exiting\n");
        return 0;
    }
    zta_state.policy = (zta_policy_t *)policy_cfg->data_struct;

    /* Resolve our own identity UUID for signing broadcast messages */
    {
        const identity_t *myself = identity_self_identity(proc);
        public_identity_t *pub = NULL;
        if (myself != NULL && identity_publish(myself, &pub) == 0 && pub) {
            memcpy(zta_state.self_uuid, pub->uuid, sizeof(uuid_t));
            smrt_deref(pub);
        }
    }

    /* Runtime gate: exit immediately if not enabled */
    if (!zta_state.policy->enabled) {
        log_info(logger, "ZTA: policy disabled, process exiting\n");
        return 0;
    }

    /* Create verifier */
    int rc = zta_policy_create_verifier(zta_state.policy, &zta_state.verifier);
    if (rc != 0) {
        log_error(logger, "ZTA: failed to create verifier (error %d)\n", rc);
        return rc;
    }

    /* Init audit log */
    char data_dir[CFG_PATH_LEN];
    get_data_dir(data_dir, sizeof(data_dir));
    char audit_path[CFG_PATH_LEN + 32];
    snprintf(audit_path, sizeof(audit_path), "%s/zta_audit.jsonl", data_dir);
    if (zta_audit_init(&zta_state.audit, audit_path) != 0) {
        log_error(logger, "ZTA: failed to init audit log at %s\n", audit_path);
        zta_state.verifier->destroy(zta_state.verifier);
        return -1;
    }
    zta_deleg_init(&zta_state.deleg);
    zta_state.initialized = true;

    log_info(logger, "ZTA: process started (reverify interval: %d sec)\n",
             zta_state.policy->reverify_interval_sec);

    /* Register handler for reputation responses from the reputation process */
    process_register_handler(proc, REP_PROTO_LOCAL_RESP,
                             (handler_ptr_t)_handle_rep_response);
    /* Members' findings (zta_delegation.h) */
    process_register_handler(proc, ZTA_PROTO_VERIFICATION, (handler_ptr_t)_handle_vouch);
    process_register_handler(proc, ZTA_PROTO_REVOCATION_ALERT, (handler_ptr_t)_handle_alert);

    /* Standard process setup */
    process_ctx_t pctx;
    rc = process_setup(proc, signal, logger, &pctx);
    if (rc != 0) {
        zta_audit_close(&zta_state.audit);
        zta_state.verifier->destroy(zta_state.verifier);
        return rc;
    }

    /* Main loop: sleep for reverify interval, then check peers */
    int cycle = 0;
    int reverify_cycles = 0;
    if (zta_state.policy->reverify_interval_sec > 0 && cadence > 0)
        reverify_cycles = (zta_state.policy->reverify_interval_sec * 1000) / cadence;

    generic_msg_t buf = {0};
    while (keep_running(proc, &pctx.sig_q, logger)) {
        sleep_until(proc, cadence);

        /* Handle incoming messages (members' findings, reputation answers) */
        messaging_recv_release(&buf);   /* the previous pass's */
        int err = messaging_recv(&buf);
        if (err == 0)
            run_message_handlers(proc, queues, buf.type, &buf);

        /* Periodic re-verification */
        if (reverify_cycles > 0 && ++cycle >= reverify_cycles) {
            cycle = 0;
            log_debug(logger, "ZTA: running periodic re-verification\n");
            _reverify_peers(proc, logger);
            _resolve_deferred(proc, logger);
        }
    }
    messaging_recv_release(&buf);

    /* Cleanup */
    zta_audit_close(&zta_state.audit);
    if (zta_state.verifier) {
        zta_state.verifier->destroy(zta_state.verifier);
        zta_state.verifier = NULL;
    }

    if (pctx.fd1 > 0)
        close(pctx.fd1);
    if (pctx.fd2 > 0)
        close(pctx.fd2);

    log_info(logger, "ZTA: process shutting down\n");
    return 0;
}

/* An extension library's process: the core's generated table does not scan
 * src/c/extensions, so it registers itself (process_tracker.h). */
DEFINE_PROCESS(zta_verify, zta_proc, zta_process_run)
/* Started by default once libat_zta is linked (AT_ZTA, still OFF by default):
 * before this, no generated configuration listed it, so background
 * re-verification ran only where an operator added it by hand. */
DEFINE_SUBSYSTEM(zta_verify, "zta_verify", "zta_proc")

/* Keeps the registration above in a static link (at_zta_link). */
void at_zta_process_link(void) {}
