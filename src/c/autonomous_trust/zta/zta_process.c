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
#include <time.h>
#include <unistd.h>
#include <jansson.h>

#include "processes/processes.h"
#include "utilities/message.h"
#include "utilities/msg_types.h"
#include "utilities/util.h"
#include "utilities/msg_types_priv.h"
#include "config/configuration.h"

#include "identity/identity.h"
#include "reputation/reputation.h"

#include "zta_process.h"
#include "zta_policy.h"
#include "zta_verifier.h"
#include "zta_audit.h"
#include "zta_protocol.h"

/* Protocol-string definitions (declared `extern char[]` in
 * zta_protocol.h). Writable arrays so they're directly assignable to
 * `char *` fields. */
char ZTA_PROTO_REVOCATION_ALERT[] = "zta_revoked";
char ZTA_PROTO_VERIFICATION[]     = "zta_verified";
char ZTA_PROTO_REVERIFY_REQ[]     = "zta_reverify";

/****************************
 * Process state
 ****************************/

#define MAX_DELEGATED_PEERS 256
#define MAX_VOUCHES_PER_PEER 16
#define MAX_REP_CACHE 128
#define MAX_PENDING_VOUCHES 32
#define REP_CACHE_TTL_SEC 600   /* Cache entries expire after 10 minutes */

/**
 * @brief Tracks delegated verification vouches for a DDIL-admitted peer.
 *
 * When the local node cannot reach ZTA infrastructure, other peers that CAN
 * reach it may verify the credential and broadcast a ZTA_PROTO_VERIFICATION
 * message.  Each such message is a "vouch".  When enough distinct peers
 * have vouched (>= delegated_verification_quorum), the DDIL reputation cap
 * is lifted.
 */
typedef struct {
    uuid_t peer_uuid;                            /* The peer being vouched for */
    uuid_t vouchers[MAX_VOUCHES_PER_PEER];       /* UUIDs of peers who vouched */
    int vouch_count;
    bool cap_lifted;
} delegated_vouch_t;

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
 * @brief A delegated vouch that arrived before we had the voucher's
 *        reputation cached.  Held until the reputation response arrives.
 */
typedef struct {
    zta_event_msg_t event;
    uuid_t voucher_uuid;
    bool active;
} pending_vouch_t;

static struct {
    zta_policy_t *policy;
    zta_verifier_t *verifier;
    zta_audit_log_t audit;
    uuid_t self_uuid;               /* Our own identity UUID */
    delegated_vouch_t vouches[MAX_DELEGATED_PEERS];
    int vouch_count;
    /* Reputation cache: local view of peer reputations for vouch gating */
    rep_cache_entry_t rep_cache[MAX_REP_CACHE];
    int rep_cache_count;
    /* Vouches waiting for a reputation lookup to complete */
    pending_vouch_t pending_vouches[MAX_PENDING_VOUCHES];
    int pending_vouch_count;
    bool initialized;
} zta_state;

/****************************
 * Internal helpers
 ****************************/

/**
 * @brief Tell the reputation process what ZTA now knows about a peer.
 *
 * ISSUES.md §10.5. This replaces `_send_reputation_penalty`, which did
 * nothing: it stamped a zero `task_uuid`, which the reputation process
 * discards by design as the "system score" sentinel
 * (`rep_proc.c::_handle_local_tx_score`), AND it sent `score = -penalty`,
 * which `tx_score_in_range` has rejected since §11.2 fixed the scale at
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
                               zta_standing_t standing, double ceiling,
                               const char *reason, logger_t *logger)
{
    (void)proc;
    generic_msg_t msg;
    memset(&msg, 0, sizeof(msg));
    msg.type = ZTA_STANDING;
    msg.size = sizeof(zta_standing_msg_t);
    memcpy(msg.info.zta_standing.peer_uuid, peer_uuid, sizeof(uuid_t));
    msg.info.zta_standing.standing = (int32_t)standing;
    msg.info.zta_standing.ceiling = ceiling;
    at_strlcpy(msg.info.zta_standing.reason, reason ? reason : "",
               sizeof(msg.info.zta_standing.reason));

    messaging_send("reputation", ZTA_STANDING, &msg, false);

    char uuid_str[37];
    uuid_unparse_lower(peer_uuid, uuid_str);
    log_info(logger, "ZTA: standing %d (ceiling %.2f) for peer %s: %s\n",
             (int)standing, ceiling, uuid_str, reason ? reason : "");
}

/** A post-admission verification failure: unwind and demote (§10.5). The peer
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
    _send_zta_standing(proc, peer_uuid, ZTA_STANDING_FAILED, ceiling,
                       "credential verification failed", logger);
}

/**
 * @brief Broadcast a revocation alert to the group
 */
/* Frama-C: skipped — [solver-timeout] logging/network preconditions */
static void _broadcast_revocation_alert(process_t *proc, const uuid_t peer_uuid,
                                        const uint8_t *cred_hash, logger_t *logger)
{
    generic_msg_t msg;
    memset(&msg, 0, sizeof(msg));
    msg.type = ZTA_REVOCATION_ALERT;
    msg.size = sizeof(zta_event_msg_t);

    memcpy(msg.info.zta_event.peer_uuid, peer_uuid, sizeof(uuid_t));
    memcpy(msg.info.zta_event.voucher_uuid, zta_state.self_uuid, sizeof(uuid_t));
    memcpy(msg.info.zta_event.credential_hash, cred_hash, ZTA_HASH_LEN);
    msg.info.zta_event.status = (int)ZTA_REVOKED;
    snprintf(msg.info.zta_event.reason, sizeof(msg.info.zta_event.reason),
             "credential revoked");

    messaging_send("network", NET_MESSAGE, &msg, false);

    char uuid_str[37];
    uuid_unparse_lower(peer_uuid, uuid_str);
    log_warn(logger, "ZTA: broadcast revocation alert for peer %s\n", uuid_str);
}

/**
 * @brief Find or create a vouch tracker for a peer
 */
/* Frama-C: skipped —
 * zta_process_run + all helpers: [solver-timeout] memcpy of public_identity_t/uuid_t (19
 * sites) + reputation cache + delegated vouch lifecycle + peer iteration + json/network
 * cascades.
 */
/*@
  requires zta_state.vouch_count >= 0;
  requires zta_state.vouch_count <= MAX_DELEGATED_PEERS;
  assigns zta_state.vouch_count, zta_state.vouches[0 .. MAX_DELEGATED_PEERS - 1];
*/
static delegated_vouch_t *_find_or_create_vouch(const uuid_t peer_uuid)
{
    for (int i = 0; i < zta_state.vouch_count; i++) {
        if (uuid_compare(zta_state.vouches[i].peer_uuid, peer_uuid) == 0)
            return &zta_state.vouches[i];
    }
    if (zta_state.vouch_count >= MAX_DELEGATED_PEERS)
        return NULL;
    delegated_vouch_t *v = &zta_state.vouches[zta_state.vouch_count++];
    memset(v, 0, sizeof(*v));
    memcpy(v->peer_uuid, peer_uuid, sizeof(uuid_t));
    return v;
}

/**
 * @brief Check if a voucher UUID is already recorded for this peer
 */
/*@
  requires \valid_read(v);
  requires v->vouch_count >= 0;
  requires \valid_read(v->vouchers + (0 .. v->vouch_count - 1));
*/
static bool _has_voucher(const delegated_vouch_t *v, const uuid_t voucher_uuid)
{
    for (int i = 0; i < v->vouch_count; i++) {
        if (uuid_compare(v->vouchers[i], voucher_uuid) == 0)
            return true;
    }
    return false;
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

    messaging_send("reputation", NET_MESSAGE, &msg, false);

    log_debug(logger, "ZTA: requested reputation for voucher %s\n", uuid_str);
}

/**
 * @brief Store a vouch as pending until we get the voucher's reputation.
 */
/* Frama-C: skipped — [solver-timeout] array/map lifecycle preconditions */
static void _defer_vouch(const zta_event_msg_t *event, const uuid_t voucher_uuid,
                         logger_t *logger)
{
    if (zta_state.pending_vouch_count >= MAX_PENDING_VOUCHES) {
        log_warn(logger, "ZTA: pending vouch queue full, dropping vouch\n");
        return;
    }
    pending_vouch_t *pv = &zta_state.pending_vouches[zta_state.pending_vouch_count++];
    memcpy(&pv->event, event, sizeof(zta_event_msg_t));
    memcpy(pv->voucher_uuid, voucher_uuid, sizeof(uuid_t));
    pv->active = true;
}

/**
 * @brief Broadcast our own verification result so other peers can use it
 */
/* Frama-C: skipped — [solver-timeout] logging/network preconditions */
static void _broadcast_verification(process_t *proc, const uuid_t peer_uuid,
                                    const zta_result_t *result, logger_t *logger)
{
    generic_msg_t msg;
    memset(&msg, 0, sizeof(msg));
    msg.type = ZTA_VERIFICATION_RESULT;
    msg.size = sizeof(zta_event_msg_t);

    _Static_assert(sizeof(msg.info.zta_event.credential_hash) == ZTA_HASH_LEN,
                   "zta_event credential_hash size must equal ZTA_HASH_LEN");
    memcpy(msg.info.zta_event.peer_uuid, peer_uuid, sizeof(uuid_t));
    memcpy(msg.info.zta_event.voucher_uuid, zta_state.self_uuid, sizeof(uuid_t));
    memcpy(msg.info.zta_event.credential_hash, result->credential_hash, ZTA_HASH_LEN);
    msg.info.zta_event.status = (int)result->status;
    /* reason[ZTA_REASON_LEN=256] -> the narrower wire field; bound the
     * conversion width to the destination so the (intentional) truncation is
     * explicit and -Wformat-truncation is satisfied. */
    snprintf(msg.info.zta_event.reason, sizeof(msg.info.zta_event.reason),
             "%.*s", (int)(sizeof(msg.info.zta_event.reason) - 1),
             result->reason);

    messaging_send("network", NET_MESSAGE, &msg, false);

    char uuid_str[37];
    uuid_unparse_lower(peer_uuid, uuid_str);
    log_debug(logger, "ZTA: broadcast verification result (%s) for peer %s\n",
              zta_status_str(result->status), uuid_str);
}

/**
 * @brief Handle a delegated verification message from another peer.
 *
 * If the vouching peer is admitted (message came through the encrypted
 * group channel), has sufficient reputation, and the result is ZTA_VERIFIED,
 * record the vouch.  When quorum is reached, lift the DDIL reputation cap
 * by resolving the deferred audit entry.
 *
 * Reputation gating prevents a DDIL-admitted attacker (capped at
 * ddil_fallback_reputation_cap) from vouching for a confederate.
 */
/* Frama-C: skipped — [solver-timeout] logging/json handler */
static void _handle_delegated_verification(process_t *proc,
                                           const zta_event_msg_t *event,
                                           const uuid_t voucher_uuid,
                                           logger_t *logger)
{
    /* Only accept VERIFIED results as vouches */
    if ((zta_status_t)event->status != ZTA_VERIFIED)
        return;

    char peer_str[37], voucher_str[37];
    uuid_unparse_lower(event->peer_uuid, peer_str);
    uuid_unparse_lower(voucher_uuid, voucher_str);

    /* --- Reputation gate ------------------------------------------------
     * The vouching peer must have at least delegated_verification_min_reputation
     * for their vouch to count.  If we don't have a cached score yet, defer
     * the vouch and request the score from the reputation process.
     * ------------------------------------------------------------------ */
    double voucher_rep = 0.0;
    if (!_rep_cache_lookup(voucher_uuid, &voucher_rep)) {
        /* Score not cached — defer this vouch and request it */
        log_debug(logger, "ZTA: voucher %s reputation not cached, deferring vouch for %s\n",
                  voucher_str, peer_str);
        _defer_vouch(event, voucher_uuid, logger);
        _request_reputation(proc, voucher_uuid, logger);
        return;
    }

    if (voucher_rep < zta_state.policy->delegated_verification_min_reputation) {
        log_warn(logger, "ZTA: rejecting vouch from %s for %s — "
                 "reputation %.2f < threshold %.2f\n",
                 voucher_str, peer_str, voucher_rep,
                 zta_state.policy->delegated_verification_min_reputation);
        return;
    }

    delegated_vouch_t *v = _find_or_create_vouch(event->peer_uuid);
    if (!v) {
        log_warn(logger, "ZTA: delegated vouch table full, ignoring vouch for %s\n",
                 peer_str);
        return;
    }

    if (v->cap_lifted) {
        log_debug(logger, "ZTA: cap already lifted for peer %s, ignoring vouch\n",
                  peer_str);
        return;
    }

    /* Don't count duplicate vouches from the same peer */
    if (_has_voucher(v, voucher_uuid)) {
        log_debug(logger, "ZTA: duplicate vouch from %s for %s, ignoring\n",
                  voucher_str, peer_str);
        return;
    }

    if (v->vouch_count >= MAX_VOUCHES_PER_PEER)
        return;

    memcpy(v->vouchers[v->vouch_count], voucher_uuid, sizeof(uuid_t));
    v->vouch_count++;

    log_info(logger, "ZTA: delegated vouch from %s for %s (%d/%d quorum)\n",
             voucher_str, peer_str, v->vouch_count,
             zta_state.policy->delegated_verification_quorum);

    /* Check quorum */
    if (v->vouch_count >= zta_state.policy->delegated_verification_quorum) {
        v->cap_lifted = true;

        /* Resolve the deferred audit entry */
        zta_result_t resolution;
        zta_result_set(&resolution, ZTA_VERIFIED, "delegated verification quorum met");
        memcpy(resolution.credential_hash, event->credential_hash, ZTA_HASH_LEN);
        zta_audit_resolve(&zta_state.audit, event->peer_uuid, &resolution);

        log_info(logger, "ZTA: delegated verification quorum met for peer %s "
                 "(%d vouches) — DDIL reputation cap lifted\n",
                 peer_str, v->vouch_count);

        /* Record the cap-lift event */
        if (zta_state.policy->audit_deferred_verifications) {
            zta_audit_entry_t entry;
            memset(&entry, 0, sizeof(entry));
            gettimeofday(&entry.timestamp, NULL);
            memcpy(entry.peer_uuid, event->peer_uuid, sizeof(uuid_t));
            snprintf(entry.action, ZTA_ACTION_LEN, "delegated_cap_lift");
            memcpy(&entry.result, &resolution, sizeof(zta_result_t));
            entry.deferred = false;
            zta_audit_record(&zta_state.audit, &entry);
        }
    }
}

/**
 * @brief Re-verify all known peers with ZTA credentials
 */
/* Frama-C: skipped — [solver-timeout] peer iteration preconditions */
static void _reverify_peers(process_t *proc, logger_t *logger)
{
    peers_read_lock(proc);
    for (size_t i = 0; i < proc->protocol.num_peers; i++) {
        public_identity_t *peer = &proc->protocol.peers[i];

        /* Skip peers without ZTA credentials */
        bool has_cred = false;
        for (int j = 0; j < 32; j++) {
            if (peer->zta_credential_hash[j] != 0) {
                has_cred = true;
                break;
            }
        }
        if (!has_cred)
            continue;

        zta_result_t result;
        zta_state.verifier->check_revocation(
            zta_state.verifier, peer->zta_credential_hash, &result);

        /* Record audit entry */
        if (zta_state.policy->audit_deferred_verifications) {
            zta_audit_entry_t entry;
            memset(&entry, 0, sizeof(entry));
            gettimeofday(&entry.timestamp, NULL);
            memcpy(entry.peer_uuid, peer->uuid, sizeof(uuid_t));
            snprintf(entry.action, ZTA_ACTION_LEN, "periodic_reverify");
            memcpy(&entry.result, &result, sizeof(zta_result_t));
            entry.deferred = (result.status == ZTA_UNAVAILABLE ||
                              result.status == ZTA_DEFERRED);
            zta_audit_record(&zta_state.audit, &entry);
        }

        char uuid_str[37];
        uuid_unparse_lower(peer->uuid, uuid_str);

        switch (result.status) {
        case ZTA_REVOKED:
            log_warn(logger, "ZTA: peer %s credential REVOKED: %s\n",
                     uuid_str, result.reason);
            _send_reputation_penalty(proc, peer->uuid,
                                     zta_state.policy->revocation_reputation_penalty,
                                     logger);
            _broadcast_revocation_alert(proc, peer->uuid,
                                        peer->zta_credential_hash, logger);
            break;

        case ZTA_EXPIRED:
            log_warn(logger, "ZTA: peer %s credential EXPIRED: %s\n",
                     uuid_str, result.reason);
            _send_reputation_penalty(proc, peer->uuid,
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
            /* Re-anchor the unwind (§10.5): everything committed up to now was
             * observed while this credential verified, so a LATER failure must
             * not reach back past this point. Also lifts any ceiling the peer
             * was under, which is what lets a DDIL admission recover once the
             * infrastructure returns. Mirrors the Python sweep. */
            _send_zta_standing(proc, peer->uuid, ZTA_STANDING_PROVED,
                               ZTA_NO_CEILING, "re-verified", logger);
            /* Share result so DDIL peers can use it for delegated verification */
            _broadcast_verification(proc, peer->uuid, &result, logger);
            break;

        case ZTA_REJECTED:
            log_warn(logger, "ZTA: peer %s credential REJECTED: %s\n",
                     uuid_str, result.reason);
            _send_reputation_penalty(proc, peer->uuid,
                                     zta_state.policy->revocation_reputation_penalty,
                                     logger);
            break;
        }
    }
    peers_read_unlock(proc);
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

        char uuid_str[37];
        uuid_unparse_lower(entry.peer_uuid, uuid_str);

        if (result.status == ZTA_VERIFIED) {
            log_info(logger, "ZTA: deferred verification resolved for peer %s: VERIFIED\n",
                     uuid_str);
            /* The DDIL condition has cleared: lift the ceiling this peer was
             * admitted under and anchor the unwind here (§10.5). Until the cap
             * was actually enforced there was nothing for this branch to lift,
             * which is why it only logged. */
            _send_zta_standing(proc, entry.peer_uuid, ZTA_STANDING_PROVED,
                               ZTA_NO_CEILING, "deferred verification resolved",
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
 * @brief Process pending vouches after a reputation response arrives.
 *
 * Re-evaluates each pending vouch whose voucher now has a cached score.
 * Accepted vouches are fed back through _handle_delegated_verification;
 * rejected ones are logged and discarded.
 */
/* Frama-C: skipped —
 * zta_process_run + all helpers: [solver-timeout] memcpy of public_identity_t/uuid_t (19
 * sites) + reputation cache + delegated vouch lifecycle + peer iteration + json/network
 * cascades.
 */
static void _process_pending_vouches(process_t *proc, logger_t *logger)
{
    for (int i = zta_state.pending_vouch_count - 1; i >= 0; i--) {
        pending_vouch_t *pv = &zta_state.pending_vouches[i];
        if (!pv->active)
            continue;

        double score = 0.0;
        if (!_rep_cache_lookup(pv->voucher_uuid, &score))
            continue;  /* still waiting */

        pv->active = false;

        /* Re-enter the vouch through the normal path (reputation is now cached) */
        _handle_delegated_verification(proc, &pv->event,
                                       pv->voucher_uuid, logger);

        /* Compact: swap with last active entry */
        if (i < zta_state.pending_vouch_count - 1)
            memcpy(pv, &zta_state.pending_vouches[--zta_state.pending_vouch_count],
                   sizeof(pending_vouch_t));
        else
            zta_state.pending_vouch_count--;
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

    /* Re-evaluate pending vouches now that we have new cache data */
    _process_pending_vouches((process_t *)proc, proc->logger);
    return true;
}

/****************************
 * Process runner
 ****************************/

/* Frama-C: skipped — [solver-timeout] logging/snprintf/process preconditions */
int zta_process_run(process_t *proc, directory_t *queues,
                    queue_id_t signal, logger_t *logger)
{
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
        data_t *id_dat = NULL;
        char id_key[] = "identity";
        if (map_get(proc->configs, id_key, &id_dat) == 0) {
            config_t *id_cfg = NULL;
            if (data_object_ptr(id_dat, (void **)&id_cfg) == 0 &&
                    id_cfg->data_struct != NULL) {
                identity_t *myself = (identity_t *)id_cfg->data_struct;
                public_identity_t *pub = NULL;
                if (identity_publish(myself, &pub) == 0 && pub) {
                    memcpy(zta_state.self_uuid, pub->uuid, sizeof(uuid_t));
                    smrt_deref(pub);
                }
            }
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
    zta_state.initialized = true;

    log_info(logger, "ZTA: process started (reverify interval: %d sec)\n",
             zta_state.policy->reverify_interval_sec);

    /* Register handler for reputation responses from the reputation process */
    process_register_handler(proc, REP_PROTO_LOCAL_RESP,
                             (handler_ptr_t)_handle_rep_response);

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

    while (keep_running(proc, &pctx.sig_q, logger)) {
        sleep_until(proc, cadence);

        /* Handle incoming messages (revocation alerts, verification results) */
        generic_msg_t buf = {0};
        int err = messaging_recv(&buf);
        if (err == 0) {
            if (buf.type == ZTA_VERIFICATION_RESULT) {
                /* Delegated verification from another peer */
                _handle_delegated_verification(proc, &buf.info.zta_event,
                                               buf.info.zta_event.voucher_uuid,
                                               logger);
            }
            run_message_handlers(proc, queues, buf.type, &buf);
        }

        /* Periodic re-verification */
        if (reverify_cycles > 0 && ++cycle >= reverify_cycles) {
            cycle = 0;
            log_debug(logger, "ZTA: running periodic re-verification\n");
            _reverify_peers(proc, logger);
            _resolve_deferred(proc, logger);
        }
    }

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

#ifdef AT_ZTA_ENABLED
DECLARE_PROCESS(zta_verify, zta_proc, zta_process_run);
#endif
