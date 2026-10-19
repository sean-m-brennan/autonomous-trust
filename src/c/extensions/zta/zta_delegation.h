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

#ifndef ZTA_DELEGATION_H
#define ZTA_DELEGATION_H

/** @addtogroup internal_zta
 *  @{
 */

/**
 * @file zta_delegation.h
 * @brief What a node does with another member's ZTA finding about a peer
 *        (doc/architecture/zta-integration.md, "Delegated verification").
 *
 * Two findings travel between members. A *vouch* (`zta_verified`) says the
 * sender's verifier proved the peer's credential; enough of them, from members
 * above the reputation bar, lift the ceiling on a peer this node could not
 * verify itself. An *alert* (`zta_revoked`) says the sender found the
 * credential revoked. It is never taken on the sender's word: this node checks
 * the credential itself first and acts on its own answer. Only when its own
 * verifier cannot answer (DDIL) are alerts counted, and a quorum of them puts
 * the peer under the DDIL ceiling until this node's own check settles it.
 *
 * Pure: membership, the recorded credential, reputation, this node's own check
 * and where a standing goes are all asked of the context, so the decisions are
 * the same in the zta_verify process, its tests and the conformance adapter.
 * Twin of Python autonomous_trust.zta._python.delegation. Uuids are lower-case
 * strings.
 */

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "utilities/msg_types.h"   /* peer_standing_t */
#include "zta_verifier.h"          /* zta_status_t, ZTA_HASH_LEN */

#define ZTA_DELEG_UUID_LEN 36
#define ZTA_DELEG_MAX_PEERS 256
#define ZTA_DELEG_MAX_SENDERS 16

/** Which finding arrived. */
typedef enum {
    ZTA_DELEG_VOUCH = 0,   /**< `zta_verified` */
    ZTA_DELEG_ALERT = 1,   /**< `zta_revoked` */
} zta_deleg_kind_t;

/** What became of one finding. The string forms (zta_deleg_verdict_str) are
 *  what the conformance corpus pins. */
typedef enum {
    ZTA_DELEG_NOT_MEMBER = 0,  /**< the sender is not in our group */
    ZTA_DELEG_NO_RECORD,       /**< we hold no credential for the peer */
    ZTA_DELEG_HASH_MISMATCH,   /**< about a credential other than the one we hold */
    ZTA_DELEG_WRONG_STATUS,    /**< a vouch not VERIFIED, an alert not REVOKED */
    ZTA_DELEG_NOT_UNVERIFIED,  /**< a vouch for a peer we are not waiting on */
    ZTA_DELEG_OWN_VERIFIED,    /**< an alert our own check contradicts */
    ZTA_DELEG_OWN_FAILED,      /**< an alert our own check confirms: FAILED published */
    ZTA_DELEG_SETTLED,         /**< the quorum was already met for this peer */
    ZTA_DELEG_PENDING,         /**< the sender's reputation is not known yet */
    ZTA_DELEG_BELOW_BAR,       /**< the sender's reputation is under the bar */
    ZTA_DELEG_DUPLICATE,       /**< this sender was already counted */
    ZTA_DELEG_COUNTED,         /**< counted, quorum not yet met */
    ZTA_DELEG_QUORUM,          /**< counted, and the quorum is met: standing published */
    ZTA_DELEG_FULL,            /**< no room to track it */
} zta_deleg_verdict_t;

/** What the decisions ask of the node. Every member is required. */
typedef struct {
    void *user;
    /** Whether @p uuid is a member of our group. */
    bool (*is_member)(void *user, const char *uuid);
    /** The credential hash we hold for @p peer; false when we hold none. */
    bool (*recorded_hash)(void *user, const char *peer, uint8_t out[ZTA_HASH_LEN]);
    /** 1 with @p score set, or 0 when it is not known yet (the caller asks
     *  for it and offers the finding again once it is). */
    int (*reputation)(void *user, const char *uuid, double *score);
    /** This node's own answer for @p peer's credential, asked now. */
    zta_status_t (*own_check)(void *user, const char *peer);
    /** Publish a ZTA standing for @p peer (ceiling < 0: none). */
    void (*standing)(void *user, const char *peer, peer_standing_t standing,
                     double ceiling, const char *reason);
    double min_reputation;      /**< delegated_verification_min_reputation */
    int quorum;                 /**< delegated_verification_quorum */
    double ddil_cap;            /**< ddil_fallback_reputation_cap */
    double revocation_penalty;  /**< revocation_reputation_penalty */
} zta_deleg_ctx_t;

typedef struct {
    char peer[ZTA_DELEG_UUID_LEN + 1];
    bool unverified;     /**< our own last check could not answer */
    bool lifted;         /**< vouch quorum met since */
    bool bounded;        /**< alert quorum met since */
    int n_vouch;
    int n_alert;
    char vouchers[ZTA_DELEG_MAX_SENDERS][ZTA_DELEG_UUID_LEN + 1];
    char alerters[ZTA_DELEG_MAX_SENDERS][ZTA_DELEG_UUID_LEN + 1];
} zta_deleg_peer_t;

typedef struct {
    zta_deleg_peer_t peers[ZTA_DELEG_MAX_PEERS];
    int n;
} zta_deleg_t;

void zta_deleg_init(zta_deleg_t *d);

/** One finding from member @p from about @p peer, credential @p hash, with the
 *  sender's @p status. Any standing it leads to goes through @p ctx. */
zta_deleg_verdict_t zta_deleg_event(zta_deleg_t *d, const zta_deleg_ctx_t *ctx,
                                    zta_deleg_kind_t kind, const char *from,
                                    const char *peer, const uint8_t hash[ZTA_HASH_LEN],
                                    zta_status_t status);

/** This node's own check of @p peer answered @p status (the re-verification
 *  sweep, or an alert's re-check). UNAVAILABLE/DEFERRED marks the peer as one
 *  we are waiting on; any other answer settles it and clears what was counted. */
void zta_deleg_own_result(zta_deleg_t *d, const char *peer, zta_status_t status);

/** The FAILED ceiling for one of our own failures: revoked and rejected cost
 *  the whole penalty, expired half (a lapse, not a lie). */
double zta_deleg_failed_ceiling(zta_status_t status, double revocation_penalty);

const char *zta_deleg_verdict_str(zta_deleg_verdict_t v);

/** @} */ /* end of internal_zta */

#endif /* ZTA_DELEGATION_H */
