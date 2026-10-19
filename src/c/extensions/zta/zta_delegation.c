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

#include "zta_delegation.h"
#include "utilities/util.h"   /* at_strlcpy */

void zta_deleg_init(zta_deleg_t *d)
{
    memset(d, 0, sizeof(*d));
}

static zta_deleg_peer_t *_find(zta_deleg_t *d, const char *peer, bool create)
{
    for (int i = 0; i < d->n; i++)
        if (strcmp(d->peers[i].peer, peer) == 0)
            return &d->peers[i];
    if (!create || d->n >= ZTA_DELEG_MAX_PEERS)
        return NULL;
    zta_deleg_peer_t *p = &d->peers[d->n++];
    memset(p, 0, sizeof(*p));
    at_strlcpy(p->peer, peer, sizeof(p->peer));
    return p;
}

static void _clear(zta_deleg_peer_t *p)
{
    p->unverified = p->lifted = p->bounded = false;
    p->n_vouch = p->n_alert = 0;
}

void zta_deleg_own_result(zta_deleg_t *d, const char *peer, zta_status_t status)
{
    bool waiting = (status == ZTA_UNAVAILABLE || status == ZTA_DEFERRED);
    zta_deleg_peer_t *p = _find(d, peer, waiting);
    if (p == NULL)
        return;
    if (waiting) {
        p->unverified = true;
        return;
    }
    /* Our own answer settles it: whatever others said is moot. */
    _clear(p);
}

double zta_deleg_failed_ceiling(zta_status_t status, double revocation_penalty)
{
    double penalty = revocation_penalty;
    if (status == ZTA_EXPIRED)
        penalty *= 0.5;
    double ceiling = 1.0 - penalty;
    if (ceiling < 0.0) ceiling = 0.0;
    if (ceiling > 1.0) ceiling = 1.0;
    return ceiling;
}

/* Count @p from in @p list; ZTA_DELEG_DUPLICATE / FULL / COUNTED. */
static zta_deleg_verdict_t _count(char list[][ZTA_DELEG_UUID_LEN + 1], int *n,
                                  const char *from)
{
    for (int i = 0; i < *n; i++)
        if (strcmp(list[i], from) == 0)
            return ZTA_DELEG_DUPLICATE;
    if (*n >= ZTA_DELEG_MAX_SENDERS)
        return ZTA_DELEG_FULL;
    at_strlcpy(list[(*n)++], from, ZTA_DELEG_UUID_LEN + 1);
    return ZTA_DELEG_COUNTED;
}

/* The reputation bar: PASS (-1), or the verdict that stops the finding. */
static int _bar(const zta_deleg_ctx_t *ctx, const char *from)
{
    double score = 0.0;
    if (ctx->reputation(ctx->user, from, &score) != 1)
        return ZTA_DELEG_PENDING;
    if (score < ctx->min_reputation)
        return ZTA_DELEG_BELOW_BAR;
    return -1;
}

zta_deleg_verdict_t zta_deleg_event(zta_deleg_t *d, const zta_deleg_ctx_t *ctx,
                                    zta_deleg_kind_t kind, const char *from,
                                    const char *peer, const uint8_t hash[ZTA_HASH_LEN],
                                    zta_status_t status)
{
    /* Who said it: only a member's finding is heard (the transport names the
     * sender, so this is not the payload's claim). */
    if (!ctx->is_member(ctx->user, from))
        return ZTA_DELEG_NOT_MEMBER;
    /* About what: the credential we hold for the peer, and no other. */
    uint8_t recorded[ZTA_HASH_LEN];
    if (!ctx->recorded_hash(ctx->user, peer, recorded))
        return ZTA_DELEG_NO_RECORD;
    if (memcmp(recorded, hash, ZTA_HASH_LEN) != 0)
        return ZTA_DELEG_HASH_MISMATCH;
    int quorum = ctx->quorum > 0 ? ctx->quorum : 1;

    if (kind == ZTA_DELEG_VOUCH) {
        if (status != ZTA_VERIFIED)
            return ZTA_DELEG_WRONG_STATUS;
        zta_deleg_peer_t *p = _find(d, peer, false);
        if (p == NULL || !p->unverified)
            return ZTA_DELEG_NOT_UNVERIFIED;
        if (p->lifted)
            return ZTA_DELEG_SETTLED;
        int bar = _bar(ctx, from);
        if (bar >= 0)
            return (zta_deleg_verdict_t)bar;
        zta_deleg_verdict_t v = _count(p->vouchers, &p->n_vouch, from);
        if (v != ZTA_DELEG_COUNTED || p->n_vouch < quorum)
            return v;
        p->lifted = true;
        ctx->standing(ctx->user, peer, PEER_STANDING_PROVED, -1.0,
                      "delegated verification quorum met");
        return ZTA_DELEG_QUORUM;
    }

    if (status != ZTA_REVOKED)
        return ZTA_DELEG_WRONG_STATUS;
    /* Never on the sender's word: our own check first, and our answer wins. */
    zta_status_t own = ctx->own_check(ctx->user, peer);
    if (own == ZTA_VERIFIED) {
        zta_deleg_own_result(d, peer, own);
        return ZTA_DELEG_OWN_VERIFIED;
    }
    if (own == ZTA_REVOKED || own == ZTA_EXPIRED || own == ZTA_REJECTED) {
        zta_deleg_own_result(d, peer, own);
        ctx->standing(ctx->user, peer, PEER_STANDING_FAILED,
                      zta_deleg_failed_ceiling(own, ctx->revocation_penalty),
                      own == ZTA_REVOKED ? "credential revoked (re-checked on an alert)"
                      : own == ZTA_EXPIRED ? "credential expired (re-checked on an alert)"
                      : "credential rejected (re-checked on an alert)");
        return ZTA_DELEG_OWN_FAILED;
    }
    /* We cannot answer (DDIL): count the alert, and bound the peer at quorum. */
    zta_deleg_peer_t *p = _find(d, peer, true);
    if (p == NULL)
        return ZTA_DELEG_FULL;
    p->unverified = true;
    if (p->bounded)
        return ZTA_DELEG_SETTLED;
    int bar = _bar(ctx, from);
    if (bar >= 0)
        return (zta_deleg_verdict_t)bar;
    zta_deleg_verdict_t v = _count(p->alerters, &p->n_alert, from);
    if (v != ZTA_DELEG_COUNTED || p->n_alert < quorum)
        return v;
    p->bounded = true;
    ctx->standing(ctx->user, peer, PEER_STANDING_CAPPED, ctx->ddil_cap,
                  "revocation alerts, unverified locally");
    return ZTA_DELEG_QUORUM;
}

const char *zta_deleg_verdict_str(zta_deleg_verdict_t v)
{
    switch (v) {
    case ZTA_DELEG_NOT_MEMBER:     return "not_member";
    case ZTA_DELEG_NO_RECORD:      return "no_record";
    case ZTA_DELEG_HASH_MISMATCH:  return "hash_mismatch";
    case ZTA_DELEG_WRONG_STATUS:   return "wrong_status";
    case ZTA_DELEG_NOT_UNVERIFIED: return "not_unverified";
    case ZTA_DELEG_OWN_VERIFIED:   return "own_verified";
    case ZTA_DELEG_OWN_FAILED:     return "own_failed";
    case ZTA_DELEG_SETTLED:        return "settled";
    case ZTA_DELEG_PENDING:        return "pending";
    case ZTA_DELEG_BELOW_BAR:      return "below_bar";
    case ZTA_DELEG_DUPLICATE:      return "duplicate";
    case ZTA_DELEG_COUNTED:        return "counted";
    case ZTA_DELEG_QUORUM:         return "quorum";
    case ZTA_DELEG_FULL:           return "full";
    }
    return "unknown";
}
