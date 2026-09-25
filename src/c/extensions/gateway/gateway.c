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

/* The gateway relay (at-over-dtn.md §4.3) as a network filter: the routing
 * envelope's wrap, unwrap and forward decisions, broadcast relay, cross-leg
 * group forward and cross-cluster discovery. Until FEATURE_SPLIT_PLAN Phase 2
 * these were #if blocks in net_proc.c behind AT_NET_ENVELOPE,
 * AT_NET_GROUP_FORWARD and AT_DISCOVERY_CROSS_CLUSTER; they are now switched
 * by the network config (network_config_t envelope / group_forward /
 * cross_cluster), and the core refuses to start a node that asks for the
 * envelope without this library (net_filters_check_config). */

#include <errno.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "at_gateway.h"
#include "net_envelope.h"
#include "network/net_filter.h"
#include "network/net_proc_priv.h"
#include "network/net_transport.h"
#include "network/net_transport_hybrid.h"
#include "network/network.h"
#include "processes/extension.h"
#include "structures/map.h"
#include "utilities/logger.h"

static bool am_gateway(const net_thread_ctx_t *ctx)
{
    return ctx->transport->is_gateway != NULL && ctx->transport->is_gateway(ctx->ctx);
}

/* Inbound envelope classification. Internal alias of net_env_disposition_t
 * so the call sites read with intention-revealing names. */
typedef enum {
    ENV_DELIVER_LOCAL = NET_ENV_DISPOSITION_LOCAL,
    ENV_DROP          = NET_ENV_DISPOSITION_DROP,
    ENV_FORWARD       = NET_ENV_DISPOSITION_FORWARD,
} env_decision_t;

static env_decision_t classify_envelope(const net_envelope_t *env,
                                        const identity_t *myself,
                                        const group_t *grp,
                                        bool gateway)
{
    static const uuid_t NIL_UUID = {0};
    return (env_decision_t)net_envelope_disposition(
        env,
        myself != NULL ? myself->uuid : NIL_UUID,
        grp != NULL ? grp->uuid : NIL_UUID,
        gateway);
}

/* ---- Broadcast-relay dedup + rate limit (cross-leg forwarding) -----
 *
 * A gateway re-broadcasts each inbound BROADCAST onto its other legs so
 * discovery announcements bridge clusters (at-over-dtn.md §4.3 item D).
 * Three controls keep that safe:
 *   1. Hop count cap (enforced by net_envelope_should_forward_broadcast).
 *   2. Fingerprint dedup ring — we don't re-forward the same broadcast
 *      twice within BCAST_DEDUP_WINDOW_MS, so mutual gateways can't
 *      infinite-loop.
 *   3. Rate-limit token bucket — cap forwards-per-second as a simple DoS
 *      gate against a rogue sender flooding new broadcasts.
 *
 * Group forward shares the ring and the bucket: fingerprints occupy
 * disjoint 2^64 spaces in practice, and the "recently forwarded" semantic
 * is identical. */
#define BCAST_DEDUP_CAP       128
#define BCAST_DEDUP_WINDOW_MS 5000
#define BCAST_RATE_PER_SEC    64

typedef struct {
    uint64_t fingerprint;
    uint64_t ts_ms;
} bcast_dedup_entry_t;

static bcast_dedup_entry_t bcast_dedup[BCAST_DEDUP_CAP];
static size_t bcast_dedup_next = 0;  /* next write slot (ring) */
static size_t bcast_tokens = BCAST_RATE_PER_SEC;
static uint64_t bcast_tokens_ts_ms = 0;
static pthread_mutex_t bcast_fwd_lock = PTHREAD_MUTEX_INITIALIZER;

static uint64_t now_ms(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000ULL + (uint64_t)(ts.tv_nsec / 1000000L);
}

/* Returns true iff this fingerprint has NOT been seen recently AND a
 * forwarding token is available. On true, the entry is recorded and a
 * token consumed — the caller must proceed to forward (or accept the
 * double-bookkeeping of a recorded-but-skipped entry; we tolerate that
 * because the window self-heals in BCAST_DEDUP_WINDOW_MS). */
static bool bcast_may_forward(uint64_t fp)
{
    uint64_t now = now_ms();
    pthread_mutex_lock(&bcast_fwd_lock);

    /* Dedup: linear scan is fine for 128 entries. */
    for (size_t i = 0; i < BCAST_DEDUP_CAP; i++) {
        if (bcast_dedup[i].fingerprint == fp &&
            bcast_dedup[i].ts_ms != 0 &&
            (now - bcast_dedup[i].ts_ms) < BCAST_DEDUP_WINDOW_MS) {
            pthread_mutex_unlock(&bcast_fwd_lock);
            return false;
        }
    }

    /* Rate limit: refill proportionally to elapsed time (cap at max). */
    if (bcast_tokens_ts_ms == 0) {
        bcast_tokens_ts_ms = now;
    } else {
        uint64_t elapsed = now - bcast_tokens_ts_ms;
        if (elapsed >= 1000) {
            size_t add = (size_t)((elapsed / 1000) * BCAST_RATE_PER_SEC);
            if (add > BCAST_RATE_PER_SEC) add = BCAST_RATE_PER_SEC;
            if (bcast_tokens + add > BCAST_RATE_PER_SEC)
                bcast_tokens = BCAST_RATE_PER_SEC;
            else
                bcast_tokens += add;
            bcast_tokens_ts_ms = now;
        }
    }
    if (bcast_tokens == 0) {
        pthread_mutex_unlock(&bcast_fwd_lock);
        return false;
    }
    bcast_tokens--;

    /* Record. */
    bcast_dedup[bcast_dedup_next].fingerprint = fp;
    bcast_dedup[bcast_dedup_next].ts_ms       = now;
    bcast_dedup_next = (bcast_dedup_next + 1) % BCAST_DEDUP_CAP;

    pthread_mutex_unlock(&bcast_fwd_lock);
    return true;
}

static void bcast_forward_reset(void)
{
    pthread_mutex_lock(&bcast_fwd_lock);
    memset(bcast_dedup, 0, sizeof(bcast_dedup));
    bcast_dedup_next = 0;
    bcast_tokens = BCAST_RATE_PER_SEC;
    bcast_tokens_ts_ms = 0;
    pthread_mutex_unlock(&bcast_fwd_lock);
}

/* Bump the hop count and mark the frame forwarded, in place. */
static int mark_forwarded(const net_envelope_t *env, uint8_t *frame, size_t frame_len)
{
    net_envelope_t next = *env;
    next.hop_count = (uint8_t)(next.hop_count + 1);
    next.flags     = (uint8_t)(next.flags | NET_ENV_FLAG_FORWARDED);
    return net_envelope_rewrite_header(&next, frame, frame_len);
}

/* Relay a PEER envelope frame out the same transport. The frame buffer is
 * mutated (hop_count bumped, FORWARDED flag set) before send. Looks up the
 * destination address by dst_uuid in the local peer registry — on a hybrid
 * transport, the inner-selection matcher then steers the send to whichever
 * inner transport serves that peer. */
static int envelope_forward(const net_thread_ctx_t *ctx, const net_envelope_t *env,
                            uint8_t *frame, size_t frame_len)
{
    const public_identity_t *dst = net_find_peer_by_uuid(ctx->proc, env->dst_uuid);
    if (dst == NULL) {
        log_debug(ctx->logger, "Envelope: no peer registered for dst uuid; dropping\n");
        return -1;
    }
    if (mark_forwarded(env, frame, frame_len) != 0)
        return -1;
    return ctx->transport->send_unicast(ctx->ctx, frame, frame_len, dst->address,
                                        ctx->net_cfg->port);
}

/* Cross-group bridging (at-over-dtn.md §4.3 stage F): a gateway re-emits a
 * GROUP envelope for a remote group on the leg the operator routed that
 * group to. Only the hybrid transport has legs and group routes, and its
 * transport_cfg is only a hybrid_config_t when it is the transport running,
 * so the name is checked before the cast.
 *
 * NOTE this is the one configuration that can violate invariant G
 * (net_proc.c): it carries opaque group ciphertext past a gateway that is
 * not in the group, by operator-configured route. See ISSUES.md §2.12. */
static bool group_forward(const net_thread_ctx_t *ctx, const net_envelope_t *env,
                          uint8_t *frame, size_t frame_len,
                          const uint8_t *inner, size_t inner_len)
{
    if (ctx->net_cfg == NULL || !ctx->net_cfg->group_forward)
        return false;
    bool gw = am_gateway(ctx);
    if (!gw || !net_envelope_should_forward_group(env, gw) ||
        ctx->transport->send_on_leg == NULL || ctx->transport_cfg == NULL ||
        strcmp(ctx->transport->name, "hybrid_net") != 0)
        return false;

    const hybrid_config_t *hcfg = ctx->transport_cfg;
    size_t leg_index = 0;
    if (hybrid_group_route_lookup(hcfg, env->dst_uuid, &leg_index) != 0)
        return false;
    if (!bcast_may_forward(net_envelope_group_fingerprint(env, inner, inner_len)))
        return false;
    if (mark_forwarded(env, frame, frame_len) != 0)
        return false;
    int rc = ctx->transport->send_on_leg(ctx->ctx, leg_index, NET_CHAN_GROUP,
                                         frame, frame_len, ctx->net_cfg->port);
    if (rc != 0 && rc != -1)
        log_debug(ctx->logger, "Network: group forward send returned %d\n", rc);
    return true;
}

/* ---- The filter ---- */

static net_filter_verdict_t envelope_inbound(const net_thread_ctx_t *ctx, net_channel_t ch,
                                             uint8_t *frame, size_t len,
                                             const char *from_addr, net_inbound_meta_t *meta)
{
    net_envelope_t env;
    const uint8_t *inner = NULL;
    size_t inner_len = 0;
    if (net_envelope_unpack(frame, len, &env, &inner, &inner_len) != 0) {
        log_debug(ctx->logger, "Network: dropping malformed %senvelope from %s\n",
                  ch == NET_CHAN_GROUP ? "group " : "", from_addr);
        return NET_FILTER_DROP;
    }

    switch (ch) {
    case NET_CHAN_BROADCAST:
        /* BROADCAST envelopes always classify local; non-broadcast types
         * should not arrive on the BCAST channel — drop defensively. */
        if (env.type != NET_ENV_TYPE_BROADCAST)
            return NET_FILTER_DROP;
        break;
    case NET_CHAN_PEER: {
        env_decision_t d = classify_envelope(&env, ctx->myself, NULL, am_gateway(ctx));
        if (d == ENV_DROP)
            return NET_FILTER_DROP;
        if (d == ENV_FORWARD) {
            envelope_forward(ctx, &env, frame, len);
            return NET_FILTER_CONSUMED;
        }
        break;
    }
    case NET_CHAN_GROUP: {
        const group_t *grp = &ctx->proc->protocol.group;
        if (classify_envelope(&env, ctx->myself, grp, am_gateway(ctx)) != ENV_DELIVER_LOCAL)
            /* Not our group: forwarded on a configured route, else dropped. */
            return group_forward(ctx, &env, frame, len, inner, inner_len)
                       ? NET_FILTER_CONSUMED : NET_FILTER_DROP;
        break;
    }
    case NET_CHAN__COUNT:
        return NET_FILTER_DROP;
    }

    meta->inner = inner;
    meta->inner_len = inner_len;
    /* Local delivery: identify the ORIGINAL sender by envelope src_uuid,
     * not by from_addr (which may be a gateway, not the originator). */
    meta->has_src_uuid = true;
    memcpy(meta->src_uuid, env.src_uuid, sizeof(uuid_t));
    meta->forwarded = (env.flags & NET_ENV_FLAG_FORWARDED) != 0;
    /* Cross-cluster discovery (stage E): when a gateway forwarded the frame,
     * from_addr is the gateway — NOT the original announcer. Keep the
     * announcer's self-reported address from the wire payload so replies
     * (ID_ACCEPT, etc.) route back through the same gateway via the hybrid
     * CIDR matcher rather than landing at the gateway itself. */
    meta->keep_reported_addr = meta->forwarded && ctx->net_cfg != NULL &&
                               ctx->net_cfg->cross_cluster;
    return NET_FILTER_CONTINUE;
}

static int envelope_outbound(const net_send_info_t *info, const uint8_t *in, size_t in_len,
                             uint8_t **out, size_t *out_len)
{
    /* Before this was a filter, the wrap read myself->uuid unguarded, and a
     * node with no identity yet crashed on its first send. Refuse instead:
     * the caller raises it. */
    if (info->src_uuid == NULL) {
        errno = EINVAL;
        return -1;
    }
    net_envelope_t env = {
        .version   = NET_ENV_VERSION,
        .type      = info->channel == NET_CHAN_BROADCAST ? NET_ENV_TYPE_BROADCAST
                   : info->channel == NET_CHAN_GROUP     ? NET_ENV_TYPE_GROUP
                                                         : NET_ENV_TYPE_PEER,
        .flags     = 0,
        .hop_count = 0,
    };
    memcpy(env.src_uuid, info->src_uuid, 16);
    if (info->dst_uuid != NULL) memcpy(env.dst_uuid, info->dst_uuid, 16);
    else                        memset(env.dst_uuid, 0, 16);   /* NIL: broadcast */

    size_t cap = NET_ENV_HEADER_LEN + in_len;
    uint8_t *frame = malloc(cap);
    if (frame == NULL)
        return -1;
    if (net_envelope_pack(&env, in, in_len, frame, cap, out_len) != 0) {
        free(frame);
        return -1;
    }
    *out = frame;
    return 0;
}

/* Gateway cross-leg relay: deliver-and-forward. The frame buffer is mutated
 * (hop++ + FORWARDED flag) before we re-emit via the same transport. On a
 * hybrid transport, send_broadcast_except_leg fans out to every leg except
 * the one that delivered this frame — so nodes on the origin leg don't
 * receive a duplicate of the broadcast they sent (D-followup). Single-leg
 * transports leave the except_leg method NULL and fall back to
 * send_broadcast. Runs whether or not the core could decode the payload. */
static void envelope_after_deliver(const net_thread_ctx_t *ctx, net_channel_t ch,
                                   uint8_t *frame, size_t len,
                                   const net_inbound_meta_t *meta)
{
    (void)meta;
    if (ch != NET_CHAN_BROADCAST)
        return;
    net_envelope_t env;
    const uint8_t *inner = NULL;
    size_t inner_len = 0;
    if (net_envelope_unpack(frame, len, &env, &inner, &inner_len) != 0)
        return;
    if (!net_envelope_should_forward_broadcast(&env, am_gateway(ctx)))
        return;
    if (!bcast_may_forward(net_envelope_broadcast_fingerprint(&env, inner, inner_len)))
        return;
    if (mark_forwarded(&env, frame, len) != 0)
        return;

    int origin_leg = -1;
    if (ctx->transport->last_recv_leg != NULL)
        origin_leg = ctx->transport->last_recv_leg(ctx->ctx, NET_CHAN_BROADCAST);

    int rc;
    if (origin_leg >= 0 && ctx->transport->send_broadcast_except_leg != NULL)
        rc = ctx->transport->send_broadcast_except_leg(ctx->ctx, NET_CHAN_BROADCAST,
                                                       frame, len, ctx->net_cfg->port,
                                                       (size_t)origin_leg);
    else
        rc = ctx->transport->send_broadcast(ctx->ctx, NET_CHAN_BROADCAST,
                                            frame, len, ctx->net_cfg->port);
    if (rc != 0 && rc != -1)
        log_debug(ctx->logger, "Network: broadcast relay send returned %d\n", rc);
}

/* Order 0: the envelope is the outermost header on the wire. */
static const net_filter_t envelope_filter = {
    .name          = NET_FILTER_ENVELOPE,
    .order         = 0,
    .inbound       = envelope_inbound,
    .outbound      = envelope_outbound,
    .after_deliver = envelope_after_deliver,
};

/* ---- The extension ---- */

/* Install the filter iff this node's network config asks for the envelope.
 * Loading the library alone must not: the envelope changes the wire format
 * for the whole cohort, and the core's loader dlopens every libat_*.so. */
static int gateway_register(process_t *proc, const char *proc_name)
{
    if (strcmp(proc_name, "network") != 0)
        return 0;
    const network_config_t *cfg = proc->conf.data_struct;
    if (cfg == NULL || !cfg->envelope)
        return 0;
    if (!net_filter_installed(NET_FILTER_ENVELOPE) &&
        net_filter_install(&envelope_filter) != 0)
        return -1;
    log_info(proc->logger, "Network: routing envelope on (group_forward %s, cross_cluster %s)\n",
             cfg->group_forward ? "on" : "off", cfg->cross_cluster ? "on" : "off");

    if (cfg->group_forward) {
        data_t *hy = NULL;
        char key[] = "hybrid_net";
        if (proc->configs == NULL || map_get(proc->configs, key, &hy) != 0)
            log_warn(proc->logger, "Network: group_forward is set but this node has no"
                                   " hybrid_net config; only the hybrid transport has"
                                   " group routes, so nothing will be forwarded\n");
    }
    return 0;
}

static void gateway_reset(void)
{
    bcast_forward_reset();
    net_filters_reset();
}

static const at_extension_t gateway_extension = {
    .name              = "gateway",
    .enabled           = NULL,   /* the network config decides */
    .register_handlers = gateway_register,
    .reset             = gateway_reset,
};
AT_EXTENSION_REGISTER(gateway, &gateway_extension)

void at_gateway_link(void) {}
