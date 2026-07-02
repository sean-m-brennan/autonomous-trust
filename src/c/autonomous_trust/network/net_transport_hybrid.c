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

/**
 * @file net_transport_hybrid.c
 * @brief Hybrid transport — composes N inner net_transport_t instances.
 */

#define _XOPEN_SOURCE 700
#define _DEFAULT_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <uuid/uuid.h>

#include "identity/identity.h"  /* ADDR_LEN */
#include "network/net_transport.h"
#include "network/net_transport_hybrid.h"
#include "network/network.h"
#include "utilities/exception.h"

#define HYBRID_INBOUND_Q_CAP 64

/* ---------- Matcher helpers ---------- */

static bool is_eid_literal(const char *target)
{
    if (target == NULL) return false;
    return (strncmp(target, "dtn:", 4) == 0 ||
            strncmp(target, "ipn:", 4) == 0);
}

/* Return true if @p ip_str (dotted-quad) falls inside @p cidr
 * ("a.b.c.d/prefix"). False on any parse failure — we silently skip rather
 * than route-mismatch; the default leg catches un-matchable targets. */
/* Frama-C: skipped —
 * [inet] addr_in_cidr4, addr_in_cidr6: strchr/strrchr/atoi CIDR parsing (same pattern as
 * network.c's cidr_split family).
 */
static bool addr_in_cidr4(const char *ip_str, const char *cidr)
{
    if (ip_str == NULL || cidr == NULL) return false;

    /* Split "a.b.c.d/prefix" */
    char buf[CIDR4_LEN + 1];
    snprintf(buf, sizeof(buf), "%s", cidr);
    char *slash = strchr(buf, '/');
    if (slash == NULL) return false;
    *slash = '\0';
    int prefix = atoi(slash + 1);
    if (prefix < 0 || prefix > 32) return false;

    struct in_addr net_a, ip_a;
    if (inet_pton(AF_INET, buf,    &net_a) != 1) return false;
    if (inet_pton(AF_INET, ip_str, &ip_a)  != 1) return false;

    uint32_t mask = (prefix == 0) ? 0 : htonl(0xffffffffu << (32 - prefix));
    return (net_a.s_addr & mask) == (ip_a.s_addr & mask);
}

/* Return true if @p ip_str (colon notation, optionally incl. v4-mapped
 * "::ffff:a.b.c.d") falls inside @p cidr ("prefix/len"). Prefix length is
 * measured against the full 128-bit address; the mask is applied
 * byte-wise so it handles any prefix without endianness gymnastics. */
/* Frama-C: skipped —
 * [inet] addr_in_cidr4, addr_in_cidr6: strchr/strrchr/atoi CIDR parsing (same pattern as
 * network.c's cidr_split family).
 */
static bool addr_in_cidr6(const char *ip_str, const char *cidr)
{
    if (ip_str == NULL || cidr == NULL) return false;

    char buf[CIDR6_LEN + 1];
    snprintf(buf, sizeof(buf), "%s", cidr);
    char *slash = strrchr(buf, '/');
    if (slash == NULL) return false;
    *slash = '\0';
    int prefix = atoi(slash + 1);
    if (prefix < 0 || prefix > 128) return false;

    struct in6_addr net_a, ip_a;
    if (inet_pton(AF_INET6, buf,    &net_a) != 1) return false;
    if (inet_pton(AF_INET6, ip_str, &ip_a)  != 1) return false;

    int full_bytes = prefix / 8;
    int rem_bits   = prefix % 8;
    if (full_bytes > 0 &&
        memcmp(net_a.s6_addr, ip_a.s6_addr, (size_t)full_bytes) != 0)
        return false;
    if (rem_bits == 0)
        return true;
    uint8_t mask = (uint8_t)(0xFF << (8 - rem_bits));
    return (net_a.s6_addr[full_bytes] & mask) ==
           (ip_a.s6_addr[full_bytes] & mask);
}

/* Dispatcher: pick v4 or v6 matcher by looking for a ':' in the CIDR. The
 * CIDR's family determines the parse — a v4 target against a v6 CIDR (or
 * vice versa) returns false via inet_pton failing, matching operator
 * intent: a "v6-only" matcher doesn't accidentally absorb v4 traffic. */
static bool addr_in_cidr(const char *ip_str, const char *cidr)
{
    if (cidr == NULL) return false;
    return strchr(cidr, ':') != NULL
        ? addr_in_cidr6(ip_str, cidr)
        : addr_in_cidr4(ip_str, cidr);
}

int hybrid_route(const hybrid_config_t *cfg, const char *target,
                 logger_t *logger)
{
    (void)logger;  /* reserved for future diagnostic logging */
    if (cfg == NULL || target == NULL) return -1;

    int default_idx = -1;
    for (size_t i = 0; i < cfg->n_inners; i++) {
        const hybrid_inner_t *in = &cfg->inners[i];
        if (in->match_eid && is_eid_literal(target))
            return (int)i;
        if (in->match_cidr[0] != '\0' && addr_in_cidr(target, in->match_cidr))
            return (int)i;
        if (in->is_default && default_idx < 0)
            default_idx = (int)i;
    }
    return default_idx;
}

/* ---------- Transport context ---------- */

typedef struct hybrid_bundle_s {
    uint8_t *buf;
    size_t   len;
    char     peer_addr[ADDR_LEN + 1];
    size_t   origin_leg;  /**< Which inner delivered this bundle (for D-followup per-leg exclusion). */
    struct hybrid_bundle_s *next;
} hybrid_bundle_t;

/* One shared queue per AT channel. Each inner × channel reader pushes to
 * the matching channel's queue; recv(channel) pops from it. */
typedef struct {
    pthread_mutex_t lock;
    pthread_cond_t  cond;
    hybrid_bundle_t *head;
    hybrid_bundle_t *tail;
    size_t len;
} chan_queue_t;

typedef struct inner_state_s {
    const net_transport_t *t;
    net_transport_ctx_t *ctx;
    pthread_t readers[NET_CHAN__COUNT];
    bool      reader_running[NET_CHAN__COUNT];
} inner_state_t;

typedef struct {
    inner_state_t inners[HYBRID_MAX_INNERS];
    size_t n_inners;
    const hybrid_config_t *cfg;  /* borrowed */
    logger_t *logger;
    chan_queue_t queues[NET_CHAN__COUNT];
    /* Origin leg of the most recent recv() on each channel, for the
     * D-followup per-leg broadcast exclusion. -1 means "no recv yet, or
     * unknown". Safe without locking because net_proc runs exactly one
     * reader thread per channel, so there's no concurrent recv on the
     * same (ctx, channel). */
    int last_recv_leg[NET_CHAN__COUNT];
    bool stop;
} hybrid_ctx_t;

/* ---------- Queue management ---------- */

static void enqueue_bundle(chan_queue_t *q, hybrid_bundle_t *b)
{
    pthread_mutex_lock(&q->lock);
    if (q->len >= HYBRID_INBOUND_Q_CAP) {
        hybrid_bundle_t *oldest = q->head;
        if (oldest != NULL) {
            q->head = oldest->next;
            if (q->head == NULL) q->tail = NULL;
            q->len--;
            free(oldest->buf);
            free(oldest);
        }
    }
    b->next = NULL;
    if (q->tail == NULL) q->head = b;
    else                 q->tail->next = b;
    q->tail = b;
    q->len++;
    pthread_cond_signal(&q->cond);
    pthread_mutex_unlock(&q->lock);
}

/* ---------- Reader thread: one per (inner, channel) ---------- */

typedef struct {
    hybrid_ctx_t *ctx;
    size_t inner_idx;
    net_channel_t channel;
} reader_arg_t;

static const int READER_POLL_MS = 100;

/* Frama-C: skipped —
 * [syscall] teardown, hybrid_open, hybrid_recv, reader_thread:
 * pthread_{create,mutex,cond}_* cascades + at_logging/at_snprintf chains.
 */
static void *reader_thread(void *arg)
{
    reader_arg_t *a = (reader_arg_t *)arg;
    hybrid_ctx_t *ctx = a->ctx;
    inner_state_t *inner = &ctx->inners[a->inner_idx];
    net_channel_t ch = a->channel;
    free(a);

    while (!ctx->stop) {
        uint8_t *buf = NULL;
        size_t   len = 0;
        char     peer_addr[ADDR_LEN + 1] = {0};

        int rc = inner->t->recv(inner->ctx, ch, &buf, &len,
                                peer_addr, sizeof(peer_addr),
                                READER_POLL_MS);
        if (rc == 0) {
            hybrid_bundle_t *b = calloc(1, sizeof(*b));
            if (b == NULL) { free(buf); continue; }
            b->buf = buf;
            b->len = len;
            snprintf(b->peer_addr, sizeof(b->peer_addr), "%s", peer_addr);
            b->origin_leg = a->inner_idx;
            enqueue_bundle(&ctx->queues[ch], b);
        } else if (rc == ENOMSG) {
            /* Normal timeout — loop. */
        } else {
            /* Negative: unrecoverable error on this inner. Log and bail;
             * the hybrid stays functional via the other legs. */
            log_warn(ctx->logger,
                     "Hybrid: inner[%zu] %s recv(channel=%d) returned %d; "
                     "stopping reader\n",
                     a->inner_idx, inner->t->name, (int)ch, rc);
            break;
        }
    }

    /* Wake any recv() waiters so they observe reader death. */
    pthread_mutex_lock(&ctx->queues[ch].lock);
    inner->reader_running[ch] = false;
    pthread_cond_broadcast(&ctx->queues[ch].cond);
    pthread_mutex_unlock(&ctx->queues[ch].lock);
    return NULL;
}

/* ---------- Teardown ---------- */

/* Frama-C: skipped —
 * [syscall] teardown, hybrid_open, hybrid_recv, reader_thread:
 * pthread_{create,mutex,cond}_* cascades + at_logging/at_snprintf chains.
 */
static void teardown(hybrid_ctx_t *ctx)
{
    ctx->stop = true;

    /* Join readers first — they need their inner's ctx to still exist. */
    for (size_t i = 0; i < ctx->n_inners; i++) {
        for (int ch = 0; ch < NET_CHAN__COUNT; ch++) {
            if (ctx->inners[i].reader_running[ch]) {
                pthread_join(ctx->inners[i].readers[ch], NULL);
                ctx->inners[i].reader_running[ch] = false;
            }
        }
    }

    /* Close each inner's context. */
    for (size_t i = 0; i < ctx->n_inners; i++) {
        if (ctx->inners[i].ctx != NULL && ctx->inners[i].t != NULL) {
            ctx->inners[i].t->close(ctx->inners[i].ctx);
            ctx->inners[i].ctx = NULL;
        }
    }

    /* Drain any unread queued bundles. */
    for (int ch = 0; ch < NET_CHAN__COUNT; ch++) {
        pthread_mutex_lock(&ctx->queues[ch].lock);
        hybrid_bundle_t *b = ctx->queues[ch].head;
        while (b != NULL) {
            hybrid_bundle_t *next = b->next;
            free(b->buf);
            free(b);
            b = next;
        }
        ctx->queues[ch].head = ctx->queues[ch].tail = NULL;
        ctx->queues[ch].len = 0;
        pthread_mutex_unlock(&ctx->queues[ch].lock);
        pthread_mutex_destroy(&ctx->queues[ch].lock);
        pthread_cond_destroy(&ctx->queues[ch].cond);
    }
}

/* ---------- Vtable ---------- */

/* Frama-C: skipped —
 * [syscall] teardown, hybrid_open, hybrid_recv, reader_thread:
 * pthread_{create,mutex,cond}_* cascades + at_logging/at_snprintf chains.
 */
static int hybrid_open(net_transport_ctx_t **out_ctx,
                       const net_transport_params_t *params)
{
    const hybrid_config_t *cfg =
        (const hybrid_config_t *)params->transport_specific;
    if (cfg == NULL || cfg->n_inners == 0) {
        log_error(params->logger,
                  "Hybrid: open() requires a hybrid_config_t via "
                  "params.transport_specific with n_inners > 0\n");
        return -1;
    }
    if (cfg->n_inners > HYBRID_MAX_INNERS) {
        log_error(params->logger, "Hybrid: too many inners (%zu; max %d)\n",
                  cfg->n_inners, HYBRID_MAX_INNERS);
        return -1;
    }

    hybrid_ctx_t *ctx = calloc(1, sizeof(*ctx));
    if (ctx == NULL) return SYS_EXCEPTION();
    ctx->cfg    = cfg;
    ctx->logger = params->logger;
    ctx->n_inners = cfg->n_inners;

    for (int ch = 0; ch < NET_CHAN__COUNT; ch++) {
        pthread_mutex_init(&ctx->queues[ch].lock, NULL);
        pthread_cond_init(&ctx->queues[ch].cond, NULL);
        ctx->last_recv_leg[ch] = -1;
    }

    /* 1) Open each inner transport. */
    for (size_t i = 0; i < cfg->n_inners; i++) {
        const hybrid_inner_t *in = &cfg->inners[i];
        if (in->kind[0] == '\0') {
            log_error(params->logger, "Hybrid: inner[%zu].kind is empty\n", i);
            teardown(ctx); free(ctx); return -1;
        }
        const net_transport_t *t = net_transport_find(in->kind);
        if (t == NULL) {
            log_error(params->logger,
                      "Hybrid: inner[%zu] kind=\"%s\" not registered\n",
                      i, in->kind);
            teardown(ctx); free(ctx); return -1;
        }
        if (t == &hybrid_net_transport) {
            /* Recursive hybrid would be possible but confusing; refuse. */
            log_error(params->logger,
                      "Hybrid: inner[%zu] kind=\"%s\" is hybrid itself; refusing\n",
                      i, in->kind);
            teardown(ctx); free(ctx); return -1;
        }
        ctx->inners[i].t = t;

        net_transport_params_t inner_params = *params;
        inner_params.net_cfg            = &in->net_cfg;
        inner_params.transport_specific = in->inner_specific;

        if (t->open(&ctx->inners[i].ctx, &inner_params) != 0) {
            log_error(params->logger,
                      "Hybrid: inner[%zu] (%s) open() failed\n", i, in->kind);
            teardown(ctx); free(ctx); return -1;
        }
    }

    /* 2) Spawn readers: one per (inner, channel). */
    for (size_t i = 0; i < cfg->n_inners; i++) {
        for (int ch = 0; ch < NET_CHAN__COUNT; ch++) {
            reader_arg_t *ra = calloc(1, sizeof(*ra));
            if (ra == NULL) { teardown(ctx); free(ctx); return -1; }
            ra->ctx       = ctx;
            ra->inner_idx = i;
            ra->channel   = (net_channel_t)ch;
            if (pthread_create(&ctx->inners[i].readers[ch], NULL,
                               reader_thread, ra) != 0) {
                free(ra);
                log_error(params->logger,
                          "Hybrid: reader spawn failed for inner[%zu] ch=%d\n",
                          i, ch);
                teardown(ctx); free(ctx); return -1;
            }
            ctx->inners[i].reader_running[ch] = true;
        }
    }

    log_info(params->logger, "Hybrid: %zu inner transport(s) ready\n",
             cfg->n_inners);
    for (size_t i = 0; i < cfg->n_inners; i++) {
        log_info(params->logger,
                 "Hybrid:   [%zu] %s (match: cidr=%s eid=%d default=%d)\n",
                 i, cfg->inners[i].kind,
                 cfg->inners[i].match_cidr[0] ? cfg->inners[i].match_cidr : "(none)",
                 (int)cfg->inners[i].match_eid,
                 (int)cfg->inners[i].is_default);
    }
    *out_ctx = (net_transport_ctx_t *)ctx;
    return 0;
}

static int hybrid_send_unicast(net_transport_ctx_t *ctx_opaque,
                               const uint8_t *wire, size_t wire_len,
                               const char *target, int port)
{
    hybrid_ctx_t *ctx = (hybrid_ctx_t *)ctx_opaque;
    int idx = hybrid_route(ctx->cfg, target, ctx->logger);
    if (idx < 0) {
        log_warn(ctx->logger,
                 "Hybrid: no inner matches target=%s (no default configured)\n",
                 target);
        return EXCEPTION(EINVAL);
    }
    return ctx->inners[idx].t->send_unicast(ctx->inners[idx].ctx,
                                            wire, wire_len, target, port);
}

static int hybrid_send_broadcast(net_transport_ctx_t *ctx_opaque,
                                 net_channel_t channel,
                                 const uint8_t *wire, size_t wire_len, int port)
{
    if (channel == NET_CHAN_PEER) return -1;

    hybrid_ctx_t *ctx = (hybrid_ctx_t *)ctx_opaque;
    /* Fan out to every inner so that e.g. a gateway's discovery broadcast
     * reaches both the local LAN and the DTN-attached cluster. Success if
     * at least one inner accepted the send. */
    int any_ok = -1;
    for (size_t i = 0; i < ctx->n_inners; i++) {
        int rc = ctx->inners[i].t->send_broadcast(ctx->inners[i].ctx,
                                                  channel, wire, wire_len, port);
        if (rc == 0) any_ok = 0;
    }
    return any_ok;
}

/* Frama-C: skipped —
 * [syscall] teardown, hybrid_open, hybrid_recv, reader_thread:
 * pthread_{create,mutex,cond}_* cascades + at_logging/at_snprintf chains.
 */
static int hybrid_recv(net_transport_ctx_t *ctx_opaque, net_channel_t channel,
                       uint8_t **out_buf, size_t *out_len,
                       char *peer_addr_out, size_t peer_addr_len,
                       int timeout_ms)
{
    hybrid_ctx_t *ctx = (hybrid_ctx_t *)ctx_opaque;
    if (channel >= NET_CHAN__COUNT) return -1;
    chan_queue_t *q = &ctx->queues[channel];

    struct timespec deadline = {0};
    clock_gettime(CLOCK_REALTIME, &deadline);
    deadline.tv_sec  += timeout_ms / 1000;
    deadline.tv_nsec += (long)(timeout_ms % 1000) * 1000000L;
    if (deadline.tv_nsec >= 1000000000L) {
        deadline.tv_sec += 1;
        deadline.tv_nsec -= 1000000000L;
    }

    pthread_mutex_lock(&q->lock);
    while (q->head == NULL && !ctx->stop) {
        bool any_reader_alive = false;
        for (size_t i = 0; i < ctx->n_inners; i++) {
            if (ctx->inners[i].reader_running[channel]) {
                any_reader_alive = true; break;
            }
        }
        if (!any_reader_alive) break;

        int rc = pthread_cond_timedwait(&q->cond, &q->lock, &deadline);
        if (rc == ETIMEDOUT) {
            pthread_mutex_unlock(&q->lock);
            return ENOMSG;
        }
    }
    if (q->head == NULL) {
        pthread_mutex_unlock(&q->lock);
        return ctx->stop ? -1 : ENOMSG;
    }
    hybrid_bundle_t *b = q->head;
    q->head = b->next;
    if (q->head == NULL) q->tail = NULL;
    q->len--;
    pthread_mutex_unlock(&q->lock);

    *out_buf = b->buf;
    *out_len = b->len;
    snprintf(peer_addr_out, peer_addr_len, "%s", b->peer_addr);
    /* Stash origin leg so a subsequent send_broadcast_except_leg can skip
     * the leg that delivered this frame. See hybrid_last_recv_leg below.
     * Safe without locking because net_proc runs exactly one consumer
     * thread per channel (per-channel receiver loop). */
    ctx->last_recv_leg[channel] = (int)b->origin_leg;
    free(b);
    return 0;
}

static int hybrid_last_recv_leg(const net_transport_ctx_t *ctx_opaque,
                                net_channel_t channel)
{
    if (channel >= NET_CHAN__COUNT) return -1;
    const hybrid_ctx_t *ctx = (const hybrid_ctx_t *)ctx_opaque;
    return ctx->last_recv_leg[channel];
}

static void hybrid_close(net_transport_ctx_t *ctx_opaque)
{
    if (ctx_opaque == NULL) return;
    hybrid_ctx_t *ctx = (hybrid_ctx_t *)ctx_opaque;
    teardown(ctx);
    free(ctx);
}

static bool hybrid_is_gateway(const net_transport_ctx_t *ctx_opaque)
{
    if (ctx_opaque == NULL) return false;
    const hybrid_ctx_t *ctx = (const hybrid_ctx_t *)ctx_opaque;
    return ctx->cfg != NULL && ctx->cfg->is_gateway;
}

/* Delegate to the inner that would actually send to @p target. Mixed
 * inner kinds (e.g., UDP + DTN) make the hybrid's latency a function of
 * the per-peer routing choice, not a single compile-time constant. */
static int hybrid_link_class_ms(const net_transport_ctx_t *ctx_opaque,
                                const char *target)
{
    if (ctx_opaque == NULL) return -1;
    const hybrid_ctx_t *ctx = (const hybrid_ctx_t *)ctx_opaque;
    int idx = hybrid_route(ctx->cfg, target, ctx->logger);
    if (idx < 0 || (size_t)idx >= ctx->n_inners) return -1;

    const net_transport_t *inner_t   = ctx->inners[idx].t;
    net_transport_ctx_t   *inner_ctx = ctx->inners[idx].ctx;
    if (inner_t == NULL || inner_t->link_class_ms == NULL) return -1;
    return inner_t->link_class_ms(inner_ctx, target);
}

static int hybrid_send_on_leg(net_transport_ctx_t *ctx_opaque,
                              size_t leg_index,
                              net_channel_t channel,
                              const uint8_t *wire, size_t wire_len, int port)
{
    if (channel == NET_CHAN_PEER) return -1;
    hybrid_ctx_t *ctx = (hybrid_ctx_t *)ctx_opaque;
    if (leg_index >= ctx->n_inners) return -1;
    const net_transport_t *t = ctx->inners[leg_index].t;
    if (t == NULL || t->send_broadcast == NULL) return -1;
    return t->send_broadcast(ctx->inners[leg_index].ctx,
                             channel, wire, wire_len, port);
}

static int hybrid_send_broadcast_except_leg(net_transport_ctx_t *ctx_opaque,
                                            net_channel_t channel,
                                            const uint8_t *wire, size_t wire_len,
                                            int port, size_t except_leg)
{
    if (channel == NET_CHAN_PEER) return -1;
    hybrid_ctx_t *ctx = (hybrid_ctx_t *)ctx_opaque;
    /* Fan out to every inner except except_leg. Success if at least one
     * inner accepted the send (same semantics as hybrid_send_broadcast).
     * An out-of-range except_leg means "no exclusion" — behaves identically
     * to hybrid_send_broadcast. */
    int any_ok = -1;
    for (size_t i = 0; i < ctx->n_inners; i++) {
        if (i == except_leg) continue;
        int rc = ctx->inners[i].t->send_broadcast(ctx->inners[i].ctx,
                                                  channel, wire, wire_len, port);
        if (rc == 0) any_ok = 0;
    }
    return any_ok;
}

const net_transport_t hybrid_net_transport = {
    .name                     = "hybrid_net",
    /* Hybrid wraps an inner socket leg (typically udp_net_4) plus a DTN
     * leg. Treat it as IPv4 for identity-address selection — the inner
     * leg carries node-local traffic and that's what `address` in
     * identity.json represents. */
    .net_proto                = NETPROTO_IPV4,
    .open                     = hybrid_open,
    .send_unicast             = hybrid_send_unicast,
    .send_broadcast           = hybrid_send_broadcast,
    .recv                     = hybrid_recv,
    .close                    = hybrid_close,
    .is_gateway               = hybrid_is_gateway,
    .link_class_ms            = hybrid_link_class_ms,
    .send_on_leg              = hybrid_send_on_leg,
    .last_recv_leg            = hybrid_last_recv_leg,
    .send_broadcast_except_leg = hybrid_send_broadcast_except_leg,
};

/* ---------- JSON serialization ---------- */

#include <jansson.h>
#include "config/configuration.h"
#include "utilities/util.h"  /* EJSN_OBJ_SET */

/* hybrid_to_json / hybrid_from_json are declared in net_transport_hybrid.h
 * (included at the top of this file). network_to_json / network_from_json
 * are declared in network.h. */

/* Frama-C: skipped —
 * [serialization] hybrid_to_json, hybrid_from_json: jansson object_get/ set/string/decref
 * + snprintf precondition cascades.
 */
int hybrid_to_json(const void *data_struct, json_t **obj_ptr)
{
    const hybrid_config_t *cfg = data_struct;
    json_t *obj = json_object();
    if (obj == NULL) return EXCEPTION(ENOMEM);
    if (json_object_set_new(obj, "typename", json_string("hybrid_net")) != 0) {
        json_decref(obj); return EXCEPTION(EJSN_OBJ_SET);
    }
    json_t *arr = json_array();
    if (arr == NULL) { json_decref(obj); return EXCEPTION(ENOMEM); }
    for (size_t i = 0; i < cfg->n_inners; i++) {
        const hybrid_inner_t *in = &cfg->inners[i];
        json_t *jin = json_object();
        if (jin == NULL) { json_decref(obj); json_decref(arr); return EXCEPTION(ENOMEM); }
        json_object_set_new(jin, "kind",       json_string(in->kind));
        json_object_set_new(jin, "match_cidr", json_string(in->match_cidr));
        json_object_set_new(jin, "match_eid",  json_boolean(in->match_eid));
        json_object_set_new(jin, "is_default", json_boolean(in->is_default));

        json_t *jnet = NULL;
        if (network_to_json(&in->net_cfg, &jnet) != 0 || jnet == NULL) {
            json_decref(jin); json_decref(arr); json_decref(obj);
            return EXCEPTION(EJSN_OBJ_SET);
        }
        json_object_set_new(jin, "net_cfg", jnet);
        json_array_append_new(arr, jin);
    }
    json_object_set_new(obj, "inners", arr);
    json_object_set_new(obj, "is_gateway", json_boolean(cfg->is_gateway));

    if (cfg->n_group_routes > 0) {
        json_t *jroutes = json_array();
        if (jroutes == NULL) { json_decref(obj); return EXCEPTION(ENOMEM); }
        for (size_t i = 0; i < cfg->n_group_routes; i++) {
            json_t *jr = json_object();
            if (jr == NULL) { json_decref(jroutes); json_decref(obj); return EXCEPTION(ENOMEM); }
            char uuid_str[37];
            uuid_unparse_lower(cfg->group_routes[i].group_uuid, uuid_str);
            json_object_set_new(jr, "group_uuid", json_string(uuid_str));
            json_object_set_new(jr, "leg_index", json_integer((json_int_t)cfg->group_routes[i].leg_index));
            json_array_append_new(jroutes, jr);
        }
        json_object_set_new(obj, "group_routes", jroutes);
    }

    *obj_ptr = obj;
    return 0;
}

/* Frama-C: skipped —
 * [serialization] hybrid_to_json, hybrid_from_json: jansson object_get/ set/string/decref
 * + snprintf precondition cascades.
 */
int hybrid_from_json(const json_t *obj, void *data_struct)
{
    hybrid_config_t *cfg = data_struct;
    memset(cfg, 0, sizeof(*cfg));

    const json_t *arr = json_object_get(obj, "inners");
    if (!json_is_array(arr))
        return EXCEPTION(EINVAL);

    size_t n = json_array_size(arr);
    if (n == 0 || n > HYBRID_MAX_INNERS)
        return EXCEPTION(EINVAL);
    cfg->n_inners = n;

    for (size_t i = 0; i < n; i++) {
        const json_t *jin = json_array_get(arr, i);
        if (!json_is_object(jin)) return EXCEPTION(EINVAL);
        hybrid_inner_t *in = &cfg->inners[i];

        const char *s = json_string_value(json_object_get(jin, "kind"));
        if (s == NULL) return EXCEPTION(EINVAL);
        snprintf(in->kind, sizeof(in->kind), "%s", s);

        s = json_string_value(json_object_get(jin, "match_cidr"));
        if (s != NULL) snprintf(in->match_cidr, sizeof(in->match_cidr), "%s", s);

        in->match_eid  = json_boolean_value(json_object_get(jin, "match_eid"));
        in->is_default = json_boolean_value(json_object_get(jin, "is_default"));

        const json_t *jnet = json_object_get(jin, "net_cfg");
        if (json_is_object(jnet)) {
            if (network_from_json(jnet, &in->net_cfg) != 0)
                return EXCEPTION(EINVAL);
        }
        /* inner_specific is never serialized — programmatic use only. */
        in->inner_specific = NULL;
    }

    /* Optional; defaults to false if absent. */
    const json_t *jgw = json_object_get(obj, "is_gateway");
    if (jgw != NULL)
        cfg->is_gateway = json_boolean_value(jgw);

    /* Optional group-UUID routing table (AT_NET_GROUP_FORWARD). Read even
     * when the feature is compiled out — keeps config schema stable. Entries
     * with an unparseable UUID or out-of-range leg_index are rejected. */
    const json_t *jroutes = json_object_get(obj, "group_routes");
    if (json_is_array(jroutes)) {
        size_t nr = json_array_size(jroutes);
        if (nr > HYBRID_MAX_GROUP_ROUTES)
            return EXCEPTION(EINVAL);
        for (size_t i = 0; i < nr; i++) {
            const json_t *jr = json_array_get(jroutes, i);
            if (!json_is_object(jr))
                return EXCEPTION(EINVAL);
            const char *us = json_string_value(json_object_get(jr, "group_uuid"));
            if (us == NULL || uuid_parse(us, cfg->group_routes[i].group_uuid) != 0)
                return EXCEPTION(EINVAL);
            json_int_t leg = json_integer_value(json_object_get(jr, "leg_index"));
            if (leg < 0 || (size_t)leg >= cfg->n_inners)
                return EXCEPTION(EINVAL);
            cfg->group_routes[i].leg_index = (size_t)leg;
        }
        cfg->n_group_routes = nr;
    }

    return 0;
}

int hybrid_group_route_lookup(const hybrid_config_t *cfg,
                              const uint8_t *dst_uuid,
                              size_t *out_leg_index)
{
    if (cfg == NULL || dst_uuid == NULL)
        return -1;
    for (size_t i = 0; i < cfg->n_group_routes; i++) {
        if (memcmp(cfg->group_routes[i].group_uuid, dst_uuid, 16) == 0) {
            if (out_leg_index != NULL)
                *out_leg_index = cfg->group_routes[i].leg_index;
            return 0;
        }
    }
    return -1;
}

/* The config-table entry key matches the transport's name ("hybrid_net")
 * so net_proc.c can look up the hybrid_config_t in proc->configs using
 * transport->name uniformly for any transport that needs extra config. */
DECLARE_CONFIGURATION(hybrid_net, sizeof(hybrid_config_t), hybrid_to_json, hybrid_from_json);

/* ---------- Process-runner entry point ---------- */

#include "network/net_proc_priv.h"
#include "processes/processes.h"

int network_hybrid_run(process_t *proc, directory_t *queues,
                       queue_id_t signal, logger_t *logger)
{ return network_run_by_name("hybrid_net", proc, queues, signal, logger); }
DECLARE_PROCESS(network, hybrid_net, network_hybrid_run);
