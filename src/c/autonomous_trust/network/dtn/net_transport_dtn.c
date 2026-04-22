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

/**
 * @file net_transport_dtn.c
 * @brief DTN/Bundle-Protocol implementation of net_transport_t.
 *
 * Maps AT's three logical channels onto bundle destinations:
 *   NET_CHAN_PEER      -> dtn://at-<peer-uuid>/peer     (BPSec bcb, NaCl Box)
 *   NET_CHAN_BROADCAST -> dtn://at-group-<hash>/bcast   (no BPSec, flooded)
 *   NET_CHAN_GROUP     -> dtn://at-group-<hash>/group   (BPSec bcb, SecretBox)
 *
 * The transport keeps one logical endpoint per channel (via service demux
 * suffixes) but receives all inbound bundles from a single backend recv
 * call; channel routing is by destination service suffix at recv time.
 *
 * A pending-bundle buffer (one slot per channel) lets recv() return a
 * message for the requested channel even if the backend delivered bundles
 * for other channels first — no thread is lost waiting.
 */

#include <errno.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

#include "network/dtn/dtn_backend.h"
#include "network/dtn/dtn_eid.h"
#include "network/net_proc_priv.h"
#include "network/net_transport.h"
#include "utilities/exception.h"
#include "processes/processes.h"
#include "identity/identity.h"
#include "identity/identity_priv.h"
#include "identity/group.h"

/* ---------- Transport context ---------- */

typedef struct {
    uint8_t *payload;
    size_t   len;
    char     src_eid[DTN_EID_MAX + 1];
    bool     pending;
} dtn_slot_t;

/* net_transport_ctx_t is opaque to net_proc.c; each transport defines its
 * own struct and casts the pointer back. DTN holds one pending-bundle slot
 * per channel so recv() can return buffered messages without stalling.
 *
 * The transport borrows @p proc so send paths can look up the current
 * peer registry (peers[]/num_peers under peers_rwlock) and the joined
 * group state (protocol.group). Both evolve at runtime as the identity/
 * fleet processes admit peers and the group key is distributed. */
typedef struct {
    const network_config_t *net_cfg;
    logger_t *logger;
    const process_t *proc;
    char local_node_eid[DTN_EID_MAX + 1];
    dtn_slot_t slots[NET_CHAN__COUNT];
    pthread_mutex_t slot_lock;
    uint32_t default_lifetime_sec;
} dtn_ctx_t;

static const uint32_t DEFAULT_BUNDLE_LIFETIME_SEC = 86400; /* 24h */

/* ---------- Helpers ---------- */

static const char *channel_suffix(net_channel_t ch)
{
    switch (ch) {
    case NET_CHAN_PEER:      return DTN_CHAN_PEER_SUFFIX;
    case NET_CHAN_BROADCAST: return DTN_CHAN_BCAST_SUFFIX;
    case NET_CHAN_GROUP:     return DTN_CHAN_GROUP_SUFFIX;
    case NET_CHAN__COUNT:    break;
    }
    return NULL;
}

static net_channel_t service_to_channel(const char *dest_service)
{
    if (dest_service == NULL) return NET_CHAN__COUNT;
    if (strcmp(dest_service, DTN_CHAN_PEER_SUFFIX) == 0)  return NET_CHAN_PEER;
    if (strcmp(dest_service, DTN_CHAN_BCAST_SUFFIX) == 0) return NET_CHAN_BROADCAST;
    if (strcmp(dest_service, DTN_CHAN_GROUP_SUFFIX) == 0) return NET_CHAN_GROUP;
    return NET_CHAN__COUNT;
}

/* ---------- Vtable methods ---------- */

static int dtn_open(net_transport_ctx_t **out_ctx,
                    const net_transport_params_t *params)
{
    dtn_ctx_t *ctx = calloc(1, sizeof(*ctx));
    if (ctx == NULL)
        return SYS_EXCEPTION();
    ctx->net_cfg = params->net_cfg;
    ctx->logger  = params->logger;
    ctx->proc    = params->proc;
    ctx->default_lifetime_sec = DEFAULT_BUNDLE_LIFETIME_SEC;
    pthread_mutex_init(&ctx->slot_lock, NULL);

    /* Derive the local node EID from myself->uuid when the identity is
     * available; otherwise fall back to a placeholder so unit tests and
     * pre-provisioning scenarios still get a usable endpoint. */
    if (params->myself != NULL) {
        if (dtn_eid_from_uuid(params->myself->uuid,
                              ctx->local_node_eid,
                              sizeof(ctx->local_node_eid)) < 0) {
            log_error(params->logger, "DTN: local EID derivation failed\n");
            pthread_mutex_destroy(&ctx->slot_lock);
            free(ctx);
            return -1;
        }
    } else {
        log_warn(params->logger, "DTN: no identity at open(); using placeholder EID\n");
        snprintf(ctx->local_node_eid, sizeof(ctx->local_node_eid),
                 "dtn://at-local/");
    }

    /* Register three endpoints so each AT channel has its own inbound
     * stream from the BPA:
     *
     *   [0] /peer  on our own node EID            — unicast, primary (source EID for sends)
     *   [1] /bcast on the group-broadcast EID     — open discovery broadcast
     *   [2] /group on the group-broadcast EID     — encrypted group multicast
     *
     * The group-broadcast EID is derived from the joined-group UUID when
     * one exists, otherwise from a stable "AT-boot" pre-join hash so a
     * brand-new node still has a well-known address for discovery. */
    char peer_eid[DTN_EID_MAX + 1];
    char group_node_eid[DTN_EID_MAX + 1];
    char bcast_eid[DTN_EID_MAX + 1];
    char group_eid[DTN_EID_MAX + 1];

    if (dtn_eid_for_service(ctx->local_node_eid, DTN_CHAN_PEER_SUFFIX,
                            peer_eid, sizeof(peer_eid)) < 0) {
        pthread_mutex_destroy(&ctx->slot_lock);
        free(ctx);
        return -1;
    }

    unsigned char hash_bytes[8] = {0};
    bool have_group = false;
    if (params->proc != NULL) {
        const group_t *grp = &params->proc->protocol.group;
        uuid_t zero = {0};
        if (memcmp(grp->uuid, zero, sizeof(uuid_t)) != 0) {
            memcpy(hash_bytes, grp->uuid, sizeof(hash_bytes));
            have_group = true;
        }
    }
    if (!have_group) {
        static const unsigned char pre_join[8] = {
            'A','T','-','b','o','o','t',0
        };
        memcpy(hash_bytes, pre_join, sizeof(hash_bytes));
    }
    if (dtn_eid_for_group(hash_bytes, sizeof(hash_bytes),
                          group_node_eid, sizeof(group_node_eid)) < 0 ||
        dtn_eid_for_service(group_node_eid, DTN_CHAN_BCAST_SUFFIX,
                            bcast_eid, sizeof(bcast_eid)) < 0 ||
        dtn_eid_for_service(group_node_eid, DTN_CHAN_GROUP_SUFFIX,
                            group_eid, sizeof(group_eid)) < 0) {
        pthread_mutex_destroy(&ctx->slot_lock);
        free(ctx);
        return -1;
    }

    const dtn_endpoint_t endpoints[NET_CHAN__COUNT] = {
        [NET_CHAN_PEER]      = { .eid = peer_eid,  .service = DTN_CHAN_PEER_SUFFIX  },
        [NET_CHAN_BROADCAST] = { .eid = bcast_eid, .service = DTN_CHAN_BCAST_SUFFIX },
        [NET_CHAN_GROUP]     = { .eid = group_eid, .service = DTN_CHAN_GROUP_SUFFIX },
    };

    if (dtn_backend.init(endpoints, NET_CHAN__COUNT, params->logger) != 0) {
        log_error(params->logger, "DTN: backend '%s' init failed\n",
                  dtn_backend.name);
        pthread_mutex_destroy(&ctx->slot_lock);
        free(ctx);
        return -1;
    }

    log_info(params->logger,
             "DTN: ready, backend=%s peer=%s bcast=%s group=%s (group_joined=%s)\n",
             dtn_backend.name, peer_eid, bcast_eid, group_eid,
             have_group ? "yes" : "no (pre-join)");
    *out_ctx = (net_transport_ctx_t *)ctx;
    return 0;
}

/* Resolve @p target (as delivered by net_proc.c — the contents of
 * public_identity_t.address) into a DTN destination EID of the form
 * dtn://at-<uuid-prefix>/peer.
 *
 * Priority:
 *   1. If @p target already parses as a scheme-qualified EID (dtn: or
 *      ipn:), use it verbatim. Lets operators provision address= as an
 *      EID directly for mixed/hybrid deployments.
 *   2. Otherwise, look the target up in the process's peer registry by
 *      matching @p target against public_identity_t.address. On hit,
 *      derive the EID from that peer's UUID — the canonical path for
 *      deployments where address= remains an IP for IP-clusters.
 *   3. Fallback: use @p target as an opaque host string in our default
 *      scheme. Keeps early unit tests and standalone sends functional.
 */
static int build_peer_eid(const dtn_ctx_t *ctx, const char *target,
                          char *out, size_t out_len)
{
    if (target == NULL || target[0] == '\0')
        return -1;

    if (strncmp(target, "dtn:", 4) == 0 || strncmp(target, "ipn:", 4) == 0) {
        int n = snprintf(out, out_len, "%s", target);
        return (n > 0 && (size_t)n < out_len) ? n : -1;
    }

    if (ctx->proc != NULL) {
        peers_read_lock(ctx->proc);
        uuid_t matched_uuid;
        bool found = false;
        for (size_t i = 0; i < ctx->proc->protocol.num_peers; i++) {
            if (strcmp(ctx->proc->protocol.peers[i].address, target) == 0) {
                memcpy(matched_uuid, ctx->proc->protocol.peers[i].uuid,
                       sizeof(matched_uuid));
                found = true;
                break;
            }
        }
        peers_read_unlock(ctx->proc);
        if (found) {
            char node_eid[DTN_EID_MAX + 1];
            if (dtn_eid_from_uuid(matched_uuid, node_eid, sizeof(node_eid)) < 0)
                return -1;
            return dtn_eid_for_service(node_eid, DTN_CHAN_PEER_SUFFIX,
                                       out, out_len);
        }
    }

    int n = snprintf(out, out_len, "dtn://at-%s/peer", target);
    return (n > 0 && (size_t)n < out_len) ? n : -1;
}

static int dtn_send_unicast(net_transport_ctx_t *ctx_opaque,
                            const uint8_t *wire, size_t wire_len,
                            const char *target, int port)
{
    (void)port;  /* DTN addressing is EID-based, not port-based */
    dtn_ctx_t *ctx = (dtn_ctx_t *)ctx_opaque;

    char dest_eid[DTN_EID_MAX + 1];
    if (build_peer_eid(ctx, target, dest_eid, sizeof(dest_eid)) < 0)
        return EXCEPTION(EINVAL);

    return dtn_backend.send(dest_eid, wire, wire_len, ctx->default_lifetime_sec);
}

static int dtn_send_broadcast(net_transport_ctx_t *ctx_opaque, net_channel_t channel,
                              const uint8_t *wire, size_t wire_len, int port)
{
    (void)port;
    if (channel == NET_CHAN_PEER)
        return -1;

    dtn_ctx_t *ctx = (dtn_ctx_t *)ctx_opaque;

    /* Derive the group EID from the current group UUID held by the network
     * process. The group is populated asynchronously (once the group key
     * has been distributed), so it may be empty here — in which case we
     * degrade to a fixed "unjoined" group EID so open-broadcast discovery
     * still works before provisioning completes. */
    unsigned char hash_bytes[8] = {0};
    bool have_group = false;
    if (ctx->proc != NULL) {
        const group_t *grp = &ctx->proc->protocol.group;
        uuid_t zero = {0};
        if (memcmp(grp->uuid, zero, sizeof(uuid_t)) != 0) {
            memcpy(hash_bytes, grp->uuid, sizeof(hash_bytes));
            have_group = true;
        }
    }
    if (!have_group) {
        /* Stable "pre-join" identifier: all nodes that haven't yet been
         * admitted converge on the same broadcast EID for discovery. */
        static const unsigned char pre_join[8] = {
            'A','T','-','b','o','o','t',0
        };
        memcpy(hash_bytes, pre_join, sizeof(hash_bytes));
    }

    char group_node_eid[DTN_EID_MAX + 1];
    if (dtn_eid_for_group(hash_bytes, sizeof(hash_bytes),
                          group_node_eid, sizeof(group_node_eid)) < 0)
        return -1;

    char dest_eid[DTN_EID_MAX + 1];
    const char *suffix = channel_suffix(channel);
    if (suffix == NULL ||
        dtn_eid_for_service(group_node_eid, suffix,
                            dest_eid, sizeof(dest_eid)) < 0)
        return -1;

    return dtn_backend.send(dest_eid, wire, wire_len, ctx->default_lifetime_sec);
}

static int dtn_recv(net_transport_ctx_t *ctx_opaque, net_channel_t channel,
                    uint8_t **out_buf, size_t *out_len,
                    char *peer_addr_out, size_t peer_addr_len,
                    int timeout_ms)
{
    dtn_ctx_t *ctx = (dtn_ctx_t *)ctx_opaque;
    if (channel >= NET_CHAN__COUNT)
        return -1;

    /* Fast path: a previous recv() already stashed a bundle for this channel. */
    pthread_mutex_lock(&ctx->slot_lock);
    if (ctx->slots[channel].pending) {
        *out_buf = ctx->slots[channel].payload;
        *out_len = ctx->slots[channel].len;
        snprintf(peer_addr_out, peer_addr_len, "%s", ctx->slots[channel].src_eid);
        ctx->slots[channel].pending = false;
        ctx->slots[channel].payload = NULL;
        pthread_mutex_unlock(&ctx->slot_lock);
        return 0;
    }
    pthread_mutex_unlock(&ctx->slot_lock);

    /* Otherwise pull one bundle from the backend and route by destination. */
    uint8_t *payload = NULL;
    size_t   plen    = 0;
    char     src_eid[DTN_EID_MAX + 1]       = {0};
    char     dest_service[DTN_EID_MAX + 1]  = {0};

    int ret = dtn_backend.recv(&payload, &plen,
                               src_eid, sizeof(src_eid),
                               dest_service, sizeof(dest_service),
                               timeout_ms);
    if (ret != 0)
        return ret;

    net_channel_t got = service_to_channel(dest_service);
    if (got == channel) {
        *out_buf = payload;
        *out_len = plen;
        snprintf(peer_addr_out, peer_addr_len, "%s", src_eid);
        return 0;
    }

    /* Wrong channel for this caller — stash for the right receiver thread. */
    if (got < NET_CHAN__COUNT) {
        pthread_mutex_lock(&ctx->slot_lock);
        if (ctx->slots[got].pending) {
            free(ctx->slots[got].payload);  /* overflow: drop oldest */
        }
        ctx->slots[got].payload = payload;
        ctx->slots[got].len = plen;
        snprintf(ctx->slots[got].src_eid, sizeof(ctx->slots[got].src_eid),
                 "%s", src_eid);
        ctx->slots[got].pending = true;
        pthread_mutex_unlock(&ctx->slot_lock);
    } else {
        log_debug(ctx->logger, "DTN: dropped bundle for unknown service '%s'\n",
                  dest_service);
        free(payload);
    }
    return ENOMSG;
}

static void dtn_close(net_transport_ctx_t *ctx_opaque)
{
    if (ctx_opaque == NULL) return;
    dtn_ctx_t *ctx = (dtn_ctx_t *)ctx_opaque;
    dtn_backend.shutdown();
    for (int i = 0; i < NET_CHAN__COUNT; i++)
        free(ctx->slots[i].payload);
    pthread_mutex_destroy(&ctx->slot_lock);
    free(ctx);
}

/* ---------- Exported descriptor ---------- */

/* Bundle Protocol over unreliable store-and-forward links — bundles can
 * sit at a forwarder for minutes or hours. Default to one minute; if an
 * operator knows their BP mesh's bundle-delivery distribution they can
 * raise the timeout_multiplier instead. */
static int dtn_link_class_ms(const net_transport_ctx_t *ctx, const char *target)
{
    (void)ctx; (void)target;
    return 60 * 1000;
}

const net_transport_t dtn_bp_transport = {
    .name           = "dtn_bp",
    .open           = dtn_open,
    .send_unicast   = dtn_send_unicast,
    .send_broadcast = dtn_send_broadcast,
    .recv           = dtn_recv,
    .close          = dtn_close,
    .link_class_ms  = dtn_link_class_ms,
};

/* ---------- Process-runner entry point ---------- */

int network_dtn_bp_run(process_t *proc, directory_t *queues,
                       queue_id_t signal, logger_t *logger)
{ return network_run_by_name("dtn_bp", proc, queues, signal, logger); }
DECLARE_PROCESS(network, dtn_bp, network_dtn_bp_run);
