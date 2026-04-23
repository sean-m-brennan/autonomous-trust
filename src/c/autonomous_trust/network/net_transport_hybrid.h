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

#ifndef NET_TRANSPORT_HYBRID_H
#define NET_TRANSPORT_HYBRID_H

/**
 * @file net_transport_hybrid.h
 * @brief Hybrid transport — composes N inner transports behind one vtable.
 *
 * Lets a single AT node speak two (or more) transports simultaneously.
 * Typical uses:
 *
 *   (a) Gateway node bridging clusters: one inner is UDP on the local LAN,
 *       the other is DTN to a remote cluster via a Bundle Protocol agent
 *       (per at-over-dtn.md §4.3).
 *
 *   (b) Multi-homed AT node: two UDP transports on different interfaces /
 *       subnets (e.g., vehicles on V2V radio + LTE backhaul), with sends
 *       routed by destination-CIDR match.
 *
 *   (c) Protocol split: TCP to wired peers, UDP to wireless peers — inners
 *       distinguished by which peer registry entry the target matches.
 *
 * The hybrid transport is protocol-agnostic: inner transports are selected
 * by name at configure time, and the routing rule is a table of matchers.
 *
 * Receive is aggregated: each inner × each channel gets a reader thread
 * that pushes incoming messages into a shared per-channel queue. recv()
 * pops from the queue, so inbound traffic on any inner is delivered at
 * the transport's natural latency without inter-inner polling overhead.
 *
 * Send path walks `inners[]` in order and picks the first whose matcher
 * accepts the target. A matcher is exactly one of:
 *   - match_cidr  : IPv4 CIDR (e.g. "10.0.0.0/24") — matches when target
 *                   is a dotted-quad inside the CIDR.
 *   - match_eid   : matches when target starts with "dtn:" or "ipn:".
 *   - is_default  : fallback catch-all; exactly one inner should set this.
 *
 * Broadcast sends are fanned out to EVERY inner, so a gateway's discovery
 * broadcasts reach both sides of the bridge.
 */

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include <jansson.h>

#include "network/net_transport.h"
#include "network/network.h"

#define HYBRID_MAX_INNERS 4       /**< plenty for 2-leg gateways + expansion. */
#define HYBRID_KIND_LEN   31      /**< fits "udp_net_4" / "hybrid_net" / "dtn_bp". */

/** Max per-gateway group routes. A gateway with more than this many distinct
 *  remote groups is unusual — raise if field ops demand it. */
#define HYBRID_MAX_GROUP_ROUTES 8

/** Per-inner-transport configuration carried by hybrid_config_t.
 *
 * Storage is inline so a hybrid_config_t can be deserialized from JSON
 * into a single contiguous allocation without pointer surgery. Fields
 * marked as matcher are mutually exclusive in practice — only set one. */
typedef struct hybrid_inner_s {
    /** Transport name, e.g. "udp_net_4", "tcp_net_6", "dtn_bp". Must be
     *  resolvable via net_transport_find(). NUL-terminated. */
    char kind[HYBRID_KIND_LEN + 1];

    /** The network_config_t passed to this inner's open(). Each inner
     *  has its own — so two udp_net_4 inners can bind different CIDRs
     *  on different interfaces. */
    network_config_t net_cfg;

    /** Transport-specific config forwarded as params.transport_specific
     *  to the inner's open(). Programmatic only (not JSON-serialized);
     *  NULL for transports that don't need it. */
    const void *inner_specific;

    /* ---- Routing matcher ---- */

    /** IPv4 CIDR ("10.0.0.0/24"). Empty string = don't match by CIDR. */
    char match_cidr[CIDR6_LEN + 1];

    /** If true, targets starting with "dtn:" or "ipn:" route to this inner. */
    bool match_eid;

    /** If true, route here when no earlier entry matches. At most one
     *  inner in the table should set this. */
    bool is_default;
} hybrid_inner_t;

/** The full hybrid configuration.
 *
 * Passed two ways:
 *   1. Programmatic: fill a stack/heap hybrid_config_t and pass
 *      address via net_transport_params_t.transport_specific.
 *   2. JSON-loaded: AT's config registry (see the macro in
 *      net_transport_hybrid.c) allocates this struct and populates
 *      from JSON; net_proc.c finds it in proc->configs["hybrid"]
 *      and points transport_specific at it. */
/** Group-routing entry for AT_NET_GROUP_FORWARD (at-over-dtn §4.3 stage F).
 *  A gateway receiving a GROUP-addressed envelope whose dst_uuid matches
 *  @c group_uuid re-emits the frame via @c leg_index. Stored inline in
 *  hybrid_config_t regardless of build flags so the JSON schema is stable;
 *  the code paths that consume them are gated on AT_NET_GROUP_FORWARD. */
typedef struct group_route_s {
    uint8_t group_uuid[16]; /**< Destination group UUID (raw, not hyphenated). */
    size_t  leg_index;      /**< Index into hybrid_config_t::inners. */
} group_route_t;

typedef struct hybrid_config_s {
    hybrid_inner_t inners[HYBRID_MAX_INNERS];
    size_t n_inners;

    /** True iff this node is a gateway — i.e., when it receives a frame
     *  whose envelope dst is not local, it should forward to the other
     *  inner transport instead of dropping. Consumed only when the build
     *  was configured with AT_NET_ENVELOPE; otherwise forwarding code is
     *  absent and this field is ignored. */
    bool is_gateway;

    /** Group UUID -> inner-leg routing table. Populated for gateways when
     *  AT_NET_GROUP_FORWARD=ON; ignored otherwise. Always present in the
     *  struct so JSON schema is stable across build variants. */
    group_route_t group_routes[HYBRID_MAX_GROUP_ROUTES];
    size_t n_group_routes;
} hybrid_config_t;

/** Find a leg index for a GROUP-forward lookup.
 *
 *  Scans @p cfg->group_routes for an entry whose @c group_uuid equals
 *  @p dst_uuid. Returns the leg index on match, -1 on miss or if
 *  @p cfg is NULL.
 *
 *  This helper is compiled unconditionally so tests can exercise route
 *  resolution without needing the AT_NET_GROUP_FORWARD code path active
 *  in net_proc.c. */
int hybrid_group_route_lookup(const hybrid_config_t *cfg,
                              const uint8_t *dst_uuid,
                              size_t *out_leg_index);

/** Pure routing-decision helper, exposed for unit tests.
 *
 * @param cfg      Hybrid config with 1..N inners populated.
 * @param target   Destination address string (IPv4 dotted-quad, EID, or
 *                 other host string).
 * @param logger   Optional; used only for diagnostic logging.
 * @return Index into @p cfg->inners of the matched inner, or -1 if no
 *         inner matches and no default is configured. */
int hybrid_route(const hybrid_config_t *cfg, const char *target,
                 logger_t *logger);

extern const net_transport_t hybrid_net_transport;

/* JSON serialization — referenced from the generated config_table_priv.h. */
int hybrid_to_json(const void *data_struct, json_t **obj_ptr);
int hybrid_from_json(const json_t *obj, void *data_struct);

/* Process-runner entry point — referenced from the generated
 * process_table_priv.h. */
#include "processes/processes.h"
int network_hybrid_run(process_t *proc, directory_t *queues,
                       queue_id_t signal, logger_t *logger);

#endif /* NET_TRANSPORT_HYBRID_H */
