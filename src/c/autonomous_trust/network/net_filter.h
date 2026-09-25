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

#ifndef NET_FILTER_H
#define NET_FILTER_H

/**
 * @file net_filter.h
 * @brief The network filter chain: how a feature library sits between the
 *        wire and the core's network handlers.
 *
 * A filter may act at three points, each optional:
 *
 *  - **inbound**, at the top of each `handle_inbound_*`, before any
 *    decryption. It may drop the frame, consume it (it forwarded it
 *    itself), or let it continue, narrowing the slice the core sees and
 *    telling the core who originated it (@ref net_inbound_meta_t).
 *  - **outbound**, just before each transport send in
 *    `net_encrypt_and_send`, where it may wrap the frame.
 *  - **after_deliver**, after the core has routed an inbound frame to its
 *    process: deliver-and-forward (broadcast relay) lives here.
 *
 * Filters are ordered by @ref net_filter_t.order, lower nearer the wire:
 * inbound and after_deliver run ascending, outbound descending, so the
 * header of the filter nearest the wire goes on last and comes off first.
 *
 * A filter is installed at network start, from its extension's
 * register_handlers(proc, "network") (processes/extension.h), before the
 * receiver threads run; after that the chain is read-only, so unlocked.
 * An empty chain changes nothing on any path.
 *
 * The routing envelope (libat_gateway, src/c/extensions/gateway/) is the
 * first filter. See doc/architecture/extensions.md.
 */

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <uuid/uuid.h>

#include "network/network.h"
#include "network/net_proc_priv.h"
#include "network/net_transport.h"
#include "utilities/logger.h"

/** Most filters the chain holds. */
#define NET_FILTER_MAX 8

/** Name the routing-envelope filter installs under. The core checks for it
 *  when the network config asks for the envelope (@ref net_filters_check_config). */
#define NET_FILTER_ENVELOPE "envelope"

/** What an inbound filter decided. */
typedef enum {
    NET_FILTER_CONTINUE = 0, /**< Hand the (possibly narrowed) frame on. */
    NET_FILTER_DROP,         /**< Discard it; the core does nothing more. */
    NET_FILTER_CONSUMED,     /**< The filter dealt with it (e.g. forwarded it). */
} net_filter_verdict_t;

/** Per inbound frame: filled by the chain, read by the core. */
typedef struct {
    const uint8_t *inner;     /**< Slice the core decodes; a filter narrows it. */
    size_t         inner_len;
    bool   has_src_uuid;      /**< @ref src_uuid is the frame's originator. */
    uuid_t src_uuid;          /**< Peer lookup and defer key, instead of the
                               *   transport address (which may be a gateway). */
    bool   forwarded;         /**< The frame came through a gateway. */
    bool   keep_reported_addr;/**< Keep the sender's self-reported address
                               *   rather than overwriting it with from_addr. */
    /** The slice each filter saw on the way in, by chain position, handed
     *  back to it in after_deliver. Written by the chain. */
    struct { uint8_t *frame; size_t len; } seen[NET_FILTER_MAX];
    size_t n_seen;
} net_inbound_meta_t;

/** Per outbound frame. */
typedef struct {
    net_channel_t        channel;
    const unsigned char *src_uuid; /**< This node; NULL if not yet configured. */
    const unsigned char *dst_uuid; /**< Peer or group; NULL for broadcast. */
} net_send_info_t;

/** One filter. Every hook is optional. */
typedef struct {
    const char *name;
    int order;  /**< Lower = nearer the wire. */

    /** Decide on one inbound frame. @p frame / @p len are the slice as the
     *  filters before this one left it; narrow it through @p meta. The
     *  frame is the receiver thread's buffer and may be rewritten in place. */
    net_filter_verdict_t (*inbound)(const net_thread_ctx_t *ctx, net_channel_t ch,
                                    uint8_t *frame, size_t len,
                                    const char *from_addr, net_inbound_meta_t *meta);

    /** Transform one outbound frame. Set @p *out = (uint8_t *)in to leave it
     *  unchanged, or to a malloc'd buffer the chain then owns. Non-zero
     *  refuses the send. */
    int (*outbound)(const net_send_info_t *info, const uint8_t *in, size_t in_len,
                    uint8_t **out, size_t *out_len);

    /** After the core delivered the frame locally. @p frame / @p len are
     *  what this filter saw inbound. */
    void (*after_deliver)(const net_thread_ctx_t *ctx, net_channel_t ch,
                          uint8_t *frame, size_t len, const net_inbound_meta_t *meta);
} net_filter_t;

/**
 * @brief Add @p f to the chain. Call at network start, before the receiver
 * threads. Refuses (-1, with a line on stderr) NULL, an unnamed filter, a
 * name already installed, and a full chain.
 */
int net_filter_install(const net_filter_t *f);

/** True iff a filter named @p name is installed. */
bool net_filter_installed(const char *name);

/** Empty the chain (network shutdown, conformance/tests). */
void net_filters_reset(void);

/**
 * @brief Run the inbound hooks over @p buf, ascending. Initializes @p meta
 * (inner = the whole buffer). Stops at the first DROP or CONSUMED.
 */
net_filter_verdict_t net_filters_inbound(const net_thread_ctx_t *ctx, net_channel_t ch,
                                         uint8_t *buf, size_t nbytes,
                                         const char *from_addr, net_inbound_meta_t *meta);

/**
 * @brief Run the outbound hooks, descending. @p *out is @p in when nothing
 * changed; otherwise a malloc'd buffer the caller frees. @return 0, or -1
 * if a filter refused (nothing to free then).
 */
int net_filters_outbound(const net_send_info_t *info, const uint8_t *in, size_t in_len,
                         uint8_t **out, size_t *out_len);

/** Run the after_deliver hooks of the filters that saw the frame, ascending. */
void net_filters_after_deliver(const net_thread_ctx_t *ctx, net_channel_t ch,
                               const net_inbound_meta_t *meta);

/**
 * @brief Refuse a network config the installed filters cannot honour: the
 * envelope asked for but no @ref NET_FILTER_ENVELOPE filter installed (its
 * library is absent), or group_forward / cross_cluster without the
 * envelope. Logs an ERROR naming the problem. @return 0 or -1.
 */
int net_filters_check_config(const network_config_t *cfg, logger_t *logger);

#endif /* NET_FILTER_H */
