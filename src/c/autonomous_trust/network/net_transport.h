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

#ifndef NET_TRANSPORT_H
#define NET_TRANSPORT_H

/**
 * @file net_transport.h
 * @brief Pluggable network-transport abstraction for AT.
 *
 * Each transport (UDP-ip4, UDP-ip6, TCP-ip4, TCP-ip6, DTN, ...) exposes
 * one `const net_transport_t` object. `net_proc.c` orchestrates the three
 * logical channels (peer, broadcast, group) against whichever transport
 * the tracker config selected — without knowing anything about sockets
 * or bundles.
 *
 * Transport implementations live in `net_transport_<kind>.c` and are
 * statically linked in based on CMake options (AT_NET_DTN, etc.).
 */

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "network/network.h"
#include "utilities/exception.h"
#include "utilities/logger.h"

/* Forward decls so the transport header doesn't drag in identity/processes. */
typedef struct identity_s identity_t;
typedef struct process_s process_t;

/* Transport error codes — DEFINE lives in net_proc.c. */
#define ENET_SEND 230
DECLARE_ERROR(ENET_SEND, "Network send failed");
#define ENET_RECV 231
DECLARE_ERROR(ENET_RECV, "Network receive failed");

/** Opaque per-transport context: socket FDs, BP endpoint handles, etc. */
typedef struct net_transport_ctx_s net_transport_ctx_t;

/**
 * @brief Logical channel the orchestrator wants to send/receive on.
 *
 * A transport decides how to realize these:
 *   - UDP: three separate sockets (ptp, bcast, mcast) per current code.
 *   - DTN: one endpoint with demux-suffix-based routing to channels.
 */
typedef enum {
    NET_CHAN_PEER = 0,       /**< Encrypted unicast peer-to-peer. */
    NET_CHAN_BROADCAST = 1,  /**< Open discovery broadcast (unencrypted). */
    NET_CHAN_GROUP = 2,      /**< Encrypted group multicast. */
    NET_CHAN__COUNT
} net_channel_t;

/**
 * @brief One-shot configuration handed to `open()`.
 *
 * The transport keeps a pointer to @p net_cfg — it is owned by the
 * process and outlives the transport context. Do not copy the struct.
 *
 * @p myself and @p proc are optional borrowed pointers that live as long
 * as the owning network process. They carry identity/peer/group state that
 * non-IP transports (e.g., DTN) need to resolve addressing. Socket
 * transports ignore both and will continue to work if they are NULL.
 */
typedef struct {
    const network_config_t *net_cfg;   /**< CIDRs, mcast addrs, base port. */
    logger_t *logger;                  /**< Logger the transport should use. */
    int port_base;                     /**< COMM_PORT; peer/broadcast use this, group uses +1. */
    const identity_t *myself;          /**< Local identity (UUID, keys); may be NULL pre-provision. */
    const process_t *proc;             /**< Owning network process; gives the transport access to
                                            protocol.peers[] (UUID↔address) and protocol.group at
                                            send time. May be NULL for unit-test harnesses. */
    const void *transport_specific;    /**< Opaque blob a specific transport interprets on its own.
                                            Socket transports ignore it. The hybrid transport casts
                                            to hybrid_config_t. Borrowed pointer; caller owns. */
} net_transport_params_t;

/**
 * @brief Transport dispatch table.
 *
 * Every implementation exposes one `const net_transport_t` with these
 * function pointers populated. Conventions:
 *
 *   - All methods return 0 on success, negative on error. `recv` returns
 *     ENOMSG when the timeout expires with no message available.
 *   - `send_unicast` / `send_broadcast` take a wire-format payload that
 *     has already been encrypted by `net_proc.c` as appropriate. The
 *     transport does not touch payload bytes.
 *   - `recv` returns a heap buffer via @p *out_buf that the caller must
 *     `free()`. @p peer_addr_out is filled with the sender's transport
 *     address (IP for UDP/TCP, EID for DTN). Truncation is silent; the
 *     caller sizes @p peer_addr_len to ADDR_LEN+1 by convention.
 */
typedef struct net_transport_s {
    /** Short identifier, also used as the process impl_name (e.g. "udp_net_4"). */
    const char *name;

    /**
     * @brief Bind/open any sockets or endpoints needed for the three channels.
     *
     * The returned @p *out_ctx is opaque; the orchestrator passes it back
     * to every other method. `close()` is responsible for releasing it.
     *
     * @return 0 on success, non-zero on bind/open failure.
     */
    int (*open)(net_transport_ctx_t **out_ctx, const net_transport_params_t *params);

    /**
     * @brief Send a wire-format datagram to a specific peer.
     *
     * @p target is a transport-native address string (IPv4/IPv6 dotted/colon
     * notation for socket transports; EID for DTN).
     */
    int (*send_unicast)(net_transport_ctx_t *ctx,
                        const uint8_t *wire, size_t wire_len,
                        const char *target, int port);

    /**
     * @brief Send a wire-format datagram to the broadcast/group destination.
     *
     * For socket transports, @p channel picks between the broadcast address
     * and the mcast group (from @p net_cfg). For DTN, @p channel selects
     * which group EID to bundle against.
     *
     * Only NET_CHAN_BROADCAST and NET_CHAN_GROUP are valid here; passing
     * NET_CHAN_PEER returns -1.
     */
    int (*send_broadcast)(net_transport_ctx_t *ctx, net_channel_t channel,
                          const uint8_t *wire, size_t wire_len, int port);

    /**
     * @brief Block up to @p timeout_ms for a message on @p channel.
     *
     * On success (return 0): @p *out_buf is a newly-allocated buffer (caller
     * frees) of length @p *out_len; @p peer_addr_out receives the sender's
     * transport address.
     *
     * Returns ENOMSG on timeout (no data available). Returns negative on
     * unrecoverable transport error (socket closed, etc.).
     */
    int (*recv)(net_transport_ctx_t *ctx, net_channel_t channel,
                uint8_t **out_buf, size_t *out_len,
                char *peer_addr_out, size_t peer_addr_len,
                int timeout_ms);

    /** Release any FDs, endpoints, threads owned by the context. */
    void (*close)(net_transport_ctx_t *ctx);

    /**
     * @brief Optional: true iff this transport was opened in gateway mode
     *        and should forward frames whose envelope dst is not local.
     *
     * Only consulted by net_proc.c when the build has AT_NET_ENVELOPE
     * enabled. A NULL function pointer means the transport does not
     * support forwarding (always treated as false). Currently implemented
     * only by the hybrid transport, which reads its hybrid_config_t's
     * is_gateway bit.
     */
    bool (*is_gateway)(const net_transport_ctx_t *ctx);

    /**
     * @brief Optional: expected one-way link latency to @p target, in
     *        milliseconds.
     *
     * Used by the timeout-adaptation layer (see utilities/timeout.h) to
     * scale consensus / voting / challenge-response deadlines when a peer
     * is reachable only via a slow transport (DTN bundles, deep-space
     * relays).
     *
     * Returns a non-negative estimate in ms on success. Returns a
     * negative value or NULL function pointer means "unknown"; the
     * caller falls back to @ref AT_TIMEOUT_DEFAULT_RTT_MS.
     *
     * Conventions per transport family:
     *   - Socket (UDP/TCP) on a LAN: ~50 ms
     *   - DTN Bundle Protocol: ~60000 ms (tunable)
     *   - Hybrid: delegates to whichever inner would send to @p target.
     */
    int (*link_class_ms)(const net_transport_ctx_t *ctx, const char *target);

    /**
     * @brief Optional: send a broadcast/group wire frame via a specific
     *        inner leg.
     *
     * Meaningful only for multi-leg transports (currently just hybrid).
     * NULL for single-leg transports. Used by AT_NET_GROUP_FORWARD, where
     * a gateway must route a GROUP-addressed envelope to the configured
     * upstream leg rather than fanning out.
     *
     * @p leg_index is opaque to the caller; it is the value stored in the
     * transport's configuration table (for hybrid, the entry in
     * hybrid_config_t::group_routes). Out-of-range values return -1.
     *
     * Only NET_CHAN_BROADCAST and NET_CHAN_GROUP are valid here;
     * NET_CHAN_PEER returns -1.
     */
    int (*send_on_leg)(net_transport_ctx_t *ctx, size_t leg_index,
                       net_channel_t channel,
                       const uint8_t *wire, size_t wire_len, int port);
} net_transport_t;

/**
 * @brief Look up a transport by name (matches the impl_name field in the
 * per-transport process-declaration macro in net_proc.c).
 * Returns NULL if not registered.
 */
const net_transport_t *net_transport_find(const char *name);

#endif /* NET_TRANSPORT_H */
