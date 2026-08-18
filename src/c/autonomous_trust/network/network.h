/********************
 *  Copyright 2024 TekFive, Inc., Sean M. Brennan, and contributors
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

#ifndef NETWORK_H
#define NETWORK_H

/** @addtogroup internal_network
 *  @{
 */

#include <stdint.h>
#include <jansson.h>
#include "utilities/allocation.h"
#include "utilities/logger.h"
#include "network/net_wire_format.h"

/* Compile-time DEFAULT base port, not a fixed one. The port a node actually
 * uses is resolved by net_port_resolve() below; the transports derive the
 * encrypted-group port as base + 1. Two nodes co-locate on one host by taking
 * different bases (or the same base on different addresses). Mirrors Python
 * system.py comm_port. */
#define COMM_PORT 27787

/* Lowest/highest base a node may be given. The upper bound leaves room for
 * the derived group port (base + 1) inside the 16-bit port space, and the
 * lower bound keeps a node off the privileged range it cannot bind unprivileged. */
#define COMM_PORT_MIN 1024
#define COMM_PORT_MAX 65534

#define IPV4_ADDR_LEN 16
#define CIDR4_LEN (IPV4_ADDR_LEN + 3)
#define IPV6_ADDR_LEN 46
#define CIDR6_LEN (IPV6_ADDR_LEN + 4)
#define MAC_ADDR_LEN 17

/* Per-peer duplicate-broadcast threshold before demotion — the DEFAULTS layer
 * for the knob, not the knob itself. Mirrors Python NetworkProcess.annoy_limit.
 * Read it through net_annoy_limit_resolve(), which applies AT_NET_ANNOY_LIMIT
 * first; comparing against this macro directly ignores the override. */
#define NET_ANNOY_LIMIT 5
#define NET_ANNOY_LIMIT_MIN 1
#define NET_ANNOY_LIMIT_MAX 10000

/* Receive-poll timeout, in milliseconds: how long a receiver thread blocks in
 * recv() before looking at the stop flag. Mirrors Python
 * NetworkProcess.socket_timeout (0.1 s = 100 ms); the unit differs because the
 * poll API does, the VALUE does not. Read via net_recv_poll_ms_resolve(). */
#define NET_RECV_POLL_MS 100
#define NET_RECV_POLL_MS_MIN 1
#define NET_RECV_POLL_MS_MAX 60000

/* How long a deferred ("mystery") encrypted message whose sender never became
 * a known peer is held before it is reclaimed, in seconds. Mirrors Python
 * NetworkProcess.mystery_max_age_s. Read via net_mystery_max_age_resolve(). */
#define NET_MYSTERY_MAX_AGE_SEC 30
#define NET_MYSTERY_MAX_AGE_SEC_MIN 1
#define NET_MYSTERY_MAX_AGE_SEC_MAX 86400

/* Persistent-connection bounds, shared with Python's AT_NET_CONN_IDLE_TTL /
 * AT_NET_MAX_CONNS (system.py). A TCP sender with pooling on keeps its
 * connection open, so the receiver holds one per active peer: the TTL closes
 * a connection gone quiet, and the cap stops a hostile peer exhausting our
 * descriptors by opening many. Read via net_conn_idle_ttl_resolve() /
 * net_max_live_conns_resolve().
 *
 * Python's TTL default is 30.0 seconds; the value is the same, only the type
 * differs (there is no sub-second use for it, and an integer keeps the knob
 * parseable by the shared resolver). */
#define NET_CONN_IDLE_TTL_SEC 30
#define NET_CONN_IDLE_TTL_SEC_MIN 1
#define NET_CONN_IDLE_TTL_SEC_MAX 86400

#define NET_MAX_LIVE_CONNS 64
#define NET_MAX_LIVE_CONNS_MIN 1
#define NET_MAX_LIVE_CONNS_MAX 256

/**
 * @brief Address family / link-layer family a transport operates on.
 *
 * Mirrors Python's `NetworkProtocol` enum (netprocess.py:40-44). Values
 * match the Python wire values so cross-impl config files agree.
 */
typedef enum {
    NETPROTO_NONE = 0,  /**< Abstract base / unset; transports must override. */
    NETPROTO_MAC  = 2,  /**< Link-layer addressing only (no IP). */
    NETPROTO_IPV4 = 4,  /**< IPv4 socket transports. */
    NETPROTO_IPV6 = 6,  /**< IPv6 socket transports. */
} network_protocol_t;

/* Wire-protocol function selectors handled by the network process
 * outbound queue (mirrors Python Network.{stats_req,stats_resp,ping_at}
 * in network.py:33-35). Defined via `extern char[]` so callers compare
 * against the same bytes the wire serializer emits — see
 * project_proto_string_arrays. */
extern char NET_FN_STATS_REQ[];
extern char NET_FN_STATS_RESP[];
/* PingAT: confirmation that an AT peer is present and answering on AT's own
 * UDP ports via a cooperating responder — NOT ICMP reachability. C implements
 * no PingAT. The selector is retained so the outbound drain recognizes the
 * request and answers {"error": "unsupported"} rather than dropping it and
 * leaving a requester to time out. Python is the only implementation. */
extern char NET_FN_PING_AT[];
/* Reputation communication cut-off control (local IPC only; mirrors Python
 * Network.exclude / Network.readmit in network.py). */
extern char NET_FN_EXCLUDE[];
extern char NET_FN_READMIT[];

/* Python's INBOUND_BUDGET=32 per-channel drain cap (netprocess.py:581).
 * C's receive path is thread-per-channel, so OS scheduling provides the
 * equivalent fairness invariant — no shared drain loop exists to cap. The
 * constant is recorded here for cross-reference with the Python audit
 * and as a documentation hook for [[divergence-sweep]] H9. */
#define NET_INBOUND_BUDGET 32

/* Multicast group addresses for peer discovery. These must match the
 * Python reference (network.py:31-32) so the two implementations join the
 * same groups by default; otherwise C and Python peers cannot see each
 * other's multicast traffic. The v4 address sits in the admin-scoped
 * 239/8 block; the v6 address is a randomly generated organization-local
 * address. Operators can still override via configuration. */
#define DEFAULT_MCAST4_ADDR "239.0.0.65"
#define DEFAULT_MCAST6_ADDR "ff00::41e9:dddc:e4c7:e7e7"

typedef struct
{
    smrt_ptr_t;
    /* data from json */
    int port;
    char mac_address[MAC_ADDR_LEN + 1];
    char ip4_cidr[CIDR4_LEN + 1];
    char mcast4_addr[IPV4_ADDR_LEN + 1];
    char ip6_cidr[CIDR6_LEN + 1];
    char mcast6_addr[IPV6_ADDR_LEN + 1];
} network_config_t;

/** Which layer supplied the base port a node is running on. */
typedef enum {
    PORT_SRC_CONFIG  = 0,  /**< network_config_t.port was non-zero. */
    PORT_SRC_ENV     = 1,  /**< AT_COMM_PORT supplied it. */
    PORT_SRC_DEFAULT = 2,  /**< Nothing did; COMM_PORT. */
} net_port_source_t;

/**
 * @brief Resolve the base port a node communicates on.
 *
 * Resolution order: a non-zero @p cfg_port (the provisioned config always
 * wins) → the AT_COMM_PORT environment variable (operator override, applied
 * only where the config is silent) → COMM_PORT. The environment value is read
 * once and cached, matching the other AT_* overrides in this tree
 * (generate.c AT_TRANSPORT, net_proc.c AT_MYSTERY_MAX_AGE_SEC,
 * configuration.c AT_SERIALIZE_MODE).
 *
 * An AT_COMM_PORT that is unparseable or outside [COMM_PORT_MIN,
 * COMM_PORT_MAX] is refused with a warning and the default kept — never a
 * silent 0. The result is always a bindable base, and base + 1 (the derived
 * encrypted-group port) is always in range.
 *
 * @param cfg_port  network_config_t.port, or 0/negative when unset.
 * @param src       Optional out-param: which layer supplied the result.
 * @param logger    Optional; used to report a refused AT_COMM_PORT.
 * @return the resolved base port, in [COMM_PORT_MIN, COMM_PORT_MAX].
 */
/*@
  requires src == \null || \valid(src);
  ensures \result >= COMM_PORT_MIN && \result <= COMM_PORT_MAX;
  ensures cfg_port >= COMM_PORT_MIN && cfg_port <= COMM_PORT_MAX
          ==> \result == cfg_port;
*/
int net_port_resolve(int cfg_port, net_port_source_t *src, logger_t *logger);

/**
 * @brief Human-readable name of a port source, for logs.
 */
/*@
  assigns \nothing;
  ensures \result != \null;
*/
const char *net_port_source_name(net_port_source_t src);

/** Which layer supplied a network tunable. */
typedef enum {
    KNOB_SRC_ENV     = 0,  /**< An AT_NET_* / AT_MYSTERY_* override supplied it. */
    KNOB_SRC_DEFAULT = 1,  /**< Nothing did; the compile-time default. */
} net_knob_source_t;

/**
 * @brief Human-readable name of a tunable's source, for logs.
 */
/*@
  assigns \nothing;
  ensures \result != \null;
*/
const char *net_knob_source_name(net_knob_source_t src);

/**
 * @brief Resolve the three network tunables from the environment.
 *
 * Resolution order is env → compile-time default, the same two-layer shape and
 * the same refusal rules as net_port_resolve's env layer: read once and cached,
 * strictly parsed (no trailing garbage), range-checked, and a bad value refused
 * with a warning while the default is kept. These exist because the knobs used
 * to be overridable class attributes in Python and bare macros in C, so a
 * deployment could tune one runtime and not the other (doc/architecture/networking.md).
 *
 * There is deliberately NO config layer: unlike the base port, these are
 * operational tuning rather than provisioned identity, and adding them to
 * network.cfg.json would widen the config wire form for a knob an operator sets
 * on a node, not on a fleet.
 *
 * @param src     Optional out-param: which layer supplied the result.
 * @param logger  Optional; used to report a refused override.
 * @return the resolved value, always within the knob's documented range.
 */
/*@
  requires src == \null || \valid(src);
  ensures \result >= NET_ANNOY_LIMIT_MIN && \result <= NET_ANNOY_LIMIT_MAX;
*/
int net_annoy_limit_resolve(net_knob_source_t *src, logger_t *logger);

/*@
  requires src == \null || \valid(src);
  ensures \result >= NET_RECV_POLL_MS_MIN && \result <= NET_RECV_POLL_MS_MAX;
*/
int net_recv_poll_ms_resolve(net_knob_source_t *src, logger_t *logger);

/*@
  requires src == \null || \valid(src);
  ensures \result >= NET_MYSTERY_MAX_AGE_SEC_MIN &&
          \result <= NET_MYSTERY_MAX_AGE_SEC_MAX;
*/
int net_mystery_max_age_resolve(net_knob_source_t *src, logger_t *logger);

/*@
  requires src == \null || \valid(src);
  ensures \result >= NET_CONN_IDLE_TTL_SEC_MIN &&
          \result <= NET_CONN_IDLE_TTL_SEC_MAX;
*/
int net_conn_idle_ttl_resolve(net_knob_source_t *src, logger_t *logger);

/*@
  requires src == \null || \valid(src);
  ensures \result >= NET_MAX_LIVE_CONNS_MIN &&
          \result <= NET_MAX_LIVE_CONNS_MAX;
*/
int net_max_live_conns_resolve(net_knob_source_t *src, logger_t *logger);

/** Default envelope encoding for a group this node MINTS (doc/architecture/network-wire-format.md).
 *  JSON, because a group's format is what all its members must speak and JSON
 *  is the one every AT node can read; a deployment opts a new cohort into proto
 *  with AT_NET_WIRE_MODE=proto. Mirrors Python system.default_net_wire_mode. */
#define NET_WIRE_MODE_DEFAULT NET_WIRE_JSON

/**
 * @brief Envelope encoding for a group this node mints, from AT_NET_WIRE_MODE.
 *
 * This knob does NOT decide what goes on the wire for an existing group -- that
 * comes from the group itself (@c group_t::wire_format), which is what keeps a
 * cohort consistent and why there is no per-message override. It decides only
 * what a NEW group is stamped with, so an operator stands up a proto cohort by
 * setting it on the node that forms the group; every joiner adopts it at
 * admission.
 *
 * Named values rather than numbers ("json" / "proto"), matching Python's
 * AT_NET_WIRE_MODE. Refusal discipline is the numeric knobs': an unrecognized
 * value is reported and the default kept. Case-insensitive, because an operator
 * writing "Proto" means proto and silently falling back to JSON there would
 * look like this whole path simply not happening.
 *
 * Mirrors Python system.resolve_net_wire_mode.
 */
/*@
  requires src == \null || \valid(src);
*/
net_wire_format_t net_wire_mode_resolve(net_knob_source_t *src, logger_t *logger);

/**
 * @brief Split a CIDR string into its address and prefix-length parts.
 *
 * The output lengths are EXPLICIT because callers legitimately differ: the IPv4
 * helpers pass @c char[IPV4_ADDR_LEN] (16) while the IPv6 helper and both socket
 * transports pass @c char[IPV6_ADDR_LEN] (46). This used to be a hard-coded
 * @c snprintf(addr, IPV4_ADDR_LEN, ...) plus @c snprintf(mask, 3, ...), which
 * silently truncated every IPv6 input -- measured: a 38-char address became 15
 * chars and a "/128" prefix became "12", and because the prefix 12 passes the
 * family sanity check, @ref cidr6_to_ip6_binary returned SUCCESS with the wrong
 * mask. Widening the hard-coded length was not an option: it would have
 * overflowed the 16-byte callers.
 *
 * Truncation is an ERROR (@ref ENET_ADDR_TOO_LONG), not a silent shortening. A
 * truncated address or prefix is not a usable approximation of anything.
 *
 * @param[in]  cidr      "address" or "address/prefix"; not modified.
 * @param[out] addr      Receives the address part, always NUL-terminated.
 * @param[in]  addr_len  sizeof the @p addr buffer; must be non-zero.
 * @param[out] mask      Receives the prefix digits, or untouched when @p cidr
 *                       carries no '/' (a missing prefix is acceptable). May be
 *                       NULL to discard.
 * @param[in]  mask_len  sizeof the @p mask buffer; ignored when @p mask is NULL.
 *                       Must be >= 4 to represent an IPv6 "128".
 * @return 0 on success, non-zero on a NULL/empty input, a zero-length buffer, or
 *         truncation of either field.
 */
/*@
  requires cidr != \null && \valid_read(cidr);
  requires addr != \null && \valid(addr + (0 .. addr_len - 1));
  requires addr_len > 0;
  requires mask == \null || \valid(mask + (0 .. mask_len - 1));
  assigns addr[0 .. addr_len - 1];
  behavior success:
    ensures \result == 0;
  behavior failure:
    ensures \result != 0;
  disjoint behaviors;
*/
int cidr_split(char *cidr, char *addr, size_t addr_len,
               char *mask, size_t mask_len);

/*@
  requires cidr != \null && \valid_read(cidr);
  requires \valid(ip);
  requires \valid(mask);
  assigns *ip, *mask;
  behavior success:
    ensures \result == 0;
    ensures *mask <= 32;
  behavior failure:
    ensures \result != 0;
  disjoint behaviors;
*/
int cidr4_to_ip4_binary(char *cidr, uint32_t *ip, uint8_t *mask);

/*@
  requires \valid(addr + (0 .. IPV4_ADDR_LEN - 1));
  assigns addr[0 .. IPV4_ADDR_LEN - 1];
  behavior success:
    ensures \result == 0;
  behavior failure:
    ensures \result != 0;
  disjoint behaviors;
*/
int ip4_binary_to_addr(uint32_t ip, char *addr);

/*@
  requires cidr != \null && \valid_read(cidr);
  requires \valid(bcast_addr + (0 .. IPV4_ADDR_LEN - 1));
  assigns bcast_addr[0 .. IPV4_ADDR_LEN - 1];
  behavior success:
    ensures \result == 0;
  behavior failure:
    ensures \result != 0;
  disjoint behaviors;
*/
int cidr4_to_broadcast(char *cidr, char *bcast_addr);

#ifdef __FRAMAC__
typedef struct { uint64_t lo; uint64_t hi; } uint128_t;
#else
typedef unsigned __int128 uint128_t;
#endif

/*@
  requires cidr != \null && \valid_read(cidr);
  requires \valid(ip);
  requires \valid(mask);
  assigns *ip, *mask;
  behavior success:
    ensures \result == 0;
    ensures *mask <= 128;
  behavior failure:
    ensures \result != 0;
  disjoint behaviors;
*/
int cidr6_to_ip6_binary(char *cidr, uint128_t *ip, uint8_t *mask);

/*@
  requires \valid(addr + (0 .. IPV6_ADDR_LEN - 1));
  assigns addr[0 .. IPV6_ADDR_LEN - 1];
  behavior success:
    ensures \result == 0;
  behavior failure:
    ensures \result != 0;
  disjoint behaviors;
*/
int ip6_binary_to_addr(uint128_t ip, char *addr);

int network_to_json(const void *data_struct, json_t **obj_ptr);
int network_from_json(const json_t *obj, void *data_struct);

#include "utilities/exception.h"

#define ENET_INVALID_MASK 220
DECLARE_ERROR(ENET_INVALID_MASK, "CIDR prefix length exceeds maximum for address family");
#define ENET_ADDR_TOO_LONG 221
DECLARE_ERROR(ENET_ADDR_TOO_LONG, "CIDR address or prefix does not fit the caller's buffer");


/** @} */ /* end of internal_network */

#endif  // NETWORK_H
