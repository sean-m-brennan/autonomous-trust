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

/* Per-peer duplicate-broadcast threshold before demotion. Mirrors
 * Python NetworkProcess.annoy_limit (netprocess.py:90). The pest-tracking
 * map IS wired into the C receive path — net_proc.c:287 compares against
 * this constant to set over_limit. Note the tunability divergence: Python
 * exposes annoy_limit as an overridable class attribute, C has only this
 * macro (see ISSUES.md, tunable-on-one-side entry). */
#define NET_ANNOY_LIMIT 5

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

/*@
  requires cidr != \null && \valid_read(cidr);
  requires addr != \null && \valid(addr + (0 .. IPV4_ADDR_LEN - 1));
  requires mask == \null || \valid(mask + (0 .. 2));
  assigns addr[0 .. IPV4_ADDR_LEN - 1];
  behavior success:
    ensures \result == 0;
  behavior failure:
    ensures \result != 0;
  disjoint behaviors;
*/
int cidr_split(char * cidr, char *addr, char *mask);

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


/** @} */ /* end of internal_network */

#endif  // NETWORK_H
