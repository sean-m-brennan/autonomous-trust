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

#ifndef NET_TRANSPORT_PRIV_H
#define NET_TRANSPORT_PRIV_H

/**
 * @file net_transport_priv.h
 * @brief Private types shared between net_proc.c and socket-family
 * transports (UDP, TCP).  Not part of the public net_transport.h
 * interface — DTN transports or other exotic implementations should
 * not pull these in.
 */

#include <stdbool.h>
#include <sys/socket.h>

#include "network/net_transport.h"
#include "utilities/logger.h"

#define UDP_PACKET_SIZE 65507
#define TCP_CHUNK_SIZE  2048

/** Socket creation parameters: maps directly to socket(2) arguments. */
typedef struct {
    int domain;    /**< AF_INET | AF_INET6 */
    int type;      /**< SOCK_DGRAM | SOCK_STREAM */
    int protocol;  /**< IPPROTO_UDP | 0 (TCP) */
} socket_cfg_t;

/** Socket-family transport context — owned by UDP/TCP implementations.
 *
 *  Three bound sockets (one per logical channel) plus the network_config
 *  pointer for CIDR/mcast lookups and the logger. */
struct net_transport_ctx_s {
    socket_cfg_t cfg;
    int recv_ptp;
    int recv_grp;
    int recv_cast;
    const network_config_t *net_cfg;
    logger_t *logger;
    bool ipv6;
    /** This node's own address, exactly as derived for the recv binds in
     *  udp_open_common / tcp_open_common. Cached at open so the send paths pin
     *  the SAME string they listen on, and so cidr_split's strdup stays off the
     *  per-send hot path. Empty when the address could not be derived, in which
     *  case the send paths transmit unbound (the historical behavior). */
    char local_addr[IPV6_ADDR_LEN];
};

/** Shared bind helper used by both UDP and TCP transports — opens a socket,
 *  sets SO_REUSEADDR, binds to address:port. For TCP, also calls listen(). */
int net_transport_ip_bind(const socket_cfg_t *cfg, const char *address,
                          int port, bool listen_sock, int *out_fd,
                          logger_t *logger);

/** Pin an outbound socket's SOURCE address before it sends or connects.
 *
 *  AT binds its recv sockets to the node's configured address but historically
 *  left the send sockets unbound, so the kernel chose the source from the route
 *  to the destination. Any node with more than one candidate source address
 *  (loopback aliases, multi-homed hosts, containers on several networks) then
 *  transmitted from an address its peers do not hold in their listing, and
 *  attribution -- which keys on the datagram's source -- missed every frame.
 *  Mirrors Python's network/udp.py bind_source_address.
 *
 *  Always binds port 0 and NEVER sets SO_REUSEADDR: the recv sockets hold
 *  (local_addr, comm_port) WITH SO_REUSEADDR, and the kernel grants a second
 *  socket that same addr:port only when both set it -- so omitting it here is
 *  precisely what stops autobind from selecting the port this node listens on.
 *
 *  @param stream  TCP: also sets IP_BIND_ADDRESS_NO_PORT where available, so
 *                 pinning the ADDRESS does not reserve a port ahead of
 *                 connect() and 4-tuple uniqueness is preserved.
 *  @return 0 if the source was pinned, -1 otherwise. A failure is NOT fatal:
 *          the caller should send anyway (losing attribution, as before) rather
 *          than take the node off the air over a bad address.
 */
int net_transport_ip_bind_source(int sock, const char *address, int domain,
                                 bool stream, logger_t *logger);

/** Join a multicast group on an already-bound socket. */
int net_transport_ip_join_mcast(int sock, bool ipv6, const char *mcast_address,
                                int port, logger_t *logger);

#endif /* NET_TRANSPORT_PRIV_H */
