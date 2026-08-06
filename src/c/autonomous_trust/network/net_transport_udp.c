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
 * @file net_transport_udp.c
 * @brief UDP (IPv4 + IPv6) implementations of the net_transport_t vtable.
 *
 * Two transports exposed: `udp_net_4` and `udp_net_6`. Each opens three
 * UDP sockets (peer / group / bcast) and services the three logical
 * channels via recvfrom() with SO_RCVTIMEO.
 */

#define _XOPEN_SOURCE 700
#define _DEFAULT_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

#include "net_transport_priv.h"
#include "utilities/exception.h"
#include "utilities/socket_helpers.h"
#include "utilities/util.h"
#include "network/network.h"

/* Whether to use mcast for the bcast channel vs. IPv4 broadcast. Matches
 * the flag historically in net_proc.c — kept constant here for now. */
static const bool use_mcast = false;

/* Frama-C: skipped —
 * [syscall] all socket-touching functions: sendto/recvfrom/setsockopt/ close stubs; same
 * pattern as tcp. open_common also hits cidr_split.
 */
static int udp_send(int sock, const uint8_t *msg, size_t msg_len,
                    const char *host, int port, bool ipv6, logger_t *logger)
{
    /* Bounded send timeout so a stalled NIC / full kernel buffer cannot
     * wedge the sender. */
    (void)at_set_sndtimeo(sock, 1000, logger);

    size_t send_len = msg_len;
    if (send_len > (size_t)UDP_PACKET_SIZE) {
        log_warn(logger, "UDP message truncated from %zu to %d bytes\n",
                 msg_len, UDP_PACKET_SIZE);
        send_len = UDP_PACKET_SIZE;
    }

    ssize_t sent;
    if (ipv6) {
        struct sockaddr_in6 addr = {0};
        addr.sin6_family = AF_INET6;
        addr.sin6_port = htons(port);
        if (inet_pton(AF_INET6, host, &addr.sin6_addr) <= 0)
            return EXCEPTION(EINVAL);
        sent = at_sendto_eintr(sock, msg, send_len, 0,
                               (struct sockaddr *)&addr, sizeof(addr));
    } else {
        struct sockaddr_in addr = {0};
        addr.sin_family = AF_INET;
        addr.sin_port = htons(port);
        if (inet_pton(AF_INET, host, &addr.sin_addr) <= 0)
            return EXCEPTION(EINVAL);
        sent = at_sendto_eintr(sock, msg, send_len, 0,
                               (struct sockaddr *)&addr, sizeof(addr));
    }
    if (sent <= 0)
        return EXCEPTION(ENET_SEND);
    return 0;
}

/* Socket picker for recv. */
static int channel_sock(net_transport_ctx_t *ctx, net_channel_t ch)
{
    switch (ch) {
    case NET_CHAN_PEER:      return ctx->recv_ptp;
    case NET_CHAN_BROADCAST: return ctx->recv_cast;
    case NET_CHAN_GROUP:     return ctx->recv_grp;
    case NET_CHAN__COUNT:    break;
    }
    return -1;
}

/* ---------- Vtable methods ---------- */

/* Frama-C: skipped —
 * [syscall] all socket-touching functions: sendto/recvfrom/setsockopt/ close stubs; same
 * pattern as tcp. open_common also hits cidr_split.
 */
static int udp_open_common(net_transport_ctx_t **out_ctx,
                           const net_transport_params_t *params,
                           bool ipv6)
{
    net_transport_ctx_t *ctx = calloc(1, sizeof(*ctx));
    if (ctx == NULL)
        return SYS_EXCEPTION();
    ctx->cfg.domain   = ipv6 ? AF_INET6 : AF_INET;
    ctx->cfg.type     = SOCK_DGRAM;
    ctx->cfg.protocol = IPPROTO_UDP;
    ctx->net_cfg      = params->net_cfg;
    ctx->logger       = params->logger;
    ctx->ipv6         = ipv6;
    ctx->recv_ptp = ctx->recv_grp = ctx->recv_cast = -1;

    char addr_buf[IPV6_ADDR_LEN] = {0};
    if (ipv6) {
        cidr_split((char *)params->net_cfg->ip6_cidr, addr_buf,
                   sizeof(addr_buf), NULL, 0);
    } else {
        cidr_split((char *)params->net_cfg->ip4_cidr, addr_buf,
                   sizeof(addr_buf), NULL, 0);
    }
    const char *address = (addr_buf[0] != '\0') ? addr_buf : NULL;
    /* Cache for the send paths, so a frame's source address is the one we are
     * listening on and peers can attribute it. */
    at_strlcpy(ctx->local_addr, addr_buf, sizeof(ctx->local_addr));

    int port = params->port_base;
    int grp_port = port + 1;

    /* Peer-to-peer recv socket */
    if (net_transport_ip_bind(&ctx->cfg, address, port, false,
                              &ctx->recv_ptp, params->logger) != 0)
        goto fail;
    log_info(params->logger, "Bound peer recv to %s:%d (UDP)\n",
             address ? address : "*", port);

    /* Group recv socket */
    if (net_transport_ip_bind(&ctx->cfg, address, grp_port, false,
                              &ctx->recv_grp, params->logger) != 0)
        goto fail;
    log_info(params->logger, "Bound group recv to %s:%d (UDP)\n",
             address ? address : "*", grp_port);

    /* Broadcast / mcast recv socket */
    if (use_mcast) {
        const char *mcast = ipv6 ? params->net_cfg->mcast6_addr
                                 : params->net_cfg->mcast4_addr;
        if (net_transport_ip_bind(&ctx->cfg, mcast, port, false,
                                  &ctx->recv_cast, params->logger) != 0)
            goto fail;
        if (net_transport_ip_join_mcast(ctx->recv_cast, ipv6, mcast, port,
                                        params->logger) != 0)
            goto fail;
    } else {
        if (ipv6) {
            log_error(params->logger, "IPv6 Anycast not implemented\n");
            goto fail;
        }
        char bcast_address[IPV4_ADDR_LEN];
        cidr4_to_broadcast((char *)params->net_cfg->ip4_cidr, bcast_address);
        if (net_transport_ip_bind(&ctx->cfg, bcast_address, port, false,
                                  &ctx->recv_cast, params->logger) != 0)
            goto fail;
    }

    *out_ctx = ctx;
    return 0;

fail:
    if (ctx->recv_ptp  > 0) close(ctx->recv_ptp);
    if (ctx->recv_grp  > 0) close(ctx->recv_grp);
    if (ctx->recv_cast > 0) close(ctx->recv_cast);
    free(ctx);
    return -1;
}

static int udp4_open(net_transport_ctx_t **out_ctx, const net_transport_params_t *p)
{ return udp_open_common(out_ctx, p, false); }

static int udp6_open(net_transport_ctx_t **out_ctx, const net_transport_params_t *p)
{ return udp_open_common(out_ctx, p, true); }

/* Frama-C: skipped —
 * [syscall] all socket-touching functions: sendto/recvfrom/setsockopt/ close stubs; same
 * pattern as tcp. open_common also hits cidr_split.
 */
static int udp_send_unicast(net_transport_ctx_t *ctx,
                            const uint8_t *wire, size_t wire_len,
                            const char *target, int port)
{
    /* Open a fresh transient socket per send — mirrors legacy behavior and
     * sidesteps state issues with the recv socket being bound to the peer port. */
    int sock = socket(ctx->cfg.domain, SOCK_DGRAM, IPPROTO_UDP);
    if (sock == -1)
        return SYS_EXCEPTION();
    int one = 1;
    setsockopt(sock, SOL_SOCKET, SO_BROADCAST, &one, sizeof(one));
    /* Transmit FROM the address peers know us by, else they cannot attribute
     * the frame. Non-fatal: send anyway if it could not be pinned. */
    (void)net_transport_ip_bind_source(sock, ctx->local_addr, ctx->cfg.domain,
                                       false, ctx->logger);
    int ret = udp_send(sock, wire, wire_len, target, port, ctx->ipv6, ctx->logger);
    close(sock);
    return ret;
}

/* Frama-C: skipped —
 * [syscall] all socket-touching functions: sendto/recvfrom/setsockopt/ close stubs; same
 * pattern as tcp. open_common also hits cidr_split.
 */
static int udp_send_broadcast(net_transport_ctx_t *ctx, net_channel_t channel,
                              const uint8_t *wire, size_t wire_len, int port)
{
    if (channel == NET_CHAN_PEER)
        return -1;

    const char *target = NULL;
    char bcast_buf[IPV4_ADDR_LEN] = {0};
    if (channel == NET_CHAN_BROADCAST) {
        if (use_mcast) {
            target = ctx->ipv6 ? ctx->net_cfg->mcast6_addr
                               : ctx->net_cfg->mcast4_addr;
        } else {
            if (ctx->ipv6)
                return -1;  /* no IPv6 broadcast */
            cidr4_to_broadcast((char *)ctx->net_cfg->ip4_cidr, bcast_buf);
            target = bcast_buf;
        }
    } else { /* NET_CHAN_GROUP */
        target = ctx->ipv6 ? ctx->net_cfg->mcast6_addr
                           : ctx->net_cfg->mcast4_addr;
    }
    if (target == NULL || target[0] == '\0')
        return -1;

    int sock = socket(ctx->cfg.domain, SOCK_DGRAM, IPPROTO_UDP);
    if (sock == -1)
        return SYS_EXCEPTION();
    int one = 1;
    setsockopt(sock, SOL_SOCKET, SO_BROADCAST, &one, sizeof(one));
    /* Also what makes our own broadcast recognisable as ours: the receive path
     * discards a frame whose source matches this node, and we receive our own
     * broadcast on the cast socket. */
    (void)net_transport_ip_bind_source(sock, ctx->local_addr, ctx->cfg.domain,
                                       false, ctx->logger);
    int ret = udp_send(sock, wire, wire_len, target, port, ctx->ipv6, ctx->logger);
    close(sock);
    return ret;
}

/* Frama-C: skipped —
 * [syscall] all socket-touching functions: sendto/recvfrom/setsockopt/ close stubs; same
 * pattern as tcp. open_common also hits cidr_split.
 */
static int udp_recv(net_transport_ctx_t *ctx, net_channel_t channel,
                    uint8_t **out_buf, size_t *out_len,
                    char *peer_addr_out, size_t peer_addr_len,
                    int timeout_ms)
{
    int sock = channel_sock(ctx, channel);
    if (sock < 0)
        return -1;

    (void)at_set_rcvtimeo(sock, timeout_ms, ctx->logger);

    uint8_t *buf = malloc(UDP_PACKET_SIZE);
    if (buf == NULL)
        return SYS_EXCEPTION();

    ssize_t nbytes;
    if (ctx->ipv6) {
        struct sockaddr_in6 sender = {0};
        socklen_t slen = sizeof(sender);
        nbytes = at_recvfrom_eintr(sock, buf, UDP_PACKET_SIZE, 0,
                                   (struct sockaddr *)&sender, &slen);
        if (nbytes > 0 && peer_addr_out != NULL)
            inet_ntop(AF_INET6, &sender.sin6_addr, peer_addr_out, peer_addr_len);
    } else {
        struct sockaddr_in sender = {0};
        socklen_t slen = sizeof(sender);
        nbytes = at_recvfrom_eintr(sock, buf, UDP_PACKET_SIZE, 0,
                                   (struct sockaddr *)&sender, &slen);
        if (nbytes > 0 && peer_addr_out != NULL)
            inet_ntop(AF_INET, &sender.sin_addr, peer_addr_out, peer_addr_len);
    }

    if (nbytes < 0) {
        free(buf);
        if (errno == EAGAIN || errno == EWOULDBLOCK)
            return ENOMSG;
        return SYS_EXCEPTION();
    }

    *out_buf = buf;
    *out_len = (size_t)nbytes;
    return 0;
}

/* Frama-C: skipped —
 * [syscall] all socket-touching functions: sendto/recvfrom/setsockopt/ close stubs; same
 * pattern as tcp. open_common also hits cidr_split.
 */
static void udp_close(net_transport_ctx_t *ctx)
{
    if (ctx == NULL) return;
    if (ctx->recv_ptp  > 0) close(ctx->recv_ptp);
    if (ctx->recv_grp  > 0) close(ctx->recv_grp);
    if (ctx->recv_cast > 0) close(ctx->recv_cast);
    free(ctx);
}

/* ---------- Exported transport descriptors ---------- */

/* Socket transport: assume a fast LAN by default. Overridden by operators
 * running over WAN by bumping the timeout multiplier rather than the
 * per-link estimate. */
static int udp_link_class_ms(const net_transport_ctx_t *ctx, const char *target)
{
    (void)ctx; (void)target;
    return 50;
}

const net_transport_t udp_ip4_transport = {
    .name           = "udp_net_4",
    .net_proto      = NETPROTO_IPV4,
    .open           = udp4_open,
    .send_unicast   = udp_send_unicast,
    .send_broadcast = udp_send_broadcast,
    .recv           = udp_recv,
    .close          = udp_close,
    .link_class_ms  = udp_link_class_ms,
};

const net_transport_t udp_ip6_transport = {
    .name           = "udp_net_6",
    .net_proto      = NETPROTO_IPV6,
    .open           = udp6_open,
    .send_unicast   = udp_send_unicast,
    .send_broadcast = udp_send_broadcast,
    .recv           = udp_recv,
    .close          = udp_close,
    .link_class_ms  = udp_link_class_ms,
};
