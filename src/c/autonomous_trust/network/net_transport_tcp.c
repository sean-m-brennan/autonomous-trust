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
 * @file net_transport_tcp.c
 * @brief TCP (IPv4 + IPv6) implementations of the net_transport_t vtable.
 *
 * Wire frame is ASCII-size-prefixed: "<N>|<N bytes of payload>". Each send
 * opens a short-lived connection to the target; each recv accept()s once
 * per invocation and reads a single framed message.
 *
 * Broadcast/group semantics are limited over TCP (no native broadcast).
 * `send_broadcast` returns -1 for these channels; the orchestrator in
 * net_proc.c falls back to per-peer unicast sends when TCP is selected.
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
#include "network/net_message.h"

/* ---------- Low-level send/recv helpers ---------- */

static int send_all(int sock, const void *buf, size_t len)
{
    const uint8_t *p = (const uint8_t *)buf;
    size_t sent = 0;
    while (sent < len) {
        ssize_t n = at_send_eintr(sock, p + sent, len - sent, 0);
        if (n < 0)
            return -1;
        if (n == 0)
            return -1; /* peer closed */
        sent += (size_t)n;
    }
    return 0;
}

/* Frama-C: skipped —
 * [syscall] all socket-touching functions: send/recv/connect/setsockopt/ close stubs have
 * no WP-usable specs. tcp_accept_and_read also has terminates_part cascade through the
 * accept/read/close sequence.
 */
static int tcp_send_to(const uint8_t *msg, size_t msg_len,
                       const char *host, int port, bool ipv6, logger_t *logger)
{
    int sock = socket(ipv6 ? AF_INET6 : AF_INET, SOCK_STREAM, 0);
    if (sock == -1)
        return SYS_EXCEPTION();

    int err;
    if (ipv6) {
        struct sockaddr_in6 addr = {0};
        addr.sin6_family = AF_INET6;
        addr.sin6_port = htons(port);
        if (inet_pton(AF_INET6, host, &addr.sin6_addr) <= 0) {
            close(sock);
            return EXCEPTION(EINVAL);
        }
        err = connect(sock, (struct sockaddr *)&addr, sizeof(addr));
    } else {
        struct sockaddr_in addr = {0};
        addr.sin_family = AF_INET;
        addr.sin_port = htons(port);
        if (inet_pton(AF_INET, host, &addr.sin_addr) <= 0) {
            close(sock);
            return EXCEPTION(EINVAL);
        }
        err = connect(sock, (struct sockaddr *)&addr, sizeof(addr));
    }
    if (err != 0) {
        close(sock);
        return EXCEPTION(ENET_SEND);
    }

    /* Size-prefix frame: "<N>|..." */
    char size_hdr[32];
    int hdr_len = snprintf(size_hdr, sizeof(size_hdr), "%zu|", msg_len);
    if (send_all(sock, size_hdr, (size_t)hdr_len) != 0) {
        close(sock);
        return EXCEPTION(ENET_SEND);
    }

    size_t total_sent = 0;
    while (total_sent < msg_len) {
        size_t chunk = msg_len - total_sent;
        if (chunk > (size_t)TCP_CHUNK_SIZE)
            chunk = TCP_CHUNK_SIZE;
        ssize_t sent = at_send_eintr(sock, msg + total_sent, chunk, 0);
        if (sent <= 0) {
            close(sock);
            return EXCEPTION(ENET_SEND);
        }
        total_sent += (size_t)sent;
    }

    close(sock);
    log_debug(logger, "TCP sent %zu bytes to %s:%d\n", total_sent, host, port);
    return 0;
}

/* Frama-C: skipped —
 * tcp_accept_and_read also has terminates_part cascade through the accept/read/close
 * sequence.
 */
static int tcp_accept_and_read(int listen_sock, uint8_t **buf_out, size_t *buf_len,
                               char *from_addr, size_t addr_len, bool ipv6)
{
    int client;
    if (ipv6) {
        struct sockaddr_in6 sender = {0};
        socklen_t slen = sizeof(sender);
        client = accept(listen_sock, (struct sockaddr *)&sender, &slen);
        if (client >= 0 && from_addr != NULL)
            inet_ntop(AF_INET6, &sender.sin6_addr, from_addr, addr_len);
    } else {
        struct sockaddr_in sender = {0};
        socklen_t slen = sizeof(sender);
        client = accept(listen_sock, (struct sockaddr *)&sender, &slen);
        if (client >= 0 && from_addr != NULL)
            inet_ntop(AF_INET, &sender.sin_addr, from_addr, addr_len);
    }
    if (client < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK)
            return ENOMSG;
        return SYS_EXCEPTION();
    }

    /* Read "<N>|" length prefix — bounded by 31 chars so it cannot overrun. */
    char size_buf[32] = {0};
    int si = 0;
    while (si < 31) {
        char c;
        ssize_t n = at_recv_eintr(client, &c, 1, 0);
        if (n <= 0) {
            close(client);
            return EXCEPTION(ENET_RECV);
        }
        if (c == '|')
            break;
        size_buf[si++] = c;
    }
    size_t data_size = (size_t)atol(size_buf);
    if (data_size == 0 || data_size > NET_MSG_MAX_DATA) {
        close(client);
        return EXCEPTION(ENET_RECV);
    }

    uint8_t *data = malloc(data_size);
    if (data == NULL) {
        close(client);
        return SYS_EXCEPTION();
    }

    size_t total = 0;
    while (total < data_size) {
        size_t chunk = data_size - total;
        if (chunk > (size_t)TCP_CHUNK_SIZE)
            chunk = TCP_CHUNK_SIZE;
        ssize_t n = at_recv_eintr(client, data + total, chunk, 0);
        if (n <= 0) {
            free(data);
            close(client);
            return EXCEPTION(ENET_RECV);
        }
        total += (size_t)n;
    }

    close(client);
    *buf_out = data;
    *buf_len = data_size;
    return 0;
}

/* ---------- Vtable methods ---------- */

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

/* Frama-C: skipped —
 * [syscall] all socket-touching functions: send/recv/connect/setsockopt/ close stubs have
 * no WP-usable specs. tcp_accept_and_read also has terminates_part cascade through the
 * accept/read/close sequence.
 */
static int tcp_open_common(net_transport_ctx_t **out_ctx,
                           const net_transport_params_t *params, bool ipv6)
{
    net_transport_ctx_t *ctx = calloc(1, sizeof(*ctx));
    if (ctx == NULL)
        return SYS_EXCEPTION();
    ctx->cfg.domain   = ipv6 ? AF_INET6 : AF_INET;
    ctx->cfg.type     = SOCK_STREAM;
    ctx->cfg.protocol = 0;
    ctx->net_cfg      = params->net_cfg;
    ctx->logger       = params->logger;
    ctx->ipv6         = ipv6;
    ctx->recv_ptp = ctx->recv_grp = ctx->recv_cast = -1;

    char addr_buf[IPV6_ADDR_LEN] = {0};
    if (ipv6) {
        cidr_split((char *)params->net_cfg->ip6_cidr, addr_buf, NULL);
    } else {
        cidr_split((char *)params->net_cfg->ip4_cidr, addr_buf, NULL);
    }
    const char *address = (addr_buf[0] != '\0') ? addr_buf : NULL;

    int port = params->port_base;
    int grp_port = port + 1;

    if (net_transport_ip_bind(&ctx->cfg, address, port, true,
                              &ctx->recv_ptp, params->logger) != 0)
        goto fail;
    log_info(params->logger, "Bound peer recv to %s:%d (TCP)\n",
             address ? address : "*", port);

    if (net_transport_ip_bind(&ctx->cfg, address, grp_port, true,
                              &ctx->recv_grp, params->logger) != 0)
        goto fail;
    log_info(params->logger, "Bound group recv to %s:%d (TCP)\n",
             address ? address : "*", grp_port);

    /* TCP has no native broadcast — recv_cast left as -1; send_broadcast
     * returns -1 so net_proc.c falls back to per-peer unicast. */

    *out_ctx = ctx;
    return 0;

fail:
    if (ctx->recv_ptp > 0) close(ctx->recv_ptp);
    if (ctx->recv_grp > 0) close(ctx->recv_grp);
    free(ctx);
    return -1;
}

static int tcp4_open(net_transport_ctx_t **out_ctx, const net_transport_params_t *p)
{ return tcp_open_common(out_ctx, p, false); }

static int tcp6_open(net_transport_ctx_t **out_ctx, const net_transport_params_t *p)
{ return tcp_open_common(out_ctx, p, true); }

static int tcp_send_unicast(net_transport_ctx_t *ctx,
                            const uint8_t *wire, size_t wire_len,
                            const char *target, int port)
{
    return tcp_send_to(wire, wire_len, target, port, ctx->ipv6, ctx->logger);
}

static int tcp_send_broadcast(net_transport_ctx_t *ctx, net_channel_t channel,
                              const uint8_t *wire, size_t wire_len, int port)
{
    (void)ctx; (void)wire; (void)wire_len; (void)port; (void)channel;
    /* Not supported: caller (net_proc.c) falls back to per-peer unicast. */
    return -1;
}

/* Frama-C: skipped —
 * [syscall] all socket-touching functions: send/recv/connect/setsockopt/ close stubs have
 * no WP-usable specs. tcp_accept_and_read also has terminates_part cascade through the
 * accept/read/close sequence.
 */
static int tcp_recv(net_transport_ctx_t *ctx, net_channel_t channel,
                    uint8_t **out_buf, size_t *out_len,
                    char *peer_addr_out, size_t peer_addr_len,
                    int timeout_ms)
{
    int sock = channel_sock(ctx, channel);
    if (sock < 0)
        return ENOMSG;  /* no socket for this channel on TCP — treat as empty */

    (void)at_set_rcvtimeo(sock, timeout_ms, ctx->logger);

    return tcp_accept_and_read(sock, out_buf, out_len,
                               peer_addr_out, peer_addr_len, ctx->ipv6);
}

/* Frama-C: skipped —
 * [syscall] all socket-touching functions: send/recv/connect/setsockopt/ close stubs have
 * no WP-usable specs. tcp_accept_and_read also has terminates_part cascade through the
 * accept/read/close sequence.
 */
static void tcp_close(net_transport_ctx_t *ctx)
{
    if (ctx == NULL) return;
    if (ctx->recv_ptp > 0) close(ctx->recv_ptp);
    if (ctx->recv_grp > 0) close(ctx->recv_grp);
    free(ctx);
}

/* ---------- Exported transport descriptors ---------- */

static int tcp_link_class_ms(const net_transport_ctx_t *ctx, const char *target)
{
    (void)ctx; (void)target;
    /* TCP's reliability guarantees come at the cost of a handshake + ACK
     * round-trip; bias the estimate slightly higher than UDP's. */
    return 100;
}

const net_transport_t tcp_ip4_transport = {
    .name           = "tcp_net_4",
    .open           = tcp4_open,
    .send_unicast   = tcp_send_unicast,
    .send_broadcast = tcp_send_broadcast,
    .recv           = tcp_recv,
    .close          = tcp_close,
    .link_class_ms  = tcp_link_class_ms,
};

const net_transport_t tcp_ip6_transport = {
    .name           = "tcp_net_6",
    .open           = tcp6_open,
    .send_unicast   = tcp_send_unicast,
    .send_broadcast = tcp_send_broadcast,
    .recv           = tcp_recv,
    .close          = tcp_close,
    .link_class_ms  = tcp_link_class_ms,
};
