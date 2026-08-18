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
 * @file net_transport_tcp.c
 * @brief TCP (IPv4 + IPv6) implementations of the net_transport_t vtable.
 *
 * Wire frame is a 4-byte network-byte-order (big-endian) unsigned length
 * prefix followed by exactly that many bytes of payload. This matches the
 * Python reference's `struct.pack('!I', len(msg))` framing so the two
 * implementations can interoperate over TCP. Each send opens a short-lived
 * connection to the target.
 *
 * The receive side holds accepted connections OPEN between frames (since
 * 2026-08-10): a sender with connection pooling on -- Python's AT_NET_POOL,
 * on by default -- writes many frames down one connection, and a receiver
 * that closes after the first turns the sender's next write into a silent
 * loss (the write succeeds into a half-closed socket; the RST arrives after
 * send() returns; see doc/architecture/network-connection-pooling.md). Each recv() call
 * therefore serves the
 * connections already held first, then accepts at most one new one. Held
 * connections are bounded by AT_NET_CONN_IDLE_TTL and AT_NET_MAX_CONNS,
 * the same knobs and defaults Python uses.
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
#include <time.h>
#include <unistd.h>

#include "net_transport_priv.h"
#include "utilities/exception.h"
#include "utilities/socket_helpers.h"
#include "utilities/util.h"
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
                       const char *host, int port, bool ipv6,
                       const char *src_addr, logger_t *logger)
{
    int sock = socket(ipv6 ? AF_INET6 : AF_INET, SOCK_STREAM, 0);
    if (sock == -1)
        return SYS_EXCEPTION();

    /* Connect FROM the address peers know us by, else they cannot attribute the
     * frame. stream=true so IP_BIND_ADDRESS_NO_PORT defers port selection to
     * connect() -- this path opens one connection per message, and reserving a
     * port per send would exhaust the ephemeral range. Non-fatal. */
    (void)net_transport_ip_bind_source(sock, src_addr,
                                       ipv6 ? AF_INET6 : AF_INET, true, logger);

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

    /* 4-byte network-byte-order length prefix (matches Python tcp.py:106:
     * `sock.send(struct.pack('!I', len(msg)))`). NET_MSG_MAX_DATA on this
     * side is 1 MB, well under UINT32_MAX, so the cast is safe. */
    uint32_t hdr_be = htonl((uint32_t)msg_len);
    if (send_all(sock, &hdr_be, sizeof(hdr_be)) != 0) {
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
/**
 * Read ONE framed message from an already-connected socket.
 *
 * Distinguishes an orderly close from a failure, because they mean different
 * things to the caller and only one of them is worth a log line: a peer that
 * hangs up between frames is normal (Python raises PeerDisconnect here and
 * logs at debug). The socket is left OPEN in every case; the caller owns it.
 *
 * @return 0 with @p buf_out/@p buf_len set; ENOTCONN on an orderly close
 *         before any byte of a frame; ENOMSG if nothing was readable yet;
 *         an EXCEPTION code on a real error or a malformed length prefix.
 */
static int tcp_read_frame(int sock, uint8_t **buf_out, size_t *buf_len)
{
    /* Read 4-byte big-endian length prefix (matches Python tcp.py:
     * `struct.unpack('!I', size_data)[0]`). Loop until 4 bytes are in hand
     * because a single recv() may return short. */
    uint8_t hdr_buf[4];
    size_t hdr_got = 0;
    while (hdr_got < sizeof(hdr_buf)) {
        ssize_t n = at_recv_eintr(sock, hdr_buf + hdr_got,
                                  sizeof(hdr_buf) - hdr_got, 0);
        if (n == 0)
            return ENOTCONN;  /* orderly close (mid-prefix counts: nothing usable) */
        if (n < 0) {
            if ((errno == EAGAIN || errno == EWOULDBLOCK) && hdr_got == 0)
                return ENOMSG;  /* idle between frames, no partial frame lost */
            return EXCEPTION(ENET_RECV);
        }
        hdr_got += (size_t)n;
    }
    uint32_t hdr_be;
    memcpy(&hdr_be, hdr_buf, sizeof(hdr_be));
    size_t data_size = (size_t)ntohl(hdr_be);
    if (data_size == 0 || data_size > NET_MSG_MAX_DATA)
        return EXCEPTION(ENET_RECV);

    uint8_t *data = malloc(data_size);
    if (data == NULL)
        return SYS_EXCEPTION();

    size_t total = 0;
    while (total < data_size) {
        size_t chunk = data_size - total;
        if (chunk > (size_t)TCP_CHUNK_SIZE)
            chunk = TCP_CHUNK_SIZE;
        ssize_t n = at_recv_eintr(sock, data + total, chunk, 0);
        if (n <= 0) {
            free(data);
            return EXCEPTION(ENET_RECV);
        }
        total += (size_t)n;
    }

    *buf_out = data;
    *buf_len = data_size;
    return 0;
}

/* ---------- Live inbound connections ---------- */

static void tcp_conn_drop(net_transport_ctx_t *ctx, int slot)
{
    if (ctx->live_conns[slot].fd >= 0)
        close(ctx->live_conns[slot].fd);
    ctx->live_conns[slot].fd = -1;
}

static int tcp_conn_count(const net_transport_ctx_t *ctx)
{
    int n = 0;
    for (int i = 0; i < TCP_MAX_LIVE_CONNS; i++)
        if (ctx->live_conns[i].fd >= 0)
            n++;
    return n;
}

/* Close connections that have gone quiet longer than the TTL, so an idle or
 * vanished peer does not hold a descriptor (and a slot) indefinitely. */
static void tcp_reap_idle(net_transport_ctx_t *ctx)
{
    time_t now = time(NULL);
    for (int i = 0; i < TCP_MAX_LIVE_CONNS; i++) {
        if (ctx->live_conns[i].fd < 0)
            continue;
        if (now - ctx->live_conns[i].last_used >= (time_t)ctx->conn_idle_ttl) {
            log_debug(ctx->logger, "TCP: closing idle connection from %s\n",
                      ctx->live_conns[i].peer);
            tcp_conn_drop(ctx, i);
        }
    }
}

/**
 * Take the next frame from a connection we are already holding open.
 *
 * @return 0 with a frame, or ENOMSG when no held connection on this channel
 *         has one ready.
 */
static int tcp_service_live(net_transport_ctx_t *ctx, net_channel_t channel,
                            uint8_t **out_buf, size_t *out_len,
                            char *peer_addr_out, size_t peer_addr_len)
{
    for (int i = 0; i < TCP_MAX_LIVE_CONNS; i++) {
        if (ctx->live_conns[i].fd < 0 || ctx->live_conns[i].channel != channel)
            continue;

        struct pollfd pfd = { .fd = ctx->live_conns[i].fd, .events = POLLIN };
        int ready = at_poll_eintr(&pfd, 1, 0);
        if (ready <= 0)
            continue;
        if ((pfd.revents & (POLLERR | POLLNVAL)) != 0) {
            tcp_conn_drop(ctx, i);
            continue;
        }

        int err = tcp_read_frame(ctx->live_conns[i].fd, out_buf, out_len);
        if (err == 0) {
            ctx->live_conns[i].last_used = time(NULL);
            if (peer_addr_out != NULL)
                at_strlcpy(peer_addr_out, ctx->live_conns[i].peer, peer_addr_len);
            return 0;
        }
        if (err == ENOMSG)
            continue;  /* POLLIN with no complete frame yet: try again later */
        if (err == ENOTCONN)
            log_debug(ctx->logger, "TCP: peer %s disconnected\n",
                      ctx->live_conns[i].peer);
        tcp_conn_drop(ctx, i);
    }
    return ENOMSG;
}

/**
 * Accept a new connection and read its first frame, KEEPING the connection
 * for subsequent frames.
 *
 * Holding it open is the whole point: a pooled sender writes many frames down
 * one connection, and closing after the first loses the sender's next write
 * silently (doc/architecture/network-connection-pooling.md).
 */
/* Frama-C: skipped —
 * [syscall] all socket-touching functions: send/recv/connect/setsockopt/close
 * stubs have no WP-usable specs; the accept/read/close sequence also cascades
 * terminates_part.
 */
static int tcp_accept_new(net_transport_ctx_t *ctx, net_channel_t channel,
                          int listen_sock, uint8_t **out_buf, size_t *out_len,
                          char *peer_addr_out, size_t peer_addr_len,
                          int timeout_ms)
{
    struct pollfd pfd = { .fd = listen_sock, .events = POLLIN };
    int ready = at_poll_eintr(&pfd, 1, timeout_ms);
    if (ready == 0)
        return ENOMSG;
    if (ready < 0)
        return SYS_EXCEPTION();

    char from_addr[IPV6_ADDR_LEN] = {0};
    int client;
    if (ctx->ipv6) {
        struct sockaddr_in6 sender = {0};
        socklen_t slen = sizeof(sender);
        client = accept(listen_sock, (struct sockaddr *)&sender, &slen);
        if (client >= 0)
            inet_ntop(AF_INET6, &sender.sin6_addr, from_addr, sizeof(from_addr));
    } else {
        struct sockaddr_in sender = {0};
        socklen_t slen = sizeof(sender);
        client = accept(listen_sock, (struct sockaddr *)&sender, &slen);
        if (client >= 0)
            inet_ntop(AF_INET, &sender.sin_addr, from_addr, sizeof(from_addr));
    }
    if (client < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK)
            return ENOMSG;
        return SYS_EXCEPTION();
    }

    /* Cap live connections, so a peer opening many cannot exhaust our
     * descriptors. Mirrors Python's max_conns drop in _accept_loop. */
    int slot = -1;
    for (int i = 0; i < TCP_MAX_LIVE_CONNS; i++) {
        if (ctx->live_conns[i].fd < 0) {
            slot = i;
            break;
        }
    }
    if (slot < 0 || tcp_conn_count(ctx) >= ctx->max_live_conns) {
        log_warn(ctx->logger,
                 "TCP: refusing connection from %s -- already holding %d "
                 "(AT_NET_MAX_CONNS)\n", from_addr, ctx->max_live_conns);
        close(client);
        return ENOMSG;
    }

    /* Bound the per-frame reads on this connection the same way the listener
     * is bounded, so a peer that stalls mid-frame cannot hold the loop. */
    (void)at_set_rcvtimeo(client, timeout_ms, ctx->logger);

    int err = tcp_read_frame(client, out_buf, out_len);
    if (err != 0) {
        if (err != ENOTCONN && err != ENOMSG)
            log_debug(ctx->logger, "TCP: first frame from %s failed\n", from_addr);
        close(client);
        return ENOMSG;
    }

    ctx->live_conns[slot].fd = client;
    ctx->live_conns[slot].channel = channel;
    ctx->live_conns[slot].last_used = time(NULL);
    at_strlcpy(ctx->live_conns[slot].peer, from_addr,
               sizeof(ctx->live_conns[slot].peer));
    if (peer_addr_out != NULL)
        at_strlcpy(peer_addr_out, from_addr, peer_addr_len);
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

    /* calloc left every slot's fd at 0, which is stdin -- a real descriptor.
     * Free slots are -1. */
    for (int i = 0; i < TCP_MAX_LIVE_CONNS; i++)
        ctx->live_conns[i].fd = -1;
    ctx->conn_idle_ttl = net_conn_idle_ttl_resolve(NULL, params->logger);
    ctx->max_live_conns = net_max_live_conns_resolve(NULL, params->logger);
    if (ctx->max_live_conns > TCP_MAX_LIVE_CONNS)
        ctx->max_live_conns = TCP_MAX_LIVE_CONNS;

    char addr_buf[IPV6_ADDR_LEN] = {0};
    if (ipv6) {
        cidr_split((char *)params->net_cfg->ip6_cidr, addr_buf,
                   sizeof(addr_buf), NULL, 0);
    } else {
        cidr_split((char *)params->net_cfg->ip4_cidr, addr_buf,
                   sizeof(addr_buf), NULL, 0);
    }
    const char *address = (addr_buf[0] != '\0') ? addr_buf : NULL;
    /* Cache for tcp_send_to, so an outbound connection's source address is the
     * one we accept on and peers can attribute it. */
    at_strlcpy(ctx->local_addr, addr_buf, sizeof(ctx->local_addr));

    int port = params->port_base;
    int grp_port = port + 1;

    /* SO_REUSEADDR on both listeners, and it costs nothing: TCP grants it only
     * over a socket in TIME_WAIT, never over a live LISTEN, so a second node
     * on this addr:port still fails EADDRINUSE. What it buys is a restart that
     * does not have to wait out TIME_WAIT on the previous run's connections. */
    if (net_transport_ip_bind(&ctx->cfg, address, port, true, true,
                              &ctx->recv_ptp, params->logger) != 0)
        goto fail;
    log_info(params->logger, "Bound peer recv to %s:%d (TCP)\n",
             address ? address : "*", port);

    if (net_transport_ip_bind(&ctx->cfg, address, grp_port, true, true,
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
    return tcp_send_to(wire, wire_len, target, port, ctx->ipv6,
                       ctx->local_addr, ctx->logger);
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

    tcp_reap_idle(ctx);

    /* Connections we already hold come first: a pooled sender's later frames
     * arrive there, and serving them before accept() keeps a busy peer from
     * being starved by a stream of new connections. */
    int err = tcp_service_live(ctx, channel, out_buf, out_len,
                               peer_addr_out, peer_addr_len);
    if (err != ENOMSG)
        return err;

    return tcp_accept_new(ctx, channel, sock, out_buf, out_len,
                          peer_addr_out, peer_addr_len, timeout_ms);
}

/* Frama-C: skipped —
 * [syscall] all socket-touching functions: send/recv/connect/setsockopt/ close stubs have
 * no WP-usable specs. tcp_accept_and_read also has terminates_part cascade through the
 * accept/read/close sequence.
 */
static void tcp_close(net_transport_ctx_t *ctx)
{
    if (ctx == NULL) return;
    for (int i = 0; i < TCP_MAX_LIVE_CONNS; i++)
        tcp_conn_drop(ctx, i);
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
    .net_proto      = NETPROTO_IPV4,
    .open           = tcp4_open,
    .send_unicast   = tcp_send_unicast,
    .send_broadcast = tcp_send_broadcast,
    .recv           = tcp_recv,
    .close          = tcp_close,
    .link_class_ms  = tcp_link_class_ms,
};

const net_transport_t tcp_ip6_transport = {
    .name           = "tcp_net_6",
    .net_proto      = NETPROTO_IPV6,
    .open           = tcp6_open,
    .send_unicast   = tcp_send_unicast,
    .send_broadcast = tcp_send_broadcast,
    .recv           = tcp_recv,
    .close          = tcp_close,
    .link_class_ms  = tcp_link_class_ms,
};
