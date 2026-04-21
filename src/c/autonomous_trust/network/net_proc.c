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

#define _XOPEN_SOURCE 700
#define _DEFAULT_SOURCE
#include <stdbool.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <pthread.h>
#include <errno.h>

#include "processes/processes.h"
#include "utilities/message.h"
#include "utilities/msg_types_priv.h"
#include "utilities/exception.h"
#include "utilities/logger.h"
#include "network/network.h"
#include "network/net_message.h"
#include "identity/identity.h"
#include "identity/identity_priv.h"
#include "identity/group.h"
#include "structures/data.h"

#define ENET_SEND 230
DEFINE_ERROR(ENET_SEND, "Network send failed");
#define ENET_RECV 231
DEFINE_ERROR(ENET_RECV, "Network receive failed");

const bool use_mcast = false;
static const int UDP_PACKET_SIZE = 65507;
static const int TCP_CHUNK_SIZE = 2048;

/****************************
 * Blacklist / rejected addresses
 ****************************/

#define MAX_REJECTED 256
static char rejected_addresses[MAX_REJECTED][IPV4_ADDR_LEN + 1];
static size_t rejected_count = 0;
static pthread_mutex_t rejected_lock = PTHREAD_MUTEX_INITIALIZER;

static bool reject_message(const char *address)
{
    bool found = false;
    pthread_mutex_lock(&rejected_lock);
    for (size_t i = 0; i < rejected_count; i++)
    {
        if (strcmp(rejected_addresses[i], address) == 0)
        {
            found = true;
            break;
        }
    }
    pthread_mutex_unlock(&rejected_lock);
    return found;
}

__attribute__((unused))
static void blacklist_address(const char *address)
{
    pthread_mutex_lock(&rejected_lock);
    /* Check for duplicate */
    for (size_t i = 0; i < rejected_count; i++)
    {
        if (strcmp(rejected_addresses[i], address) == 0)
        {
            pthread_mutex_unlock(&rejected_lock);
            return;
        }
    }
    if (rejected_count < MAX_REJECTED)
    {
        strncpy(rejected_addresses[rejected_count], address, IPV4_ADDR_LEN);
        rejected_addresses[rejected_count][IPV4_ADDR_LEN] = '\0';
        rejected_count++;
    }
    pthread_mutex_unlock(&rejected_lock);
}

/****************************
 * Deferred encrypted message queue (mystery handler)
 ****************************/

#define MAX_DEFERRED 64

typedef struct {
    uint8_t data[65507]; /* UDP_PACKET_SIZE */
    size_t len;
    char from_addr[IPV4_ADDR_LEN + 1];
} deferred_msg_t;

static deferred_msg_t deferred_messages[MAX_DEFERRED];
static size_t deferred_count = 0;
static pthread_mutex_t deferred_lock = PTHREAD_MUTEX_INITIALIZER;

static void defer_message(const uint8_t *data, size_t len, const char *from_addr)
{
    pthread_mutex_lock(&deferred_lock);
    if (deferred_count < MAX_DEFERRED)
    {
        size_t idx = deferred_count;
        if (len > sizeof(deferred_messages[0].data))
            len = sizeof(deferred_messages[0].data);
        memcpy(deferred_messages[idx].data, data, len);
        deferred_messages[idx].len = len;
        strncpy(deferred_messages[idx].from_addr, from_addr, IPV4_ADDR_LEN);
        deferred_messages[idx].from_addr[IPV4_ADDR_LEN] = '\0';
        deferred_count++;
    }
    pthread_mutex_unlock(&deferred_lock);
}

/****************************
 * Per-peer statistics tracking
 ****************************/

typedef struct {
    char address[ADDR_LEN + 1];   /* sized for IPv4 or IPv6 via ADDR_LEN */
    size_t bytes_sent;
    size_t bytes_recv;
    size_t send_errors;
    size_t recv_errors;
} net_stat_t;

#define MAX_STATS DEFAULT_MAX_PEERS
static net_stat_t peer_stats[MAX_STATS];
static size_t stats_count = 0;

static net_stat_t *find_or_create_stat(const char *address)
{
    for (size_t i = 0; i < stats_count; i++)
    {
        if (strcmp(peer_stats[i].address, address) == 0)
            return &peer_stats[i];
    }
    if (stats_count < MAX_STATS)
    {
        net_stat_t *st = &peer_stats[stats_count];
        memset(st, 0, sizeof(*st));
        /* snprintf truncates + NUL-terminates deterministically */
        snprintf(st->address, sizeof(st->address), "%s", address);
        stats_count++;
        return st;
    }
    return NULL;
}

static void track_send(const char *address, size_t bytes)
{
    net_stat_t *st = find_or_create_stat(address);
    if (st != NULL)
        st->bytes_sent += bytes;
}

static void track_send_error(const char *address)
{
    net_stat_t *st = find_or_create_stat(address);
    if (st != NULL)
        st->send_errors++;
}

static void track_recv(const char *address, size_t bytes)
{
    net_stat_t *st = find_or_create_stat(address);
    if (st != NULL)
        st->bytes_recv += bytes;
}

typedef struct
{
    int domain;
    int type;
    int protocol;
} socket_t;

typedef struct
{
    int level;
    int optname;
    const void *optval;
    socklen_t optlen;
} sock_opts_t;

typedef struct
{
    int recv_ptp;
    int recv_grp;
    int recv_cast;
} recvrs_t;

typedef struct
{
    socket_t *cfg;
    recvrs_t *socks;
    process_t *proc;
    directory_t *queues;
    logger_t *logger;
    network_config_t *net_cfg;
    identity_t *myself;
    bool *stop;
    int port;
    bool ipv6;
} net_thread_ctx_t;

/****************************
 * UDP send/recv
 ****************************/

static int _send_udp(const uint8_t *msg, size_t msg_len, const char *host, int port, logger_t *logger)
{
    int sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (sock == -1)
        return SYS_EXCEPTION();

    /* Required for sending to broadcast addresses */
    int one = 1;
    setsockopt(sock, SOL_SOCKET, SO_BROADCAST, &one, sizeof(one));

    /* Bounded send timeout so a stalled NIC / full kernel buffer cannot
     * wedge the sender thread.  1s is generous for LAN paths while still
     * surfacing a genuine stall as ENET_SEND below. */
    struct timeval sndto = { .tv_sec = 1, .tv_usec = 0 };
    if (setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &sndto, sizeof(sndto)) != 0)
        log_warn(logger, "UDP: failed to set SO_SNDTIMEO: %s\n", strerror(errno));

    struct sockaddr_in addr = {0};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    if (inet_pton(AF_INET, host, &addr.sin_addr) <= 0)
    {
        close(sock);
        return EXCEPTION(EINVAL);
    }

    size_t send_len = msg_len;
    if (send_len > (size_t)UDP_PACKET_SIZE)
    {
        log_warn(logger, "UDP message truncated from %zu to %d bytes\n", msg_len, UDP_PACKET_SIZE);
        send_len = UDP_PACKET_SIZE;
    }

    ssize_t sent = sendto(sock, msg, send_len, 0,
                          (struct sockaddr *)&addr, sizeof(addr));
    close(sock);
    if (sent <= 0)
        return EXCEPTION(ENET_SEND);

    return 0;
}

static int _recv_udp(int sock, uint8_t *buf, size_t buf_size,
                     char *from_addr, size_t addr_len, int *from_port)
{
    struct sockaddr_in sender = {0};
    socklen_t slen = sizeof(sender);

    ssize_t numbytes = recvfrom(sock, buf, buf_size, 0,
                                (struct sockaddr *)&sender, &slen);
    if (numbytes < 0)
    {
        if (errno == EAGAIN || errno == EWOULDBLOCK)
            return ENOMSG;
        return SYS_EXCEPTION();
    }

    if (from_addr != NULL)
        inet_ntop(AF_INET, &sender.sin_addr, from_addr, addr_len);
    if (from_port != NULL)
        *from_port = ntohs(sender.sin_port);

    return (int)numbytes;
}

/****************************
 * TCP send/recv
 ****************************/

/* Loop until `len` bytes are sent or an unrecoverable error occurs.
 * Retries on EINTR; returns 0 on success, -1 on permanent error. */
static int _send_all(int sock, const void *buf, size_t len)
{
    const uint8_t *p = (const uint8_t *)buf;
    size_t sent = 0;
    while (sent < len) {
        ssize_t n = send(sock, p + sent, len - sent, 0);
        if (n < 0) {
            if (errno == EINTR) continue;
            return -1;
        }
        if (n == 0) return -1;      /* peer closed */
        sent += (size_t)n;
    }
    return 0;
}

static int _send_tcp(const uint8_t *msg, size_t msg_len, const char *host, int port, logger_t *logger)
{
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock == -1)
        return SYS_EXCEPTION();

    struct sockaddr_in addr = {0};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    if (inet_pton(AF_INET, host, &addr.sin_addr) <= 0)
    {
        close(sock);
        return EXCEPTION(EINVAL);
    }

    if (connect(sock, (struct sockaddr *)&addr, sizeof(addr)) != 0)
    {
        close(sock);
        return EXCEPTION(ENET_SEND);
    }

    /* Send frame: "size|" header.  Loop-until-done via _send_all so short
     * sends under buffer pressure and EINTR don't drop the whole frame. */
    char size_hdr[32];
    int hdr_len = snprintf(size_hdr, sizeof(size_hdr), "%zu|", msg_len);
    if (_send_all(sock, size_hdr, (size_t)hdr_len) != 0)
    {
        close(sock);
        return EXCEPTION(ENET_SEND);
    }

    /* Send data in chunks. Chunking retained for any future migration to
     * non-blocking sockets; EINTR retried, short sends absorbed naturally. */
    size_t total_sent = 0;
    while (total_sent < msg_len)
    {
        size_t chunk = msg_len - total_sent;
        if (chunk > (size_t)TCP_CHUNK_SIZE)
            chunk = TCP_CHUNK_SIZE;
        ssize_t sent = send(sock, msg + total_sent, chunk, 0);
        if (sent < 0) {
            if (errno == EINTR) continue;
            close(sock);
            return EXCEPTION(ENET_SEND);
        }
        if (sent == 0) {
            close(sock);
            return EXCEPTION(ENET_SEND);
        }
        total_sent += (size_t)sent;
    }

    close(sock);
    log_debug(logger, "TCP sent %zu bytes to %s:%d\n", total_sent, host, port);
    return 0;
}

static int _recv_tcp(int listen_sock, uint8_t **buf_out, size_t *buf_len,
                     char *from_addr, size_t addr_len, int *from_port)
{
    struct sockaddr_in sender = {0};
    socklen_t slen = sizeof(sender);

    int client = accept(listen_sock, (struct sockaddr *)&sender, &slen);
    if (client < 0)
    {
        if (errno == EAGAIN || errno == EWOULDBLOCK)
            return ENOMSG;
        return SYS_EXCEPTION();
    }

    if (from_addr != NULL)
        inet_ntop(AF_INET, &sender.sin_addr, from_addr, addr_len);
    if (from_port != NULL)
        *from_port = ntohs(sender.sin_port);

    /* Read size header: bytes until '|'.  Loop is bounded by si < 31 so the
     * buffer cannot be overrun even under a malicious sender; data_size is
     * then bounded by NET_MSG_MAX_DATA below. */
    char size_buf[32] = {0};
    int si = 0;
    while (si < 31)
    {
        char c;
        ssize_t n = recv(client, &c, 1, 0);
        if (n <= 0)
        {
            close(client);
            return EXCEPTION(ENET_RECV);
        }
        if (c == '|')
            break;
        size_buf[si++] = c;
    }
    size_t data_size = (size_t)atol(size_buf);
    if (data_size == 0 || data_size > NET_MSG_MAX_DATA)
    {
        close(client);
        return EXCEPTION(ENET_RECV);
    }

    /* Read exactly data_size bytes */
    uint8_t *data = malloc(data_size);
    if (data == NULL)
    {
        close(client);
        return SYS_EXCEPTION();
    }

    size_t total = 0;
    while (total < data_size)
    {
        size_t chunk = data_size - total;
        if (chunk > (size_t)TCP_CHUNK_SIZE)
            chunk = TCP_CHUNK_SIZE;
        ssize_t n = recv(client, data + total, chunk, 0);
        if (n <= 0)
        {
            free(data);
            close(client);
            return EXCEPTION(ENET_RECV);
        }
        total += n;
    }

    close(client);
    *buf_out = data;
    *buf_len = data_size;
    return 0;
}

/****************************
 * Encrypt/decrypt helpers
 ****************************/

int net_encrypt_and_send(const identity_t *myself, const net_wire_msg_t *msg,
                         const socket_t *cfg, int port, logger_t *logger)
{
    uint8_t *wire = NULL;
    size_t wire_len = 0;
    if (net_message_to_wire(msg, myself, &wire, &wire_len) != 0)
        return -1;

    if (msg->to_whom.type == RECIPIENT_BROADCAST)
    {
        /* Broadcast: no encryption */
        int ret;
        if (cfg->type == SOCK_DGRAM)
            ret = _send_udp(wire, wire_len, msg->to_whom.target.peer.address, port, logger);
        else
            ret = _send_tcp(wire, wire_len, msg->to_whom.target.peer.address, port, logger);
        if (ret == 0)
            track_send(msg->to_whom.target.peer.address, wire_len);
        else
            track_send_error(msg->to_whom.target.peer.address);
        free(wire);
        return ret;
    }

    if (msg->encrypt && msg->to_whom.type == RECIPIENT_PEER)
    {
        /* libsodium init is idempotent; defensive per identity.c:79-94 */
        if (sodium_init() < 0)
        {
            free(wire);
            return SYS_EXCEPTION();
        }

        /* Encrypt for a specific peer */
        unsigned char nonce[crypto_box_NONCEBYTES];
        randombytes_buf(nonce, sizeof(nonce));

        msg_str_t plain = {.msg = wire, .len = wire_len};
        size_t cipher_len = wire_len + crypto_box_MACBYTES;
        unsigned char *cipher = malloc(cipher_len);
        if (cipher == NULL)
        {
            free(wire);
            return SYS_EXCEPTION();
        }

        int ret = identity_encrypt(myself, &plain, &msg->to_whom.target.peer, nonce, cipher);
        free(wire);
        if (ret != 0)
        {
            free(cipher);
            return ret;
        }

        /* Frame: nonce + ciphertext */
        size_t frame_len = sizeof(nonce) + cipher_len;
        uint8_t *frame = malloc(frame_len);
        if (frame == NULL)
        {
            free(cipher);
            return SYS_EXCEPTION();
        }
        memcpy(frame, nonce, sizeof(nonce));
        memcpy(frame + sizeof(nonce), cipher, cipher_len);
        free(cipher);

        const char *host = msg->to_whom.target.peer.address;
        if (cfg->type == SOCK_DGRAM)
            ret = _send_udp(frame, frame_len, host, port, logger);
        else
            ret = _send_tcp(frame, frame_len, host, port, logger);
        if (ret == 0)
            track_send(host, frame_len);
        else
            track_send_error(host);
        free(frame);
        return ret;
    }

    /* Unencrypted peer send */
    const char *host = msg->to_whom.target.peer.address;
    int ret;
    if (cfg->type == SOCK_DGRAM)
        ret = _send_udp(wire, wire_len, host, port, logger);
    else
        ret = _send_tcp(wire, wire_len, host, port, logger);
    if (ret == 0)
        track_send(host, wire_len);
    else
        track_send_error(host);
    free(wire);
    return ret;
}

static int decrypt_message(const identity_t *myself, const public_identity_t *peer,
                           const uint8_t *frame, size_t frame_len,
                           uint8_t **plain_out, size_t *plain_len)
{
    if (frame_len <= crypto_box_NONCEBYTES + crypto_box_MACBYTES)
        return EXCEPTION(ENET_RECV);

    const unsigned char *nonce = frame;
    const unsigned char *cipher = frame + crypto_box_NONCEBYTES;
    size_t cipher_len = frame_len - crypto_box_NONCEBYTES;
    size_t plen = cipher_len - crypto_box_MACBYTES;

    unsigned char *plain = malloc(plen);
    if (plain == NULL)
        return SYS_EXCEPTION();

    msg_str_t cmsg = {.msg = (unsigned char *)cipher, .len = cipher_len};
    int ret = identity_decrypt(myself, &cmsg, peer, nonce, plain);
    if (ret != 0)
    {
        free(plain);
        return ret;
    }

    *plain_out = plain;
    *plain_len = plen;
    return 0;
}

/****************************
 * Find peer by address
 ****************************/

static const public_identity_t *find_peer_by_address(const process_t *proc, const char *addr)
{
    /* peers[] is append-only & the underlying array is inline (never reallocated),
     * so a pointer obtained under the read lock stays valid and stable afterward. */
    peers_read_lock(proc);
    const public_identity_t *match = NULL;
    for (size_t i = 0; i < proc->protocol.num_peers; i++)
    {
        if (strcmp(proc->protocol.peers[i].address, addr) == 0)
        {
            match = &proc->protocol.peers[i];
            break;
        }
    }
    peers_read_unlock(proc);
    return match;
}

/****************************
 * Route message to process queue
 ****************************/

static int route_to_process(const net_wire_msg_t *wmsg, process_t *proc,
                            directory_t *queues, logger_t *logger)
{
    /* Build a generic_msg_t with NET_MESSAGE type.  obj/data are POINTER
     * ASSIGNMENTS, not copies — no heap-overflow possible regardless of
     * data_len.  Ownership of wmsg->data passes through to the downstream
     * queue; function is the only owned string we need to strdup/free. */
    generic_msg_t gmsg = {0};
    gmsg.type = NET_MESSAGE;
    snprintf(gmsg.info.net_msg.process, sizeof(gmsg.info.net_msg.process),
             "%s", wmsg->process);
    gmsg.info.net_msg.function = strdup(wmsg->function);
    gmsg.info.net_msg.obj = wmsg->data;
    gmsg.info.net_msg.len = wmsg->data_len;
    memcpy(&gmsg.info.net_msg.from_whom, &wmsg->from_whom, sizeof(public_identity_t));
    gmsg.info.net_msg.encrypt = wmsg->encrypt;

    /* Send to the target process queue */
    int ret = messaging_send(wmsg->process, NET_MESSAGE, &gmsg, false);
    if (ret != 0)
    {
        log_error(logger, "Failed to route message to process '%s'\n", wmsg->process);
        if (gmsg.info.net_msg.function != NULL)
            free(gmsg.info.net_msg.function);
        return ret;
    }

    log_debug(logger, "Routed %s.%s from %s\n", wmsg->process, wmsg->function,
              wmsg->from_whom.fullname);
    if (gmsg.info.net_msg.function != NULL)
        free(gmsg.info.net_msg.function);
    return 0;
}

/****************************
 * Receiver thread functions
 ****************************/

static void *peer_receiver_thread(void *arg)
{
    net_thread_ctx_t *ctx = (net_thread_ctx_t *)arg;
    uint8_t buf[UDP_PACKET_SIZE];

    struct timeval tv;
    tv.tv_sec = 0;
    tv.tv_usec = 100000; /* 0.1 seconds */
    if (setsockopt(ctx->socks->recv_ptp, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) != 0)
        log_warn(ctx->logger, "peer_receiver: SO_RCVTIMEO failed: %s\n", strerror(errno));

    while (!(*ctx->stop))
    {
        char from_addr[IPV4_ADDR_LEN] = {0};
        int from_port = 0;

        if (ctx->cfg->type == SOCK_DGRAM)
        {
            int nbytes = _recv_udp(ctx->socks->recv_ptp, buf, sizeof(buf),
                                   from_addr, sizeof(from_addr), &from_port);
            if (nbytes == ENOMSG || nbytes < 0)
                continue;

            log_debug(ctx->logger, "Network: peer_recv got %d bytes from %s\n",
                      nbytes, from_addr);

            /* Skip messages from self */
            char my_addr[IPV4_ADDR_LEN] = {0};
            cidr_split(ctx->net_cfg->ip4_cidr, my_addr, NULL);
            if (strcmp(from_addr, my_addr) == 0)
                continue;

            /* Skip messages from blacklisted addresses */
            if (reject_message(from_addr))
                continue;

            track_recv(from_addr, (size_t)nbytes);

            const public_identity_t *peer = find_peer_by_address(ctx->proc, from_addr);
            if (peer != NULL)
            {
                /* Decrypt */
                uint8_t *plain = NULL;
                size_t plain_len = 0;
                int dec_ret = decrypt_message(ctx->myself, peer, buf, nbytes, &plain, &plain_len);
                if (dec_ret == 0)
                {
                    net_wire_msg_t wmsg;
                    if (net_message_from_wire(plain, plain_len, peer, &wmsg) == 0)
                        route_to_process(&wmsg, ctx->proc, ctx->queues, ctx->logger);
                    free(plain);
                    net_wire_msg_free(&wmsg);
                }
                else
                {
                    log_error(ctx->logger, "Network: decrypt failed (%d) from peer %s\n",
                              dec_ret, from_addr);
                }
            }
            else
            {
                /* Try as unencrypted message (e.g. access_granted to unknown peer) */
                net_wire_msg_t wmsg;
                if (net_message_from_wire(buf, nbytes, NULL, &wmsg) == 0)
                {
                    strncpy(wmsg.from_whom.address, from_addr, ADDR_LEN);
                    log_debug(ctx->logger, "Network: unencrypted msg %s.%s from unknown %s\n",
                              wmsg.process, wmsg.function, from_addr);
                    route_to_process(&wmsg, ctx->proc, ctx->queues, ctx->logger);
                    net_wire_msg_free(&wmsg);
                }
                else
                {
                    /* Encrypted message from unknown peer — defer for retry */
                    log_debug(ctx->logger, "Deferred encrypted message from unknown peer %s\n", from_addr);
                    defer_message(buf, (size_t)nbytes, from_addr);
                }
            }
        }
        else
        {
            /* TCP */
            uint8_t *data = NULL;
            size_t data_len = 0;
            int ret = _recv_tcp(ctx->socks->recv_ptp, &data, &data_len,
                                from_addr, sizeof(from_addr), &from_port);
            if (ret == ENOMSG || ret < 0)
                continue;

            char my_addr[IPV4_ADDR_LEN] = {0};
            cidr_split(ctx->net_cfg->ip4_cidr, my_addr, NULL);
            if (strcmp(from_addr, my_addr) == 0)
            {
                free(data);
                continue;
            }

            const public_identity_t *peer = find_peer_by_address(ctx->proc, from_addr);
            if (peer != NULL)
            {
                uint8_t *plain = NULL;
                size_t plain_len = 0;
                if (decrypt_message(ctx->myself, peer, data, data_len, &plain, &plain_len) == 0)
                {
                    net_wire_msg_t wmsg;
                    if (net_message_from_wire(plain, plain_len, peer, &wmsg) == 0)
                        route_to_process(&wmsg, ctx->proc, ctx->queues, ctx->logger);
                    free(plain);
                    net_wire_msg_free(&wmsg);
                }
            }
            free(data);
        }
    }
    return NULL;
}

static void *broadcast_receiver_thread(void *arg)
{
    net_thread_ctx_t *ctx = (net_thread_ctx_t *)arg;
    uint8_t buf[UDP_PACKET_SIZE];

    struct timeval tv;
    tv.tv_sec = 0;
    tv.tv_usec = 100000;
    if (setsockopt(ctx->socks->recv_cast, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) != 0)
        log_warn(ctx->logger, "broadcast_receiver: SO_RCVTIMEO failed: %s\n", strerror(errno));

    while (!(*ctx->stop))
    {
        char from_addr[IPV4_ADDR_LEN] = {0};
        int from_port = 0;

        int nbytes = _recv_udp(ctx->socks->recv_cast, buf, sizeof(buf),
                               from_addr, sizeof(from_addr), &from_port);
        if (nbytes == ENOMSG || nbytes < 0)
            continue;

        char my_addr[IPV4_ADDR_LEN] = {0};
        cidr_split(ctx->net_cfg->ip4_cidr, my_addr, NULL);
        if (strcmp(from_addr, my_addr) == 0)
            continue;

        /* Skip messages from blacklisted addresses */
        if (reject_message(from_addr))
            continue;

        track_recv(from_addr, (size_t)nbytes);

        log_info(ctx->logger, "Network: broadcast received %d bytes from %s\n", nbytes, from_addr);

        /* Broadcast messages are unencrypted */
        net_wire_msg_t wmsg;
        if (net_message_from_wire(buf, nbytes, NULL, &wmsg) == 0)
        {
            log_debug(ctx->logger, "Network: broadcast msg %s.%s from %s\n",
                      wmsg.process, wmsg.function, wmsg.from_whom.fullname);
            /* Populate sender address from UDP source so recipient can respond */
            strncpy(wmsg.from_whom.address, from_addr, ADDR_LEN);
            route_to_process(&wmsg, ctx->proc, ctx->queues, ctx->logger);
        }
        else
        {
            log_error(ctx->logger, "Network: failed to deserialize broadcast from %s\n", from_addr);
        }
        net_wire_msg_free(&wmsg);
    }
    return NULL;
}

/****************************
 * Group receiver thread
 ****************************/

static void *group_receiver_thread(void *arg)
{
    net_thread_ctx_t *ctx = (net_thread_ctx_t *)arg;
    uint8_t buf[UDP_PACKET_SIZE];

    struct timeval tv;
    tv.tv_sec = 0;
    tv.tv_usec = 100000; /* 0.1 seconds */
    if (setsockopt(ctx->socks->recv_grp, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) != 0)
        log_warn(ctx->logger, "group_receiver: SO_RCVTIMEO failed: %s\n", strerror(errno));

    while (!(*ctx->stop))
    {
        char from_addr[IPV4_ADDR_LEN] = {0};
        int from_port = 0;

        if (ctx->cfg->type == SOCK_DGRAM)
        {
            int nbytes = _recv_udp(ctx->socks->recv_grp, buf, sizeof(buf),
                                   from_addr, sizeof(from_addr), &from_port);
            if (nbytes == ENOMSG || nbytes < 0)
                continue;

            log_debug(ctx->logger, "Network: group_recv got %d bytes from %s\n",
                      nbytes, from_addr);

            /* Skip messages from self */
            char my_addr[IPV4_ADDR_LEN] = {0};
            cidr_split(ctx->net_cfg->ip4_cidr, my_addr, NULL);
            if (strcmp(from_addr, my_addr) == 0)
                continue;

            /* Skip messages from blacklisted addresses */
            if (reject_message(from_addr))
                continue;

            track_recv(from_addr, (size_t)nbytes);

            /* Group messages are encrypted with the group key */
            group_t *grp = &ctx->proc->protocol.group;
            if (grp->address[0] == '\0')
            {
                log_debug(ctx->logger, "Network: group key not yet available, dropping msg from %s\n",
                          from_addr);
                continue;
            }

            /* Decrypt using group key: frame = nonce + ciphertext */
            if ((size_t)nbytes <= crypto_box_NONCEBYTES + crypto_box_MACBYTES)
            {
                log_error(ctx->logger, "Network: group message too short from %s\n", from_addr);
                continue;
            }

            const unsigned char *nonce = buf;
            const unsigned char *cipher = buf + crypto_box_NONCEBYTES;
            size_t cipher_len = (size_t)nbytes - crypto_box_NONCEBYTES;
            size_t plain_len = cipher_len - crypto_box_MACBYTES;

            unsigned char *plain = malloc(plain_len);
            if (plain == NULL)
                continue;

            msg_str_t cmsg = {.msg = (unsigned char *)cipher, .len = cipher_len};
            int dec_ret = group_decrypt(grp, &cmsg, grp, nonce, plain);
            if (dec_ret != 0)
            {
                free(plain);
                log_error(ctx->logger, "Network: group decrypt failed (%d) from %s\n",
                          dec_ret, from_addr);
                continue;
            }

            net_wire_msg_t wmsg;
            if (net_message_from_wire(plain, plain_len, NULL, &wmsg) == 0)
            {
                strncpy(wmsg.from_whom.address, from_addr, ADDR_LEN);
                route_to_process(&wmsg, ctx->proc, ctx->queues, ctx->logger);
            }
            free(plain);
            net_wire_msg_free(&wmsg);
        }
        else
        {
            /* TCP */
            uint8_t *data = NULL;
            size_t data_len = 0;
            int ret = _recv_tcp(ctx->socks->recv_grp, &data, &data_len,
                                from_addr, sizeof(from_addr), &from_port);
            if (ret == ENOMSG || ret < 0)
                continue;

            char my_addr[IPV4_ADDR_LEN] = {0};
            cidr_split(ctx->net_cfg->ip4_cidr, my_addr, NULL);
            if (strcmp(from_addr, my_addr) == 0)
            {
                free(data);
                continue;
            }

            if (reject_message(from_addr))
            {
                free(data);
                continue;
            }

            track_recv(from_addr, data_len);

            group_t *grp = &ctx->proc->protocol.group;
            if (grp->address[0] != '\0' &&
                data_len > crypto_box_NONCEBYTES + crypto_box_MACBYTES)
            {
                const unsigned char *nonce = data;
                const unsigned char *cipher = data + crypto_box_NONCEBYTES;
                size_t cipher_len = data_len - crypto_box_NONCEBYTES;
                size_t plain_len = cipher_len - crypto_box_MACBYTES;

                unsigned char *plain = malloc(plain_len);
                if (plain != NULL)
                {
                    msg_str_t cmsg = {.msg = (unsigned char *)cipher, .len = cipher_len};
                    if (group_decrypt(grp, &cmsg, grp, nonce, plain) == 0)
                    {
                        net_wire_msg_t wmsg;
                        if (net_message_from_wire(plain, plain_len, NULL, &wmsg) == 0)
                        {
                            strncpy(wmsg.from_whom.address, from_addr, ADDR_LEN);
                            route_to_process(&wmsg, ctx->proc, ctx->queues, ctx->logger);
                        }
                        net_wire_msg_free(&wmsg);
                    }
                    free(plain);
                }
            }
            free(data);
        }
    }
    return NULL;
}

/****************************
 * Network shutdown
 ****************************/

void network_shutdown(recvrs_t *socks)
{
    if (socks->recv_cast > 0)
        close(socks->recv_cast);
    if (socks->recv_grp > 0)
        close(socks->recv_grp);
    if (socks->recv_ptp > 0)
        close(socks->recv_ptp);
}

/****************************
 * Network process main
 ****************************/

int network_run(socket_t *cfg, process_t *proc, directory_t *queues, queue_id_t signal, logger_t *logger, bool ipv6)
{
    recvrs_t socks = {0};
    int backlog = 5;
    network_config_t *net_cfg = (network_config_t *)proc->conf.data_struct;
    int one = 1;

    char *address = NULL;
    char addr_buf[IPV6_ADDR_LEN];
    if (ipv6) {
        cidr_split(net_cfg->ip6_cidr, addr_buf, NULL);
        address = addr_buf;
    } else {
        cidr_split(net_cfg->ip4_cidr, addr_buf, NULL);
        address = addr_buf;
    }

    struct addrinfo *res;
    struct addrinfo hints = {0};
    hints.ai_family = cfg->domain;
    hints.ai_socktype = cfg->type;
    if (address == NULL)
        hints.ai_flags = AI_PASSIVE;

    int port_num = net_cfg->port;
    if (port_num == 0)
        port_num = COMM_PORT;
    int grp_port = port_num + 1;
    char port_str[32] = {0};
    snprintf(port_str, 31, "%d", port_num);
    char grp_port_str[32] = {0};
    snprintf(grp_port_str, 31, "%d", grp_port);

    int err = getaddrinfo(address, port_str, &hints, &res);
    if (err != 0)
    {
        if (err == EAI_SYSTEM)
        {
            SYS_EXCEPTION();
            log_exception(logger);
            return -1;
        }
        EXCEPTION(err);
        log_exception(logger);
        return -1;
    }
    socks.recv_ptp = socket(cfg->domain, cfg->type, cfg->protocol);
    if (socks.recv_ptp == -1)
    {
        SYS_EXCEPTION();
        log_exception(logger);
        return -1;
    }
    err = setsockopt(socks.recv_ptp, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(int));
    if (err != 0)
    {
        network_shutdown(&socks);
        SYS_EXCEPTION();
        log_exception(logger);
        return -1;
    }
    err = bind(socks.recv_ptp, res->ai_addr, res->ai_addrlen);
    if (err != 0)
    {
        network_shutdown(&socks);
        SYS_EXCEPTION();
        log_exception(logger);
        return -1;
    }
    if (SOCK_STREAM == cfg->type) {
        err = listen(socks.recv_ptp, backlog);
        if (err != 0)
        {
            network_shutdown(&socks);
            SYS_EXCEPTION();
            log_exception(logger);
            return -1;
        }
    }
    log_info(logger, "Bound peer recv to %s:%d\n", address, port_num);
    freeaddrinfo(res);

    err = getaddrinfo(address, grp_port_str, &hints, &res);
    if (err != 0)
    {
        network_shutdown(&socks);
        if (err == EAI_SYSTEM)
        {
            SYS_EXCEPTION();
            log_exception(logger);
            return -1;
        }
        EXCEPTION(err);
        log_exception(logger);
        return -1;
    }
    socks.recv_grp = socket(cfg->domain, cfg->type, cfg->protocol);
    if (socks.recv_grp == -1)
    {
        network_shutdown(&socks);
        SYS_EXCEPTION();
        log_exception(logger);
        return -1;
    }
    err = setsockopt(socks.recv_grp, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(int));
    if (err != 0)
    {
        network_shutdown(&socks);
        SYS_EXCEPTION();
        log_exception(logger);
        return -1;
    }
    err = bind(socks.recv_grp, res->ai_addr, res->ai_addrlen);
    if (err != 0)
    {
        network_shutdown(&socks);
        SYS_EXCEPTION();
        log_exception(logger);
        return -1;
    }
    if (SOCK_STREAM == cfg->type) {
        err = listen(socks.recv_grp, backlog);
        if (err != 0)
        {
            network_shutdown(&socks);
            SYS_EXCEPTION();
            log_exception(logger);
            return -1;
        }
    }
    log_info(logger, "Bound group recv to %s:%d\n", address, grp_port);
    freeaddrinfo(res);

    if (use_mcast)
    {
        char *mcast_address = NULL;
        if (ipv6)
            mcast_address = net_cfg->mcast6_addr;
        else
            mcast_address = net_cfg->mcast4_addr;

        err = getaddrinfo(mcast_address, port_str, &hints, &res);
        if (err != 0)
        {
            network_shutdown(&socks);
            if (err == EAI_SYSTEM)
            {
                SYS_EXCEPTION();
                log_exception(logger);
                return -1;
            }
            EXCEPTION(err);
            log_exception(logger);
            return -1;
        }
        socks.recv_cast = socket(cfg->domain, SOCK_DGRAM, IPPROTO_UDP);
        if (socks.recv_cast == -1)
        {
            network_shutdown(&socks);
            SYS_EXCEPTION();
            log_exception(logger);
            return -1;
        }
        err = setsockopt(socks.recv_cast, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(int));
        if (err != 0)
        {
            network_shutdown(&socks);
            SYS_EXCEPTION();
            log_exception(logger);
            return -1;
        }
        err = bind(socks.recv_cast, res->ai_addr, res->ai_addrlen);
        if (err != 0)
        {
            network_shutdown(&socks);
            SYS_EXCEPTION();
            log_exception(logger);
            return -1;
        }
        if (ipv6) {
            struct ipv6_mreq mreq6;
            memcpy(&mreq6.ipv6mr_multiaddr,
                   &((struct sockaddr_in6 *)res->ai_addr)->sin6_addr,
                   sizeof(mreq6.ipv6mr_multiaddr));
            mreq6.ipv6mr_interface = 0;
            err = setsockopt(socks.recv_cast, IPPROTO_IPV6, IPV6_JOIN_GROUP,
                             &mreq6, sizeof(mreq6));
        } else {
            struct ip_mreq mreq4;
            mreq4.imr_multiaddr = ((struct sockaddr_in *)res->ai_addr)->sin_addr;
            mreq4.imr_interface.s_addr = htonl(INADDR_ANY);
            err = setsockopt(socks.recv_cast, IPPROTO_IP, IP_ADD_MEMBERSHIP,
                             &mreq4, sizeof(mreq4));
        }
        if (err != 0) {
            network_shutdown(&socks);
            SYS_EXCEPTION();
            log_exception(logger);
            freeaddrinfo(res);
            return -1;
        }
        freeaddrinfo(res);
    }
    else
    {
        if (ipv6)
        {
            log_error(logger, "IPv6 Anycast not implemented\n");
            return EXCEPTION(EINVAL);
        }

        char bcast_address[IPV4_ADDR_LEN];
        cidr4_to_broadcast(net_cfg->ip4_cidr, bcast_address);
        err = getaddrinfo(bcast_address, port_str, &hints, &res);
        if (err != 0)
        {
            network_shutdown(&socks);
            if (err == EAI_SYSTEM)
            {
                SYS_EXCEPTION();
                log_exception(logger);
            }
            EXCEPTION(err);
            log_exception(logger);
            return -1;
        }
        socks.recv_cast = socket(cfg->domain, SOCK_DGRAM, IPPROTO_UDP);
        if (socks.recv_cast == -1)
        {
            network_shutdown(&socks);
            SYS_EXCEPTION();
            log_exception(logger);
            return -1;
        }
        err = setsockopt(socks.recv_cast, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(int));
        if (err != 0)
        {
            network_shutdown(&socks);
            SYS_EXCEPTION();
            log_exception(logger);
            return -1;
        }
        err = bind(socks.recv_cast, res->ai_addr, res->ai_addrlen);
        if (err != 0)
        {
            network_shutdown(&socks);
            SYS_EXCEPTION();
            log_exception(logger);
            return -1;
        }
        freeaddrinfo(res);
    }

    /* Get identity from configs */
    identity_t *myself = NULL;
    public_identity_t *my_public = NULL;
    data_t *id_dat = NULL;
    char id_key[] = "identity";
    if (map_get(proc->configs, id_key, &id_dat) == 0)
    {
        config_t *id_cfg = NULL;
        if (data_object_ptr(id_dat, (void **)&id_cfg) == 0 && id_cfg->data_struct != NULL)
        {
            myself = (identity_t *)id_cfg->data_struct;
            identity_publish(myself, &my_public);
        }
    }

    /* Preserve network sockets across daemonize (which closes all FDs) */
    proc->flags |= NO_CLOSE_FILES;

    /* Daemonize first, then start receiver threads in the child */
    process_ctx_t pctx = {0};
    int ret = process_setup(proc, signal, logger, &pctx);
    if (ret != 0)
    {
        network_shutdown(&socks);
        if (my_public != NULL)
            smrt_deref(my_public);
        return ret;
    }

    /* Start receiver threads (now in the daemonized child) */
    bool stop = false;
    net_thread_ctx_t thread_ctx = {
        .cfg = cfg,
        .socks = &socks,
        .proc = proc,
        .queues = queues,
        .logger = logger,
        .net_cfg = net_cfg,
        .myself = myself,
        .stop = &stop,
        .port = port_num,
        .ipv6 = ipv6,
    };

    pthread_t peer_thread, bcast_thread, grp_thread;
    pthread_create(&peer_thread, NULL, peer_receiver_thread, &thread_ctx);
    pthread_create(&bcast_thread, NULL, broadcast_receiver_thread, &thread_ctx);
    pthread_create(&grp_thread, NULL, group_receiver_thread, &thread_ctx);

    /* Network-specific message loop: handle outbound sends */
    char bcast_addr[IPV4_ADDR_LEN] = {0};
    cidr4_to_broadcast(net_cfg->ip4_cidr, bcast_addr);
    log_info(logger, "Network: ready, broadcast=%s port=%d recv_ptp=%d recv_cast=%d\n",
             bcast_addr, port_num, socks.recv_ptp, socks.recv_cast);

    while (keep_running(proc, &pctx.sig_q, logger))
    {
        sleep_until(proc, cadence);

        generic_msg_t buf = {0};
        err = messaging_recv(&buf);
        if (err == -1 || err == ENOMSG)
            continue;

        if (buf.type == NET_MESSAGE)
        {
            net_msg_t *nmsg = &buf.info.net_msg;

            /* Convert IPC net_msg_t to wire format */
            net_wire_msg_t wmsg = {0};
            snprintf(wmsg.process, sizeof(wmsg.process), "%s", nmsg->process);
            wmsg.function = nmsg->function;
            wmsg.data = nmsg->obj;
            wmsg.data_len = nmsg->len;
            wmsg.encrypt = nmsg->encrypt;

            /* Always stamp from_whom with our own identity.
             * Callers (id_proc, fleet_proc, etc.) may not populate from_whom,
             * and for unencrypted messages (e.g. access_granted) the receiver
             * needs the sender's full identity (UUID, name, keys) to register
             * it as a peer. */
            if (my_public != NULL)
                memcpy(&wmsg.from_whom, my_public, sizeof(public_identity_t));
            else
                memcpy(&wmsg.from_whom, &nmsg->from_whom, sizeof(public_identity_t));

            /* Determine broadcast vs peer from to_whom address */
            bool is_broadcast = (nmsg->to_whom.address[0] == '\0');
            if (is_broadcast)
            {
                wmsg.to_whom.type = RECIPIENT_BROADCAST;
                strncpy(wmsg.to_whom.target.peer.address, bcast_addr, ADDR_LEN);
                log_debug(logger, "Network: broadcasting %s.%s to %s\n",
                          nmsg->process, nmsg->function, bcast_addr);
            }
            else
            {
                wmsg.to_whom.type = RECIPIENT_PEER;
                memcpy(&wmsg.to_whom.target.peer, &nmsg->to_whom, sizeof(public_identity_t));
            }

            ret = net_encrypt_and_send(myself, &wmsg, cfg, port_num, logger);
            if (ret != 0)
            {
                log_error(logger, "Network: send failed for %s.%s\n", nmsg->process, nmsg->function);
                log_exception(logger);
            }
            else
            {
                log_info(logger, "Network: sent %s.%s to %s\n", nmsg->process, nmsg->function,
                         is_broadcast ? bcast_addr : nmsg->to_whom.address);
            }
        }
        else if (buf.type == PEER)
        {
            /* A new peer was accepted — add to our peer list for encrypted messaging */
            public_identity_t *new_peer = &buf.info.peer;
            peers_write_lock(proc);
            bool appended = false;
            if (new_peer->fullname[0] != '\0' && proc->protocol.num_peers < MAX_PEERS)
            {
                /* Check for duplicate */
                bool found = false;
                for (size_t i = 0; i < proc->protocol.num_peers; i++)
                {
                    if (uuid_compare(proc->protocol.peers[i].uuid, new_peer->uuid) == 0)
                    {
                        found = true;
                        break;
                    }
                }
                if (!found)
                {
                    memcpy(&proc->protocol.peers[proc->protocol.num_peers],
                           new_peer, sizeof(public_identity_t));
                    proc->protocol.num_peers++;
                    appended = true;
                }
            }
            peers_write_unlock(proc);
            if (appended)
            {
                log_info(logger, "Network: added peer %s (%s) for encrypted messaging\n",
                         new_peer->fullname, new_peer->address);

                    /* Retry deferred encrypted messages with the new peer */
                    pthread_mutex_lock(&deferred_lock);
                    size_t remaining = 0;
                    for (size_t di = 0; di < deferred_count; di++)
                    {
                        deferred_msg_t *dm = &deferred_messages[di];
                        if (strcmp(dm->from_addr, new_peer->address) == 0)
                        {
                            uint8_t *plain = NULL;
                            size_t plain_len = 0;
                            if (decrypt_message(myself, new_peer, dm->data, dm->len,
                                                &plain, &plain_len) == 0)
                            {
                                net_wire_msg_t wmsg;
                                if (net_message_from_wire(plain, plain_len, new_peer, &wmsg) == 0)
                                {
                                    route_to_process(&wmsg, proc, queues, logger);
                                    log_info(logger, "Network: replayed deferred message from %s\n",
                                             dm->from_addr);
                                }
                                free(plain);
                                net_wire_msg_free(&wmsg);
                            }
                            else
                            {
                                /* Still can't decrypt, keep it */
                                if (remaining != di)
                                    deferred_messages[remaining] = *dm;
                                remaining++;
                            }
                        }
                        else
                        {
                            if (remaining != di)
                                deferred_messages[remaining] = *dm;
                            remaining++;
                        }
                    }
                    deferred_count = remaining;
                    pthread_mutex_unlock(&deferred_lock);
            }
        }
        else
        {
            /* Non-network messages: use generic handler */
            run_message_handlers(proc, queues, buf.type, &buf);
        }
    }

    /* Cleanup */
    if (pctx.fd1 > 0)
        close(pctx.fd1);
    if (pctx.fd2 > 0)
        close(pctx.fd2);

    /* Signal threads to stop and join */
    stop = true;
    pthread_join(peer_thread, NULL);
    pthread_join(bcast_thread, NULL);
    pthread_join(grp_thread, NULL);
    network_shutdown(&socks);
    if (my_public != NULL)
        smrt_deref(my_public);

    return ret;
}

/**********/

int network_udp_ip4_run(process_t *proc, directory_t *queues, queue_id_t signal, logger_t *logger)
{
    socket_t cfg = {.domain = AF_INET, .type = SOCK_DGRAM, .protocol = IPPROTO_UDP};
    return network_run(&cfg, proc, queues, signal, logger, false);
}
DECLARE_PROCESS(network, udp_net_4, network_udp_ip4_run);

int network_udp_ip6_run(process_t *proc, directory_t *queues, queue_id_t signal, logger_t *logger)
{
    socket_t cfg = {.domain = AF_INET6, .type = SOCK_DGRAM, .protocol = IPPROTO_UDP};
    return network_run(&cfg, proc, queues, signal, logger, true);
}
DECLARE_PROCESS(network, udp_net_6, network_udp_ip6_run);

int network_tcp_ip4_run(process_t *proc, directory_t *queues, queue_id_t signal, logger_t *logger)
{
    socket_t cfg = {.domain = AF_INET, .type = SOCK_STREAM, .protocol = 0};
    return network_run(&cfg, proc, queues, signal, logger, false);
}
DECLARE_PROCESS(network, tcp_net_4, network_tcp_ip4_run);

int network_tcp_ip6_run(process_t *proc, directory_t *queues, queue_id_t signal, logger_t *logger)
{
    socket_t cfg = {.domain = AF_INET6, .type = SOCK_STREAM, .protocol = 0};
    return network_run(&cfg, proc, queues, signal, logger, true);
}
DECLARE_PROCESS(network, tcp_net_6, network_tcp_ip6_run);
