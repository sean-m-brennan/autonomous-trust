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
 * @file dtn_backend_ud3tn.c
 * @brief uD3TN (d3tn GmbH) Bundle Protocol backend using AAP v1.
 *
 * Implements the dtn_backend_t vtable against uD3TN's legacy AAP v1 framing
 * — plain binary over a Unix-domain or TCP socket, no protobuf dependency.
 * Wire format per `doc/ud3tn_aap.md` in the uD3TN repo:
 *
 *   0x12 REGISTER    eid_len:u16_be | eid_bytes
 *   0x13 SENDBUNDLE  eid_len:u16_be | dst_eid | payload_len:u64_be | payload
 *   0x14 RECVBUNDLE  eid_len:u16_be | src_eid | payload_len:u64_be | payload
 *   0x10 ACK / 0x11 NACK / 0x15 SENDCONFIRM: single byte
 *
 * Multi-endpoint support: each AAP v1 connection registers exactly one
 * agent-id, so N endpoints means N sockets and N reader threads. Readers
 * tag inbound bundles with the service-suffix of their endpoint before
 * pushing to a shared FIFO; recv() consumes the FIFO regardless of which
 * endpoint the bundle arrived at. The first endpoint is the "primary" —
 * all outbound sends use its socket, so the daemon reports the primary
 * EID as the bundle source.
 *
 * Connection target is read from the AT_DTN_UD3TN_SOCKET environment
 * variable:
 *   unix:/path/to/ud3tn.aap.socket   (default: unix:./ud3tn.aap.socket)
 *   tcp:host:port                    (e.g. tcp:127.0.0.1:4242)
 *
 * Limitations:
 *   - AAP v1 has no bundle-lifetime field in SENDBUNDLE; the daemon
 *     applies its configured default. Our lifetime parameter is logged
 *     but not transmitted.
 */

#define _XOPEN_SOURCE 700
#define _DEFAULT_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/un.h>
#include <unistd.h>

#include "network/dtn/dtn_backend.h"
#include "network/dtn/dtn_eid.h"

#define AAP_ACK         0x10
#define AAP_NACK        0x11
#define AAP_REGISTER    0x12
#define AAP_SENDBUNDLE  0x13
#define AAP_RECVBUNDLE  0x14
#define AAP_SENDCONFIRM 0x15
#define AAP_PING        0x18

#define AAP_MAX_PAYLOAD   (16u * 1024u * 1024u)
#define INBOUND_QUEUE_CAP 64
#define MAX_ENDPOINTS     4  /* peer/bcast/group + slack for future channels */

typedef struct ud3tn_bundle_s {
    uint8_t *payload;
    size_t   len;
    char     src_eid[DTN_EID_MAX + 1];
    char     service[DTN_EID_MAX + 1];
    struct ud3tn_bundle_s *next;
} ud3tn_bundle_t;

/* Per-endpoint state: one AAP connection + one reader thread. */
typedef struct endpoint_s {
    int fd;
    char eid[DTN_EID_MAX + 1];
    char service[DTN_EID_MAX + 1];
    pthread_t reader;
    bool reader_running;
} endpoint_t;

static struct {
    endpoint_t eps[MAX_ENDPOINTS];
    size_t n_eps;
    logger_t *logger;

    pthread_mutex_t q_lock;
    pthread_cond_t  q_cond;
    ud3tn_bundle_t *q_head;
    ud3tn_bundle_t *q_tail;
    size_t q_len;

    /* Send path: only the primary-endpoint reader thread reads from the
     * primary fd. A sender writes its SENDBUNDLE frame under send_lock,
     * then blocks on send_reply_cond waiting for the reader to decode
     * the next SENDCONFIRM/NACK and publish a status. This avoids the
     * two-reader race that would otherwise exist on the primary fd. */
    pthread_mutex_t send_lock;
    pthread_cond_t  send_reply_cond;
    bool            send_reply_pending;
    int             send_reply_status;  /* 0=ok, -1=NACK, -2=socket error */

    bool stop;
} g = {
    .q_lock = PTHREAD_MUTEX_INITIALIZER,
    .q_cond = PTHREAD_COND_INITIALIZER,
    .send_lock = PTHREAD_MUTEX_INITIALIZER,
    .send_reply_cond = PTHREAD_COND_INITIALIZER,
};

/* ---------- socket helpers ---------- */

static int read_exact(int fd, void *buf, size_t n)
{
    uint8_t *p = buf;
    size_t got = 0;
    while (got < n) {
        ssize_t r = read(fd, p + got, n - got);
        if (r == 0) return -1;
        if (r < 0) {
            if (errno == EINTR) continue;
            return -1;
        }
        got += (size_t)r;
    }
    return 0;
}

static int write_exact(int fd, const void *buf, size_t n)
{
    const uint8_t *p = buf;
    size_t sent = 0;
    while (sent < n) {
        ssize_t w = write(fd, p + sent, n - sent);
        if (w < 0) {
            if (errno == EINTR) continue;
            return -1;
        }
        sent += (size_t)w;
    }
    return 0;
}

static int connect_unix(const char *path)
{
    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) return -1;
    struct sockaddr_un addr = {0};
    addr.sun_family = AF_UNIX;
    if (strlen(path) >= sizeof(addr.sun_path)) {
        close(fd);
        errno = ENAMETOOLONG;
        return -1;
    }
    snprintf(addr.sun_path, sizeof(addr.sun_path), "%s", path);
    if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        close(fd);
        return -1;
    }
    return fd;
}

static int connect_tcp(const char *host, const char *port)
{
    struct addrinfo hints = {0}, *res = NULL;
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    if (getaddrinfo(host, port, &hints, &res) != 0)
        return -1;
    int fd = -1;
    for (struct addrinfo *ai = res; ai != NULL; ai = ai->ai_next) {
        fd = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
        if (fd < 0) continue;
        if (connect(fd, ai->ai_addr, ai->ai_addrlen) == 0) break;
        close(fd);
        fd = -1;
    }
    freeaddrinfo(res);
    return fd;
}

/* Parse AT_DTN_UD3TN_SOCKET forms:
 *   unix:/path
 *   tcp:host:port
 * Anything else is treated as a Unix path (backwards-compatible default). */
static int open_backend_socket(const char *url, logger_t *logger)
{
    if (url == NULL || url[0] == '\0')
        url = "unix:./ud3tn.aap.socket";

    if (strncmp(url, "unix:", 5) == 0) {
        int fd = connect_unix(url + 5);
        if (fd < 0)
            log_error(logger, "DTN[ud3tn]: connect(unix:%s): %s\n",
                      url + 5, strerror(errno));
        return fd;
    }
    if (strncmp(url, "tcp:", 4) == 0) {
        const char *rest = url + 4;
        const char *colon = strrchr(rest, ':');
        if (colon == NULL || colon == rest) {
            log_error(logger, "DTN[ud3tn]: malformed tcp: URL '%s'\n", url);
            errno = EINVAL;
            return -1;
        }
        size_t host_len = (size_t)(colon - rest);
        const char *host_start = rest;
        size_t hl = host_len;
        if (hl >= 2 && host_start[0] == '[' && host_start[hl - 1] == ']') {
            host_start++;
            hl -= 2;
        }
        char host[256];
        if (hl >= sizeof(host)) {
            errno = ENAMETOOLONG;
            return -1;
        }
        memcpy(host, host_start, hl);
        host[hl] = '\0';
        int fd = connect_tcp(host, colon + 1);
        if (fd < 0)
            log_error(logger, "DTN[ud3tn]: connect(tcp:%s:%s): %s\n",
                      host, colon + 1, strerror(errno));
        return fd;
    }
    return connect_unix(url);
}

/* ---------- AAP frame helpers ---------- */

static int aap_write_u16(int fd, uint16_t v)
{
    uint16_t be = htons(v);
    return write_exact(fd, &be, 2);
}

static int aap_read_u16(int fd, uint16_t *out)
{
    uint16_t be;
    if (read_exact(fd, &be, 2) != 0) return -1;
    *out = ntohs(be);
    return 0;
}

static int aap_write_u64(int fd, uint64_t v)
{
    uint8_t be[8];
    for (int i = 7; i >= 0; i--) { be[i] = (uint8_t)(v & 0xff); v >>= 8; }
    return write_exact(fd, be, 8);
}

static int aap_read_u64(int fd, uint64_t *out)
{
    uint8_t be[8];
    if (read_exact(fd, be, 8) != 0) return -1;
    uint64_t v = 0;
    for (int i = 0; i < 8; i++) v = (v << 8) | be[i];
    *out = v;
    return 0;
}

static int aap_send_register(int fd, const char *eid, logger_t *logger)
{
    size_t eid_len = strlen(eid);
    if (eid_len > UINT16_MAX) {
        log_error(logger, "DTN[ud3tn]: REGISTER EID too long (%zu)\n", eid_len);
        errno = EMSGSIZE;
        return -1;
    }
    uint8_t type = AAP_REGISTER;
    if (write_exact(fd, &type, 1) != 0 ||
        aap_write_u16(fd, (uint16_t)eid_len) != 0 ||
        write_exact(fd, eid, eid_len) != 0)
        return -1;

    uint8_t resp;
    if (read_exact(fd, &resp, 1) != 0) return -1;
    if (resp != AAP_ACK) {
        log_error(logger, "DTN[ud3tn]: REGISTER(%s) returned 0x%02x (expected ACK)\n",
                  eid, resp);
        return -1;
    }
    return 0;
}

/* Write-only helper: push a SENDBUNDLE frame on @p fd. The reply will
 * arrive asynchronously on the same fd and is consumed by the primary
 * endpoint's reader thread (see read_one_frame()). Caller must hold
 * g.send_lock so only one frame is in flight at a time. */
static int aap_write_sendbundle_frame(int fd, const char *dst_eid,
                                      const uint8_t *payload, size_t payload_len)
{
    size_t eid_len = strlen(dst_eid);
    if (eid_len > UINT16_MAX || payload_len > AAP_MAX_PAYLOAD) {
        errno = EMSGSIZE;
        return -1;
    }
    uint8_t type = AAP_SENDBUNDLE;
    if (write_exact(fd, &type, 1) != 0 ||
        aap_write_u16(fd, (uint16_t)eid_len) != 0 ||
        write_exact(fd, dst_eid, eid_len) != 0 ||
        aap_write_u64(fd, (uint64_t)payload_len) != 0 ||
        write_exact(fd, payload, payload_len) != 0)
        return -1;
    return 0;
}

/* ---------- queue ---------- */

static void enqueue_bundle(ud3tn_bundle_t *b)
{
    pthread_mutex_lock(&g.q_lock);
    if (g.q_len >= INBOUND_QUEUE_CAP) {
        ud3tn_bundle_t *oldest = g.q_head;
        if (oldest != NULL) {
            g.q_head = oldest->next;
            if (g.q_head == NULL) g.q_tail = NULL;
            g.q_len--;
            free(oldest->payload);
            free(oldest);
        }
    }
    b->next = NULL;
    if (g.q_tail == NULL) g.q_head = b;
    else                  g.q_tail->next = b;
    g.q_tail = b;
    g.q_len++;
    pthread_cond_signal(&g.q_cond);
    pthread_mutex_unlock(&g.q_lock);
}

/* ---------- reader thread ---------- */

typedef struct {
    size_t ep_idx;  /* index into g.eps */
} reader_arg_t;

/* NOTE: on the PRIMARY endpoint's socket the reader and senders share
 * the fd — reader reads, senders write. On all OTHER endpoints only
 * the reader uses the fd. This asymmetry is fine because AAP v1 framing
 * is half-duplex request/response for the send path (locked by
 * g.send_lock) and async-push for the receive path. The reader on the
 * primary endpoint must therefore tolerate seeing SENDCONFIRM/NACK/ACK
 * bytes — it should pass them through without treating them as frames,
 * because they are being read by the sender holding g.send_lock.
 *
 * That shared-socket model would race: the reader might consume a
 * SENDCONFIRM byte meant for the sender, or vice versa. To avoid it,
 * the primary endpoint uses a DIFFERENT socket for sends than for
 * receives when we have an inbound-only need. But AAP v1 only gives us
 * one socket per REGISTER. So the sender holds g.send_lock AND takes
 * the reader offline briefly by setting a pause flag — at which point
 * only the sender reads the sync reply. See send() below. */

/* Publish a SENDBUNDLE reply status to the sender that is blocked in
 * ud3tn_send(). No-op if no sender is currently waiting — daemon sent
 * a SENDCONFIRM we didn't expect. */
static void publish_send_reply(int status)
{
    pthread_mutex_lock(&g.send_lock);
    if (g.send_reply_pending) {
        g.send_reply_status  = status;
        g.send_reply_pending = false;
        pthread_cond_signal(&g.send_reply_cond);
    }
    pthread_mutex_unlock(&g.send_lock);
}

static int read_one_frame(int fd, const char *service, logger_t *logger)
{
    uint8_t type;
    if (read_exact(fd, &type, 1) != 0) return -1;

    switch (type) {
    case AAP_PING:
        return 0;
    case AAP_ACK:
        /* Post-REGISTER path already consumed its ACK directly. A stray
         * ACK here is benign keepalive/confirm of something else. */
        return 0;
    case AAP_SENDCONFIRM: {
        /* Followed by a uint64 bundle-id we don't need. */
        uint64_t bundle_id;
        if (aap_read_u64(fd, &bundle_id) != 0) return -1;
        publish_send_reply(0);
        return 0;
    }
    case AAP_NACK:
        log_warn(logger, "DTN[ud3tn]: SENDBUNDLE rejected by daemon (NACK)\n");
        publish_send_reply(-1);
        return 0;
    case AAP_RECVBUNDLE: {
        uint16_t eid_len;
        if (aap_read_u16(fd, &eid_len) != 0) return -1;
        if (eid_len > DTN_EID_MAX) {
            log_error(logger, "DTN[ud3tn]: RECVBUNDLE EID too long (%u)\n", eid_len);
            return -1;
        }
        char src_eid[DTN_EID_MAX + 1] = {0};
        if (eid_len > 0 && read_exact(fd, src_eid, eid_len) != 0) return -1;
        src_eid[eid_len] = '\0';

        uint64_t payload_len;
        if (aap_read_u64(fd, &payload_len) != 0) return -1;
        if (payload_len > AAP_MAX_PAYLOAD) {
            log_error(logger,
                      "DTN[ud3tn]: RECVBUNDLE payload too large (%llu)\n",
                      (unsigned long long)payload_len);
            return -1;
        }
        uint8_t *payload = NULL;
        if (payload_len > 0) {
            payload = malloc((size_t)payload_len);
            if (payload == NULL) return -1;
            if (read_exact(fd, payload, (size_t)payload_len) != 0) {
                free(payload);
                return -1;
            }
        }
        ud3tn_bundle_t *b = calloc(1, sizeof(*b));
        if (b == NULL) { free(payload); return -1; }
        b->payload = payload;
        b->len = (size_t)payload_len;
        snprintf(b->src_eid, sizeof(b->src_eid), "%s", src_eid);
        snprintf(b->service, sizeof(b->service), "%s", service);
        enqueue_bundle(b);
        return 0;
    }
    default:
        log_warn(logger, "DTN[ud3tn]: unexpected async frame 0x%02x on %s\n",
                 type, service);
        return 0;
    }
}

static void *reader_thread(void *arg)
{
    reader_arg_t *a = (reader_arg_t *)arg;
    size_t idx = a->ep_idx;
    endpoint_t *ep = &g.eps[idx];
    free(a);

    while (true) {
        pthread_mutex_lock(&g.q_lock);
        bool stop = g.stop;
        pthread_mutex_unlock(&g.q_lock);
        if (stop) break;
        if (read_one_frame(ep->fd, ep->service, g.logger) != 0) break;
    }
    pthread_mutex_lock(&g.q_lock);
    ep->reader_running = false;
    pthread_cond_broadcast(&g.q_cond);
    pthread_mutex_unlock(&g.q_lock);
    /* If we're the primary reader and a sender is waiting for a reply,
     * wake it so it sees the connection death. */
    if (idx == 0) {
        pthread_mutex_lock(&g.send_lock);
        g.send_reply_pending = false;
        g.send_reply_status = -2;
        pthread_cond_broadcast(&g.send_reply_cond);
        pthread_mutex_unlock(&g.send_lock);
    }
    return NULL;
}

/* ---------- backend vtable ---------- */

static void teardown(void)
{
    /* Wake every reader. Closing the fd is the only reliable way to
     * unblock a read() inside read_exact(). */
    pthread_mutex_lock(&g.q_lock);
    g.stop = true;
    pthread_cond_broadcast(&g.q_cond);
    pthread_mutex_unlock(&g.q_lock);

    for (size_t i = 0; i < g.n_eps; i++) {
        if (g.eps[i].fd >= 0) {
            shutdown(g.eps[i].fd, SHUT_RDWR);
        }
    }
    for (size_t i = 0; i < g.n_eps; i++) {
        if (g.eps[i].reader_running) {
            pthread_join(g.eps[i].reader, NULL);
        }
        if (g.eps[i].fd >= 0) {
            close(g.eps[i].fd);
            g.eps[i].fd = -1;
        }
    }

    pthread_mutex_lock(&g.q_lock);
    ud3tn_bundle_t *b = g.q_head;
    while (b != NULL) {
        ud3tn_bundle_t *next = b->next;
        free(b->payload);
        free(b);
        b = next;
    }
    g.q_head = g.q_tail = NULL;
    g.q_len = 0;
    pthread_mutex_unlock(&g.q_lock);

    g.n_eps = 0;
}

static int ud3tn_init(const dtn_endpoint_t *endpoints, size_t n_endpoints,
                      logger_t *logger)
{
    if (n_endpoints == 0 || n_endpoints > MAX_ENDPOINTS) {
        log_error(logger, "DTN[ud3tn]: invalid endpoint count %zu (max %d)\n",
                  n_endpoints, MAX_ENDPOINTS);
        return -1;
    }
    if (g.n_eps != 0) {
        log_warn(logger, "DTN[ud3tn]: already initialized\n");
        return -1;
    }

    g.logger = logger;
    g.stop = false;
    g.q_head = g.q_tail = NULL;
    g.q_len = 0;
    for (size_t i = 0; i < MAX_ENDPOINTS; i++) {
        g.eps[i].fd = -1;
        g.eps[i].reader_running = false;
    }

    const char *url = getenv("AT_DTN_UD3TN_SOCKET");

    /* Open + REGISTER each endpoint on its own connection. */
    for (size_t i = 0; i < n_endpoints; i++) {
        if (endpoints[i].eid == NULL || endpoints[i].service == NULL) {
            log_error(logger, "DTN[ud3tn]: endpoint[%zu] has NULL eid or service\n", i);
            teardown();
            return -1;
        }
        snprintf(g.eps[i].eid,     sizeof(g.eps[i].eid),     "%s", endpoints[i].eid);
        snprintf(g.eps[i].service, sizeof(g.eps[i].service), "%s", endpoints[i].service);
        g.eps[i].fd = open_backend_socket(url, logger);
        if (g.eps[i].fd < 0) {
            teardown();
            return -1;
        }
        if (aap_send_register(g.eps[i].fd, g.eps[i].eid, logger) != 0) {
            teardown();
            return -1;
        }
        g.n_eps = i + 1;  /* track progress so teardown cleans what we opened */
    }

    /* Spawn a reader per endpoint. */
    for (size_t i = 0; i < n_endpoints; i++) {
        reader_arg_t *a = calloc(1, sizeof(*a));
        if (a == NULL) { teardown(); return -1; }
        a->ep_idx = i;
        if (pthread_create(&g.eps[i].reader, NULL, reader_thread, a) != 0) {
            free(a);
            log_error(logger, "DTN[ud3tn]: reader spawn failed for %s: %s\n",
                      g.eps[i].eid, strerror(errno));
            teardown();
            return -1;
        }
        g.eps[i].reader_running = true;
    }

    log_info(logger, "DTN[ud3tn]: %zu endpoint(s) registered on %s\n",
             n_endpoints, url ? url : "unix:./ud3tn.aap.socket");
    for (size_t i = 0; i < n_endpoints; i++) {
        log_info(logger, "DTN[ud3tn]:   [%zu] %s -> %s\n",
                 i, g.eps[i].eid, g.eps[i].service);
    }
    return 0;
}

static void ud3tn_shutdown(void)
{
    teardown();
}

/* Sender writes the SENDBUNDLE frame then sleeps on send_reply_cond;
 * the primary reader thread decodes SENDCONFIRM/NACK off the wire and
 * publishes the status. This keeps fd reads single-owner so there is
 * no race with inbound RECVBUNDLE frames. */
static int ud3tn_send(const char *dest_eid,
                      const uint8_t *payload, size_t payload_len,
                      uint32_t lifetime_sec)
{
    (void)lifetime_sec;
    if (g.n_eps == 0 || g.eps[0].fd < 0) return -1;

    pthread_mutex_lock(&g.send_lock);
    if (aap_write_sendbundle_frame(g.eps[0].fd, dest_eid,
                                   payload, payload_len) != 0) {
        pthread_mutex_unlock(&g.send_lock);
        return -1;
    }
    g.send_reply_pending = true;
    g.send_reply_status  = -2;  /* sentinel: never updated = connection died */
    while (g.send_reply_pending && !g.stop && g.eps[0].reader_running) {
        pthread_cond_wait(&g.send_reply_cond, &g.send_lock);
    }
    int status = g.send_reply_pending ? -2 : g.send_reply_status;
    g.send_reply_pending = false;
    pthread_mutex_unlock(&g.send_lock);

    if (status != 0)
        log_warn(g.logger, "DTN[ud3tn]: SENDBUNDLE to %s failed (status=%d)\n",
                 dest_eid, status);
    return status;
}

static int ud3tn_recv(uint8_t **out_payload, size_t *out_len,
                      char *src_eid, size_t src_eid_len,
                      char *dest_service, size_t dest_service_len,
                      int timeout_ms)
{
    struct timespec deadline = {0};
    clock_gettime(CLOCK_REALTIME, &deadline);
    deadline.tv_sec  += timeout_ms / 1000;
    deadline.tv_nsec += (long)(timeout_ms % 1000) * 1000000L;
    if (deadline.tv_nsec >= 1000000000L) {
        deadline.tv_sec += 1;
        deadline.tv_nsec -= 1000000000L;
    }

    pthread_mutex_lock(&g.q_lock);
    while (g.q_head == NULL && !g.stop) {
        /* Is every reader dead? Then no more bundles will ever arrive. */
        bool any_reader_alive = false;
        for (size_t i = 0; i < g.n_eps; i++) {
            if (g.eps[i].reader_running) { any_reader_alive = true; break; }
        }
        if (!any_reader_alive) break;

        int rc = pthread_cond_timedwait(&g.q_cond, &g.q_lock, &deadline);
        if (rc == ETIMEDOUT) {
            pthread_mutex_unlock(&g.q_lock);
            return ENOMSG;
        }
    }
    if (g.q_head == NULL) {
        pthread_mutex_unlock(&g.q_lock);
        return g.stop ? -1 : ENOMSG;
    }
    ud3tn_bundle_t *b = g.q_head;
    g.q_head = b->next;
    if (g.q_head == NULL) g.q_tail = NULL;
    g.q_len--;
    pthread_mutex_unlock(&g.q_lock);

    *out_payload = b->payload;
    *out_len     = b->len;
    snprintf(src_eid,      src_eid_len,      "%s", b->src_eid);
    snprintf(dest_service, dest_service_len, "%s", b->service);
    free(b);
    return 0;
}

const dtn_backend_t dtn_backend = {
    .name     = "ud3tn",
    .init     = ud3tn_init,
    .shutdown = ud3tn_shutdown,
    .send     = ud3tn_send,
    .recv     = ud3tn_recv,
};
