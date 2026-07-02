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
 * @file dtn_backend_ud3tnv2.c
 * @brief uD3TN (d3tn GmbH) Bundle Protocol backend using AAP 2.0.
 *
 * Implements the dtn_backend_t vtable against uD3TN's AAP 2.0 protocol.
 * Reference spec: doc/aap20.md in the uD3TN repo. Message schema is the
 * vendored proto/aap2.proto (generated to C via protobuf-c at build time).
 *
 * Wire framing (per-socket):
 *    varint(length) | AAPMessage bytes
 *    varint(length) | AAPResponse bytes
 * BundleADU is special: the protobuf message carries `payload_length`,
 * then exactly that many raw payload bytes follow on the same socket,
 * outside the protobuf envelope.
 *
 * Topology (one backend instance):
 *   - 1 SENDER connection, client-initiator (is_subscriber=false).
 *     Registered to the primary endpoint EID (endpoint[0]) so that
 *     outbound bundles carry the canonical source EID.
 *   - N SUBSCRIBER connections, one per registered endpoint
 *     (is_subscriber=true). After the handshake, the SERVER becomes
 *     the initiator and pushes incoming BundleADUs to us; a per-
 *     connection reader thread enqueues them and replies with a
 *     SUCCESS AAPResponse.
 *
 * Connection handshake (every socket):
 *   1. Server writes a bare 0x2F byte (v1-reject marker).
 *   2. Server writes varint + AAPMessage{welcome:Welcome}.
 *   3. Client writes varint + AAPResponse{status=ACK}.
 *   4. Client writes varint + AAPMessage{config:ConnectionConfig{...}}.
 *   5. Server writes varint + AAPResponse{status=SUCCESS}.
 *
 * Endpoint URL: AT_DTN_UD3TN_SOCKET (same env var as v1 backend;
 *   unix:/path or tcp:host:port). Default: unix:./ud3tn.aap2.socket.
 */

#define _XOPEN_SOURCE 700
#define _DEFAULT_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <netdb.h>
#include <netinet/in.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <time.h>
#include <unistd.h>

#include "aap2.pb-c.h"
#include "network/dtn/dtn_backend.h"
#include "network/dtn/dtn_eid.h"

#define AAP_V1_REJECT_BYTE 0x2F
#define AAP2_MAX_MESSAGE   (1u * 1024u * 1024u)   /* 1 MB protobuf envelope cap */
#define AAP2_MAX_PAYLOAD   (16u * 1024u * 1024u)
#define INBOUND_QUEUE_CAP  64
#define MAX_ENDPOINTS      4

/* ---------- Types ---------- */

typedef struct ud3tn2_bundle_s {
    uint8_t *payload;
    size_t   len;
    char     src_eid[DTN_EID_MAX + 1];
    char     service[DTN_EID_MAX + 1];
    struct ud3tn2_bundle_s *next;
} ud3tn2_bundle_t;

typedef struct subscriber_s {
    int fd;
    char eid[DTN_EID_MAX + 1];
    char service[DTN_EID_MAX + 1];
    pthread_t reader;
    bool reader_running;
} subscriber_t;

static struct {
    /* Sender connection — serial request/reply from client (us). */
    int sender_fd;
    char primary_eid[DTN_EID_MAX + 1];
    pthread_mutex_t send_lock;

    /* Subscriber connections — async push from server (daemon). */
    subscriber_t subs[MAX_ENDPOINTS];
    size_t n_subs;

    logger_t *logger;

    /* Shared inbound queue filled by subscriber readers, drained by recv(). */
    pthread_mutex_t q_lock;
    pthread_cond_t  q_cond;
    ud3tn2_bundle_t *q_head;
    ud3tn2_bundle_t *q_tail;
    size_t q_len;

    bool stop;
} g = {
    .sender_fd = -1,
    .send_lock = PTHREAD_MUTEX_INITIALIZER,
    .q_lock    = PTHREAD_MUTEX_INITIALIZER,
    .q_cond    = PTHREAD_COND_INITIALIZER,
};

/* ---------- I/O primitives ---------- */

/* Frama-C: skipped —
 * [solver-timeout] ud3tnv2_init: 7x at_logging + 3x pthread_create + getenv/snprintf
 * cascade. teardown/recv/send: logging/snprintf + socket shutdown/close (2 FDs for AAP2:
 * adu + ctrl). subscriber_reader/handle_pushed_adu: logging/snprintf in loop body.
 * do_handshake/consume_greeting: 7x at_logging cascade in protocol…
 */
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

/* Frama-C: skipped —
 * [solver-timeout] ud3tnv2_init: 7x at_logging + 3x pthread_create + getenv/snprintf
 * cascade. teardown/recv/send: logging/snprintf + socket shutdown/close (2 FDs for AAP2:
 * adu + ctrl). subscriber_reader/handle_pushed_adu: logging/snprintf in loop body.
 * do_handshake/consume_greeting: 7x at_logging cascade in protocol…
 */
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

/* Proto3 varint (LEB128, 7 bits per byte, MSB = continuation). */
/* Frama-C: skipped — varint_write/varint_read: terminates on byte-by-byte varint loops. */
static int varint_write(int fd, uint64_t v)
{
    uint8_t buf[10];
    size_t n = 0;
    while (v >= 0x80) {
        buf[n++] = (uint8_t)(v & 0x7f) | 0x80;
        v >>= 7;
    }
    buf[n++] = (uint8_t)v;
    return write_exact(fd, buf, n);
}

/* Frama-C: skipped — varint_write/varint_read: terminates on byte-by-byte varint loops. */
static int varint_read(int fd, uint64_t *out)
{
    uint64_t v = 0;
    int shift = 0;
    for (int i = 0; i < 10; i++) {
        uint8_t b;
        if (read_exact(fd, &b, 1) != 0) return -1;
        v |= ((uint64_t)(b & 0x7f)) << shift;
        if ((b & 0x80) == 0) { *out = v; return 0; }
        shift += 7;
    }
    return -1;  /* overlong — malformed */
}

/* ---------- Socket URL parsing (shared shape with v1 backend) ---------- */

/* Frama-C: skipped —
 * [solver-timeout] ud3tnv2_init: 7x at_logging + 3x pthread_create + getenv/snprintf
 * cascade. teardown/recv/send: logging/snprintf + socket shutdown/close (2 FDs for AAP2:
 * adu + ctrl). subscriber_reader/handle_pushed_adu: logging/snprintf in loop body.
 * do_handshake/consume_greeting: 7x at_logging cascade in protocol…
 */
static int connect_unix(const char *path)
{
    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) return -1;
    struct sockaddr_un addr = {0};
    addr.sun_family = AF_UNIX;
    if (strlen(path) >= sizeof(addr.sun_path)) {
        close(fd); errno = ENAMETOOLONG; return -1;
    }
    snprintf(addr.sun_path, sizeof(addr.sun_path), "%s", path);
    if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        close(fd); return -1;
    }
    return fd;
}

/* Frama-C: skipped —
 * [solver-timeout] ud3tnv2_init: 7x at_logging + 3x pthread_create + getenv/snprintf
 * cascade. teardown/recv/send: logging/snprintf + socket shutdown/close (2 FDs for AAP2:
 * adu + ctrl). subscriber_reader/handle_pushed_adu: logging/snprintf in loop body.
 * do_handshake/consume_greeting: 7x at_logging cascade in protocol…
 */
static int connect_tcp(const char *host, const char *port)
{
    struct addrinfo hints = {0}, *res = NULL;
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    if (getaddrinfo(host, port, &hints, &res) != 0) return -1;
    int fd = -1;
    for (struct addrinfo *ai = res; ai != NULL; ai = ai->ai_next) {
        fd = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
        if (fd < 0) continue;
        if (connect(fd, ai->ai_addr, ai->ai_addrlen) == 0) break;
        close(fd); fd = -1;
    }
    freeaddrinfo(res);
    return fd;
}

/* Frama-C: skipped —
 * [solver-timeout] ud3tnv2_init: 7x at_logging + 3x pthread_create + getenv/snprintf
 * cascade. teardown/recv/send: logging/snprintf + socket shutdown/close (2 FDs for AAP2:
 * adu + ctrl). subscriber_reader/handle_pushed_adu: logging/snprintf in loop body.
 * do_handshake/consume_greeting: 7x at_logging cascade in protocol…
 */
static int open_backend_socket(const char *url, logger_t *logger)
{
    if (url == NULL || url[0] == '\0')
        url = "unix:./ud3tn.aap2.socket";

    if (strncmp(url, "unix:", 5) == 0) {
        int fd = connect_unix(url + 5);
        if (fd < 0)
            log_error(logger, "DTN[ud3tnv2]: connect(unix:%s): %s\n",
                      url + 5, strerror(errno));
        return fd;
    }
    if (strncmp(url, "tcp:", 4) == 0) {
        const char *rest = url + 4;
        const char *colon = strrchr(rest, ':');
        if (colon == NULL || colon == rest) {
            log_error(logger, "DTN[ud3tnv2]: malformed tcp: URL '%s'\n", url);
            errno = EINVAL; return -1;
        }
        size_t hl = (size_t)(colon - rest);
        const char *host_start = rest;
        if (hl >= 2 && host_start[0] == '[' && host_start[hl - 1] == ']') {
            host_start++; hl -= 2;
        }
        char host[256];
        if (hl >= sizeof(host)) { errno = ENAMETOOLONG; return -1; }
        memcpy(host, host_start, hl);
        host[hl] = '\0';
        int fd = connect_tcp(host, colon + 1);
        if (fd < 0)
            log_error(logger, "DTN[ud3tnv2]: connect(tcp:%s:%s): %s\n",
                      host, colon + 1, strerror(errno));
        return fd;
    }
    return connect_unix(url);
}

/* ---------- AAP 2.0 message framing ---------- */

/* Write a complete AAPMessage to @p fd. Caller must hold any required
 * per-fd lock. Protobuf message body is encoded to a heap buffer first
 * so we can prepend its length as a varint. */
static int write_aap_message(int fd, const Aap2__AAPMessage *msg)
{
    size_t sz = aap2__aapmessage__get_packed_size(msg);
    if (sz > AAP2_MAX_MESSAGE) { errno = EMSGSIZE; return -1; }
    uint8_t *buf = malloc(sz);
    if (buf == NULL) return -1;
    size_t packed = aap2__aapmessage__pack(msg, buf);
    int rc = -1;
    if (packed == sz &&
        varint_write(fd, (uint64_t)sz) == 0 &&
        write_exact(fd, buf, sz) == 0)
        rc = 0;
    free(buf);
    return rc;
}

static int write_aap_response(int fd, Aap2__ResponseStatus status)
{
    Aap2__AAPResponse resp = AAP2__AAPRESPONSE__INIT;
    resp.response_status = status;

    size_t sz = aap2__aapresponse__get_packed_size(&resp);
    if (sz > AAP2_MAX_MESSAGE) { errno = EMSGSIZE; return -1; }
    uint8_t *buf = malloc(sz);
    if (buf == NULL) return -1;
    size_t packed = aap2__aapresponse__pack(&resp, buf);
    int rc = -1;
    if (packed == sz &&
        varint_write(fd, (uint64_t)sz) == 0 &&
        write_exact(fd, buf, sz) == 0)
        rc = 0;
    free(buf);
    return rc;
}

/* Read one varint-delimited envelope from @p fd. Returned buffer is
 * heap-allocated (caller frees); *out_len is set. Enforces size cap. */
static int read_envelope(int fd, uint8_t **out_buf, size_t *out_len)
{
    uint64_t sz;
    if (varint_read(fd, &sz) != 0) return -1;
    if (sz == 0 || sz > AAP2_MAX_MESSAGE) return -1;
    uint8_t *buf = malloc((size_t)sz);
    if (buf == NULL) return -1;
    if (read_exact(fd, buf, (size_t)sz) != 0) { free(buf); return -1; }
    *out_buf = buf;
    *out_len = (size_t)sz;
    return 0;
}

static int read_aap_message(int fd, Aap2__AAPMessage **out)
{
    uint8_t *buf = NULL; size_t len = 0;
    if (read_envelope(fd, &buf, &len) != 0) return -1;
    *out = aap2__aapmessage__unpack(NULL, len, buf);
    free(buf);
    return (*out != NULL) ? 0 : -1;
}

static int read_aap_response(int fd, Aap2__AAPResponse **out)
{
    uint8_t *buf = NULL; size_t len = 0;
    if (read_envelope(fd, &buf, &len) != 0) return -1;
    *out = aap2__aapresponse__unpack(NULL, len, buf);
    free(buf);
    return (*out != NULL) ? 0 : -1;
}

/* ---------- Connection setup (shared by sender + subscribers) ---------- */

/* Consume the v1-reject greeting byte. Returns 0 on success, -1 on
 * mismatch (server isn't AAP 2.0). */
/* Frama-C: skipped —
 * do_handshake/consume_greeting: 7x at_logging cascade in protocol negotiation.
 */
static int consume_greeting(int fd, logger_t *logger)
{
    uint8_t byte;
    if (read_exact(fd, &byte, 1) != 0) return -1;
    if (byte != AAP_V1_REJECT_BYTE) {
        log_error(logger,
                  "DTN[ud3tnv2]: expected AAP 2.0 greeting 0x%02x, got 0x%02x "
                  "(is the daemon in v1 mode?)\n", AAP_V1_REJECT_BYTE, byte);
        return -1;
    }
    return 0;
}

/* Perform the Welcome + ConnectionConfig handshake on @p fd.
 * @p is_subscriber controls which role the client takes after SUCCESS. */
/* Frama-C: skipped —
 * do_handshake/consume_greeting: 7x at_logging cascade in protocol negotiation.
 */
static int do_handshake(int fd, const char *eid, bool is_subscriber,
                        logger_t *logger)
{
    if (consume_greeting(fd, logger) != 0) return -1;

    /* 1. Read Welcome. */
    Aap2__AAPMessage *welcome_msg = NULL;
    if (read_aap_message(fd, &welcome_msg) != 0) {
        log_error(logger, "DTN[ud3tnv2]: failed to read Welcome\n");
        return -1;
    }
    if (welcome_msg->msg_case != AAP2__AAPMESSAGE__MSG_WELCOME) {
        log_error(logger, "DTN[ud3tnv2]: first frame was not Welcome (case=%d)\n",
                  welcome_msg->msg_case);
        aap2__aapmessage__free_unpacked(welcome_msg, NULL);
        return -1;
    }
    if (welcome_msg->welcome && welcome_msg->welcome->node_id)
        log_info(logger, "DTN[ud3tnv2]: connected to node_id=%s\n",
                 welcome_msg->welcome->node_id);
    aap2__aapmessage__free_unpacked(welcome_msg, NULL);

    /* 2. Acknowledge Welcome. */
    if (write_aap_response(fd, AAP2__RESPONSE_STATUS__RESPONSE_STATUS_ACK) != 0) {
        log_error(logger, "DTN[ud3tnv2]: failed to ACK Welcome\n");
        return -1;
    }

    /* 3. Send ConnectionConfig. */
    Aap2__AAPMessage cfg_msg = AAP2__AAPMESSAGE__INIT;
    Aap2__ConnectionConfig cfg = AAP2__CONNECTION_CONFIG__INIT;
    cfg.is_subscriber      = is_subscriber;
    cfg.auth_type          = AAP2__AUTH_TYPE__AUTH_TYPE_DEFAULT;
    cfg.endpoint_id        = (char *)eid;
    cfg.keepalive_seconds  = 0;
    cfg_msg.msg_case = AAP2__AAPMESSAGE__MSG_CONFIG;
    cfg_msg.config   = &cfg;
    if (write_aap_message(fd, &cfg_msg) != 0) {
        log_error(logger, "DTN[ud3tnv2]: failed to send ConnectionConfig\n");
        return -1;
    }

    /* 4. Read AAPResponse (expect SUCCESS). */
    Aap2__AAPResponse *resp = NULL;
    if (read_aap_response(fd, &resp) != 0) {
        log_error(logger, "DTN[ud3tnv2]: no AAPResponse after ConnectionConfig\n");
        return -1;
    }
    int rc = 0;
    if (resp->response_status != AAP2__RESPONSE_STATUS__RESPONSE_STATUS_SUCCESS) {
        log_error(logger,
                  "DTN[ud3tnv2]: ConnectionConfig rejected (status=%d) for eid=%s\n",
                  resp->response_status, eid);
        rc = -1;
    }
    aap2__aapresponse__free_unpacked(resp, NULL);
    return rc;
}

/* ---------- Queue management ---------- */

static void enqueue_bundle(ud3tn2_bundle_t *b)
{
    pthread_mutex_lock(&g.q_lock);
    if (g.q_len >= INBOUND_QUEUE_CAP) {
        ud3tn2_bundle_t *oldest = g.q_head;
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

/* ---------- Subscriber reader thread ---------- */

typedef struct {
    size_t sub_idx;
} reader_arg_t;

/* Frama-C: skipped — subscriber_reader/handle_pushed_adu: logging/snprintf in loop body. */
static int handle_pushed_adu(subscriber_t *sub, Aap2__AAPMessage *msg)
{
    Aap2__BundleADU *adu = msg->adu;
    if (adu == NULL) return -1;

    if (adu->payload_length > AAP2_MAX_PAYLOAD) {
        log_error(g.logger, "DTN[ud3tnv2]: inbound payload too large (%llu)\n",
                  (unsigned long long)adu->payload_length);
        return -1;
    }

    uint8_t *payload = NULL;
    size_t   plen    = (size_t)adu->payload_length;
    if (plen > 0) {
        payload = malloc(plen);
        if (payload == NULL) return -1;
        if (read_exact(sub->fd, payload, plen) != 0) {
            free(payload);
            return -1;
        }
    }

    ud3tn2_bundle_t *b = calloc(1, sizeof(*b));
    if (b == NULL) { free(payload); return -1; }
    b->payload = payload;
    b->len = plen;
    if (adu->src_eid != NULL)
        snprintf(b->src_eid, sizeof(b->src_eid), "%s", adu->src_eid);
    snprintf(b->service, sizeof(b->service), "%s", sub->service);
    enqueue_bundle(b);
    return 0;
}

/* Frama-C: skipped — subscriber_reader/handle_pushed_adu: logging/snprintf in loop body. */
static void *subscriber_reader(void *arg)
{
    reader_arg_t *a = (reader_arg_t *)arg;
    size_t idx = a->sub_idx;
    subscriber_t *sub = &g.subs[idx];
    free(a);

    while (true) {
        pthread_mutex_lock(&g.q_lock);
        bool stop = g.stop;
        pthread_mutex_unlock(&g.q_lock);
        if (stop) break;

        Aap2__AAPMessage *msg = NULL;
        if (read_aap_message(sub->fd, &msg) != 0) break;

        bool should_ack = true;
        switch (msg->msg_case) {
        case AAP2__AAPMESSAGE__MSG_ADU:
            if (handle_pushed_adu(sub, msg) != 0) {
                log_warn(g.logger, "DTN[ud3tnv2]: ADU handling failed on %s\n",
                         sub->service);
            }
            break;
        case AAP2__AAPMESSAGE__MSG_KEEPALIVE:
            /* Just ACK. */
            break;
        case AAP2__AAPMESSAGE__MSG__NOT_SET:
        case AAP2__AAPMESSAGE__MSG_WELCOME:
        case AAP2__AAPMESSAGE__MSG_CONFIG:
        case AAP2__AAPMESSAGE__MSG_DISPATCH_EVENT:
        case AAP2__AAPMESSAGE__MSG_LINK:
        case _AAP2__AAPMESSAGE__MSG__CASE_IS_INT_SIZE:
            /* Not expected from the server on a subscriber connection;
             * ACK and continue rather than tearing down the socket. */
            log_debug(g.logger, "DTN[ud3tnv2]: ignoring msg_case=%d on %s\n",
                      msg->msg_case, sub->service);
            break;
        }
        aap2__aapmessage__free_unpacked(msg, NULL);

        if (should_ack) {
            if (write_aap_response(sub->fd,
                    AAP2__RESPONSE_STATUS__RESPONSE_STATUS_SUCCESS) != 0)
                break;
        }
    }

    pthread_mutex_lock(&g.q_lock);
    sub->reader_running = false;
    pthread_cond_broadcast(&g.q_cond);
    pthread_mutex_unlock(&g.q_lock);
    return NULL;
}

/* ---------- Teardown ---------- */

/* Frama-C: skipped —
 * teardown/recv/send: logging/snprintf + socket shutdown/close (2 FDs for AAP2: adu +
 * ctrl).
 */
static void teardown(void)
{
    pthread_mutex_lock(&g.q_lock);
    g.stop = true;
    pthread_cond_broadcast(&g.q_cond);
    pthread_mutex_unlock(&g.q_lock);

    for (size_t i = 0; i < g.n_subs; i++) {
        if (g.subs[i].fd >= 0)
            shutdown(g.subs[i].fd, SHUT_RDWR);
    }
    if (g.sender_fd >= 0)
        shutdown(g.sender_fd, SHUT_RDWR);

    for (size_t i = 0; i < g.n_subs; i++) {
        if (g.subs[i].reader_running)
            pthread_join(g.subs[i].reader, NULL);
        if (g.subs[i].fd >= 0) {
            close(g.subs[i].fd);
            g.subs[i].fd = -1;
        }
    }
    if (g.sender_fd >= 0) {
        close(g.sender_fd);
        g.sender_fd = -1;
    }

    pthread_mutex_lock(&g.q_lock);
    ud3tn2_bundle_t *b = g.q_head;
    while (b != NULL) {
        ud3tn2_bundle_t *next = b->next;
        free(b->payload);
        free(b);
        b = next;
    }
    g.q_head = g.q_tail = NULL;
    g.q_len = 0;
    pthread_mutex_unlock(&g.q_lock);

    g.n_subs = 0;
}

/* ---------- Backend vtable ---------- */

/* Frama-C: skipped —
 * [solver-timeout] ud3tnv2_init: 7x at_logging + 3x pthread_create + getenv/snprintf
 * cascade.
 */
static int ud3tnv2_init(const dtn_endpoint_t *endpoints, size_t n_endpoints,
                        logger_t *logger)
{
    if (n_endpoints == 0 || n_endpoints > MAX_ENDPOINTS) {
        log_error(logger, "DTN[ud3tnv2]: invalid endpoint count %zu (max %d)\n",
                  n_endpoints, MAX_ENDPOINTS);
        return -1;
    }
    if (g.sender_fd >= 0 || g.n_subs != 0) {
        log_warn(logger, "DTN[ud3tnv2]: already initialized\n");
        return -1;
    }

    g.logger = logger;
    g.stop = false;
    g.q_head = g.q_tail = NULL;
    g.q_len = 0;
    for (size_t i = 0; i < MAX_ENDPOINTS; i++) {
        g.subs[i].fd = -1;
        g.subs[i].reader_running = false;
    }

    const char *url = getenv("AT_DTN_UD3TN_SOCKET");

    /* 1. Sender connection, is_subscriber=false, registered to primary EID. */
    snprintf(g.primary_eid, sizeof(g.primary_eid), "%s", endpoints[0].eid);
    g.sender_fd = open_backend_socket(url, logger);
    if (g.sender_fd < 0) { teardown(); return -1; }
    if (do_handshake(g.sender_fd, g.primary_eid, false, logger) != 0) {
        teardown(); return -1;
    }

    /* 2. Subscriber per endpoint, is_subscriber=true. */
    for (size_t i = 0; i < n_endpoints; i++) {
        if (endpoints[i].eid == NULL || endpoints[i].service == NULL) {
            log_error(logger, "DTN[ud3tnv2]: endpoint[%zu] has NULL eid or service\n", i);
            teardown(); return -1;
        }
        snprintf(g.subs[i].eid,     sizeof(g.subs[i].eid),     "%s", endpoints[i].eid);
        snprintf(g.subs[i].service, sizeof(g.subs[i].service), "%s", endpoints[i].service);
        g.subs[i].fd = open_backend_socket(url, logger);
        if (g.subs[i].fd < 0) { teardown(); return -1; }
        if (do_handshake(g.subs[i].fd, g.subs[i].eid, true, logger) != 0) {
            teardown(); return -1;
        }
        g.n_subs = i + 1;
    }

    /* 3. Spawn a reader per subscriber. */
    for (size_t i = 0; i < n_endpoints; i++) {
        reader_arg_t *a = calloc(1, sizeof(*a));
        if (a == NULL) { teardown(); return -1; }
        a->sub_idx = i;
        if (pthread_create(&g.subs[i].reader, NULL, subscriber_reader, a) != 0) {
            free(a);
            log_error(logger, "DTN[ud3tnv2]: reader spawn failed for %s: %s\n",
                      g.subs[i].eid, strerror(errno));
            teardown(); return -1;
        }
        g.subs[i].reader_running = true;
    }

    log_info(logger,
             "DTN[ud3tnv2]: ready — sender=%s + %zu subscribers on %s\n",
             g.primary_eid, n_endpoints, url ? url : "unix:./ud3tn.aap2.socket");
    for (size_t i = 0; i < n_endpoints; i++) {
        log_info(logger, "DTN[ud3tnv2]:   [%zu] %s -> %s\n",
                 i, g.subs[i].eid, g.subs[i].service);
    }
    return 0;
}

static void ud3tnv2_shutdown(void)
{
    teardown();
}

/* Frama-C: skipped —
 * [solver-timeout] ud3tnv2_init: 7x at_logging + 3x pthread_create + getenv/snprintf
 * cascade. teardown/recv/send: logging/snprintf + socket shutdown/close (2 FDs for AAP2:
 * adu + ctrl). subscriber_reader/handle_pushed_adu: logging/snprintf in loop body.
 * do_handshake/consume_greeting: 7x at_logging cascade in protocol…
 */
static int ud3tnv2_send(const char *dest_eid,
                        const uint8_t *payload, size_t payload_len,
                        uint32_t lifetime_sec)
{
    (void)lifetime_sec;  /* AAP 2.0 BundleADU has no lifetime field; daemon default applies. */
    if (g.sender_fd < 0 || payload_len > AAP2_MAX_PAYLOAD) {
        errno = EINVAL;
        return -1;
    }

    Aap2__AAPMessage msg = AAP2__AAPMESSAGE__INIT;
    Aap2__BundleADU  adu = AAP2__BUNDLE_ADU__INIT;
    adu.src_eid        = g.primary_eid;
    adu.dst_eid        = (char *)dest_eid;
    adu.payload_length = payload_len;
    msg.msg_case = AAP2__AAPMESSAGE__MSG_ADU;
    msg.adu      = &adu;

    pthread_mutex_lock(&g.send_lock);
    int rc = -1;
    if (write_aap_message(g.sender_fd, &msg) == 0 &&
        (payload_len == 0 ||
         write_exact(g.sender_fd, payload, payload_len) == 0)) {
        /* Read the AAPResponse. */
        Aap2__AAPResponse *resp = NULL;
        if (read_aap_response(g.sender_fd, &resp) == 0) {
            if (resp->response_status == AAP2__RESPONSE_STATUS__RESPONSE_STATUS_SUCCESS) {
                rc = 0;
            } else {
                log_warn(g.logger, "DTN[ud3tnv2]: send to %s got status=%d\n",
                         dest_eid, resp->response_status);
            }
            aap2__aapresponse__free_unpacked(resp, NULL);
        }
    }
    pthread_mutex_unlock(&g.send_lock);
    return rc;
}

/* Frama-C: skipped —
 * [solver-timeout] ud3tnv2_init: 7x at_logging + 3x pthread_create + getenv/snprintf
 * cascade. teardown/recv/send: logging/snprintf + socket shutdown/close (2 FDs for AAP2:
 * adu + ctrl). subscriber_reader/handle_pushed_adu: logging/snprintf in loop body.
 * do_handshake/consume_greeting: 7x at_logging cascade in protocol…
 */
static int ud3tnv2_recv(uint8_t **out_payload, size_t *out_len,
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
        bool any_reader = false;
        for (size_t i = 0; i < g.n_subs; i++) {
            if (g.subs[i].reader_running) { any_reader = true; break; }
        }
        if (!any_reader) break;

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
    ud3tn2_bundle_t *b = g.q_head;
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
    .name     = "ud3tnv2",
    .init     = ud3tnv2_init,
    .shutdown = ud3tnv2_shutdown,
    .send     = ud3tnv2_send,
    .recv     = ud3tnv2_recv,
};
