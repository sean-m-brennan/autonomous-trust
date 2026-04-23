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
 * @file net_proc.c
 * @brief AT network process — transport-agnostic orchestrator.
 *
 * Selects a network transport by name (udp_net_4, tcp_net_6, etc.), opens
 * three logical channels through it, spawns receiver threads per channel,
 * and handles outbound encryption + routing.  Socket specifics live in
 * the transport implementations (net_transport_udp.c, net_transport_tcp.c).
 */

#define _XOPEN_SOURCE 700
#define _DEFAULT_SOURCE
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <time.h>
#include <unistd.h>
#include <pthread.h>

#include "processes/processes.h"
#include "utilities/message.h"
#include "utilities/msg_types_priv.h"
#include "utilities/exception.h"
#include "utilities/logger.h"
#include "network/network.h"
#include "network/net_message.h"
#include "network/net_transport.h"
#include "network/net_proc_priv.h"
#ifdef AT_NET_ENVELOPE
#include "network/net_envelope.h"
#endif
#ifdef AT_NET_GROUP_FORWARD
#include "network/net_transport_hybrid.h"
#endif
#include "identity/identity.h"
#include "identity/identity_priv.h"
#include "identity/group.h"
#include "structures/data.h"
#include "structures/array.h"

DEFINE_ERROR(ENET_SEND, "Network send failed");
DEFINE_ERROR(ENET_RECV, "Network receive failed");

static const int RECV_POLL_TIMEOUT_MS = 100;

/****************************
 * Blacklist / rejected addresses
 ****************************/

#define MAX_REJECTED 256
static char rejected_addresses[MAX_REJECTED][ADDR_LEN + 1];
static size_t rejected_count = 0;
static pthread_mutex_t rejected_lock = PTHREAD_MUTEX_INITIALIZER;

static bool reject_message(const char *address)
{
    bool found = false;
    pthread_mutex_lock(&rejected_lock);
    for (size_t i = 0; i < rejected_count; i++) {
        if (strcmp(rejected_addresses[i], address) == 0) {
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
    for (size_t i = 0; i < rejected_count; i++) {
        if (strcmp(rejected_addresses[i], address) == 0) {
            pthread_mutex_unlock(&rejected_lock);
            return;
        }
    }
    if (rejected_count < MAX_REJECTED) {
        snprintf(rejected_addresses[rejected_count], sizeof(rejected_addresses[0]),
                 "%s", address);
        rejected_count++;
    }
    pthread_mutex_unlock(&rejected_lock);
}

/****************************
 * Deferred encrypted message queue (mystery handler)
 ****************************/

#define MAX_DEFERRED 64
#define DEFERRED_MSG_MAX 65507

typedef struct {
    uint8_t data[DEFERRED_MSG_MAX];
    size_t len;
    char from_addr[ADDR_LEN + 1];
    uuid_t src_uuid;        /* Original sender's UUID (envelope mode). */
    bool   has_src_uuid;    /* True iff src_uuid is meaningful. */
} deferred_msg_t;

static deferred_msg_t deferred_messages[MAX_DEFERRED];
static size_t deferred_count = 0;
static pthread_mutex_t deferred_lock = PTHREAD_MUTEX_INITIALIZER;

/* @p src_uuid is optional — pass NULL in non-envelope mode. When non-NULL,
 * the entry will be matched against a newly-admitted peer's UUID (the
 * from_addr field alone is ambiguous under gateway forwarding because the
 * transport reports the gateway's address, not the original sender's). */
static void defer_message(const uint8_t *data, size_t len,
                          const char *from_addr, const uuid_t src_uuid)
{
    pthread_mutex_lock(&deferred_lock);
    if (deferred_count < MAX_DEFERRED) {
        size_t idx = deferred_count;
        if (len > sizeof(deferred_messages[0].data))
            len = sizeof(deferred_messages[0].data);
        memcpy(deferred_messages[idx].data, data, len);
        deferred_messages[idx].len = len;
        snprintf(deferred_messages[idx].from_addr,
                 sizeof(deferred_messages[idx].from_addr), "%s", from_addr);
        if (src_uuid != NULL) {
            memcpy(deferred_messages[idx].src_uuid, src_uuid, 16);
            deferred_messages[idx].has_src_uuid = true;
        } else {
            memset(deferred_messages[idx].src_uuid, 0, 16);
            deferred_messages[idx].has_src_uuid = false;
        }
        deferred_count++;
    }
    pthread_mutex_unlock(&deferred_lock);
}

/* Match predicate: a deferred entry matches a newly-admitted peer iff
 * the entry's src_uuid is set AND equals the peer's UUID, OR (fallback,
 * non-envelope mode) its from_addr matches the peer's address. */
static bool deferred_matches_peer(const deferred_msg_t *dm,
                                  const public_identity_t *new_peer)
{
    if (dm->has_src_uuid)
        return memcmp(dm->src_uuid, new_peer->uuid, 16) == 0;
    return strcmp(dm->from_addr, new_peer->address) == 0;
}

/* Test-only hooks — declarations in net_proc_priv.h. */
size_t net_proc_test_deferred_count(void)
{
    pthread_mutex_lock(&deferred_lock);
    size_t n = deferred_count;
    pthread_mutex_unlock(&deferred_lock);
    return n;
}

void net_proc_test_reset_deferred(void)
{
    pthread_mutex_lock(&deferred_lock);
    deferred_count = 0;
    pthread_mutex_unlock(&deferred_lock);
}

bool net_proc_test_deferred_matches_peer(size_t idx,
                                         const public_identity_t *new_peer)
{
    bool m = false;
    pthread_mutex_lock(&deferred_lock);
    if (idx < deferred_count)
        m = deferred_matches_peer(&deferred_messages[idx], new_peer);
    pthread_mutex_unlock(&deferred_lock);
    return m;
}

/* Capture of the most recent from_whom.address handed to route_to_process,
 * so cross-cluster discovery tests can observe whether the envelope-based
 * overwrite suppression preserved the wire payload's self-reported
 * address (AT_DISCOVERY_CROSS_CLUSTER). Empty string after reset. */
static char          _test_last_routed_from_addr[ADDR_LEN + 1] = {0};
static pthread_mutex_t _test_last_routed_lock = PTHREAD_MUTEX_INITIALIZER;

void net_proc_test_reset_last_routed_from_addr(void)
{
    pthread_mutex_lock(&_test_last_routed_lock);
    _test_last_routed_from_addr[0] = '\0';
    pthread_mutex_unlock(&_test_last_routed_lock);
}

void net_proc_test_get_last_routed_from_addr(char *out, size_t outlen)
{
    if (out == NULL || outlen == 0) return;
    pthread_mutex_lock(&_test_last_routed_lock);
    snprintf(out, outlen, "%s", _test_last_routed_from_addr);
    pthread_mutex_unlock(&_test_last_routed_lock);
}

/****************************
 * Per-peer statistics tracking
 ****************************/

typedef struct {
    char address[ADDR_LEN + 1];
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
    for (size_t i = 0; i < stats_count; i++) {
        if (strcmp(peer_stats[i].address, address) == 0)
            return &peer_stats[i];
    }
    if (stats_count < MAX_STATS) {
        net_stat_t *st = &peer_stats[stats_count];
        memset(st, 0, sizeof(*st));
        snprintf(st->address, sizeof(st->address), "%s", address);
        stats_count++;
        return st;
    }
    return NULL;
}

static void track_send(const char *address, size_t bytes)
{
    net_stat_t *st = find_or_create_stat(address);
    if (st != NULL) st->bytes_sent += bytes;
}

static void track_send_error(const char *address)
{
    net_stat_t *st = find_or_create_stat(address);
    if (st != NULL) st->send_errors++;
}

static void track_recv(const char *address, size_t bytes)
{
    net_stat_t *st = find_or_create_stat(address);
    if (st != NULL) st->bytes_recv += bytes;
}

/****************************
 * Peer lookup
 ****************************/

#ifndef AT_NET_ENVELOPE
static const public_identity_t *find_peer_by_address(const process_t *proc, const char *addr)
{
    /* peers[] is append-only; the underlying array is inline (never reallocated),
     * so a pointer obtained under the read lock stays valid and stable afterward. */
    peers_read_lock(proc);
    const public_identity_t *match = NULL;
    for (size_t i = 0; i < proc->protocol.num_peers; i++) {
        if (strcmp(proc->protocol.peers[i].address, addr) == 0) {
            match = &proc->protocol.peers[i];
            break;
        }
    }
    peers_read_unlock(proc);
    return match;
}
#endif

#ifdef AT_NET_ENVELOPE
static const public_identity_t *find_peer_by_uuid(const process_t *proc, const uuid_t uuid)
{
    peers_read_lock(proc);
    const public_identity_t *match = NULL;
    for (size_t i = 0; i < proc->protocol.num_peers; i++) {
        if (memcmp(proc->protocol.peers[i].uuid, uuid, 16) == 0) {
            match = &proc->protocol.peers[i];
            break;
        }
    }
    peers_read_unlock(proc);
    return match;
}
#endif

/****************************
 * Decrypt helper (peer-to-peer messages)
 ****************************/

static int decrypt_message(const identity_t *myself, const public_identity_t *peer,
                           const uint8_t *frame, size_t frame_len,
                           uint8_t **plain_out, size_t *plain_len)
{
    if (frame_len <= crypto_box_NONCEBYTES + crypto_box_MACBYTES)
        return EXCEPTION(ENET_RECV);

    const unsigned char *nonce  = frame;
    const unsigned char *cipher = frame + crypto_box_NONCEBYTES;
    size_t cipher_len = frame_len - crypto_box_NONCEBYTES;
    size_t plen = cipher_len - crypto_box_MACBYTES;

    unsigned char *plain = malloc(plen);
    if (plain == NULL) return SYS_EXCEPTION();

    msg_str_t cmsg = {.msg = (unsigned char *)cipher, .len = cipher_len};
    int ret = identity_decrypt(myself, &cmsg, peer, nonce, plain);
    if (ret != 0) { free(plain); return ret; }

    *plain_out = plain;
    *plain_len = plen;
    return 0;
}

/****************************
 * Route a decoded wire message to the target process queue
 ****************************/

static int route_to_process(const net_wire_msg_t *wmsg, process_t *proc,
                            directory_t *queues, logger_t *logger)
{
    (void)proc; (void)queues;
    /* Test-hook capture: record the from_whom.address the downstream
     * handler will observe. See net_proc_test_get_last_routed_from_addr. */
    pthread_mutex_lock(&_test_last_routed_lock);
    snprintf(_test_last_routed_from_addr, sizeof(_test_last_routed_from_addr),
             "%s", wmsg->from_whom.address);
    pthread_mutex_unlock(&_test_last_routed_lock);

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

    int ret = messaging_send(wmsg->process, NET_MESSAGE, &gmsg, false);
    if (ret != 0) {
        log_error(logger, "Failed to route message to process '%s'\n", wmsg->process);
        if (gmsg.info.net_msg.function != NULL) free(gmsg.info.net_msg.function);
        return ret;
    }
    log_debug(logger, "Routed %s.%s from %s\n", wmsg->process, wmsg->function,
              wmsg->from_whom.fullname);
    if (gmsg.info.net_msg.function != NULL) free(gmsg.info.net_msg.function);
    return 0;
}

#ifdef AT_NET_ENVELOPE
/****************************
 * Envelope helpers (gateway forwarding — at-over-dtn.md §4.3)
 ****************************/

/* Wrap an inner payload in the plaintext forwarding envelope. Caller owns
 * @p *out_frame and must free(). @p payload is copied; caller retains its
 * own ownership. @p dst_uuid may be NULL for NET_ENV_TYPE_BROADCAST (NIL dst). */
static int envelope_wrap(net_env_type_t type,
                         const uuid_t src_uuid, const uuid_t dst_uuid,
                         const uint8_t *payload, size_t payload_len,
                         uint8_t **out_frame, size_t *out_frame_len)
{
    net_envelope_t env = {
        .version   = NET_ENV_VERSION,
        .type      = type,
        .flags     = 0,
        .hop_count = 0,
    };
    memcpy(env.src_uuid, src_uuid, 16);
    if (dst_uuid != NULL) memcpy(env.dst_uuid, dst_uuid, 16);
    else                  memset(env.dst_uuid, 0, 16);

    size_t cap = NET_ENV_HEADER_LEN + payload_len;
    uint8_t *frame = malloc(cap);
    if (frame == NULL) return SYS_EXCEPTION();

    if (net_envelope_pack(&env, payload, payload_len, frame, cap, out_frame_len) != 0) {
        free(frame);
        return -1;
    }
    *out_frame = frame;
    return 0;
}

/* Inbound envelope classification. Internal alias of net_env_disposition_t
 * so the existing call sites keep reading with intention-revealing names. */
typedef enum {
    ENV_DELIVER_LOCAL = NET_ENV_DISPOSITION_LOCAL,
    ENV_DROP          = NET_ENV_DISPOSITION_DROP,
    ENV_FORWARD       = NET_ENV_DISPOSITION_FORWARD,
} env_decision_t;

static env_decision_t classify_envelope(const net_envelope_t *env,
                                        const identity_t *myself,
                                        const group_t *grp,
                                        bool gateway)
{
    static const uuid_t NIL_UUID = {0};
    return (env_decision_t)net_envelope_disposition(
        env,
        myself != NULL ? myself->uuid : NIL_UUID,
        grp != NULL ? grp->uuid : NIL_UUID,
        gateway);
}

/* ---- Broadcast-relay dedup + rate limit (cross-leg forwarding) -----
 *
 * A gateway re-broadcasts each inbound BROADCAST onto its other legs so
 * discovery announcements bridge clusters (at-over-dtn.md §4.3 item D).
 * Three controls keep that safe:
 *   1. Hop count cap (enforced by net_envelope_should_forward_broadcast).
 *   2. Fingerprint dedup ring — we don't re-forward the same broadcast
 *      twice within BCAST_DEDUP_WINDOW_MS, so mutual gateways can't
 *      infinite-loop.
 *   3. Rate-limit token bucket — cap forwards-per-second as a simple DoS
 *      gate against a rogue sender flooding new broadcasts.
 *
 * Known limitation (not handled here; documented for the reader):
 * hybrid->send_broadcast fans out to ALL inners, so nodes on the
 * originating leg see a re-forwarded copy. Discovery payloads are
 * idempotent at the upper layer, so this is acceptable; a future slice
 * could add per-leg source tracking to the transport API. */
#define BCAST_DEDUP_CAP       128
#define BCAST_DEDUP_WINDOW_MS 5000
#define BCAST_RATE_PER_SEC    64

typedef struct {
    uint64_t fingerprint;
    uint64_t ts_ms;
} bcast_dedup_entry_t;

static bcast_dedup_entry_t bcast_dedup[BCAST_DEDUP_CAP];
static size_t bcast_dedup_next = 0;  /* next write slot (ring) */
static size_t bcast_tokens = BCAST_RATE_PER_SEC;
static uint64_t bcast_tokens_ts_ms = 0;
static pthread_mutex_t bcast_fwd_lock = PTHREAD_MUTEX_INITIALIZER;

static uint64_t now_ms(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000ULL + (uint64_t)(ts.tv_nsec / 1000000L);
}

/* Returns true iff this fingerprint has NOT been seen recently AND a
 * forwarding token is available. On true, the entry is recorded and a
 * token consumed — the caller must proceed to forward (or accept the
 * double-bookkeeping of a recorded-but-skipped entry; we tolerate that
 * because the window self-heals in BCAST_DEDUP_WINDOW_MS). */
static bool bcast_may_forward(uint64_t fp)
{
    uint64_t now = now_ms();
    pthread_mutex_lock(&bcast_fwd_lock);

    /* Dedup: linear scan is fine for 128 entries. */
    for (size_t i = 0; i < BCAST_DEDUP_CAP; i++) {
        if (bcast_dedup[i].fingerprint == fp &&
            bcast_dedup[i].ts_ms != 0 &&
            (now - bcast_dedup[i].ts_ms) < BCAST_DEDUP_WINDOW_MS) {
            pthread_mutex_unlock(&bcast_fwd_lock);
            return false;
        }
    }

    /* Rate limit: refill proportionally to elapsed time (cap at max). */
    if (bcast_tokens_ts_ms == 0) {
        bcast_tokens_ts_ms = now;
    } else {
        uint64_t elapsed = now - bcast_tokens_ts_ms;
        if (elapsed >= 1000) {
            size_t add = (size_t)((elapsed / 1000) * BCAST_RATE_PER_SEC);
            if (add > BCAST_RATE_PER_SEC) add = BCAST_RATE_PER_SEC;
            if (bcast_tokens + add > BCAST_RATE_PER_SEC)
                bcast_tokens = BCAST_RATE_PER_SEC;
            else
                bcast_tokens += add;
            bcast_tokens_ts_ms = now;
        }
    }
    if (bcast_tokens == 0) {
        pthread_mutex_unlock(&bcast_fwd_lock);
        return false;
    }
    bcast_tokens--;

    /* Record. */
    bcast_dedup[bcast_dedup_next].fingerprint = fp;
    bcast_dedup[bcast_dedup_next].ts_ms       = now;
    bcast_dedup_next = (bcast_dedup_next + 1) % BCAST_DEDUP_CAP;

    pthread_mutex_unlock(&bcast_fwd_lock);
    return true;
}

/* Relay a PEER envelope frame out the same transport. The frame buffer is
 * mutated (hop_count bumped, FORWARDED flag set) before send. Looks up the
 * destination address by dst_uuid in the local peer registry — on a hybrid
 * transport, the inner-selection matcher then steers the send to whichever
 * inner transport serves that peer. */
static int envelope_forward(const net_envelope_t *env_in,
                            uint8_t *frame, size_t frame_len,
                            const process_t *proc,
                            const net_transport_t *transport,
                            net_transport_ctx_t *ctx,
                            int port, logger_t *logger)
{
    const public_identity_t *dst = find_peer_by_uuid(proc, env_in->dst_uuid);
    if (dst == NULL) {
        log_debug(logger, "Envelope: no peer registered for dst uuid; dropping\n");
        return -1;
    }
    net_envelope_t next = *env_in;
    next.hop_count = (uint8_t)(next.hop_count + 1);
    next.flags     = (uint8_t)(next.flags | NET_ENV_FLAG_FORWARDED);
    if (net_envelope_rewrite_header(&next, frame, frame_len) != 0)
        return -1;
    return transport->send_unicast(ctx, frame, frame_len, dst->address, port);
}
#endif /* AT_NET_ENVELOPE */

/****************************
 * Encrypt + send (transport-agnostic)
 ****************************/

static int net_encrypt_and_send(const identity_t *myself, const net_wire_msg_t *msg,
                                const net_transport_t *transport,
                                net_transport_ctx_t *ctx,
                                int port, logger_t *logger)
{
    uint8_t *wire = NULL;
    size_t wire_len = 0;
    if (net_message_to_wire(msg, myself, &wire, &wire_len) != 0)
        return -1;

    /* Broadcast: no encryption; falls back to per-peer unicast if the
     * transport has no native broadcast (e.g., TCP). */
    if (msg->to_whom.type == RECIPIENT_BROADCAST) {
        const uint8_t *send_buf = wire;
        size_t         send_len = wire_len;
#ifdef AT_NET_ENVELOPE
        uint8_t *env_frame = NULL;
        size_t   env_frame_len = 0;
        if (envelope_wrap(NET_ENV_TYPE_BROADCAST, myself->uuid, NULL,
                          wire, wire_len, &env_frame, &env_frame_len) != 0) {
            free(wire);
            return SYS_EXCEPTION();
        }
        send_buf = env_frame;
        send_len = env_frame_len;
#endif
        int ret = transport->send_broadcast(ctx, NET_CHAN_BROADCAST,
                                            send_buf, send_len, port);
        if (ret == 0) {
            track_send(msg->to_whom.target.peer.address, send_len);
        } else if (ret == -1) {
            /* Transport can't broadcast; caller can retry as unicast. */
            log_debug(logger, "Network: transport lacks broadcast; skipping\n");
        } else {
            track_send_error(msg->to_whom.target.peer.address);
        }
#ifdef AT_NET_ENVELOPE
        free(env_frame);
#endif
        free(wire);
        return ret;
    }

    /* Encrypted peer: wrap wire bytes in nonce|ciphertext. */
    if (msg->encrypt && msg->to_whom.type == RECIPIENT_PEER) {
        /* libsodium init is idempotent; defensive per identity.c:79-94 */
        if (sodium_init() < 0) {
            free(wire);
            return SYS_EXCEPTION();
        }

        unsigned char nonce[crypto_box_NONCEBYTES];
        randombytes_buf(nonce, sizeof(nonce));

        msg_str_t plain = {.msg = wire, .len = wire_len};
        size_t cipher_len = wire_len + crypto_box_MACBYTES;
        unsigned char *cipher = malloc(cipher_len);
        if (cipher == NULL) {
            free(wire);
            return SYS_EXCEPTION();
        }

        int enc = identity_encrypt(myself, &plain, &msg->to_whom.target.peer, nonce, cipher);
        free(wire);
        if (enc != 0) {
            free(cipher);
            return enc;
        }

        size_t frame_len = sizeof(nonce) + cipher_len;
        uint8_t *frame = malloc(frame_len);
        if (frame == NULL) {
            free(cipher);
            return SYS_EXCEPTION();
        }
        memcpy(frame, nonce, sizeof(nonce));
        memcpy(frame + sizeof(nonce), cipher, cipher_len);
        free(cipher);

        const uint8_t *send_buf = frame;
        size_t         send_len = frame_len;
#ifdef AT_NET_ENVELOPE
        uint8_t *env_frame = NULL;
        size_t   env_frame_len = 0;
        if (envelope_wrap(NET_ENV_TYPE_PEER, myself->uuid,
                          msg->to_whom.target.peer.uuid,
                          frame, frame_len, &env_frame, &env_frame_len) != 0) {
            free(frame);
            return SYS_EXCEPTION();
        }
        send_buf = env_frame;
        send_len = env_frame_len;
#endif
        const char *host = msg->to_whom.target.peer.address;
        int ret = transport->send_unicast(ctx, send_buf, send_len, host, port);
        if (ret == 0) track_send(host, send_len);
        else          track_send_error(host);
#ifdef AT_NET_ENVELOPE
        free(env_frame);
#endif
        free(frame);
        return ret;
    }

    /* Unencrypted peer send */
    const uint8_t *send_buf = wire;
    size_t         send_len = wire_len;
#ifdef AT_NET_ENVELOPE
    uint8_t *env_frame = NULL;
    size_t   env_frame_len = 0;
    if (envelope_wrap(NET_ENV_TYPE_PEER, myself->uuid,
                      msg->to_whom.target.peer.uuid,
                      wire, wire_len, &env_frame, &env_frame_len) != 0) {
        free(wire);
        return SYS_EXCEPTION();
    }
    send_buf = env_frame;
    send_len = env_frame_len;
#endif
    const char *host = msg->to_whom.target.peer.address;
    int ret = transport->send_unicast(ctx, send_buf, send_len, host, port);
    if (ret == 0) track_send(host, send_len);
    else          track_send_error(host);
#ifdef AT_NET_ENVELOPE
    free(env_frame);
#endif
    free(wire);
    return ret;
}

/****************************
 * Receiver threads (transport-agnostic)
 *
 * The per-channel thread functions below are thin loops around the
 * corresponding handle_inbound_* handlers. Handlers are declared in
 * net_proc_priv.h so tests can drive them directly without bringing up
 * real sockets or daemonize()'d processes. The thread loop owns the
 * recv-buffer lifetime — it frees @c buf after the handler returns.
 ****************************/

/* Return the local address string for comparing to the packet sender. */
static void my_address(const network_config_t *net_cfg, bool ipv6, char *out)
{
    out[0] = '\0';
    if (ipv6)
        cidr_split((char *)net_cfg->ip6_cidr, out, NULL);
    else
        cidr_split((char *)net_cfg->ip4_cidr, out, NULL);
}

void handle_inbound_peer(net_thread_ctx_t *ctx,
                         uint8_t *buf, size_t nbytes,
                         const char *from_addr)
{
    const uint8_t *inner_buf = buf;
    size_t         inner_len = nbytes;
    const public_identity_t *peer = NULL;

#ifdef AT_NET_ENVELOPE
    net_envelope_t env;
    if (net_envelope_unpack(buf, nbytes, &env, &inner_buf, &inner_len) != 0) {
        log_debug(ctx->logger, "Network: dropping malformed envelope from %s\n", from_addr);
        return;
    }
    bool gw = (ctx->transport->is_gateway != NULL &&
               ctx->transport->is_gateway(ctx->ctx));
    env_decision_t d = classify_envelope(&env, ctx->myself, NULL, gw);
    if (d == ENV_DROP)
        return;
    if (d == ENV_FORWARD) {
        envelope_forward(&env, buf, nbytes, ctx->proc,
                         ctx->transport, ctx->ctx,
                         ctx->net_cfg->port, ctx->logger);
        return;
    }
    /* Local delivery: identify the ORIGINAL sender by envelope src_uuid,
     * not by from_addr (which may be a gateway, not the originator). */
    peer = find_peer_by_uuid(ctx->proc, env.src_uuid);
#else
    peer = find_peer_by_address(ctx->proc, from_addr);
#endif

    if (peer != NULL) {
        uint8_t *plain = NULL;
        size_t plain_len = 0;
        int dec = decrypt_message(ctx->myself, peer, inner_buf, inner_len,
                                  &plain, &plain_len);
        if (dec == 0) {
            net_wire_msg_t wmsg;
            if (net_message_from_wire(plain, plain_len, peer, &wmsg) == 0)
                route_to_process(&wmsg, ctx->proc, ctx->queues, ctx->logger);
            free(plain);
            net_wire_msg_free(&wmsg);
        } else {
            log_error(ctx->logger, "Network: decrypt failed (%d) from peer %s\n",
                      dec, from_addr);
        }
    } else {
        /* Try as unencrypted (e.g. access_granted to unknown peer) */
        net_wire_msg_t wmsg;
        if (net_message_from_wire(inner_buf, inner_len, NULL, &wmsg) == 0) {
            snprintf(wmsg.from_whom.address, sizeof(wmsg.from_whom.address),
                     "%s", from_addr);
            route_to_process(&wmsg, ctx->proc, ctx->queues, ctx->logger);
            net_wire_msg_free(&wmsg);
        } else {
            /* Encrypted message from unknown peer — defer for retry. In
             * envelope mode the retry key is env.src_uuid (the originator),
             * NOT from_addr — the latter is the gateway's address under a
             * forwarded frame, and the future peer IPC arrives carrying
             * the original sender's own address, not the gateway's. */
            log_debug(ctx->logger, "Deferred encrypted message from unknown peer %s\n",
                      from_addr);
#ifdef AT_NET_ENVELOPE
            defer_message(inner_buf, inner_len, from_addr, env.src_uuid);
#else
            defer_message(inner_buf, inner_len, from_addr, NULL);
#endif
        }
    }
}

static void *peer_receiver_thread(void *arg)
{
    net_thread_ctx_t *ctx = (net_thread_ctx_t *)arg;
    while (!(*ctx->stop))
    {
        uint8_t *buf = NULL;
        size_t nbytes = 0;
        char from_addr[ADDR_LEN + 1] = {0};

        int ret = ctx->transport->recv(ctx->ctx, NET_CHAN_PEER,
                                       &buf, &nbytes,
                                       from_addr, sizeof(from_addr),
                                       RECV_POLL_TIMEOUT_MS);
        if (ret == ENOMSG || ret < 0) {
            free(buf);
            continue;
        }

        char my_addr[ADDR_LEN + 1] = {0};
        my_address(ctx->net_cfg, false, my_addr);
        if (strcmp(from_addr, my_addr) == 0 || reject_message(from_addr)) {
            free(buf);
            continue;
        }
        track_recv(from_addr, nbytes);

        handle_inbound_peer(ctx, buf, nbytes, from_addr);
        free(buf);
    }
    return NULL;
}

void handle_inbound_broadcast(net_thread_ctx_t *ctx,
                              uint8_t *buf, size_t nbytes,
                              const char *from_addr)
{
    const uint8_t *inner_buf = buf;
    size_t         inner_len = nbytes;

#ifdef AT_NET_ENVELOPE
    net_envelope_t env;
    if (net_envelope_unpack(buf, nbytes, &env, &inner_buf, &inner_len) != 0) {
        log_debug(ctx->logger, "Network: dropping malformed envelope from %s\n", from_addr);
        return;
    }
    /* BROADCAST envelopes always classify local; non-broadcast types
     * should not arrive on the BCAST channel — drop defensively. */
    if (env.type != NET_ENV_TYPE_BROADCAST)
        return;
#endif

    /* Broadcast messages are unencrypted */
    net_wire_msg_t wmsg;
    if (net_message_from_wire(inner_buf, inner_len, NULL, &wmsg) == 0) {
        bool preserve_self_reported = false;
#ifdef AT_DISCOVERY_CROSS_CLUSTER
        /* Cross-cluster discovery: when the envelope was forwarded by a
         * gateway, from_addr is the gateway — NOT the original announcer.
         * Preserve the announcer's self-reported address from the wire
         * payload so replies (ID_ACCEPT, etc.) route back through the
         * same gateway via the hybrid CIDR matcher rather than landing
         * at the gateway itself. */
        if ((env.flags & NET_ENV_FLAG_FORWARDED) != 0)
            preserve_self_reported = true;
#endif
        if (!preserve_self_reported)
            snprintf(wmsg.from_whom.address, sizeof(wmsg.from_whom.address),
                     "%s", from_addr);
        route_to_process(&wmsg, ctx->proc, ctx->queues, ctx->logger);
        net_wire_msg_free(&wmsg);
    } else {
        log_error(ctx->logger, "Network: failed to deserialize broadcast from %s\n",
                  from_addr);
    }

#ifdef AT_NET_ENVELOPE
    /* Gateway cross-leg relay: deliver-and-forward. The frame buffer is
     * mutated (hop++ + FORWARDED flag) before we re-emit via the same
     * transport. On a hybrid transport, send_broadcast fans out to all
     * inners — which is exactly what makes cross-leg bridging work. */
    bool gw = (ctx->transport->is_gateway != NULL &&
               ctx->transport->is_gateway(ctx->ctx));
    if (!net_envelope_should_forward_broadcast(&env, gw))
        return;

    uint64_t fp = net_envelope_broadcast_fingerprint(&env, inner_buf, inner_len);
    if (!bcast_may_forward(fp))
        return;

    net_envelope_t next = env;
    next.hop_count = (uint8_t)(next.hop_count + 1);
    next.flags     = (uint8_t)(next.flags | NET_ENV_FLAG_FORWARDED);
    if (net_envelope_rewrite_header(&next, buf, nbytes) != 0)
        return;

    int rc = ctx->transport->send_broadcast(ctx->ctx, NET_CHAN_BROADCAST,
                                            buf, nbytes, ctx->net_cfg->port);
    if (rc != 0 && rc != -1)
        log_debug(ctx->logger, "Network: broadcast relay send returned %d\n", rc);
#endif
}

static void *broadcast_receiver_thread(void *arg)
{
    net_thread_ctx_t *ctx = (net_thread_ctx_t *)arg;
    while (!(*ctx->stop))
    {
        uint8_t *buf = NULL;
        size_t nbytes = 0;
        char from_addr[ADDR_LEN + 1] = {0};

        int ret = ctx->transport->recv(ctx->ctx, NET_CHAN_BROADCAST,
                                       &buf, &nbytes,
                                       from_addr, sizeof(from_addr),
                                       RECV_POLL_TIMEOUT_MS);
        if (ret == ENOMSG || ret < 0) {
            free(buf);
            continue;
        }

        char my_addr[ADDR_LEN + 1] = {0};
        my_address(ctx->net_cfg, false, my_addr);
        if (strcmp(from_addr, my_addr) == 0 || reject_message(from_addr)) {
            free(buf);
            continue;
        }
        track_recv(from_addr, nbytes);

        handle_inbound_broadcast(ctx, buf, nbytes, from_addr);
        free(buf);
    }
    return NULL;
}

static void *group_receiver_thread(void *arg)
{
    net_thread_ctx_t *ctx = (net_thread_ctx_t *)arg;
    while (!(*ctx->stop))
    {
        uint8_t *buf = NULL;
        size_t nbytes = 0;
        char from_addr[ADDR_LEN + 1] = {0};

        int ret = ctx->transport->recv(ctx->ctx, NET_CHAN_GROUP,
                                       &buf, &nbytes,
                                       from_addr, sizeof(from_addr),
                                       RECV_POLL_TIMEOUT_MS);
        if (ret == ENOMSG || ret < 0) {
            free(buf);
            continue;
        }

        char my_addr[ADDR_LEN + 1] = {0};
        my_address(ctx->net_cfg, false, my_addr);
        if (strcmp(from_addr, my_addr) == 0 || reject_message(from_addr)) {
            free(buf);
            continue;
        }
        track_recv(from_addr, nbytes);

        handle_inbound_group(ctx, buf, nbytes, from_addr);
        free(buf);
    }
    return NULL;
}

void handle_inbound_group(net_thread_ctx_t *ctx,
                          uint8_t *buf, size_t nbytes,
                          const char *from_addr)
{
    group_t *grp = &ctx->proc->protocol.group;

    const uint8_t *inner_buf = buf;
    size_t         inner_len = nbytes;

#ifdef AT_NET_ENVELOPE
    net_envelope_t env;
    if (net_envelope_unpack(buf, nbytes, &env, &inner_buf, &inner_len) != 0) {
        log_debug(ctx->logger, "Network: dropping malformed group envelope from %s\n", from_addr);
        return;
    }
    bool am_gateway = (ctx->transport->is_gateway != NULL &&
                       ctx->transport->is_gateway(ctx->ctx));
    env_decision_t d = classify_envelope(&env, ctx->myself, grp, am_gateway);
    if (d != ENV_DELIVER_LOCAL) {
#ifdef AT_NET_GROUP_FORWARD
        /* Cross-group bridging: if we're a gateway and the operator has
         * configured a route for this dst_uuid, forward via the target
         * leg. Dedup ring is shared with broadcast relay — fingerprints
         * occupy disjoint 2^64 spaces in practice, and the "recently
         * forwarded" semantic is identical. */
        if (am_gateway &&
            net_envelope_should_forward_group(&env, am_gateway) &&
            ctx->transport->send_on_leg != NULL &&
            ctx->transport_cfg != NULL) {
            const hybrid_config_t *hcfg = ctx->transport_cfg;
            size_t leg_index = 0;
            if (hybrid_group_route_lookup(hcfg, env.dst_uuid, &leg_index) == 0) {
                uint64_t fp = net_envelope_group_fingerprint(&env, inner_buf, inner_len);
                if (bcast_may_forward(fp)) {
                    net_envelope_t next = env;
                    next.hop_count = (uint8_t)(next.hop_count + 1);
                    next.flags     = (uint8_t)(next.flags | NET_ENV_FLAG_FORWARDED);
                    if (net_envelope_rewrite_header(&next, buf, nbytes) == 0) {
                        int rc = ctx->transport->send_on_leg(
                            ctx->ctx, leg_index, NET_CHAN_GROUP,
                            buf, nbytes, ctx->net_cfg->port);
                        if (rc != 0 && rc != -1)
                            log_debug(ctx->logger,
                                      "Network: group forward send returned %d\n", rc);
                    }
                }
            }
        }
#endif
        /* Not our group and either not a gateway or no route matches. */
        return;
    }
#endif

    /* Local-delivery path requires group membership (need the group key
     * to decrypt). A gateway forwarding without being in the group takes
     * the branch above and returns before reaching here. */
    if (grp->address[0] == '\0') {
        log_debug(ctx->logger, "Network: group key not yet available, dropping msg from %s\n",
                  from_addr);
        return;
    }

    if (inner_len <= crypto_box_NONCEBYTES + crypto_box_MACBYTES) {
        log_error(ctx->logger, "Network: group message too short from %s\n", from_addr);
        return;
    }

    const unsigned char *nonce  = inner_buf;
    const unsigned char *cipher = inner_buf + crypto_box_NONCEBYTES;
    size_t cipher_len = inner_len - crypto_box_NONCEBYTES;
    size_t plain_len  = cipher_len - crypto_box_MACBYTES;

    unsigned char *plain = malloc(plain_len);
    if (plain == NULL) return;

    msg_str_t cmsg = {.msg = (unsigned char *)cipher, .len = cipher_len};
    int dec = group_decrypt(grp, &cmsg, grp, nonce, plain);
    if (dec == 0) {
        net_wire_msg_t wmsg;
        if (net_message_from_wire(plain, plain_len, NULL, &wmsg) == 0) {
            snprintf(wmsg.from_whom.address, sizeof(wmsg.from_whom.address),
                     "%s", from_addr);
            route_to_process(&wmsg, ctx->proc, ctx->queues, ctx->logger);
            net_wire_msg_free(&wmsg);
        }
    } else {
        log_error(ctx->logger, "Network: group decrypt failed (%d) from %s\n",
                  dec, from_addr);
    }
    free(plain);
}

/* Fan out a PEER_RTT_UPDATE to every sibling queue (excluding our own).
 * Called after net_proc stores peer_rtt_ms[idx] for a freshly-added peer,
 * so identity/negotiation/reputation/fleet processes can keep their
 * parallel peer_rtt_ms[] arrays in sync. IPC-only; the struct does not
 * traverse the network transport. Non-fatal on per-queue send errors —
 * this is telemetry, not protocol correctness.
 *
 * Known race (documented in BUGS / caveats): if the PEER_RTT_UPDATE
 * arrives at a sibling BEFORE the corresponding PEER message, the handler
 * won't find the peer and logs-and-drops. Periodic re-emission from
 * net_proc is a future refinement. */
static void broadcast_rtt_update(const process_t *proc, directory_t *queues,
                                 const uuid_t peer_uuid, int rtt_ms,
                                 logger_t *logger)
{
    generic_msg_t msg = {0};
    msg.type = PEER_RTT_UPDATE;
    msg.size = sizeof(peer_rtt_update_msg_t);
    memcpy(msg.info.peer_rtt_update.peer_uuid, peer_uuid, 16);
    msg.info.peer_rtt_update.rtt_ms = rtt_ms;

    size_t qsize = array_size(queues);
    for (size_t i = 0; i < qsize; i++) {
        data_t *name_val = NULL;
        if (array_get(queues, (int)i, &name_val) != 0)
            continue;
        char *qname = NULL;
        if (data_string_ptr(name_val, &qname) != 0)
            continue;
        if (strcmp(qname, proc->name) == 0)
            continue;
        int rc = messaging_send(qname, PEER_RTT_UPDATE, &msg, false);
        if (rc != 0)
            log_debug(logger, "Network: rtt_update to %s returned %d\n", qname, rc);
    }
}

/****************************
 * Network process main
 ****************************/

static int network_run(const net_transport_t *transport,
                       process_t *proc, directory_t *queues,
                       queue_id_t signal, logger_t *logger)
{
    network_config_t *net_cfg = (network_config_t *)proc->conf.data_struct;
    int port_num = net_cfg->port ? net_cfg->port : COMM_PORT;

    /* Extract identity before opening the transport — non-IP transports
     * (DTN) derive their local endpoint name from myself->uuid and need
     * it at open() time. Socket transports ignore it. */
    identity_t *myself = NULL;
    public_identity_t *my_public = NULL;
    data_t *id_dat = NULL;
    char id_key[] = "identity";
    if (map_get(proc->configs, id_key, &id_dat) == 0) {
        config_t *id_cfg = NULL;
        if (data_object_ptr(id_dat, (void **)&id_cfg) == 0 &&
            id_cfg->data_struct != NULL) {
            myself = (identity_t *)id_cfg->data_struct;
            identity_publish(myself, &my_public);
        }
    }

    /* Some transports (currently: hybrid_net) require an extra config blob
     * that isn't in the standard network_config_t. Look for a same-named
     * entry in proc->configs; if present, pass its data_struct through as
     * params.transport_specific. The hybrid transport expects this to be
     * a hybrid_config_t. Other transports ignore the field. */
    const void *transport_specific = NULL;
    data_t *ts_dat = NULL;
    char ts_key[CFG_NAME_SIZE];
    snprintf(ts_key, sizeof(ts_key), "%s", transport->name);
    if (map_get(proc->configs, ts_key, &ts_dat) == 0) {
        config_t *ts_cfg = NULL;
        if (data_object_ptr(ts_dat, (void **)&ts_cfg) == 0 && ts_cfg != NULL)
            transport_specific = ts_cfg->data_struct;
    }

    net_transport_params_t params = {
        .net_cfg            = net_cfg,
        .logger             = logger,
        .port_base          = port_num,
        .myself             = myself,
        .proc               = proc,
        .transport_specific = transport_specific,
    };
    net_transport_ctx_t *tctx = NULL;
    if (transport->open(&tctx, &params) != 0) {
        log_error(logger, "Network: transport '%s' failed to open\n", transport->name);
        if (my_public != NULL) smrt_deref(my_public);
        return -1;
    }

    /* Preserve network FDs across daemonize */
    proc->flags |= NO_CLOSE_FILES;

    process_ctx_t pctx = {0};
    int ret = process_setup(proc, signal, logger, &pctx);
    if (ret != 0) {
        transport->close(tctx);
        if (my_public != NULL) smrt_deref(my_public);
        return ret;
    }

    /* Spawn receiver threads (in the daemonized child) */
    bool stop = false;
    net_thread_ctx_t thread_ctx = {
        .transport     = transport,
        .ctx           = tctx,
        .proc          = proc,
        .queues        = queues,
        .logger        = logger,
        .net_cfg       = net_cfg,
        .myself        = myself,
        .stop          = &stop,
        .transport_cfg = transport_specific,
    };

    pthread_t peer_thread, bcast_thread, grp_thread;
    pthread_create(&peer_thread,  NULL, peer_receiver_thread,      &thread_ctx);
    pthread_create(&bcast_thread, NULL, broadcast_receiver_thread, &thread_ctx);
    pthread_create(&grp_thread,   NULL, group_receiver_thread,     &thread_ctx);

    char bcast_addr[IPV4_ADDR_LEN] = {0};
    cidr4_to_broadcast(net_cfg->ip4_cidr, bcast_addr);
    log_info(logger, "Network: ready (transport=%s, broadcast=%s port=%d)\n",
             transport->name, bcast_addr, port_num);

    while (keep_running(proc, &pctx.sig_q, logger))
    {
        sleep_until(proc, cadence);

        generic_msg_t buf = {0};
        int err = messaging_recv(&buf);
        if (err == -1 || err == ENOMSG)
            continue;

        if (buf.type == NET_MESSAGE) {
            net_msg_t *nmsg = &buf.info.net_msg;

            net_wire_msg_t wmsg = {0};
            snprintf(wmsg.process, sizeof(wmsg.process), "%s", nmsg->process);
            wmsg.function = nmsg->function;
            wmsg.data     = nmsg->obj;
            wmsg.data_len = nmsg->len;
            wmsg.encrypt  = nmsg->encrypt;

            /* Stamp from_whom with our identity so unencrypted-to-unknown-peer
             * messages carry full identity (UUID, name, keys). */
            if (my_public != NULL)
                memcpy(&wmsg.from_whom, my_public, sizeof(public_identity_t));
            else
                memcpy(&wmsg.from_whom, &nmsg->from_whom, sizeof(public_identity_t));

            bool is_broadcast = (nmsg->to_whom.address[0] == '\0');
            if (is_broadcast) {
                wmsg.to_whom.type = RECIPIENT_BROADCAST;
                snprintf(wmsg.to_whom.target.peer.address,
                         sizeof(wmsg.to_whom.target.peer.address),
                         "%s", bcast_addr);
                log_debug(logger, "Network: broadcasting %s.%s to %s\n",
                          nmsg->process, nmsg->function, bcast_addr);
            } else {
                wmsg.to_whom.type = RECIPIENT_PEER;
                memcpy(&wmsg.to_whom.target.peer, &nmsg->to_whom,
                       sizeof(public_identity_t));
            }

            int send_ret = net_encrypt_and_send(myself, &wmsg, transport, tctx,
                                                port_num, logger);
            if (send_ret != 0) {
                log_error(logger, "Network: send failed for %s.%s\n",
                          nmsg->process, nmsg->function);
                log_exception(logger);
            } else {
                log_info(logger, "Network: sent %s.%s to %s\n",
                         nmsg->process, nmsg->function,
                         is_broadcast ? bcast_addr : nmsg->to_whom.address);
            }
        }
        else if (buf.type == PEER) {
            /* A new peer was accepted — add for encrypted messaging */
            public_identity_t *new_peer = &buf.info.peer;
            peers_write_lock(proc);
            bool appended = false;
            int snapshot_rtt = 0;  /* captured under lock for rtt fan-out */
            if (new_peer->fullname[0] != '\0' &&
                proc->protocol.num_peers < MAX_PEERS) {
                bool found = false;
                for (size_t i = 0; i < proc->protocol.num_peers; i++) {
                    if (uuid_compare(proc->protocol.peers[i].uuid,
                                     new_peer->uuid) == 0) {
                        found = true;
                        break;
                    }
                }
                if (!found) {
                    size_t idx = proc->protocol.num_peers;
                    memcpy(&proc->protocol.peers[idx],
                           new_peer, sizeof(public_identity_t));
                    /* Ask the active transport what link latency it
                     * expects for this peer's address. Unknown → 0,
                     * which the scaling helper interprets as the
                     * fast-LAN default. */
                    int rtt = 0;
                    if (transport->link_class_ms != NULL) {
                        int est = transport->link_class_ms(tctx, new_peer->address);
                        if (est >= 0) rtt = est;
                    }
                    proc->protocol.peer_rtt_ms[idx] = rtt;
                    snapshot_rtt = rtt;
                    proc->protocol.num_peers++;
                    appended = true;
                }
            }
            peers_write_unlock(proc);

            if (appended) {
                log_info(logger, "Network: added peer %s (%s)\n",
                         new_peer->fullname, new_peer->address);

                /* Push the freshly-computed rtt to sibling processes so their
                 * peer_rtt_ms[] arrays track net_proc's view. Local IPC only.
                 * Uses the snapshot captured under the write lock above. */
                broadcast_rtt_update(proc, queues, new_peer->uuid,
                                     snapshot_rtt, logger);

                /* Retry deferred encrypted messages with the new peer. Match
                 * by envelope src_uuid when the entry has one (gateway-
                 * forwarded traffic under AT_NET_ENVELOPE); otherwise by
                 * the transport-reported from_addr (legacy / non-envelope). */
                pthread_mutex_lock(&deferred_lock);
                size_t remaining = 0;
                for (size_t di = 0; di < deferred_count; di++) {
                    deferred_msg_t *dm = &deferred_messages[di];
                    if (deferred_matches_peer(dm, new_peer)) {
                        uint8_t *plain = NULL;
                        size_t plain_len = 0;
                        if (decrypt_message(myself, new_peer, dm->data, dm->len,
                                            &plain, &plain_len) == 0) {
                            net_wire_msg_t wmsg;
                            if (net_message_from_wire(plain, plain_len, new_peer, &wmsg) == 0) {
                                route_to_process(&wmsg, proc, queues, logger);
                                log_info(logger, "Network: replayed deferred message from %s\n",
                                         dm->from_addr);
                            }
                            free(plain);
                            net_wire_msg_free(&wmsg);
                        } else {
                            if (remaining != di) deferred_messages[remaining] = *dm;
                            remaining++;
                        }
                    } else {
                        if (remaining != di) deferred_messages[remaining] = *dm;
                        remaining++;
                    }
                }
                deferred_count = remaining;
                pthread_mutex_unlock(&deferred_lock);
            }
        }
        else {
            /* Non-network messages: generic handler */
            run_message_handlers(proc, queues, buf.type, &buf);
        }
    }

    /* Cleanup */
    if (pctx.fd1 > 0) close(pctx.fd1);
    if (pctx.fd2 > 0) close(pctx.fd2);

    stop = true;
    pthread_join(peer_thread,  NULL);
    pthread_join(bcast_thread, NULL);
    pthread_join(grp_thread,   NULL);

    transport->close(tctx);
    if (my_public != NULL) smrt_deref(my_public);
    return ret;
}

/****************************
 * Entry points — thin adapters per transport name
 ****************************/

int network_run_by_name(const char *impl_name,
                        process_t *proc, directory_t *queues,
                        queue_id_t signal, logger_t *logger)
{
    const net_transport_t *t = net_transport_find(impl_name);
    if (t == NULL) {
        log_error(logger, "Network: unknown transport '%s'\n", impl_name);
        return -1;
    }
    return network_run(t, proc, queues, signal, logger);
}

int network_udp_ip4_run(process_t *proc, directory_t *queues, queue_id_t signal, logger_t *logger)
{ return network_run_by_name("udp_net_4", proc, queues, signal, logger); }
DECLARE_PROCESS(network, udp_net_4, network_udp_ip4_run);

int network_udp_ip6_run(process_t *proc, directory_t *queues, queue_id_t signal, logger_t *logger)
{ return network_run_by_name("udp_net_6", proc, queues, signal, logger); }
DECLARE_PROCESS(network, udp_net_6, network_udp_ip6_run);

int network_tcp_ip4_run(process_t *proc, directory_t *queues, queue_id_t signal, logger_t *logger)
{ return network_run_by_name("tcp_net_4", proc, queues, signal, logger); }
DECLARE_PROCESS(network, tcp_net_4, network_tcp_ip4_run);

int network_tcp_ip6_run(process_t *proc, directory_t *queues, queue_id_t signal, logger_t *logger)
{ return network_run_by_name("tcp_net_6", proc, queues, signal, logger); }
DECLARE_PROCESS(network, tcp_net_6, network_tcp_ip6_run);

/* DTN runner + its process declaration live in network/dtn/net_transport_dtn.c
 * so the table generator excludes them when AT_NET_DTN is off; the dtn/
 * subdirectory is excluded from preprocess.py in that case. */
