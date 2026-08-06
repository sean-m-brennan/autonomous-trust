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
#include "utilities/probes.h"
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
#include "structures/map.h"
#include "structures/data.h"

/* Group partition recovery — drop-site signal to IdentityProcess.
 *   See doc/architecture/partition-recovery.md §5.1 and the matching
 *   id_proc.c side. The string MUST match id_proc.c's
 *   ID_PARTITION_SIGNAL[] (which mirrors Python
 *   IdentityProtocol.partition_signal). Drift between the two breaks
 *   dispatch silently. */
static char NET_ID_PARTITION_SIGNAL[] = "partition_signal";

/* Per-from-addr last-signal-timestamp (CLOCK_MONOTONIC microseconds,
 * truncated to seconds for `integer_data` compatibility). 5s cooldown
 * per address keeps the identity queue clear under a chatty foreign
 * group. The map is initialized lazily on first use. */
static struct {
    map_t cooldown;
    bool inited;
    pthread_mutex_t lock;
} _net_partition_signal_state = {
    .inited = false,
};

static void _net_partition_signal_init_once(void)
{
    if (!_net_partition_signal_state.inited) {
        map_init(&_net_partition_signal_state.cooldown);
        pthread_mutex_init(&_net_partition_signal_state.lock, NULL);
        _net_partition_signal_state.inited = true;
    }
}

/* Forward a partition-recovery signal to IdentityProcess. Rate-limited
 * at one signal per `from_addr` per 5 seconds. Called from the group-
 * channel drop site (group_decrypt failure) — same role as Python's
 * NetProcess._signal_partition. */
static void _net_signal_partition(net_thread_ctx_t *ctx, const char *from_addr)
{
    if (ctx == NULL || from_addr == NULL || from_addr[0] == '\0') return;
    _net_partition_signal_init_once();

    /* 5s cooldown lookup. */
    struct timespec ts;
    if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0) return;
    int64_t now_s = (int64_t)ts.tv_sec;

    pthread_mutex_lock(&_net_partition_signal_state.lock);
    data_t *prev = NULL;
    if (map_get(&_net_partition_signal_state.cooldown,
                (map_key_t)from_addr, &prev) == 0 && prev != NULL) {
        int prev_s = 0;
        if (data_integer(prev, &prev_s) == 0 && now_s - prev_s < 5) {
            pthread_mutex_unlock(&_net_partition_signal_state.lock);
            return;
        }
    }
    char key_buf[64];
    snprintf(key_buf, sizeof(key_buf), "%s", from_addr);
    data_t *now_dat = integer_data((int)now_s);
    if (now_dat != NULL)
        map_set(&_net_partition_signal_state.cooldown, key_buf, now_dat);
    pthread_mutex_unlock(&_net_partition_signal_state.lock);

    /* Build a Message-like envelope with the from_addr as a JSON
     * string payload. */
    generic_msg_t sig = {0};
    sig.type = NET_MESSAGE;
    strncpy(sig.info.net_msg.process, "identity", PROC_NAME_LEN);
    sig.info.net_msg.function = NET_ID_PARTITION_SIGNAL;
    sig.info.net_msg.encrypt = false;
    json_t *body = json_string(from_addr);
    if (body != NULL) {
        net_msg_pack_json(&sig.info.net_msg, body);
        json_decref(body);
        int rc = messaging_send("identity", NET_MESSAGE, &sig, false);
        if (rc != 0) {
            log_debug(ctx->logger,
                      "Network: partition_signal: messaging_send failed (%d)\n",
                      rc);
        }
    }
}
#include "identity/group.h"
#include "structures/data.h"
#include "structures/array.h"

DEFINE_ERROR(ENET_SEND, "Network send failed");
DEFINE_ERROR(ENET_RECV, "Network receive failed");

/* Protocol-string definitions (declared `extern char[]` in network.h). */
char NET_FN_STATS_REQ[]  = "stats_req";
char NET_FN_STATS_RESP[] = "stats_resp";
char NET_FN_PING_AT[]    = "ping_at";
/* Reputation communication cut-off control (local IPC from rep_proc's
 * _publish_exclusion). Mirror: Python Network.exclude / Network.readmit. */
char NET_FN_EXCLUDE[]    = "exclude";
char NET_FN_READMIT[]    = "readmit";

static const int RECV_POLL_TIMEOUT_MS = 100;

/****************************
 * Base port resolution
 ****************************/

/* AT_COMM_PORT, read once and cached — same habit as the other AT_* overrides
 * (generate.c AT_TRANSPORT, AT_MYSTERY_MAX_AGE_SEC below, configuration.c
 * AT_SERIALIZE_MODE). 0 means "no usable override"; a value that is present but
 * unparseable or out of range is refused once, loudly, and the default kept —
 * never a silent 0, which would ask the kernel for an ephemeral port and put
 * the node somewhere no peer is looking. */
static int  env_comm_port       = 0;
static bool env_comm_port_read  = false;
static bool env_comm_port_bad   = false;
static char env_comm_port_raw[32] = {0};

static int comm_port_from_env(logger_t *logger)
{
    if (!env_comm_port_read) {
        env_comm_port_read = true;
        const char *raw = getenv("AT_COMM_PORT");
        if (raw != NULL && raw[0] != '\0') {
            snprintf(env_comm_port_raw, sizeof(env_comm_port_raw), "%s", raw);
            char *end = NULL;
            errno = 0;
            long val = strtol(raw, &end, 10);
            if (errno != 0 || end == raw || (end != NULL && *end != '\0') ||
                val < COMM_PORT_MIN || val > COMM_PORT_MAX) {
                env_comm_port_bad = true;
            } else {
                env_comm_port = (int)val;
            }
        }
    }
    if (env_comm_port_bad) {
        /* Report every time it is consulted with a logger: the resolver may be
         * called before the logger exists, and a refused override must not be
         * the one thing that goes unlogged. */
        log_warn(logger,
                 "Network: refusing AT_COMM_PORT='%s' (want an integer in "
                 "[%d, %d]); using default %d\n",
                 env_comm_port_raw, COMM_PORT_MIN, COMM_PORT_MAX, COMM_PORT);
    }
    return env_comm_port;
}

const char *net_port_source_name(net_port_source_t src)
{
    switch (src) {
        case PORT_SRC_CONFIG: return "config";
        case PORT_SRC_ENV:    return "AT_COMM_PORT";
        case PORT_SRC_DEFAULT:
        default:              return "default";
    }
}

int net_port_resolve(int cfg_port, net_port_source_t *src, logger_t *logger)
{
    if (cfg_port >= COMM_PORT_MIN && cfg_port <= COMM_PORT_MAX) {
        /* The provisioned config wins. Say so when an override was also given,
         * rather than letting the operator believe AT_COMM_PORT took effect. */
        if (comm_port_from_env(logger) != 0 && env_comm_port != cfg_port)
            log_info(logger,
                     "Network: config port %d overrides AT_COMM_PORT=%d\n",
                     cfg_port, env_comm_port);
        if (src != NULL) *src = PORT_SRC_CONFIG;
        return cfg_port;
    }
    if (cfg_port != 0)
        log_warn(logger,
                 "Network: refusing configured port %d (want an integer in "
                 "[%d, %d]); falling back\n",
                 cfg_port, COMM_PORT_MIN, COMM_PORT_MAX);

    int from_env = comm_port_from_env(logger);
    if (from_env != 0) {
        if (src != NULL) *src = PORT_SRC_ENV;
        return from_env;
    }
    if (src != NULL) *src = PORT_SRC_DEFAULT;
    return COMM_PORT;
}

/* Test seam: forget the cached AT_COMM_PORT so a test can exercise more than
 * one value in one process. Not declared in network.h — tests declare it. */
void net_port_resolve_reset(void)
{
    env_comm_port      = 0;
    env_comm_port_read = false;
    env_comm_port_bad  = false;
    env_comm_port_raw[0] = '\0';
}

/****************************
 * Blacklist / rejected addresses
 ****************************/

#define MAX_REJECTED 256
static char rejected_addresses[MAX_REJECTED][ADDR_LEN + 1];
static size_t rejected_count = 0;
static pthread_mutex_t rejected_lock = PTHREAD_MUTEX_INITIALIZER;

/* Canonicalize an address to the peer-listing key form (strip any
 * '/suffix', e.g. a CIDR mask), so an exclusion keyed on a peer's stored
 * address matches the raw from_addr seen at recv. Mirrors Python
 * NetworkProcess._norm_addr. @p out must hold ADDR_LEN + 1 bytes. */
static void _norm_addr(const char *address, char *out, size_t outlen)
{
    if (address == NULL || out == NULL || outlen == 0) {
        if (out != NULL && outlen > 0) out[0] = '\0';
        return;
    }
    size_t i = 0;
    for (; address[i] != '\0' && address[i] != '/' && i < outlen - 1; i++)
        out[i] = address[i];
    out[i] = '\0';
}

static bool reject_message(const char *address)
{
    char norm[ADDR_LEN + 1];
    _norm_addr(address, norm, sizeof(norm));
    bool found = false;
    pthread_mutex_lock(&rejected_lock);
    for (size_t i = 0; i < rejected_count; i++) {
        if (strcmp(rejected_addresses[i], norm) == 0) {
            found = true;
            break;
        }
    }
    pthread_mutex_unlock(&rejected_lock);
    return found;
}

static void blacklist_address(const char *address)
{
    char norm[ADDR_LEN + 1];
    _norm_addr(address, norm, sizeof(norm));
    pthread_mutex_lock(&rejected_lock);
    for (size_t i = 0; i < rejected_count; i++) {
        if (strcmp(rejected_addresses[i], norm) == 0) {
            pthread_mutex_unlock(&rejected_lock);
            return;
        }
    }
    if (rejected_count < MAX_REJECTED) {
        snprintf(rejected_addresses[rejected_count], sizeof(rejected_addresses[0]),
                 "%s", norm);
        rejected_count++;
    }
    pthread_mutex_unlock(&rejected_lock);
}

/* Reverse a blacklist/exclusion (explicit rehabilitation / readmit).
 * Removes @p address (normalized) from the rejection list, compacting the
 * fixed array. Mirrors Python NetworkProcess.handle_readmit's discard. */
static void remove_rejected_address(const char *address)
{
    char norm[ADDR_LEN + 1];
    _norm_addr(address, norm, sizeof(norm));
    pthread_mutex_lock(&rejected_lock);
    for (size_t i = 0; i < rejected_count; i++) {
        if (strcmp(rejected_addresses[i], norm) == 0) {
            /* memmove, not snprintf: source and destination are slots of the
             * same array, which violates snprintf's restrict contract. */
            if (i + 1 < rejected_count)
                memmove(rejected_addresses[i], rejected_addresses[i + 1],
                        (rejected_count - i - 1) * sizeof(rejected_addresses[0]));
            rejected_count--;
            rejected_addresses[rejected_count][0] = '\0';
            break;
        }
    }
    pthread_mutex_unlock(&rejected_lock);
}

/****************************
 * Per-peer "pest" counter (divergence.md M13)
 *
 * Tracks repeated misbehavior (failed decryption, malformed wire) from
 * a known sender. Once a peer's count exceeds NET_ANNOY_LIMIT it is
 * added to the rejection list so subsequent traffic is dropped before
 * any further processing. Mirrors Python NetworkProcess.pests +
 * annoy_limit (netprocess.py:307-312).
 ****************************/

#define MAX_PESTS DEFAULT_MAX_PEERS
typedef struct {
    char  address[ADDR_LEN + 1];
    int   count;
} peer_pest_t;

static peer_pest_t   peer_pests[MAX_PESTS];
static size_t        pest_count = 0;
static pthread_mutex_t pest_lock = PTHREAD_MUTEX_INITIALIZER;

/* Increment the annoy counter for @p address; promote to the rejection
 * list (and clear the counter slot) once the count exceeds
 * NET_ANNOY_LIMIT. Safe to call with an empty/NULL address — it's a
 * no-op then. */
static void pest_track_annoy(const char *address)
{
    if (address == NULL || address[0] == '\0') return;
    pthread_mutex_lock(&pest_lock);
    size_t slot = pest_count;  /* default: append if not found */
    for (size_t i = 0; i < pest_count; i++) {
        if (strcmp(peer_pests[i].address, address) == 0) {
            slot = i;
            break;
        }
    }
    int new_count = 0;
    bool over_limit = false;
    if (slot < pest_count) {
        peer_pests[slot].count++;
        new_count = peer_pests[slot].count;
    } else if (pest_count < MAX_PESTS) {
        slot = pest_count;
        snprintf(peer_pests[slot].address, sizeof(peer_pests[slot].address),
                 "%s", address);
        peer_pests[slot].count = 1;
        new_count = 1;
        pest_count++;
    }
    over_limit = (new_count > NET_ANNOY_LIMIT);
    if (over_limit) {
        /* compact slot out of the array */
        for (size_t i = slot; i + 1 < pest_count; i++)
            peer_pests[i] = peer_pests[i + 1];
        pest_count--;
    }
    pthread_mutex_unlock(&pest_lock);
    if (over_limit)
        blacklist_address(address);
}

/****************************
 * Deferred encrypted message queue (mystery handler)
 ****************************/

/* MAX_DEFERRED bounds peak DoS exposure (a misbehaving peer can't make
 * us hold unbounded memory by spraying encrypted messages we can't yet
 * decrypt). DEFERRED_MSG_MAX is the UDP-payload sanity cap (65535 IP
 * MTU minus IP+UDP headers); anything larger is malformed by
 * construction and gets truncated to this size.
 *
 * Storage is heap-backed (was static BSS pre-2026-05-28). The previous
 * design preallocated MAX_DEFERRED × DEFERRED_MSG_MAX ≈ 4.0 MiB of BSS
 * regardless of actual traffic, which dominated libautonomous_trust's
 * load image and made Cortex-M ports infeasible. Per-slot allocation
 * sized to the real message means typical traffic (consensus messages
 * < 1 KiB) consumes ~64 KiB rather than ~4 MiB peak. See
 * STRETCH_GOAL_3_EMBEDDED_PLAN.md §3 Q1 for the footprint story. */
#define MAX_DEFERRED 64
#define DEFERRED_MSG_MAX 65507

/* Flexible array member: each slot is one allocation of
 * sizeof(deferred_msg_t) + len, with the encrypted payload appended
 * inline. Compaction becomes a pointer move; no 65 KiB memcpy. */
typedef struct {
    size_t len;
    char from_addr[ADDR_LEN + 1];
    uuid_t src_uuid;        /* Original sender's UUID (envelope mode). */
    bool   has_src_uuid;    /* True iff src_uuid is meaningful. */
    int64_t deferred_at_s;  /* CLOCK_MONOTONIC seconds when deferred (age-out). */
    uint8_t data[];         /* Flexible: allocated with `len` bytes. */
} deferred_msg_t;

static deferred_msg_t *deferred_messages[MAX_DEFERRED];   /* owning ptrs, NULL when slot free */
static size_t deferred_count = 0;
static pthread_mutex_t deferred_lock = PTHREAD_MUTEX_INITIALIZER;

/* Age-out: a deferred entry whose sender never becomes a known peer is
 * reclaimed after this many seconds. Mirrors Python netprocess.py's
 * mystery_max_retries (60 retries × ~0.5s ≈ 30s) — but the C retry is
 * event-driven (on peer admission), not a polling thread, so we bound the
 * lifetime by wall-time instead of retry count. Without this, a burst of
 * un-resolvable encrypted frames permanently occupies the bounded queue and
 * starves legitimate deferrals. Overridable via AT_MYSTERY_MAX_AGE_SEC. */
#define DEFERRED_MAX_AGE_SEC_DEFAULT 30
static int64_t _deferred_max_age_s(void)
{
    const char *e = getenv("AT_MYSTERY_MAX_AGE_SEC");
    if (e != NULL && e[0] != '\0') {
        long v = atol(e);
        if (v > 0)
            return (int64_t)v;
    }
    return DEFERRED_MAX_AGE_SEC_DEFAULT;
}

static int64_t _deferred_now_s(void)
{
    struct timespec ts;
    if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0)
        return 0;
    return (int64_t)ts.tv_sec;
}

/* Free + compact out entries older than the age-out window, preserving
 * insertion order (so slot 0 remains the oldest survivor). Caller MUST hold
 * deferred_lock. Emits a net.mystery/aged_out counter per reclaimed entry,
 * mirroring Python's _probes.counter('net.mystery', 'drop', 'max_retries'). */
static void _deferred_sweep_stale_locked(int64_t now_s)
{
    int64_t max_age = _deferred_max_age_s();
    size_t remaining = 0;
    for (size_t i = 0; i < deferred_count; i++) {
        deferred_msg_t *dm = deferred_messages[i];
        if (dm == NULL)
            continue;
        if (now_s - dm->deferred_at_s >= max_age) {
            probes_counter("net.mystery", "aged_out", "max_age");
            free(dm);
            deferred_messages[i] = NULL;
        } else {
            if (remaining != i) {
                deferred_messages[remaining] = dm;
                deferred_messages[i] = NULL;
            }
            remaining++;
        }
    }
    deferred_count = remaining;
}

/* @p src_uuid is optional — pass NULL in non-envelope mode. When non-NULL,
 * the entry will be matched against a newly-admitted peer's UUID (the
 * from_addr field alone is ambiguous under gateway forwarding because the
 * transport reports the gateway's address, not the original sender's). */
/* Frama-C: skipped —
 * [solver-timeout] find_or_create_stat/defer_message: memset + memcpy + strcmp
 * preconditions.
 */
static void defer_message(const uint8_t *data, size_t len,
                          const char *from_addr, const uuid_t src_uuid)
{
    if (len > DEFERRED_MSG_MAX)
        len = DEFERRED_MSG_MAX;
    /* Allocate header + payload as one block so the slot is freed by a
     * single free(). On OOM, drop the message — same observable
     * behaviour as the prior "queue full" branch. */
    deferred_msg_t *dm = malloc(sizeof(*dm) + len);
    if (dm == NULL)
        return;
    dm->len = len;
    memcpy(dm->data, data, len);
    snprintf(dm->from_addr, sizeof(dm->from_addr), "%s", from_addr);
    if (src_uuid != NULL) {
        memcpy(dm->src_uuid, src_uuid, 16);
        dm->has_src_uuid = true;
    } else {
        memset(dm->src_uuid, 0, 16);
        dm->has_src_uuid = false;
    }
    int64_t now_s = _deferred_now_s();
    dm->deferred_at_s = now_s;
    pthread_mutex_lock(&deferred_lock);
    /* Reclaim aged-out entries first so a self-cleaning queue makes room
     * without a polling thread. */
    _deferred_sweep_stale_locked(now_s);
    if (deferred_count >= MAX_DEFERRED) {
        /* Still full of fresh (un-aged) entries: FIFO-evict the oldest (slot 0,
         * insertion order preserved) so this fresh — possibly legitimate —
         * deferral isn't starved by older, likely-unresolvable traffic. The
         * prior design dropped the NEW message here, which is what let a burst
         * starve later legitimate deferrals. */
        probes_counter("net.mystery", "evicted", "overflow");
        free(deferred_messages[0]);
        memmove(&deferred_messages[0], &deferred_messages[1],
                (MAX_DEFERRED - 1) * sizeof(deferred_messages[0]));
        deferred_count = MAX_DEFERRED - 1;
    }
    deferred_messages[deferred_count++] = dm;  /* ownership transferred */
    pthread_mutex_unlock(&deferred_lock);
}

/* Match predicate: a deferred entry matches a newly-admitted peer iff
 * the entry's src_uuid is set AND equals the peer's UUID, OR (fallback,
 * non-envelope mode) its from_addr matches the peer's address. */
/* Frama-C: skipped — deferred_matches_peer: strcmp cascade. */
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
    /* Per-slot owning pointers — free everything before resetting the
     * count, otherwise we leak the heap-backed payloads. */
    for (size_t i = 0; i < deferred_count; i++) {
        free(deferred_messages[i]);
        deferred_messages[i] = NULL;
    }
    deferred_count = 0;
    pthread_mutex_unlock(&deferred_lock);
}

bool net_proc_test_deferred_matches_peer(size_t idx,
                                         const public_identity_t *new_peer)
{
    bool m = false;
    pthread_mutex_lock(&deferred_lock);
    if (idx < deferred_count && deferred_messages[idx] != NULL)
        m = deferred_matches_peer(deferred_messages[idx], new_peer);
    pthread_mutex_unlock(&deferred_lock);
    return m;
}

/* Defer a message (non-envelope) — lets tests populate the queue without a
 * live socket. Wraps the static defer_message. */
void net_proc_test_defer(const uint8_t *data, size_t len, const char *from_addr)
{
    defer_message(data, len, from_addr, NULL);
}

/* Backdate every queued entry by @p secs so a test can simulate the passage of
 * time without sleeping, then exercise the age-out sweep. */
void net_proc_test_backdate_deferred(int64_t secs)
{
    pthread_mutex_lock(&deferred_lock);
    for (size_t i = 0; i < deferred_count; i++)
        if (deferred_messages[i] != NULL)
            deferred_messages[i]->deferred_at_s -= secs;
    pthread_mutex_unlock(&deferred_lock);
}

/* Run the age-out sweep at the current time and return how many entries
 * survive. */
size_t net_proc_test_sweep_stale(void)
{
    pthread_mutex_lock(&deferred_lock);
    _deferred_sweep_stale_locked(_deferred_now_s());
    size_t n = deferred_count;
    pthread_mutex_unlock(&deferred_lock);
    return n;
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

/* Frama-C: skipped —
 * [solver-timeout] find_or_create_stat/defer_message: memset + memcpy + strcmp
 * preconditions.
 */
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

/* Frama-C: skipped — decrypt_message: identity_decrypt stub precondition. */
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

/* Frama-C: skipped — [alloc-pattern] route_to_process: at_memcpy + strdup + messaging_send. */
/* stats_req / ping_at interception (divergence.md H7, H8) does NOT live here —
 * it lives in the outbound queue drain at the end of net_process_run(),
 * mirroring Python netprocess.py:501-528 which intercepts on the OUTBOUND
 * path (after the local process puts the request into the network process's
 * own queue). A remote peer's stats_req routes through route_to_process →
 * messaging_send("network", ...) → outbound drain, so a single intercept
 * site there handles both local and remote requesters. */
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
    gmsg.info.net_msg.from_rank = wmsg->from_rank;
    gmsg.info.net_msg.encrypt = wmsg->encrypt;
    /* Carry trace_id across the IPC hop so probes_trace_msg in the
     * downstream process stays correlated with the wire side. */
    memcpy(gmsg.info.net_msg.trace_id, wmsg->trace_id,
           sizeof(gmsg.info.net_msg.trace_id));
    /* Carry signature-verification result so downstream handlers can
     * reject spoofed Paxos / consensus messages. Mirrors Python
     * netprocess where Message.verified is set in deserialize_message
     * (network/message.py:243) and read by repprocess.handle_*. */
    gmsg.info.net_msg.verified = wmsg->verified;
    gmsg.info.net_msg.has_signature = wmsg->has_signature;

    int ret = messaging_send(wmsg->process, NET_MESSAGE, &gmsg, false);
    if (ret != 0) {
        log_error(logger, "Failed to route message to process '%s'\n", wmsg->process);
        if (gmsg.info.net_msg.function != NULL) free(gmsg.info.net_msg.function);
        return ret;
    }
    log_debug(logger, "Routed %s.%s from %s\n", wmsg->process, wmsg->function,
              wmsg->from_whom.nickname);
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

/* Forward declaration; defined immediately below this section. */
static int net_encrypt_and_send(const identity_t *myself, const net_wire_msg_t *msg,
                                const net_transport_t *transport,
                                net_transport_ctx_t *ctx,
                                int port, logger_t *logger);

/****************************
 * stats_req / ping_at outbound interception (divergence.md H7, H8)
 *
 * Mirrors Python netprocess.py:501-528. The local outbound drain
 * checks `process==network` plus a function selector and either
 * (H7) synthesizes a stats_resp pointed back at from_whom, or
 * (H8) answers the ping_at selector (C implements no PingAT; it once
 * RFC5905-style synchronous loop and posts a stats Message back
 * into the requester's queue via return_to.
 ****************************/

/* Serialize peer_stats[] as a JSON object keyed by address. C tracks
 * cumulative bytes + error counts (not bps like Python — no timestamp
 * series), so the value is an array `[bytes_sent, bytes_recv,
 * send_errors, recv_errors]`. Returns a heap-allocated NUL-terminated
 * byte buffer (caller frees). Returns NULL on allocation failure. */
static uint8_t *peer_stats_to_json_bytes(size_t *out_len)
{
    json_t *root = json_object();
    if (root == NULL) return NULL;
    for (size_t i = 0; i < stats_count; i++) {
        json_t *arr = json_array();
        if (arr == NULL) { json_decref(root); return NULL; }
        json_array_append_new(arr, json_integer((json_int_t)peer_stats[i].bytes_sent));
        json_array_append_new(arr, json_integer((json_int_t)peer_stats[i].bytes_recv));
        json_array_append_new(arr, json_integer((json_int_t)peer_stats[i].send_errors));
        json_array_append_new(arr, json_integer((json_int_t)peer_stats[i].recv_errors));
        json_object_set_new(root, peer_stats[i].address, arr);
    }
    char *s = json_dumps(root, JSON_COMPACT);
    json_decref(root);
    if (s == NULL) return NULL;
    *out_len = strlen(s);
    return (uint8_t *)s;
}

/* Answer a `ping_at` request with an explicit refusal.
 *
 * PingAT confirms an AT peer is present and answering on AT's own UDP ports via
 * a cooperating responder; it is NOT ICMP reachability. C implements no PingAT
 * responder or client, so the selector is intercepted here only so a
 * requester gets an answer. The reply carries the SAME function selector the
 * requester is waiting on, with an error body, so it fails fast instead of
 * waiting out its own timeout; a distinct "unsupported" selector would be
 * ignored by a requester blocked on `ping_at`. This is a local IPC reply into
 * return_to (as the removed ping worker did), never a wire message.
 *
 * Returns 0 when the refusal was posted, non-zero on allocation/send failure
 * (caller logs). Python performs the PingAT instead (netprocess.py) and
 * is the only implementation — see ISSUES.md. */
int refuse_ping_at_unsupported(const char *target_addr,
                            const char *return_to, logger_t *logger)
{
    json_t *jr = json_object();
    if (jr == NULL) return SYS_EXCEPTION();
    json_object_set_new(jr, "error", json_string("unsupported"));
    json_object_set_new(jr, "function", json_string(NET_FN_PING_AT));
    json_object_set_new(jr, "host", json_string(target_addr != NULL ? target_addr : ""));
    char *body = json_dumps(jr, JSON_COMPACT);
    json_decref(jr);
    if (body == NULL) return SYS_EXCEPTION();

    generic_msg_t gmsg = {0};
    gmsg.type = NET_MESSAGE;
    snprintf(gmsg.info.net_msg.process, sizeof(gmsg.info.net_msg.process), "network");
    gmsg.info.net_msg.function = strdup(NET_FN_PING_AT);
    gmsg.info.net_msg.obj = (uint8_t *)body;
    gmsg.info.net_msg.len = strlen(body);
    gmsg.info.net_msg.encrypt = false;
    int rc = messaging_send(return_to, NET_MESSAGE, &gmsg, false);
    if (rc != 0)
        log_warn(logger, "Network: failed to post ping_at refusal to '%s'\n", return_to);
    if (gmsg.info.net_msg.function != NULL) free(gmsg.info.net_msg.function);
    free(body);
    return rc;
}

/* Handle a stats_req intercepted on the outbound drain. Sends a
 * stats_resp wire message back to the requester via the same transport
 * the outbound drain would have used. Returns 0 on dispatch (caller
 * skips net_encrypt_and_send for this message). */
static int handle_outbound_stats_req(const net_msg_t *nmsg,
                                     const identity_t *myself,
                                     const net_transport_t *transport,
                                     net_transport_ctx_t *tctx,
                                     int port, logger_t *logger)
{
    size_t body_len = 0;
    uint8_t *body = peer_stats_to_json_bytes(&body_len);
    if (body == NULL) return SYS_EXCEPTION();

    net_wire_msg_t resp = {0};
    snprintf(resp.process, sizeof(resp.process), "network");
    resp.function = strdup(NET_FN_STATS_RESP);
    resp.data     = body;
    resp.data_len = body_len;
    resp.encrypt  = nmsg->encrypt;
    /* The requester rides on from_whom (preserved by route_to_process
     * from the inbound wire message). Reply unicast to that peer. */
    resp.to_whom.type = RECIPIENT_PEER;
    memcpy(&resp.to_whom.target.peer, &nmsg->from_whom, sizeof(public_identity_t));

    int rc = net_encrypt_and_send(myself, &resp, transport, tctx, port, logger);
    if (rc != 0)
        log_error(logger, "Network: stats_resp send to %s failed\n",
                  nmsg->from_whom.address);
    else
        log_debug(logger, "Network: replied stats_resp to %s\n",
                  nmsg->from_whom.address);

    if (resp.function != NULL) free(resp.function);
    free(body);
    return 0;
}

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
 *
 * Fairness (divergence.md H9, Python INBOUND_BUDGET=32): C parallelizes
 * the three logical channels (peer / broadcast / group) across distinct
 * OS threads, each blocking in recv() with RECV_POLL_TIMEOUT_MS=100ms.
 * One channel's traffic cannot starve another's because they have no
 * shared drain loop or shared work queue; OS scheduling provides the
 * fairness invariant that Python's single-event-loop drain has to
 * enforce manually with a per-iter cap. NET_INBOUND_BUDGET stays in
 * network.h as a documentation hook (cross-references Python's audit
 * site) but no C code path consumes it.
 ****************************/

/* Return the local address string for comparing to the packet sender.
 * `out_len` is explicit and callers pass IPV6_ADDR_LEN buffers: ADDR_LEN (32) is
 * too small for a full IPv6 literal (up to 45 chars), and the result feeds a
 * self-filter -- `strcmp(from_addr, my_addr) == 0` -- so a truncated value would
 * silently stop a node recognising its own traffic. cidr_split now clears `out`
 * and reports ENET_ADDR_TOO_LONG rather than truncating, which turns that into a
 * non-match instead of a wrong match. */
static void my_address(const network_config_t *net_cfg, bool ipv6, char *out,
                       size_t out_len)
{
    out[0] = '\0';
    if (ipv6)
        cidr_split((char *)net_cfg->ip6_cidr, out, out_len, NULL, 0);
    else
        cidr_split((char *)net_cfg->ip4_cidr, out, out_len, NULL, 0);
}

/* Deliver a PLAINTEXT frame from a peer we already know, but only an
 * allowlisted verb that declares itself unencrypted.
 *
 * Three conditions, all required: the bytes parse as a wire message, the
 * envelope's own encrypt flag is false, and the verb is one this protocol sends
 * in plaintext (identity_verb_is_unencrypted). A frame that merely failed to
 * decrypt is NOT accepted -- corrupt ciphertext, a stale group key or a forged
 * frame all fall through to the caller's existing log + annoy path.
 *
 * Parses with a NULL peer, i.e. without signature verification, mirroring
 * Python's validate=False on the same path. Only the ADDRESS is stamped onto
 * from_whom, exactly as the unknown-sender branch below does: public_identity_t
 * carries heap members (operator_key_binding, zta_credential) that
 * net_wire_msg_free does not release, so copying a whole peer struct over
 * from_whom would leak them and alias the peer's own pointers.
 *
 * Frama-C: skipped — [serialization] net_message_from_wire + at_logging.
 */
static bool try_unencrypted_from_known_peer(net_thread_ctx_t *ctx,
                                           const uint8_t *buf, size_t len,
                                           const char *from_addr)
{
    net_wire_msg_t wmsg;
    if (net_message_from_wire(buf, len, NULL, &wmsg) != 0)
        return false;
    if (wmsg.encrypt || !identity_verb_is_unencrypted(wmsg.function)) {
        if (!wmsg.encrypt && wmsg.function != NULL)
            log_warn(ctx->logger, "Refusing plaintext %s from known peer %s: "
                     "not an unencrypted verb\n", wmsg.function, from_addr);
        net_wire_msg_free(&wmsg);
        return false;
    }
    snprintf(wmsg.from_whom.address, sizeof(wmsg.from_whom.address),
             "%s", from_addr);
    route_to_process(&wmsg, ctx->proc, ctx->queues, ctx->logger);
    net_wire_msg_free(&wmsg);
    return true;
}

/* Frama-C: skipped —
 * [serialization] handle_inbound_peer/handle_inbound_group: net_message_from_wire +
 * group_decrypt + at_logging.
 */
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
            if (net_message_from_wire(plain, plain_len, peer, &wmsg) == 0) {
                route_to_process(&wmsg, ctx->proc, ctx->queues, ctx->logger);
            } else {
                /* Decrypted successfully but the inner wire is malformed —
                 * still annoy-worthy from a known peer. */
                pest_track_annoy(from_addr);
            }
            free(plain);
            net_wire_msg_free(&wmsg);
        } else if (try_unencrypted_from_known_peer(ctx, inner_buf, inner_len,
                                                   from_addr)) {
            /* A verb this protocol sends in plaintext by design. Delivered, and
             * deliberately NOT annoy-tracked: penalising it would have driven a
             * well-behaved peer toward blacklist for following the protocol. */
        } else {
            log_error(ctx->logger, "Network: decrypt failed (%d) from peer %s\n",
                      dec, from_addr);
            /* Mirror Python netprocess.py:307-312 pest tracking. Each
             * undecryptable frame from a known peer adds one annoy
             * point; over NET_ANNOY_LIMIT triggers blacklist. */
            pest_track_annoy(from_addr);
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

        char my_addr[IPV6_ADDR_LEN] = {0};
        my_address(ctx->net_cfg, false, my_addr, sizeof(my_addr));
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
     * transport. On a hybrid transport, send_broadcast_except_leg fans
     * out to every leg except the one that delivered this frame — so
     * nodes on the origin leg don't receive a duplicate of the broadcast
     * they sent (§4.3 D-followup). Single-leg transports leave the
     * except_leg method NULL and fall back to send_broadcast. */
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

    int origin_leg = -1;
    if (ctx->transport->last_recv_leg != NULL)
        origin_leg = ctx->transport->last_recv_leg(ctx->ctx, NET_CHAN_BROADCAST);

    int rc;
    if (origin_leg >= 0 && ctx->transport->send_broadcast_except_leg != NULL) {
        rc = ctx->transport->send_broadcast_except_leg(
            ctx->ctx, NET_CHAN_BROADCAST, buf, nbytes,
            ctx->net_cfg->port, (size_t)origin_leg);
    } else {
        rc = ctx->transport->send_broadcast(ctx->ctx, NET_CHAN_BROADCAST,
                                            buf, nbytes, ctx->net_cfg->port);
    }
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

        char my_addr[IPV6_ADDR_LEN] = {0};
        my_address(ctx->net_cfg, false, my_addr, sizeof(my_addr));
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

        char my_addr[IPV6_ADDR_LEN] = {0};
        my_address(ctx->net_cfg, false, my_addr, sizeof(my_addr));
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

/* Frama-C: skipped —
 * [serialization] handle_inbound_peer/handle_inbound_group: net_message_from_wire +
 * group_decrypt + at_logging.
 */
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
        /* Forward a partition-recovery signal to IdentityProcess. The
         * decrypt failure is the C analog of Python's
         * `from_addr not in self.group.addresses`: in both cases we've
         * received traffic from a peer who is not (currently) part of
         * our group. IdentityProcess will rate-limit + emit a
         * `partition_probe` and, on a response, initiate a normal
         * request_access to absorb the foreign group. See
         * doc/architecture/partition-recovery.md §5.1. */
        _net_signal_partition(ctx, from_addr);
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

/* Frama-C: skipped —
 * [solver-timeout] network_run: state-cascade through smrt_deref/
 * process_setup/map_get/identity_publish/at_logging (same pattern as
 * reputation_run/fleet_run/artifact_run).
 */
static int network_run(const net_transport_t *transport,
                       process_t *proc, directory_t *queues,
                       queue_id_t signal, logger_t *logger)
{
    network_config_t *net_cfg = (network_config_t *)proc->conf.data_struct;
    net_port_source_t port_src = PORT_SRC_DEFAULT;
    int port_num = net_port_resolve(net_cfg->port, &port_src, logger);
    log_info(logger, "Network: base port %d from %s (group %d)\n",
             port_num, net_port_source_name(port_src), port_num + 1);

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

            /* H7/H8 intercept: messages addressed to "network" with a
             * stats_req / ping selector never leave on the wire as-is.
             * stats_req synthesizes a stats_resp reply back to from_whom;
             * ping spawns a worker that posts the result into return_to.
             * See divergence.md H7, H8 and Python netprocess.py:501-528. */
            if (nmsg->function != NULL &&
                strcmp(nmsg->process, "network") == 0) {
                if (strcmp(nmsg->function, NET_FN_STATS_REQ) == 0) {
                    handle_outbound_stats_req(nmsg, myself, transport, tctx,
                                              port_num, logger);
                    continue;
                }
                if (strcmp(nmsg->function, NET_FN_PING_AT) == 0) {
                    const char *ret_q = nmsg->return_to[0] != '\0'
                                         ? nmsg->return_to : "network";
                    log_warn(logger,
                             "Network: ping_at is unsupported in C, refusing "
                             "request for %s (requester '%s')\n",
                             nmsg->to_whom.address, ret_q);
                    refuse_ping_at_unsupported(nmsg->to_whom.address, ret_q, logger);
                    continue;
                }
                /* Reputation communication cut-off enforcement. rep_proc's
                 * _publish_exclusion feeds an exclude/readmit control message
                 * carrying the peer's address (JSON string). An excluded
                 * address's inbound frames are dropped (reject_message gate in
                 * the ptp/group/any recv loops) and it is skipped as an
                 * outbound target. Mirrors Python netprocess handle_exclude /
                 * handle_readmit. Never leaves on the wire. */
                if (strcmp(nmsg->function, NET_FN_EXCLUDE) == 0 ||
                    strcmp(nmsg->function, NET_FN_READMIT) == 0) {
                    json_t *body = NULL;
                    char addr[ADDR_LEN + 1];
                    addr[0] = '\0';
                    if (net_msg_unpack_json(nmsg, &body) == 0 && body != NULL) {
                        const char *a = json_string_value(body);
                        if (a != NULL)
                            snprintf(addr, sizeof(addr), "%s", a);
                        json_decref(body);
                    }
                    if (addr[0] != '\0') {
                        if (strcmp(nmsg->function, NET_FN_EXCLUDE) == 0) {
                            blacklist_address(addr);
                            log_info(logger,
                                     "Network: reputation cut-off, excluding %s\n",
                                     addr);
                        } else {
                            remove_rejected_address(addr);
                            log_info(logger,
                                     "Network: reputation readmit %s\n", addr);
                        }
                    }
                    continue;
                }
            }

            /* Outbound-skip gate (reputation cut-off): never forward a
             * targeted (unicast) message to an excluded peer. Broadcasts
             * (empty to_whom) are unaffected — a receiver-side inbound-drop
             * gate handles those. Mirrors Python netprocess's outbound-skip
             * in the group-send / pseudo-multicast loops. */
            if (nmsg->to_whom.address[0] != '\0' &&
                reject_message(nmsg->to_whom.address)) {
                log_debug(logger,
                          "Network: outbound skip to excluded %s (%s.%s)\n",
                          nmsg->to_whom.address, nmsg->process,
                          nmsg->function ? nmsg->function : "?");
                continue;
            }

            net_wire_msg_t wmsg = {0};
            snprintf(wmsg.process, sizeof(wmsg.process), "%s", nmsg->process);
            wmsg.function = nmsg->function;
            wmsg.data     = nmsg->obj;
            wmsg.data_len = nmsg->len;
            wmsg.encrypt  = nmsg->encrypt;
            /* Forward trace_id if the sibling process set one; an empty
             * string causes net_message_to_wire to mint a fresh id. */
            memcpy(wmsg.trace_id, nmsg->trace_id, sizeof(wmsg.trace_id));

            /* Stamp from_whom with our identity so unencrypted-to-unknown-peer
             * messages carry full identity (UUID, name, keys). */
            if (my_public != NULL)
                memcpy(&wmsg.from_whom, my_public, sizeof(public_identity_t));
            else
                memcpy(&wmsg.from_whom, &nmsg->from_whom, sizeof(public_identity_t));
            /* Carry our topology rank on the envelope (public_identity_t drops
             * rank; `myself` is the full identity_t). from_whom is stamped self
             * above, so the rank is self's — mirrors Python from_whom._rank on
             * the wire. Fall back to whatever the sibling process set when we
             * are relaying a non-self from_whom. */
            wmsg.from_rank = (my_public != NULL && myself != NULL)
                             ? myself->rank : nmsg->from_rank;

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
                /* Mirrors Python netprocess.py:495 outbound-routed trace.
                 * The wire-side trace_id is in wmsg (possibly minted by
                 * net_message_to_wire when nmsg's was empty) — read from
                 * there so the trace event reflects what actually went
                 * onto the wire. */
                probes_trace_msg(wmsg.trace_id, nmsg->process, nmsg->function,
                                 "outbound_routed",
                                 "to_addr",
                                 is_broadcast ? bcast_addr : nmsg->to_whom.address,
                                 NULL);
            }
        }
        else if (buf.type == PEER) {
            /* A new peer was accepted — add for encrypted messaging */
            public_identity_t *new_peer = &buf.info.peer;
            peers_write_lock(proc);
            bool appended = false;
            int snapshot_rtt = 0;  /* captured under lock for rtt fan-out */
            if (new_peer->nickname[0] != '\0' &&
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
                         new_peer->nickname, new_peer->address);

                /* Push the freshly-computed rtt to sibling processes so their
                 * peer_rtt_ms[] arrays track net_proc's view. Local IPC only.
                 * Uses the snapshot captured under the write lock above. */
                broadcast_rtt_update(proc, queues, new_peer->uuid,
                                     snapshot_rtt, logger);

                /* Retry deferred encrypted messages with the new peer. Match
                 * by envelope src_uuid when the entry has one (gateway-
                 * forwarded traffic under AT_NET_ENVELOPE); otherwise by
                 * the transport-reported from_addr (legacy / non-envelope).
                 *
                 * Slots are owning heap pointers (post-2026-05-28). On
                 * successful replay we free the slot; on no-match or
                 * decrypt-failure we keep it and compact via pointer
                 * move (no payload copy). */
                pthread_mutex_lock(&deferred_lock);
                /* Reclaim aged-out entries before the match pass so stale,
                 * never-resolved mysteries don't linger across admissions. */
                _deferred_sweep_stale_locked(_deferred_now_s());
                size_t remaining = 0;
                for (size_t di = 0; di < deferred_count; di++) {
                    deferred_msg_t *dm = deferred_messages[di];
                    if (dm != NULL && deferred_matches_peer(dm, new_peer)) {
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
                            free(dm);             /* slot consumed */
                            deferred_messages[di] = NULL;
                        } else {
                            if (remaining != di) {
                                deferred_messages[remaining] = dm;
                                deferred_messages[di] = NULL;
                            }
                            remaining++;
                        }
                    } else {
                        if (remaining != di) {
                            deferred_messages[remaining] = dm;
                            deferred_messages[di] = NULL;
                        }
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
