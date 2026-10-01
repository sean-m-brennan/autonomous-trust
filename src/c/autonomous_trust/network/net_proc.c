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
#include <ctype.h>
#include <time.h>
#include <unistd.h>
#include <pthread.h>

#include "processes/processes.h"
#include "processes/extension.h"
#include "utilities/message.h"
#include "utilities/msg_types_priv.h"
#include "utilities/exception.h"
#include "utilities/logger.h"
#include "utilities/probes.h"
#include "network/network.h"
#include "network/net_message.h"
#include "network/net_transport.h"
#include "network/net_proc_priv.h"
#include "network/net_filter.h"
#include "identity/identity.h"
#include "identity/identity_priv.h"
#include "structures/map.h"
#include "structures/data.h"

/* ADDR_LEN (identity.h) sizes `public_identity_t.address` as
 * `char[ADDR_LEN + 1]`, and that buffer must hold any address inet_ntop can
 * produce -- IPV6_ADDR_LEN is INET6_ADDRSTRLEN. The two constants live in
 * different headers and were out of step for a long time (32 vs 46), which
 * truncated IPv6 addresses silently. This is the only file that includes both,
 * so it is where they get pinned together. */
_Static_assert(ADDR_LEN + 1 >= IPV6_ADDR_LEN,
               "ADDR_LEN + 1 must hold a full IPv6 literal (IPV6_ADDR_LEN)");

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
        net_msg_free_obj(&sig.info.net_msg);
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
#include "net_relay.h"
#include "net_registry.h"
#include "net_hub.h"
#include "contacts/area_card.h"
#include "contacts/directory.h"

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
char NET_FN_RELAY_ROUTE[] = "relay_route";
/* network -> identity, local IPC: one of our OWN relays proved who it is
 * ({relay: host:port, uuid, fp}), so the links identity mints can pin it.
 * Mirror: Python Network.relay_identity. */
char NET_FN_RELAY_IDENTITY[] = "relay_identity";
char NET_FN_RELAY_PEER[] = "relay_peer";
/* identity -> network, local IPC: our own reachability record ({body, sig}) to
 * file at each of our relays. Mirror: Python Network.reach_publish. */
char NET_FN_REACH_PUBLISH[] = "reach_publish";
/* The identity verb a contact's reachability record rides (contacts/reach.h);
 * the network hands relay lookup answers to identity under it. Mirror: Python
 * IdentityProtocol.reach_record. */
static char NET_ID_REACH_RECORD[] = "reach_record";
/* identity -> network, local IPC: the directory (net_registry.h). Mirror:
 * Python Network.dir_publish / dir_withdraw / dir_lookup. */
char NET_FN_DIR_PUBLISH[] = "dir_publish";
char NET_FN_DIR_WITHDRAW[] = "dir_withdraw";
char NET_FN_DIR_LOOKUP[] = "dir_lookup";
/* network -> identity: a lookup's one outcome, and a registry's word on our
 * publish or withdraw. Mirror: Python IdentityProtocol.dir_result / dir_status. */
char NET_ID_DIR_RESULT[] = "dir_result";
char NET_ID_DIR_STATUS[] = "dir_status";
/* Area hubs (net_hub.h), the same shape. Mirror: Python Network.hub_* and
 * IdentityProtocol.hub_result / hub_status. */
char NET_FN_HUB_PUBLISH[] = "hub_publish";
char NET_FN_HUB_WITHDRAW[] = "hub_withdraw";
char NET_FN_HUB_LOOKUP[] = "hub_lookup";
char NET_ID_HUB_RESULT[] = "hub_result";
char NET_ID_HUB_STATUS[] = "hub_status";


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
 * Network tunables (env → default)
 *
 * One resolver shared by all three knobs, because the cache-refuse-and-keep-
 * the-default logic is the interesting part and triplicating it is how the
 * three would drift from each other the way C drifted from Python. Same
 * discipline as comm_port_from_env above: read once, strict parse, range
 * check, refuse loudly.
 ****************************/

typedef struct {
    const char *env_name;
    int         dflt;
    int         min;
    int         max;
    /* cache */
    int         value;      /**< resolved override; only meaningful when found */
    bool        read;
    bool        found;      /**< a usable override was present */
    bool        bad;
    char        raw[32];
} net_knob_t;

static net_knob_t knob_annoy_limit = {
    "AT_NET_ANNOY_LIMIT", NET_ANNOY_LIMIT,
    NET_ANNOY_LIMIT_MIN, NET_ANNOY_LIMIT_MAX, 0, false, false, false, {0},
};
static net_knob_t knob_recv_poll_ms = {
    "AT_NET_RECV_POLL_MS", NET_RECV_POLL_MS,
    NET_RECV_POLL_MS_MIN, NET_RECV_POLL_MS_MAX, 0, false, false, false, {0},
};
static net_knob_t knob_mystery_max_age = {
    "AT_MYSTERY_MAX_AGE_SEC", NET_MYSTERY_MAX_AGE_SEC,
    NET_MYSTERY_MAX_AGE_SEC_MIN, NET_MYSTERY_MAX_AGE_SEC_MAX,
    0, false, false, false, {0},
};
/* Env names match Python's (system.py) exactly -- the point of these knobs is
 * that one deployment setting tunes both runtimes. */
static net_knob_t knob_conn_idle_ttl = {
    "AT_NET_CONN_IDLE_TTL", NET_CONN_IDLE_TTL_SEC,
    NET_CONN_IDLE_TTL_SEC_MIN, NET_CONN_IDLE_TTL_SEC_MAX,
    0, false, false, false, {0},
};
static net_knob_t knob_max_live_conns = {
    "AT_NET_MAX_CONNS", NET_MAX_LIVE_CONNS,
    NET_MAX_LIVE_CONNS_MIN, NET_MAX_LIVE_CONNS_MAX,
    0, false, false, false, {0},
};

/* The named counterpart of net_knob_t, for a knob whose values are NAMES
 * rather than numbers. Separate rather than generalized: the numeric resolver's
 * range check IS most of it, and a knob with two legal spellings needs a
 * membership test instead. Same cache-once and same refusal discipline. */
typedef struct {
    const char *env_name;
    /* cache */
    char        raw[32];
    bool        read;
    bool        found;
    bool        bad;
    net_wire_format_t value;
} net_str_knob_t;

static net_str_knob_t knob_wire_mode = { "AT_NET_WIRE_MODE", {0}, false, false, false, NET_WIRE_JSON };

net_wire_format_t net_wire_mode_resolve(net_knob_source_t *src, logger_t *logger)
{
    net_str_knob_t *k = &knob_wire_mode;
    if (!k->read) {
        k->read = true;
        const char *raw = getenv(k->env_name);
        if (raw != NULL && raw[0] != '\0') {
            snprintf(k->raw, sizeof(k->raw), "%s", raw);
            /* Trim and lowercase before matching: an operator writing " Proto"
             * means proto, and treating that as a refusal would present as this
             * whole path not happening. Python's resolve_env_choice does the
             * same. */
            char norm[sizeof(k->raw)];
            size_t n = 0;
            for (const char *c = raw; *c != '\0' && n + 1 < sizeof(norm); c++) {
                if (n == 0 && (*c == ' ' || *c == '\t')) continue;
                norm[n++] = (char)tolower((unsigned char)*c);
            }
            while (n > 0 && (norm[n - 1] == ' ' || norm[n - 1] == '\t')) n--;
            norm[n] = '\0';
            if (strcmp(norm, "proto") == 0) {
                k->value = NET_WIRE_PROTO;
                k->found = true;
            } else if (strcmp(norm, "json") == 0) {
                k->value = NET_WIRE_JSON;
                k->found = true;
            } else {
                k->bad = true;
            }
        }
    }
    if (k->bad) {
        /* Reported on every consultation that carries a logger, as the numeric
         * knobs are: the resolver can run before the logger exists, and a
         * refused override must not be the one thing that goes unlogged. */
        log_warn(logger,
                 "Network: refusing %s='%s' (want json|proto); using default %s\n",
                 k->env_name, k->raw, net_wire_format_name(NET_WIRE_MODE_DEFAULT));
    }
    if (k->found) {
        if (src != NULL) *src = KNOB_SRC_ENV;
        return k->value;
    }
    if (src != NULL) *src = KNOB_SRC_DEFAULT;
    return NET_WIRE_MODE_DEFAULT;
}

const char *net_knob_source_name(net_knob_source_t src)
{
    switch (src) {
        case KNOB_SRC_ENV: return "env";
        case KNOB_SRC_DEFAULT:
        default:           return "default";
    }
}

static int net_knob_resolve(net_knob_t *k, net_knob_source_t *src,
                            logger_t *logger)
{
    if (!k->read) {
        k->read = true;
        const char *raw = getenv(k->env_name);
        if (raw != NULL && raw[0] != '\0') {
            snprintf(k->raw, sizeof(k->raw), "%s", raw);
            char *end = NULL;
            errno = 0;
            long val = strtol(raw, &end, 10);
            if (errno != 0 || end == raw || (end != NULL && *end != '\0') ||
                val < (long)k->min || val > (long)k->max) {
                k->bad = true;
            } else {
                k->value = (int)val;
                k->found = true;
            }
        }
    }
    if (k->bad) {
        /* Reported on every consultation that carries a logger, for the same
         * reason as the port: the resolver can run before the logger exists,
         * and a refused override must not be the one thing that goes
         * unlogged. */
        log_warn(logger,
                 "Network: refusing %s='%s' (want an integer in [%d, %d]); "
                 "using default %d\n",
                 k->env_name, k->raw, k->min, k->max, k->dflt);
    }
    if (k->found) {
        if (src != NULL) *src = KNOB_SRC_ENV;
        return k->value;
    }
    if (src != NULL) *src = KNOB_SRC_DEFAULT;
    return k->dflt;
}

int net_annoy_limit_resolve(net_knob_source_t *src, logger_t *logger)
{
    return net_knob_resolve(&knob_annoy_limit, src, logger);
}

int net_recv_poll_ms_resolve(net_knob_source_t *src, logger_t *logger)
{
    return net_knob_resolve(&knob_recv_poll_ms, src, logger);
}

int net_mystery_max_age_resolve(net_knob_source_t *src, logger_t *logger)
{
    return net_knob_resolve(&knob_mystery_max_age, src, logger);
}

int net_conn_idle_ttl_resolve(net_knob_source_t *src, logger_t *logger)
{
    return net_knob_resolve(&knob_conn_idle_ttl, src, logger);
}

int net_max_live_conns_resolve(net_knob_source_t *src, logger_t *logger)
{
    return net_knob_resolve(&knob_max_live_conns, src, logger);
}

/* Test seam, as net_port_resolve_reset above: forget every cached tunable so
 * one process can exercise more than one value. Not declared in network.h. */
void net_knobs_resolve_reset(void)
{
    net_knob_t *all[] = { &knob_annoy_limit, &knob_recv_poll_ms,
                          &knob_mystery_max_age, &knob_conn_idle_ttl,
                          &knob_max_live_conns };
    for (size_t i = 0; i < sizeof(all) / sizeof(all[0]); i++) {
        all[i]->value  = 0;
        all[i]->read   = false;
        all[i]->found  = false;
        all[i]->bad    = false;
        all[i]->raw[0] = '\0';
    }
    /* The named knob caches separately and must reset with them, or a test that
     * exercises two AT_NET_WIRE_MODE values silently measures the first one
     * twice -- exactly the failure this seam exists to prevent. */
    knob_wire_mode.value  = NET_WIRE_JSON;
    knob_wire_mode.read   = false;
    knob_wire_mode.found  = false;
    knob_wire_mode.bad    = false;
    knob_wire_mode.raw[0] = '\0';
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
    /* Resolved, not the bare macro: AT_NET_ANNOY_LIMIT must reach this
     * comparison or the override is decorative. Cached after the first call,
     * so this stays cheap on the receive path. */
    over_limit = (new_count > net_annoy_limit_resolve(NULL, NULL));
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

/* ---- Test-only hooks; see net_proc_priv.h for why they exist. ---- */

void net_proc_test_reset_pests(void)
{
    pthread_mutex_lock(&pest_lock);
    pest_count = 0;
    pthread_mutex_unlock(&pest_lock);
    pthread_mutex_lock(&rejected_lock);
    rejected_count = 0;
    pthread_mutex_unlock(&rejected_lock);
}

void net_proc_test_track_annoy(const char *address)
{
    pest_track_annoy(address);
}

bool net_proc_test_is_rejected(const char *address)
{
    return reject_message(address);
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
 * starves legitimate deferrals. Overridable via AT_MYSTERY_MAX_AGE_SEC.
 *
 * Python bounds the same queue the same way as of 2026-08-10 (doc/architecture/networking.md):
 * it used to count retries on a ~0.5 s polling loop, which only approximated a
 * wall-time bound and drifted under load. Both sides now hold a deferral for
 * NET_MYSTERY_MAX_AGE_SEC seconds. */
static int64_t _deferred_max_age_s(void)
{
    return (int64_t)net_mystery_max_age_resolve(NULL, NULL);
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
 * deferred_lock. Emits a net.mystery/aged_out/max_age counter per reclaimed
 * entry — the identical triple Python emits since 2026-08-10, when it moved
 * from a retry count to this age bound (doc/architecture/networking.md). */
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
 * address (the gateway's cross_cluster switch). Empty string after reset. */
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

const public_identity_t *net_find_peer_by_uuid(const process_t *proc, const uuid_t uuid)
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

/* Run the network filter chain (net_filter.h) over one outbound frame. On
 * success *out is @p in when no filter changed it, else a buffer the caller
 * frees. */
static int filter_outbound(net_channel_t ch, const identity_t *myself,
                           const unsigned char *dst_uuid,
                           const uint8_t *in, size_t in_len,
                           const uint8_t **out, size_t *out_len)
{
    net_send_info_t info = {
        .channel  = ch,
        .src_uuid = myself != NULL ? myself->uuid : NULL,
        .dst_uuid = dst_uuid,
    };
    uint8_t *o = NULL;
    if (net_filters_outbound(&info, in, in_len, &o, out_len) != 0)
        return -1;
    *out = o;
    return 0;
}

/* Forward declaration; defined immediately below this section. */
static int net_encrypt_and_send(const identity_t *myself, const group_t *grp,
                                const net_wire_msg_t *msg,
                                const net_transport_t *transport,
                                net_transport_ctx_t *ctx,
                                int port, net_wire_format_t fmt, logger_t *logger);

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
 * is the only implementation — see doc/architecture/networking.md. */
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
                                     const group_t *grp,
                                     const net_transport_t *transport,
                                     net_transport_ctx_t *tctx,
                                     int port, net_wire_format_t fmt,
                                     logger_t *logger)
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

    int rc = net_encrypt_and_send(myself, grp, &resp, transport, tctx, port, fmt, logger);
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

/****************************
 * Rendezvous relays (net_relay.h)
 *
 * Which peers are reached through relays (uuid -> its relays in preference
 * order, the ACTIVE one first), and one registered client per relay. Filled
 * from identity's relay_route (an invitation's hints, or a saved contact's at
 * startup) and from inbound relayed frames (replies go back the way they came).
 * One relay carries a peer's traffic at a time; a failure rotates the next to
 * the front. Mirrors Python NetworkProcess._relay_routes / _relay_clients.
 ****************************/

#define NET_RELAY_MAX_ROUTES 128
#define NET_RELAY_MAX_CLIENTS 16
#define NET_RELAY_RETRY_SEC 5
#define NET_RELAY_UNREACHABLE_QUEUE 32
#define NET_RELAY_MAX_EXCLUDED 256
#define NET_RELAY_RECORD_QUEUE 32
#define NET_RELAY_LOOKUP_INTERVAL_SEC 60

typedef struct {
    uuid_t uuid;
    net_relay_ep_t eps[AT_RELAY_MAX];   /* eps[0] is the active relay */
    size_t n;
    /* The last frame sent to this peer by relay, and the relays it has been
     * tried through: a relay acknowledges nothing, so its later "unreachable"
     * is the only signal, and the frame is resent through the next relay. */
    uint8_t *last;
    size_t last_len;
    net_relay_ep_t tried[AT_RELAY_MAX];
    size_t n_tried;
    net_relay_ep_t live;                /* the relay its traffic last came by */
    bool has_live;
    /* A frame every relay refused is walked again, a few times: the peer may
     * register moments later (a relay restarting, or it minted its link before
     * its own registration finished). 0 = nothing to retry. */
    time_t retry_due;
    int retry_rounds;
} net_relay_route_t;

/* How many times a frame every relay refused is walked again. Same as
 * Python NetworkProcess.RELAY_RETRY_ROUNDS. */
#define NET_RELAY_RETRY_ROUNDS 3

typedef struct {
    net_relay_ep_t ep;
    char to[UUID_STR_LEN + 1];
} net_relay_refusal_t;

static struct {
    pthread_mutex_t lock;
    net_relay_route_t routes[NET_RELAY_MAX_ROUTES];
    size_t n_routes;
    struct {
        net_relay_ep_t ep;
        net_relay_client_t *client;
        time_t last_try;
        bool connecting;
        /* Our own relay's pin reached identity. The first try races
         * identity's startup (a local datagram to a process not yet listening
         * is dropped), so the loop retries until it lands. */
        bool announced;
    } clients[NET_RELAY_MAX_CLIENTS];
    size_t n_clients;
    net_relay_refusal_t refusals[NET_RELAY_UNREACHABLE_QUEUE];
    size_t n_refusals;
    net_relay_server_t *server;
    net_thread_ctx_t *ctx;          /* the receivers' context, for delivery */
    net_relay_test_send_fn test_send;
    int retry_sec;                  /* NET_RELAY_RETRY_SEC; tests shorten it */
    /* endpoint -> which relay answers there (a link's or our config's pin). */
    struct {
        net_relay_ep_t ep;
        net_relay_pin_t pin;
    } pins[NET_RELAY_MAX_CLIENTS];
    size_t n_pins;
    /* Who reputation cut off, by uuid and by signing key (hex), so a
     * distrusted relay or client gains nothing by claiming a new uuid. */
    char excluded_uuids[NET_RELAY_MAX_EXCLUDED][UUID_STR_LEN + 1];
    size_t n_excluded_uuids;
    char excluded_keys[NET_RELAY_MAX_EXCLUDED][crypto_sign_PUBLICKEYBYTES * 2 + 1];
    size_t n_excluded_keys;
    const process_t *test_proc;     /* whose peers[] tests consult (no ctx) */
    json_t *own_record;             /* our reachability record ({body, sig}) */
    /* Lookup answers from the relay readers, handed to identity by the loop. */
    char *record_answers[NET_RELAY_RECORD_QUEUE];
    size_t n_record_answers;
    /* Peers looked up lately (uuid -> time), so a lost peer is asked about
     * once a minute, not on every failed send. */
    struct {
        char uuid[UUID_STR_LEN + 1];
        time_t at;
    } asked[NET_RELAY_MAX_ROUTES];
    size_t n_asked;
    /* The directory: our own entries (handle -> wire), refiled at every
     * registration with our relays; registry answers from the readers; and
     * lookups in flight, answered to identity once. Mirrors Python
     * NetworkProcess._own_entries / relay_dir / _dir_lookups. */
    json_t *own_entries;
    net_registry_t *registry;
    struct {
        net_relay_ep_t ep;
        char *text;
    } dir_answers[NET_RELAY_RECORD_QUEUE];
    size_t n_dir_answers;
    net_dir_lookup_t lookups[NET_DIR_MAX_LOOKUPS];
    net_relay_test_dir_fn test_dir;
    /* Area hubs, the same shape: our own cards (area -> wire), refiled at
     * every registration; hub answers from the readers; and lookups in
     * flight, answered to identity once with every card any hub held.
     * Mirrors Python NetworkProcess._own_cards / relay_hub / _hub_lookups. */
    json_t *own_cards;
    net_hub_t *hub;
    struct {
        net_relay_ep_t ep;
        char *text;
    } hub_answers[NET_RELAY_RECORD_QUEUE];
    size_t n_hub_answers;
    struct {
        bool used;
        char area[AT_AREA_MAX + 1];
        net_relay_ep_t asked[NET_DIR_MAX_ASKED];
        bool answered[NET_DIR_MAX_ASKED];
        size_t n_asked;
        bool limited;
        json_t *cards;              /* [{card, relay}, ...] */
        double since;
    } hub_lookups[NET_HUB_MAX_LOOKUPS];
    net_relay_test_hub_fn test_hub;
} net_relay = { .lock = PTHREAD_MUTEX_INITIALIZER, .retry_sec = NET_RELAY_RETRY_SEC };

static bool _ep_eq(const net_relay_ep_t *a, const net_relay_ep_t *b)
{
    return a->port == b->port && strcmp(a->host, b->host) == 0;
}

static net_relay_route_t *_route_find_locked(const uuid_t uuid, bool create)
{
    for (size_t i = 0; i < net_relay.n_routes; i++)
        if (uuid_compare(net_relay.routes[i].uuid, uuid) == 0)
            return &net_relay.routes[i];
    if (!create)
        return NULL;
    size_t i = net_relay.n_routes;
    if (i == NET_RELAY_MAX_ROUTES)
        i = 0;                          /* full: overwrite the oldest slot */
    else
        net_relay.n_routes++;
    net_relay_route_t *r = &net_relay.routes[i];
    free(r->last);
    memset(r, 0, sizeof(*r));
    uuid_copy(r->uuid, uuid);
    return r;
}

static void _route_rotate_locked(net_relay_route_t *r)
{
    if (r->n < 2)
        return;
    net_relay_ep_t head = r->eps[0];
    memmove(&r->eps[0], &r->eps[1], (r->n - 1) * sizeof(r->eps[0]));
    r->eps[r->n - 1] = head;
}

/* @p eps go ahead of what the route already names, deduplicated and capped:
 * Python relay.merge_endpoints. */
static void _relay_route_set_list(const uuid_t uuid, const net_relay_ep_t *eps,
                                  size_t n)
{
    pthread_mutex_lock(&net_relay.lock);
    net_relay_route_t *r = _route_find_locked(uuid, true);
    net_relay_ep_t merged[AT_RELAY_MAX];
    size_t m = 0;
    for (size_t pass = 0; pass < 2; pass++) {
        const net_relay_ep_t *src = pass == 0 ? eps : r->eps;
        size_t cnt = pass == 0 ? n : r->n;
        for (size_t i = 0; i < cnt && m < AT_RELAY_MAX; i++) {
            bool dup = false;
            for (size_t j = 0; j < m && !dup; j++)
                dup = _ep_eq(&merged[j], &src[i]);
            if (!dup)
                merged[m++] = src[i];
        }
    }
    memcpy(r->eps, merged, m * sizeof(merged[0]));
    r->n = m;
    pthread_mutex_unlock(&net_relay.lock);
}

static bool _relay_route_active(const uuid_t uuid, net_relay_ep_t *out)
{
    pthread_mutex_lock(&net_relay.lock);
    net_relay_route_t *r = _route_find_locked(uuid, false);
    bool found = r != NULL && r->n > 0;
    if (found)
        *out = r->eps[0];
    pthread_mutex_unlock(&net_relay.lock);
    return found;
}

static bool _in_list(char list[][crypto_sign_PUBLICKEYBYTES * 2 + 1], size_t n,
                     const char *v)
{
    for (size_t i = 0; i < n; i++)
        if (strcasecmp(list[i], v) == 0)
            return true;
    return false;
}

/* The signing key (hex, lower-case) this node holds for @p uuid, or false. */
static bool _peer_key(const char *uuid, char *out, size_t out_len)
{
    uuid_t u;
    const process_t *proc = net_relay.ctx != NULL ? net_relay.ctx->proc
                                                  : net_relay.test_proc;
    if (proc == NULL || uuid_parse(uuid, u) != 0)
        return false;
    const public_identity_t *p = net_find_peer_by_uuid(proc, u);
    if (p == NULL || p->signature.public_hex[0] == '\0')
        return false;
    at_strlcpy(out, (const char *)p->signature.public_hex, out_len);
    for (char *q = out; *q; q++)
        if (*q >= 'A' && *q <= 'Z')
            *q = (char)(*q - 'A' + 'a');
    return true;
}

/* The relay gate, both directions: reputation cut @p uuid off, or the proven
 * key belongs to someone it cut off, or @p uuid is a peer we know under a
 * DIFFERENT key (an impostor). Unknown and neutral pass. Mirrors Python
 * NetworkProcess._is_distrusted. */
bool net_relay_is_distrusted(const char *uuid, const char *pubkey_hex)
{
    if (uuid == NULL)
        return false;
    const char *key = pubkey_hex != NULL ? pubkey_hex : "";
    pthread_mutex_lock(&net_relay.lock);
    bool bad = false;
    for (size_t i = 0; i < net_relay.n_excluded_uuids && !bad; i++)
        bad = strcasecmp(net_relay.excluded_uuids[i], uuid) == 0;
    if (!bad && key[0] != '\0')
        bad = _in_list(net_relay.excluded_keys, net_relay.n_excluded_keys, key);
    pthread_mutex_unlock(&net_relay.lock);
    if (bad)
        return true;
    char known[crypto_sign_PUBLICKEYBYTES * 2 + 1];
    return key[0] != '\0' && _peer_key(uuid, known, sizeof(known))
           && strcasecmp(known, key) != 0;
}

/* A lookup's answer, on a relay reader thread: queued for the loop, which hands
 * it to identity (the single writer of contacts, and the one that verifies). */
static void _relay_on_record(void *arg, const char *rid, const json_t *wire)
{
    (void)arg;
    (void)rid;
    if (wire == NULL)
        return;
    char *text = json_dumps(wire, JSON_COMPACT);
    if (text == NULL)
        return;
    pthread_mutex_lock(&net_relay.lock);
    if (net_relay.n_record_answers < NET_RELAY_RECORD_QUEUE) {
        net_relay.record_answers[net_relay.n_record_answers++] = text;
        text = NULL;
    }
    pthread_mutex_unlock(&net_relay.lock);
    free(text);
}

void net_relay_drain_records(void)
{
    for (;;) {
        pthread_mutex_lock(&net_relay.lock);
        char *text = NULL;
        if (net_relay.n_record_answers > 0) {
            text = net_relay.record_answers[0];
            memmove(&net_relay.record_answers[0], &net_relay.record_answers[1],
                    (net_relay.n_record_answers - 1) * sizeof(char *));
            net_relay.n_record_answers--;
        }
        pthread_mutex_unlock(&net_relay.lock);
        if (text == NULL)
            return;
        json_t *wire = json_loads(text, 0, NULL);
        free(text);
        if (wire == NULL)
            continue;
        generic_msg_t msg = {0};
        msg.type = NET_MESSAGE;
        at_strlcpy(msg.info.net_msg.process, "identity",
                   sizeof(msg.info.net_msg.process));
        msg.info.net_msg.function = NET_ID_REACH_RECORD;
        msg.info.net_msg.encrypt = false;
        net_msg_pack_json(&msg.info.net_msg, wire);
        json_decref(wire);
        messaging_send("identity", NET_MESSAGE, &msg, false);
        net_msg_free_obj(&msg.info.net_msg);
    }
}

static bool _relay_distrust(void *arg, const char *uuid, const char *pubkey_hex)
{
    (void)arg;
    return net_relay_is_distrusted(uuid, pubkey_hex);
}

static void _relay_on_unreachable(void *arg, const char *to, const char *host,
                                  int port)
{
    (void)arg;
    pthread_mutex_lock(&net_relay.lock);
    if (net_relay.n_refusals < NET_RELAY_UNREACHABLE_QUEUE) {
        net_relay_refusal_t *f = &net_relay.refusals[net_relay.n_refusals++];
        at_strlcpy(f->ep.host, host, sizeof(f->ep.host));
        f->ep.port = port;
        at_strlcpy(f->to, to, sizeof(f->to));
    }
    pthread_mutex_unlock(&net_relay.lock);
}

static void _relay_deliver(void *arg, const char *from_uuid,
                           const uint8_t *frame, size_t len,
                           const char *host, int port)
{
    net_thread_ctx_t *ctx = arg;
    uuid_t u;
    if (ctx == NULL || uuid_parse(from_uuid, u) != 0)
        return;
    net_relay_ep_t ep;
    at_strlcpy(ep.host, host, sizeof(ep.host));
    ep.port = port;
    /* Replies go back the way this came: that relay becomes the active one. */
    _relay_route_set_list(u, &ep, 1);
    if (net_find_peer_by_uuid(ctx->proc, u) != NULL) {
        pthread_mutex_lock(&net_relay.lock);
        net_relay_route_t *r = _route_find_locked(u, false);
        bool changed = r != NULL && (!r->has_live || !_ep_eq(&r->live, &ep));
        if (changed) {
            r->live = ep;
            r->has_live = true;
        }
        pthread_mutex_unlock(&net_relay.lock);
        /* Once per change, so an operator can see which relay carries a peer,
         * and when it failed over. */
        if (changed) {
            log_info(ctx->logger, "Relay: %.8s is talking to us through %s:%d\n",
                     from_uuid, host, port);
            /* Tell identity: first contact answers a contact with our record
             * (NET_FN_RELAY_PEER). */
            json_t *body = json_pack("{s:s}", "uuid", from_uuid);
            if (body != NULL) {
                generic_msg_t msg = {0};
                msg.type = NET_MESSAGE;
                at_strlcpy(msg.info.net_msg.process, "identity",
                           sizeof(msg.info.net_msg.process));
                msg.info.net_msg.function = NET_FN_RELAY_PEER;
                msg.info.net_msg.encrypt = false;
                net_msg_pack_json(&msg.info.net_msg, body);
                json_decref(body);
                if (messaging_send("identity", NET_MESSAGE, &msg, false) != 0)
                    log_debug(ctx->logger, "Relay: relay_peer for %.8s not sent\n",
                              from_uuid);
                net_msg_free_obj(&msg.info.net_msg);
            }
        }
    }
    handle_inbound_relayed(ctx, frame, len, from_uuid);
}

static net_relay_client_t *_relay_client(const net_relay_ep_t *ep)
{
    net_relay_client_t *c = NULL;
    pthread_mutex_lock(&net_relay.lock);
    for (size_t i = 0; i < net_relay.n_clients && c == NULL; i++)
        if (_ep_eq(&net_relay.clients[i].ep, ep))
            c = net_relay.clients[i].client;
    if (c == NULL && net_relay.n_clients < NET_RELAY_MAX_CLIENTS
        && net_relay.ctx != NULL) {
        c = net_relay_client_new(ep->host, ep->port, net_relay.ctx->myself,
                                 _relay_deliver, net_relay.ctx,
                                 net_relay.ctx->logger);
        if (c != NULL) {
            net_relay_client_on_unreachable(c, _relay_on_unreachable, NULL);
            net_relay_client_set_distrust(c, _relay_distrust, NULL);
            net_relay_client_on_record(c, _relay_on_record, NULL);
            net_relay_client_on_dir(c, net_relay_dir_answer, NULL);
            net_relay_client_on_hub(c, net_relay_hub_answer, NULL);
            for (size_t i = 0; i < net_relay.n_pins; i++)
                if (_ep_eq(&net_relay.pins[i].ep, ep))
                    net_relay_client_set_pin(c, &net_relay.pins[i].pin);
            size_t i = net_relay.n_clients++;
            net_relay.clients[i].ep = *ep;
            net_relay.clients[i].client = c;
            net_relay.clients[i].last_try = 0;
            net_relay.clients[i].connecting = false;
            net_relay.clients[i].announced = false;
        }
    }
    pthread_mutex_unlock(&net_relay.lock);
    return c;
}

/* Remember that @p pin answers at @p ep. A second, DIFFERENT pin for the same
 * endpoint is refused (logged): two links disagreeing on who a relay is means
 * one of them is wrong, and the first wins. Mirrors Python _pin_relay. */
static void _relay_pin(const net_relay_ep_t *ep, const net_relay_pin_t *pin)
{
    if (pin == NULL || !pin->set)
        return;
    logger_t *logger = net_relay.ctx != NULL ? net_relay.ctx->logger : NULL;
    net_relay_client_t *client = NULL;
    bool changed = false;
    pthread_mutex_lock(&net_relay.lock);
    size_t i;
    for (i = 0; i < net_relay.n_pins; i++)
        if (_ep_eq(&net_relay.pins[i].ep, ep))
            break;
    if (i < net_relay.n_pins) {
        const net_relay_pin_t *known = &net_relay.pins[i].pin;
        if (strcmp(known->uuid, pin->uuid) != 0 || strcmp(known->fp, pin->fp) != 0) {
            pthread_mutex_unlock(&net_relay.lock);
            log_warn(logger, "Relay: %s:%d is pinned to %.8s already; ignoring a "
                     "pin to %.8s\n", ep->host, ep->port, known->uuid, pin->uuid);
            return;
        }
    } else if (net_relay.n_pins < NET_RELAY_MAX_CLIENTS) {
        net_relay.pins[net_relay.n_pins].ep = *ep;
        net_relay.pins[net_relay.n_pins].pin = *pin;
        net_relay.n_pins++;
        changed = true;
    }
    for (size_t k = 0; k < net_relay.n_clients; k++)
        if (_ep_eq(&net_relay.clients[k].ep, ep))
            client = net_relay.clients[k].client;
    pthread_mutex_unlock(&net_relay.lock);
    if (client != NULL && changed) {
        net_relay_client_set_pin(client, pin);
        net_relay_pin_t proven;
        if (net_relay_client_connected(client)
            && (!net_relay_client_proven(client, &proven, NULL, 0)
                || strcmp(proven.uuid, pin->uuid) != 0
                || strcmp(proven.fp, pin->fp) != 0)) {
            log_warn(logger, "Relay: %s:%d is not the pinned relay; "
                     "disconnecting\n", ep->host, ep->port);
            net_relay_client_close(client);
        }
    }
}

/* Tell identity that one of our own relays proved who it is, so the links it
 * mints pin that relay. Local IPC. Mirrors Python _announce_own_relay. */
static void _relay_announce_own(const net_relay_ep_t *ep, net_relay_client_t *c)
{
    net_relay_ep_t own[AT_RELAY_MAX];
    size_t n = net_relay_own_list(own, AT_RELAY_MAX);
    bool mine = false;
    for (size_t i = 0; i < n && !mine; i++)
        mine = _ep_eq(&own[i], ep);
    if (mine && c != NULL) {
        /* File our record here too: a relay holds records in memory, so every
         * registration refills it. */
        pthread_mutex_lock(&net_relay.lock);
        json_t *rec = net_relay.own_record != NULL
                    ? json_incref(net_relay.own_record) : NULL;
        pthread_mutex_unlock(&net_relay.lock);
        if (rec != NULL) {
            (void)net_relay_client_publish(c, rec);
            json_decref(rec);
        }
        /* And our directory entries: a registry holds them in memory too. */
        pthread_mutex_lock(&net_relay.lock);
        json_t *entries = net_relay.own_entries != NULL
                        ? json_deep_copy(net_relay.own_entries) : NULL;
        pthread_mutex_unlock(&net_relay.lock);
        const char *h;
        json_t *w;
        json_object_foreach(entries, h, w)
            (void)net_relay_client_dir_publish(c, w);
        json_decref(entries);
        /* And our area cards: a hub holds them in memory too. */
        pthread_mutex_lock(&net_relay.lock);
        json_t *cards = net_relay.own_cards != NULL
                      ? json_deep_copy(net_relay.own_cards) : NULL;
        pthread_mutex_unlock(&net_relay.lock);
        json_object_foreach(cards, h, w)
            (void)net_relay_client_hub_publish(c, w);
        json_decref(cards);
    }
    net_relay_pin_t pin;
    if (!mine || c == NULL || !net_relay_client_proven(c, &pin, NULL, 0))
        return;
    char where[AT_RELAY_HOST_LEN + 16];
    snprintf(where, sizeof(where), strchr(ep->host, ':') ? "[%s]:%d" : "%s:%d",
             ep->host, ep->port);
    json_t *body = json_object();
    json_object_set_new(body, "relay", json_string(where));
    json_object_set_new(body, "uuid", json_string(pin.uuid));
    json_object_set_new(body, "fp", json_string(pin.fp));
    generic_msg_t msg = {0};
    msg.type = NET_MESSAGE;
    at_strlcpy(msg.info.net_msg.process, "identity", sizeof(msg.info.net_msg.process));
    msg.info.net_msg.function = NET_FN_RELAY_IDENTITY;
    msg.info.net_msg.encrypt = false;
    net_msg_pack_json(&msg.info.net_msg, body);
    json_decref(body);
    int sent = messaging_send("identity", NET_MESSAGE, &msg, false);
    net_msg_free_obj(&msg.info.net_msg);
    if (sent == 0) {
        pthread_mutex_lock(&net_relay.lock);
        for (size_t i = 0; i < net_relay.n_clients; i++)
            if (_ep_eq(&net_relay.clients[i].ep, ep))
                net_relay.clients[i].announced = true;
        pthread_mutex_unlock(&net_relay.lock);
    }
}

/* Act on a new exclusion at once: evict a distrusted client from the relay we
 * serve, and hang up on a relay we distrust (its peers' routes then fail
 * over). Mirrors Python _drop_distrusted_relays. */
static void _relay_drop_distrusted(const char *uuid)
{
    if (net_relay.server != NULL)
        net_relay_server_evict(net_relay.server, uuid);
    net_relay_client_t *clients[NET_RELAY_MAX_CLIENTS];
    size_t n = 0;
    pthread_mutex_lock(&net_relay.lock);
    for (size_t i = 0; i < net_relay.n_clients; i++)
        clients[n++] = net_relay.clients[i].client;
    pthread_mutex_unlock(&net_relay.lock);
    for (size_t i = 0; i < n; i++) {
        net_relay_pin_t proven;
        char key[crypto_sign_PUBLICKEYBYTES * 2 + 1];
        if (net_relay_client_connected(clients[i])
            && net_relay_client_proven(clients[i], &proven, key, sizeof(key))
            && net_relay_is_distrusted(proven.uuid, key)) {
            log_warn(net_relay.ctx != NULL ? net_relay.ctx->logger : NULL,
                     "Relay: relay %.8s is now distrusted; disconnecting\n",
                     proven.uuid);
            net_relay_client_close(clients[i]);
        }
    }
}

void net_relay_note_exclusion(const char *uuid, bool excluded)
{
    uuid_t u;
    if (uuid == NULL || uuid_parse(uuid, u) != 0)
        return;
    char ul[UUID_STR_LEN + 1], key[crypto_sign_PUBLICKEYBYTES * 2 + 1];
    uuid_unparse_lower(u, ul);
    bool have_key = _peer_key(ul, key, sizeof(key));
    pthread_mutex_lock(&net_relay.lock);
    if (excluded) {
        bool known = false;
        for (size_t i = 0; i < net_relay.n_excluded_uuids && !known; i++)
            known = strcmp(net_relay.excluded_uuids[i], ul) == 0;
        if (!known && net_relay.n_excluded_uuids < NET_RELAY_MAX_EXCLUDED)
            at_strlcpy(net_relay.excluded_uuids[net_relay.n_excluded_uuids++], ul,
                       sizeof(net_relay.excluded_uuids[0]));
        if (have_key && !_in_list(net_relay.excluded_keys, net_relay.n_excluded_keys, key)
            && net_relay.n_excluded_keys < NET_RELAY_MAX_EXCLUDED)
            at_strlcpy(net_relay.excluded_keys[net_relay.n_excluded_keys++], key,
                       sizeof(net_relay.excluded_keys[0]));
    } else {
        for (size_t i = 0; i < net_relay.n_excluded_uuids; i++)
            if (strcmp(net_relay.excluded_uuids[i], ul) == 0) {
                memcpy(net_relay.excluded_uuids[i],
                       net_relay.excluded_uuids[--net_relay.n_excluded_uuids],
                       sizeof(net_relay.excluded_uuids[0]));
                break;
            }
        for (size_t i = 0; have_key && i < net_relay.n_excluded_keys; i++)
            if (strcasecmp(net_relay.excluded_keys[i], key) == 0) {
                memcpy(net_relay.excluded_keys[i],
                       net_relay.excluded_keys[--net_relay.n_excluded_keys],
                       sizeof(net_relay.excluded_keys[0]));
                break;
            }
    }
    pthread_mutex_unlock(&net_relay.lock);
    if (excluded)
        _relay_drop_distrusted(ul);
}

/* One frame to @p to through relay @p ep: 0, or -1 if it cannot be reached. */
static int _relay_send_via(const net_relay_ep_t *ep, const uuid_t to,
                           const uint8_t *buf, size_t len)
{
    if (net_relay.test_send != NULL)
        return net_relay.test_send(ep->host, ep->port, to, buf, len);
    net_relay_client_t *c = _relay_client(ep);
    return (c != NULL && net_relay_client_send(c, to, buf, len) == 0) ? 0 : -1;
}

/* We lost @p uuid through every relay we know: ask each relay we are
 * registered at for its reachability record (filed under its key's
 * fingerprint). Answers go to identity, which verifies them. Once a minute per
 * peer. Mirrors Python NetworkProcess._lookup_reach. */
static void _relay_lookup_reach(const uuid_t peer)
{
    char u[UUID_STR_LEN + 1], key[crypto_sign_PUBLICKEYBYTES * 2 + 1];
    char rid[AT_RELAY_FP_BYTES * 2 + 1];
    uuid_unparse_lower(peer, u);
    if (!_peer_key(u, key, sizeof(key))
        || net_relay_key_fingerprint(key, rid, sizeof(rid)) != 0)
        return;
    time_t now = time(NULL);
    bool ask = true;
    net_relay_client_t *clients[NET_RELAY_MAX_CLIENTS];
    size_t n = 0;
    pthread_mutex_lock(&net_relay.lock);
    size_t i;
    for (i = 0; i < net_relay.n_asked; i++)
        if (strcmp(net_relay.asked[i].uuid, u) == 0)
            break;
    if (i < net_relay.n_asked) {
        ask = now - net_relay.asked[i].at >= NET_RELAY_LOOKUP_INTERVAL_SEC;
    } else if (net_relay.n_asked < NET_RELAY_MAX_ROUTES) {
        i = net_relay.n_asked++;
        at_strlcpy(net_relay.asked[i].uuid, u, sizeof(net_relay.asked[i].uuid));
    } else {
        i = 0;                              /* full: reuse the first slot */
        at_strlcpy(net_relay.asked[0].uuid, u, sizeof(net_relay.asked[0].uuid));
    }
    if (ask) {
        net_relay.asked[i].at = now;
        for (size_t k = 0; k < net_relay.n_clients; k++)
            clients[n++] = net_relay.clients[k].client;
    }
    pthread_mutex_unlock(&net_relay.lock);
    size_t asked = 0;
    for (size_t k = 0; k < n; k++)
        if (net_relay_client_connected(clients[k])
            && net_relay_client_lookup(clients[k], rid) == 0)
            asked++;
    if (asked > 0)
        log_info(net_relay.ctx != NULL ? net_relay.ctx->logger : NULL,
                 "Relay: looking up where %.8s is now (%zu relay(s))\n", u, asked);
}

int net_relay_send_to_peer(const uuid_t peer, const uint8_t *buf, size_t len)
{
    pthread_mutex_lock(&net_relay.lock);
    net_relay_route_t *r = _route_find_locked(peer, false);
    size_t attempts = r != NULL ? r->n : 0;
    pthread_mutex_unlock(&net_relay.lock);
    if (attempts == 0)
        return 1;                       /* no route: not ours to send */
    logger_t *logger = net_relay.ctx != NULL ? net_relay.ctx->logger : NULL;
    for (size_t i = 0; i < attempts; i++) {
        net_relay_ep_t ep;
        if (!_relay_route_active(peer, &ep))
            return -1;
        if (_relay_send_via(&ep, peer, buf, len) == 0) {
            uint8_t *copy = malloc(len > 0 ? len : 1);
            pthread_mutex_lock(&net_relay.lock);
            r = _route_find_locked(peer, false);
            if (r != NULL) {
                free(r->last);
                r->last = copy;
                r->last_len = copy != NULL ? len : 0;
                if (copy != NULL && len > 0)
                    memcpy(copy, buf, len);
                r->tried[0] = ep;
                r->n_tried = 1;
                r->retry_due = 0;       /* a new frame: the old one is moot */
                r->retry_rounds = 0;
                copy = NULL;
            }
            pthread_mutex_unlock(&net_relay.lock);
            free(copy);
            return 0;
        }
        log_info(logger, "Relay: %s:%d unusable for a peer; trying the next\n",
                 ep.host, ep.port);
        pthread_mutex_lock(&net_relay.lock);
        r = _route_find_locked(peer, false);
        if (r != NULL && r->n > 0 && _ep_eq(&r->eps[0], &ep))
            _route_rotate_locked(r);
        pthread_mutex_unlock(&net_relay.lock);
    }
    _relay_lookup_reach(peer);
    return -1;
}

void net_relay_note_unreachable(const char *host, int port, const char *to_uuid)
{
    _relay_on_unreachable(NULL, to_uuid, host, port);
}

/* A relay said it cannot reach a peer: fail over to the peer's next relay and
 * resend the frame the refusal answers. Each frame is tried at most once per
 * relay, so a peer registered nowhere ends the walk. Mirrors Python
 * NetworkProcess._drain_relay_unreachable. */
void net_relay_drain_unreachable(void)
{
    logger_t *logger = net_relay.ctx != NULL ? net_relay.ctx->logger : NULL;
    for (;;) {
        pthread_mutex_lock(&net_relay.lock);
        if (net_relay.n_refusals == 0) {
            pthread_mutex_unlock(&net_relay.lock);
            return;
        }
        net_relay_refusal_t f = net_relay.refusals[0];
        memmove(&net_relay.refusals[0], &net_relay.refusals[1],
                (net_relay.n_refusals - 1) * sizeof(net_relay.refusals[0]));
        net_relay.n_refusals--;
        uuid_t to;
        net_relay_route_t *r = uuid_parse(f.to, to) == 0
                             ? _route_find_locked(to, false) : NULL;
        if (r == NULL || r->n == 0 || !_ep_eq(&r->eps[0], &f.ep)
            || r->last == NULL) {
            if (r != NULL && r->n > 0 && _ep_eq(&r->eps[0], &f.ep))
                _route_rotate_locked(r);
            pthread_mutex_unlock(&net_relay.lock);
            continue;                   /* stale, or nothing to resend */
        }
        _route_rotate_locked(r);
        uint8_t *frame = malloc(r->last_len > 0 ? r->last_len : 1);
        size_t flen = r->last_len;
        if (frame != NULL && flen > 0)
            memcpy(frame, r->last, flen);
        pthread_mutex_unlock(&net_relay.lock);
        if (frame == NULL)
            continue;
        bool sent = false;
        for (;;) {
            pthread_mutex_lock(&net_relay.lock);
            r = _route_find_locked(to, false);
            bool seen = r == NULL || r->n == 0;
            net_relay_ep_t next = {0};
            if (!seen) {
                next = r->eps[0];
                for (size_t i = 0; i < r->n_tried && !seen; i++)
                    seen = _ep_eq(&r->tried[i], &next);
                if (!seen && r->n_tried < AT_RELAY_MAX)
                    r->tried[r->n_tried++] = next;
            }
            size_t n_eps = r != NULL ? r->n : 0;
            bool retry = false;
            if (seen && r != NULL) {
                retry = r->retry_rounds < NET_RELAY_RETRY_ROUNDS;
                if (retry) {
                    r->retry_rounds++;
                    r->retry_due = time(NULL) + net_relay.retry_sec;
                } else {
                    r->retry_rounds = 0;
                    r->retry_due = 0;
                }
            }
            pthread_mutex_unlock(&net_relay.lock);
            if (seen)
                _relay_lookup_reach(to);
            if (seen) {
                if (retry)
                    log_info(logger, "Relay: none of %zu relay(s) reaches %.8s "
                             "yet; retrying in %d s\n", n_eps, f.to,
                             net_relay.retry_sec);
                else
                    log_warn(logger, "Relay: none of %zu relay(s) reaches %.8s\n",
                             n_eps, f.to);
                break;
            }
            if (_relay_send_via(&next, to, frame, flen) == 0) {
                log_info(logger, "Relay: %.8s now reached through %s:%d\n",
                         f.to, next.host, next.port);
                sent = true;
                break;
            }
            pthread_mutex_lock(&net_relay.lock);
            r = _route_find_locked(to, false);
            if (r != NULL && r->n > 0 && _ep_eq(&r->eps[0], &next))
                _route_rotate_locked(r);
            pthread_mutex_unlock(&net_relay.lock);
        }
        (void)sent;
        free(frame);
    }
}

/* Resend each frame every relay refused, once its retry is due, as a fresh
 * walk down the peer's route. Mirrors Python
 * NetworkProcess._retry_refused_relayed. */
void net_relay_retry_refused(void)
{
    time_t now = time(NULL);
    for (size_t i = 0;; i++) {
        pthread_mutex_lock(&net_relay.lock);
        if (i >= net_relay.n_routes) {
            pthread_mutex_unlock(&net_relay.lock);
            return;
        }
        net_relay_route_t *r = &net_relay.routes[i];
        if (r->retry_due == 0 || now < r->retry_due || r->last == NULL
            || r->n == 0) {
            pthread_mutex_unlock(&net_relay.lock);
            continue;
        }
        /* Parked until the walk it starts ends: a refusal re-arms it. */
        r->retry_due = 0;
        uuid_t to;
        uuid_copy(to, r->uuid);
        net_relay_ep_t ep = r->eps[0];
        r->tried[0] = ep;
        r->n_tried = 1;
        size_t flen = r->last_len;
        uint8_t *frame = malloc(flen > 0 ? flen : 1);
        if (frame != NULL && flen > 0)
            memcpy(frame, r->last, flen);
        pthread_mutex_unlock(&net_relay.lock);
        if (frame == NULL)
            continue;
        if (_relay_send_via(&ep, to, frame, flen) != 0) {
            char us[UUID_STR_LEN + 1];
            uuid_unparse_lower(to, us);
            _relay_on_unreachable(NULL, us, ep.host, ep.port);
        }
        free(frame);
    }
}

void net_relay_set_retry_sec(int sec)
{
    net_relay.retry_sec = sec;
}

/* One unicast to a peer: through its relays when it has a route, else the
 * transport. The frame is already sealed for the peer either way. */
static int _peer_unicast(const net_transport_t *transport,
                         net_transport_ctx_t *ctx, const uuid_t peer,
                         const uint8_t *buf, size_t len, const char *host,
                         int port)
{
    int rc = net_relay_send_to_peer(peer, buf, len);
    if (rc != 1)
        return rc;
    return transport->send_unicast(ctx, buf, len, host, port);
}

typedef struct {
    net_relay_ep_t ep;
} net_relay_connect_arg_t;

static void *_relay_connect_thread(void *arg)
{
    net_relay_connect_arg_t *a = arg;
    net_relay_client_t *c = _relay_client(&a->ep);
    if (c != NULL && net_relay_client_connect(c) == 0) {
        pthread_mutex_lock(&net_relay.lock);
        for (size_t i = 0; i < net_relay.n_clients; i++)
            if (_ep_eq(&net_relay.clients[i].ep, &a->ep))
                net_relay.clients[i].announced = false;  /* a new proof */
        pthread_mutex_unlock(&net_relay.lock);
        _relay_announce_own(&a->ep, c);
    }
    pthread_mutex_lock(&net_relay.lock);
    for (size_t i = 0; i < net_relay.n_clients; i++)
        if (_ep_eq(&net_relay.clients[i].ep, &a->ep))
            net_relay.clients[i].connecting = false;
    pthread_mutex_unlock(&net_relay.lock);
    free(a);
    return NULL;
}

/* Keep our registrations alive: our own relays (AT_USE_RELAY) and every one a
 * peer's route names -- a peer reaches us only through a relay we are
 * registered at, and may fail over to any on its list. Without this nobody
 * reaches us, and a node that only listens never sends, so "retry on the next
 * send" would never come. Each attempt runs on its own thread: a dead relay
 * costs a connect timeout the network loop must not wait out. */
static void _relay_maintain(void)
{
    if (net_relay.ctx == NULL)
        return;
    net_relay_ep_t held[NET_RELAY_MAX_CLIENTS];
    size_t n = net_relay_own_list(held, AT_RELAY_MAX);
    pthread_mutex_lock(&net_relay.lock);
    for (size_t i = 0; i < net_relay.n_routes; i++)
        for (size_t j = 0; j < net_relay.routes[i].n; j++) {
            bool dup = false;
            for (size_t k = 0; k < n && !dup; k++)
                dup = _ep_eq(&held[k], &net_relay.routes[i].eps[j]);
            if (!dup && n < NET_RELAY_MAX_CLIENTS)
                held[n++] = net_relay.routes[i].eps[j];
        }
    pthread_mutex_unlock(&net_relay.lock);
    time_t now = time(NULL);
    for (size_t k = 0; k < n; k++) {
        net_relay_client_t *c = _relay_client(&held[k]);
        bool announced = true;
        pthread_mutex_lock(&net_relay.lock);
        for (size_t i = 0; i < net_relay.n_clients; i++)
            if (_ep_eq(&net_relay.clients[i].ep, &held[k]))
                announced = net_relay.clients[i].announced;
        pthread_mutex_unlock(&net_relay.lock);
        if (c != NULL && !announced && net_relay_client_connected(c))
            _relay_announce_own(&held[k], c);
        if (c == NULL || net_relay_client_connected(c))
            continue;
        bool go = false;
        pthread_mutex_lock(&net_relay.lock);
        for (size_t i = 0; i < net_relay.n_clients; i++) {
            if (!_ep_eq(&net_relay.clients[i].ep, &held[k]))
                continue;
            if (!net_relay.clients[i].connecting
                && now - net_relay.clients[i].last_try >= NET_RELAY_RETRY_SEC) {
                net_relay.clients[i].connecting = true;
                net_relay.clients[i].last_try = now;
                go = true;
            }
            break;
        }
        pthread_mutex_unlock(&net_relay.lock);
        if (!go)
            continue;
        net_relay_connect_arg_t *a = malloc(sizeof(*a));
        pthread_t t;
        if (a != NULL) {
            a->ep = held[k];
            if (pthread_create(&t, NULL, _relay_connect_thread, a) == 0) {
                pthread_detach(t);
                continue;
            }
            free(a);
        }
        pthread_mutex_lock(&net_relay.lock);
        for (size_t i = 0; i < net_relay.n_clients; i++)
            if (_ep_eq(&net_relay.clients[i].ep, &held[k]))
                net_relay.clients[i].connecting = false;
        pthread_mutex_unlock(&net_relay.lock);
    }
}

static int net_encrypt_and_send(const identity_t *myself, const group_t *grp,
                                const net_wire_msg_t *msg,
                                const net_transport_t *transport,
                                net_transport_ctx_t *ctx,
                                int port, net_wire_format_t fmt, logger_t *logger)
{
    uint8_t *wire = NULL;
    size_t wire_len = 0;
    /* `fmt` comes from the ADDRESSED group (doc/architecture/network-wire-format.md),
     * resolved by the caller -- this function encrypts and sends, it does not decide
     * policy. */
    if (myself == NULL)
        /* Nothing serialized here can ever be verified by anyone: the wire
         * writer attaches a signature only when it is given a signer. Every
         * verified-gated handler on the far side will silently ignore it. */
        log_warn(logger, "Network: sending '%s' WITHOUT A SIGNER — the receiver "
                 "cannot verify it\n", msg->function ? msg->function : "(none)");
    if (net_message_to_wire_fmt(msg, myself, fmt, &wire, &wire_len) != 0)
        return -1;

    /* Broadcast: no encryption; falls back to per-peer unicast if the
     * transport has no native broadcast (e.g., TCP). */
    if (msg->to_whom.type == RECIPIENT_BROADCAST) {
        const uint8_t *send_buf = wire;
        size_t         send_len = wire_len;
        if (filter_outbound(NET_CHAN_BROADCAST, myself, NULL,
                            wire, wire_len, &send_buf, &send_len) != 0) {
            free(wire);
            return SYS_EXCEPTION();
        }
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
        if (send_buf != wire)
            free((void *)send_buf);
        free(wire);
        return ret;
    }

    /* Encrypted group multicast (Increment 7): group_encrypt the wire bytes
     * under the shared cohort key and send on NET_CHAN_GROUP. Mirrors the
     * broadcast branch's transport shape and the encrypted-peer branch's
     * nonce|ciphertext framing, but keyed to the group instead of one peer. The
     * receive side is handle_inbound_group (group_decrypt + route_to_process). */
    if (msg->to_whom.type == RECIPIENT_GROUP) {
        if (grp == NULL || grp->address[0] == '\0') {
            /* No group key held (not admitted / public-only view): a multicast
             * we cannot encrypt is dropped rather than leaked in the clear. */
            log_debug(logger, "Network: group multicast with no group key; dropping\n");
            free(wire);
            return -1;
        }
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
        /* Which key are we actually multicasting under? A group forked by uuid,
         * epoch or ownership is invisible in every other log line — the send
         * "succeeds" and the cohort simply never hears it — so name the key
         * here. has_private=0 means we hold only a PUBLIC view and are about to
         * encrypt with a zero secret, which nobody can open. */
        {
            char kfp[17] = {0};
            sodium_bin2hex(kfp, sizeof(kfp), grp->encryptor.public, 8);
            log_info(logger,
                     "Network: group multicast under key %s… epoch %lld has_private=%d\n",
                     kfp, (long long)grp->key_epoch,
                     sodium_is_zero(grp->encryptor.private,
                                    crypto_box_SECRETKEYBYTES) ? 0 : 1);
        }
        int enc = group_encrypt(grp, &plain, grp, nonce, cipher);
        free(wire);
        if (enc != 0) {
            log_error(logger, "Network: group_encrypt failed (%d) for %s\n",
                      enc, grp->address);
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
        if (filter_outbound(NET_CHAN_GROUP, myself, grp->uuid,
                            frame, frame_len, &send_buf, &send_len) != 0) {
            free(frame);
            return SYS_EXCEPTION();
        }
        int ret = transport->send_broadcast(ctx, NET_CHAN_GROUP,
                                            send_buf, send_len, port);
        if (ret == -1)
            log_debug(logger, "Network: transport lacks group multicast; skipping\n");
        if (send_buf != frame)
            free((void *)send_buf);
        free(frame);
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
        if (filter_outbound(NET_CHAN_PEER, myself, msg->to_whom.target.peer.uuid,
                            frame, frame_len, &send_buf, &send_len) != 0) {
            free(frame);
            return SYS_EXCEPTION();
        }
        const char *host = msg->to_whom.target.peer.address;
        int ret = _peer_unicast(transport, ctx, msg->to_whom.target.peer.uuid,
                                send_buf, send_len, host, port);
        if (ret == 0) track_send(host, send_len);
        else          track_send_error(host);
        if (send_buf != frame)
            free((void *)send_buf);
        free(frame);
        return ret;
    }

    /* Unencrypted peer send */
    const uint8_t *send_buf = wire;
    size_t         send_len = wire_len;
    if (filter_outbound(NET_CHAN_PEER, myself, msg->to_whom.target.peer.uuid,
                        wire, wire_len, &send_buf, &send_len) != 0) {
        free(wire);
        return SYS_EXCEPTION();
    }
    const char *host = msg->to_whom.target.peer.address;
    int ret = _peer_unicast(transport, ctx, msg->to_whom.target.peer.uuid,
                            send_buf, send_len, host, port);
    if (ret == 0) track_send(host, send_len);
    else          track_send_error(host);
    if (send_buf != wire)
        free((void *)send_buf);
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
 * OS threads, each blocking in recv() for the resolved poll timeout
 * (NET_RECV_POLL_MS=100ms by default, AT_NET_RECV_POLL_MS to override).
 * One channel's traffic cannot starve another's because they have no
 * shared drain loop or shared work queue; OS scheduling provides the
 * fairness invariant that Python's single-event-loop drain has to
 * enforce manually with a per-iter cap. NET_INBOUND_BUDGET stays in
 * network.h as a documentation hook (cross-references Python's audit
 * site) but no C code path consumes it.
 ****************************/

/* Return the local address string for comparing to the packet sender.
 * `out_len` is explicit and callers pass IPV6_ADDR_LEN buffers. That was
 * originally a local workaround: ADDR_LEN was 32, too small for a full IPv6
 * literal (up to 45 chars), and the result feeds a self-filter --
 * `strcmp(from_addr, my_addr) == 0` -- so a truncated value silently stopped a
 * node recognising its own traffic. ADDR_LEN is now 45, so an ADDR_LEN + 1
 * buffer would also be exactly big enough; the explicit `out_len` stays because
 * it is the right shape regardless, and cidr_split clears `out` and reports
 * ENET_ADDR_TOO_LONG rather than truncating, turning any future overflow into a
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

/* The envelope format traffic with `address` rides in
 * (doc/architecture/network-wire-format.md).
 *
 * A group lookup, because the format belongs to the GROUP: an address we can place in
 * our cohort speaks the cohort's format, and anything we cannot place -- a stranger, a
 * pre-admission newcomer, a peer in a group we do not hold -- is JSON. JSON is the
 * format every AT node can read, so it is the only safe answer when there is no group
 * to consult, and that is also why bootstrap is JSON unconditionally: discovery happens
 * before a group exists to ask.
 *
 * Mirrors Python NetworkProcess._wire_format_for_addr. Note what this does NOT do: look
 * at the arriving bytes. Deciding the format from the frame is detection, which is
 * deliberately unimplemented (doc/architecture/network-wire-format.md).
 */
static net_wire_format_t wire_format_for_address(const group_t *grp,
                                                 const char *address)
{
    /* Delegates rather than walking the address map itself: the rule belongs to
     * the group (group_wire_format_for_address), and one copy is what keeps the
     * production selection and the conformance-pinned one from drifting. */
    return group_wire_format_for_address(grp, address);
}

/* ---- The gateway boundary ------------------------------------------------
 *
 * Two invariants, both normative
 * (doc/architecture/network-wire-format.md, "The gateway boundary"), and the
 * C twin of Python NetworkProcess._held_groups / _groups_containing /
 * _crosses_gateway / _boundary_refuse:
 *
 *   G. A GROUP STOPS AT THE GATEWAY. A gateway is a full MEMBER of each cohort
 *      it bridges; no group spans it. So no address but the gateway's own may
 *      appear in two of the groups it holds.
 *   B. BOOTSTRAP DOES NOT CROSS THE GATEWAY. The pre-admission handshake
 *      (identity_verb_is_bootstrap) is domain-local. This is what ENFORCES G:
 *      the only way a group comes to span a gateway is for a node on one side
 *      to be admitted by a cohort on the other.
 *
 * Together these are why wire-format DETECTION is unnecessary rather than
 * merely risky (R+D.md Sec 2.5): every frame is either from a member of a group
 * we hold -- so the format is a lookup, wire_format_for_address above -- or it
 * is local bootstrap, so the format is JSON by rule. Relax either one and
 * detection is back on the table.
 *
 * NOTE the one configuration that can violate G: the gateway's group_forward
 * (libat_gateway, off unless the network config sets it) relays opaque group
 * ciphertext across transport legs by operator-configured route, which by
 * construction carries a group past a gateway that is not in it. See
 * extensions/gateway/gateway.c and doc/architecture/network-wire-format.md.
 */

/* Whether `address` is listed by a group, by walking its address_map values.
 * Factored out of wire_format_for_address so the boundary checks and the format
 * lookup cannot disagree about what "in this group" means. */
static bool group_lists_address(const group_t *grp, const char *address)
{
    if (grp == NULL || address == NULL || address[0] == '\0')
        return false;
    bool found = false;
    map_key_t key;
    data_t *value;
    map_entries_for_each((map_t *)&grp->address_map, key, value)
        string_t addr = NULL;
        if (data_string_ptr(value, &addr) == 0 && addr != NULL &&
            strcmp((const char *)addr, address) == 0)
            found = true;
    map_end_for_each
    return found;
}

/* How many of the groups we hold (primary + every child cohort we gateway)
 * list `address`, EXCLUDING our own address.
 *
 * A gateway is by construction a member of both its primary group and each
 * child cohort, so its own address is in every map and is never a violation.
 * Any OTHER address in two maps means those groups have merged across this
 * gateway -- invariant G. */
static size_t held_groups_containing(const process_t *proc,
                                     const identity_t *myself,
                                     const char *address)
{
    if (proc == NULL || address == NULL || address[0] == '\0')
        return 0;
    if (myself != NULL && strcmp(myself->address, address) == 0)
        return 0;
    size_t count = 0;
    if (group_lists_address(&proc->protocol.group, address))
        count++;
    if (proc->protocol.child_groups != NULL) {
        map_key_t key;
        data_t *value;
        map_entries_for_each(proc->protocol.child_groups, key, value)
            void *gp = NULL;
            if (data_object_ptr(value, &gp) == 0 && gp != NULL &&
                group_lists_address((const group_t *)gp, address))
                count++;
        map_end_for_each
    }
    return count;
}

/* True when `address` sits on the FAR side of a gateway boundary from our
 * primary group: a member of a child cohort we bridge but not of our own group.
 * Always false on a leaf node (no child groups), so the historical path is
 * untouched. */
static bool address_crosses_gateway(const process_t *proc,
                                    const identity_t *myself,
                                    const char *address)
{
    if (proc == NULL || proc->protocol.child_groups == NULL)
        return false;
    if (myself != NULL && address != NULL &&
        strcmp(myself->address, address) == 0)
        return false;
    if (group_lists_address(&proc->protocol.group, address))
        return false;   /* in our own group: not across anything */
    bool in_child = false;
    map_key_t key;
    data_t *value;
    map_entries_for_each(proc->protocol.child_groups, key, value)
        void *gp = NULL;
        if (data_object_ptr(value, &gp) == 0 && gp != NULL &&
            group_lists_address((const group_t *)gp, address))
            in_child = true;
    map_end_for_each
    return in_child;
}

/* Count + rate-limited log for a boundary refusal. Always returns true so call
 * sites read `if (boundary_refuse(...)) return;`.
 *
 * Logged at error, not debug, for the same reason the foreign-format drop is:
 * a boundary violation presents downstream as a peer having silently gone
 * quiet, and this line is the only thing that says why. The counter is
 * per-KIND rather than per-address (no dict here), which is enough to keep a
 * chatty violator from flooding the log. */
static bool boundary_refuse(logger_t *logger, const char *kind,
                            const char *address, const char *detail)
{
    static unsigned long counts[4] = {0, 0, 0, 0};
    size_t slot = 0;
    if (kind != NULL)
        slot = (size_t)((unsigned char)kind[0]) % 4;
    unsigned long n = ++counts[slot];
    if (n == 1 || (n % 10) == 0)
        log_error(logger,
                  "Network: gateway boundary refusing %s involving %s -- %s "
                  "(count: %lu)\n",
                  kind != NULL ? kind : "?",
                  (address != NULL && address[0] != '\0') ? address : "<unknown>",
                  detail != NULL ? detail : "", n);
    return true;
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
                                           const char *from_addr,
                                           net_wire_format_t fmt)
{
    net_wire_msg_t wmsg;
    if (net_message_from_wire_fmt(buf, len, NULL, fmt, &wmsg) != 0)
        return false;
    if (!wmsg.verified && wmsg.function != NULL
        && strcmp(wmsg.function, "group_key_update") == 0)
        log_warn(ctx->logger,
                 "Network: group_key_update arrived UNVERIFIED via %s "
                 "(has_signature=%d) — the rotation will be ignored\n",
                 "plaintext-from-known-peer", (int)wmsg.has_signature);
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

    /* Filters first (net_filter.h): they may drop or consume the frame, and
     * narrow what is decoded below. */
    net_inbound_meta_t meta;
    if (net_filters_inbound(ctx, NET_CHAN_PEER, buf, nbytes, from_addr, &meta)
        != NET_FILTER_CONTINUE)
        return;
    inner_buf = meta.inner;
    inner_len = meta.inner_len;
    /* A filter that knows the ORIGINAL sender (the routing envelope) names
     * it; from_addr may be a gateway, not the originator. */
    peer = meta.has_src_uuid ? net_find_peer_by_uuid(ctx->proc, meta.src_uuid)
                             : find_peer_by_address(ctx->proc, from_addr);

    if (peer != NULL) {
        uint8_t *plain = NULL;
        size_t plain_len = 0;
        int dec = decrypt_message(ctx->myself, peer, inner_buf, inner_len,
                                  &plain, &plain_len);
        if (dec == 0) {
            net_wire_msg_t wmsg;
            /* Keyed on the PEER's own address, not from_addr: under a forwarded
             * envelope from_addr is the gateway, and the format belongs to the
             * originator's group. */
            net_wire_format_t fmt =
                wire_format_for_address(&ctx->proc->protocol.group, peer->address);
            if (net_message_from_wire_fmt(plain, plain_len, peer, fmt, &wmsg) == 0) {
                /* A frame that DECRYPTED (so the peer's encryption key is the
                 * one we hold) but whose signature does not check out against
                 * the SAME peer entry's signing key. Those two keys arrive
                 * together in a PEER message, so a mismatch here means one of
                 * them is stale — and every handler gated on `verified`
                 * silently does nothing, which is how 107 group-key rotations
                 * were minted across 25 cohort runs and not one was ever
                 * adopted. Warned once per frame, naming the verb, because the
                 * damage is per-verb and invisible at the transport. */
                if (!wmsg.verified) {
                    /* Name WHICH of the two failures this is. They need
                     * different fixes and are indistinguishable from outside:
                     * an unsigned frame means the sender never signed it, a
                     * failed check means our peer entry's signing key is not
                     * the key it signed with, and an all-zero key means the
                     * entry never carried one at all. */
                    char sigkey[17] = {0};
                    sodium_bin2hex(sigkey, sizeof(sigkey),
                                   peer->signature.public, 8);
                    bool no_key = sodium_is_zero(peer->signature.public,
                                                 crypto_sign_PUBLICKEYBYTES);
                    log_warn(ctx->logger,
                             "Network: frame '%s' from %s DECRYPTED but is "
                             "UNVERIFIED (%s; peer signing key %s) — every "
                             "verified-gated handler will silently ignore it\n",
                             wmsg.function != NULL ? wmsg.function : "(none)",
                             peer->address,
                             !wmsg.has_signature ? "carries no signature"
                                                 : "signature did not check out",
                             no_key ? "ABSENT (all zero)" : sigkey);
                }
                /* Gateway boundary, invariant B. False on a leaf node and for
                 * a peer in our own group, so this is a gateway-only gate. */
                if (identity_verb_is_bootstrap(wmsg.function) &&
                    address_crosses_gateway(ctx->proc, ctx->myself,
                                            peer->address)) {
                    boundary_refuse(ctx->logger, "bootstrap_across_gateway",
                                    peer->address,
                                    "admitting across the boundary would make a "
                                    "group span it");
                } else {
                    route_to_process(&wmsg, ctx->proc, ctx->queues, ctx->logger);
                }
            } else {
                /* Decrypted successfully but the inner wire is malformed —
                 * still annoy-worthy from a known peer.
                 *
                 * THIS WAS SILENT, and net_message.h's own note on
                 * ENET_WIRE_FORMAT says why that is the worst possible place
                 * for silence: "a cohort misprovisioned into two formats
                 * presents as one peer having gone silent, and only a counter
                 * that says 'foreign format' rather than 'bad message' explains
                 * it." The frame authenticated — it IS this peer — so this is
                 * never ordinary noise. Name the format and the length: a
                 * format disagreement and a truncated payload are different
                 * faults and were previously indistinguishable, both presenting
                 * as a verb that vanishes between two healthy nodes. */
                log_warn(ctx->logger,
                         "Network: frame from %s decrypted but did not parse as"
                         " %s (%zu bytes, errnum %d) — DROPPED\n",
                         from_addr,
                         fmt == NET_WIRE_PROTO ? "protobuf" : "JSON",
                         plain_len, _exception.errnum);
                pest_track_annoy(from_addr);
            }
            free(plain);
            net_wire_msg_free(&wmsg);
        } else if (try_unencrypted_from_known_peer(
                       ctx, inner_buf, inner_len, from_addr,
                       wire_format_for_address(&ctx->proc->protocol.group,
                                               peer->address))) {
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
        /* Try as unencrypted (e.g. access_granted to unknown peer).
         * JSON, not a lookup: a sender we cannot place in any group is
         * bootstrap traffic by definition (doc/architecture/network-wire-format.md). */
        net_wire_msg_t wmsg;
        if (net_message_from_wire_fmt(inner_buf, inner_len, NULL,
                                      NET_WIRE_JSON, &wmsg) == 0) {
            snprintf(wmsg.from_whom.address, sizeof(wmsg.from_whom.address),
                     "%s", from_addr);
            if (!wmsg.verified && wmsg.function != NULL
                && strcmp(wmsg.function, "group_key_update") == 0)
                log_warn(ctx->logger,
                         "Network: group_key_update arrived UNVERIFIED via "
                         "unknown-sender-plaintext (has_signature=%d) — the rotation will be "
                         "ignored\\n", (int)wmsg.has_signature);
            route_to_process(&wmsg, ctx->proc, ctx->queues, ctx->logger);
            net_wire_msg_free(&wmsg);
        } else {
            /* Encrypted message from unknown peer — defer for retry. In
             * envelope mode the retry key is the originator's uuid (meta.src_uuid),
             * NOT from_addr — the latter is the gateway's address under a
             * forwarded frame, and the future peer IPC arrives carrying
             * the original sender's own address, not the gateway's. */
            /* INFO, not debug: with the envelope layer off this is the LAST
             * silent path a datagram can take on the receive side, and at
             * debug it is invisible in a cohort run — which leaves "the frame
             * never arrived" and "it arrived from an address we could not place"
             * looking identical from the logs. Bounded by MAX_DEFERRED, so it
             * cannot flood. */
            log_info(ctx->logger,
                     "Network: deferring encrypted frame (%zu bytes) from %s —"
                     " no peer known at that address yet\n",
                     inner_len, from_addr);
            defer_message(inner_buf, inner_len, from_addr,
                          meta.has_src_uuid ? meta.src_uuid : NULL);
        }
    }
}

int net_handle_relay_route(net_msg_t *nmsg, logger_t *logger)
{
    if (!uuid_is_null(nmsg->from_whom.uuid)) {
        log_warn(logger, "Network: refusing relay_route from the wire\n");
        return -1;
    }
    /* {uuid, relays: [host:port, ...]} in preference order; {uuid, relay} (one)
     * is also accepted. They go ahead of any the route already names. */
    json_t *body = NULL;
    uuid_t ru;
    const char *us = NULL;
    net_relay_ep_t eps[AT_RELAY_MAX];
    size_t n = 0;
    bool usable = false;
    if (net_msg_unpack_json(nmsg, &body) == 0 && body != NULL
        && (us = json_string_value(json_object_get(body, "uuid"))) != NULL
        && uuid_parse(us, ru) == 0) {
        json_t *list = json_object_get(body, "relays");
        json_t *one = json_object_get(body, "relay");
        size_t cnt = json_is_array(list) ? json_array_size(list)
                   : json_is_string(one) ? 1 : 0;
        usable = cnt > 0 && (list == NULL || json_is_array(list));
        for (size_t i = 0; usable && i < cnt && n < AT_RELAY_MAX; i++) {
            const char *text = json_is_array(list)
                ? json_string_value(json_array_get(list, i))
                : json_string_value(one);
            net_relay_pin_t pin;
            if (text != NULL
                && net_relay_parse_hint(text, eps[n].host, sizeof(eps[n].host),
                                        &eps[n].port, &pin) == 0) {
                _relay_pin(&eps[n], &pin);
                n++;
            } else {
                log_warn(logger, "Network: relay_route: %s is not "
                         "[uuid:fp@]host:port\n",
                         text != NULL ? text : "(not a string)");
            }
        }
    }
    int rc = -1;
    if (usable && n > 0) {
        _relay_route_set_list(ru, eps, n);
        rc = 0;
        /* Register with the first now: the hello that follows goes through it.
         * The rest are registered in the background. */
        net_relay_ep_t active;
        if (net_relay.test_send == NULL && _relay_route_active(ru, &active)) {
            net_relay_client_t *c = _relay_client(&active);
            if (c == NULL || net_relay_client_connect(c) != 0)
                log_warn(logger, "Relay: cannot register with %s:%d\n",
                         active.host, active.port);
            else
                _relay_announce_own(&active, c);
        }
        _relay_maintain();
    } else if (!usable) {
        log_warn(logger, "Network: unusable relay_route\n");
    }
    if (body != NULL)
        json_decref(body);
    return rc;
}

int net_handle_reach_publish(net_msg_t *nmsg, logger_t *logger)
{
    if (!uuid_is_null(nmsg->from_whom.uuid)) {
        log_warn(logger, "Network: refusing reach_publish from the wire\n");
        return -1;
    }
    json_t *wire = NULL;
    if (net_msg_unpack_json(nmsg, &wire) != 0 || !json_is_object(wire)
        || !json_is_string(json_object_get(wire, "body"))
        || !json_is_string(json_object_get(wire, "sig"))) {
        json_decref(wire);
        log_warn(logger, "Network: reach_publish: unusable record\n");
        return -1;
    }
    pthread_mutex_lock(&net_relay.lock);
    json_decref(net_relay.own_record);
    net_relay.own_record = json_incref(wire);
    pthread_mutex_unlock(&net_relay.lock);
    /* File it at each of our relays we are registered with now. */
    net_relay_ep_t own[AT_RELAY_MAX];
    size_t n = net_relay_own_list(own, AT_RELAY_MAX);
    for (size_t i = 0; i < n; i++) {
        net_relay_client_t *c = NULL;
        pthread_mutex_lock(&net_relay.lock);
        for (size_t k = 0; k < net_relay.n_clients; k++)
            if (_ep_eq(&net_relay.clients[k].ep, &own[i]))
                c = net_relay.clients[k].client;
        pthread_mutex_unlock(&net_relay.lock);
        if (c != NULL && net_relay_client_connected(c))
            (void)net_relay_client_publish(c, wire);
    }
    json_decref(wire);
    return 0;
}

/****************************
 * The directory (net_registry.h): identity's publish / withdraw / lookup, and
 * the registries' answers. Mirrors Python NetworkProcess.handle_dir_* and
 * _drain_relay_dir.
 ****************************/

void net_relay_set_test_dir(net_relay_test_dir_fn fn)
{
    pthread_mutex_lock(&net_relay.lock);
    net_relay.test_dir = fn;
    pthread_mutex_unlock(&net_relay.lock);
}

/* The relays an op goes to: connected clients (own relays only when
 * @p own_only), or, under a test stand-in, our own list. */
static size_t _dir_targets(bool own_only, net_relay_ep_t *eps, net_relay_client_t **cs,
                           size_t max)
{
    net_relay_ep_t own[AT_RELAY_MAX];
    size_t n_own = net_relay_own_list(own, AT_RELAY_MAX);
    size_t n = 0;
    pthread_mutex_lock(&net_relay.lock);
    if (net_relay.test_dir != NULL) {
        for (size_t i = 0; i < n_own && n < max; i++) {
            eps[n] = own[i];
            cs[n++] = NULL;
        }
    } else {
        for (size_t i = 0; i < net_relay.n_clients && n < max; i++) {
            bool mine = !own_only;
            for (size_t k = 0; k < n_own && !mine; k++)
                mine = _ep_eq(&own[k], &net_relay.clients[i].ep);
            if (mine && net_relay_client_connected(net_relay.clients[i].client)) {
                eps[n] = net_relay.clients[i].ep;
                cs[n++] = net_relay.clients[i].client;
            }
        }
    }
    pthread_mutex_unlock(&net_relay.lock);
    return n;
}

static int _dir_ask(const net_relay_ep_t *ep, net_relay_client_t *c, const char *op,
                    const char *handle, const json_t *entry)
{
    net_relay_test_dir_fn fn;
    pthread_mutex_lock(&net_relay.lock);
    fn = net_relay.test_dir;
    pthread_mutex_unlock(&net_relay.lock);
    if (fn != NULL)
        return fn(ep->host, ep->port, op, handle, entry);
    if (strcmp(op, "dir_publish") == 0)
        return net_relay_client_dir_publish(c, entry);
    if (strcmp(op, "dir_withdraw") == 0)
        return net_relay_client_dir_withdraw(c, handle);
    return net_relay_client_dir_lookup(c, handle);
}

static json_t *_local_payload(net_msg_t *nmsg, const char *verb, logger_t *logger)
{
    if (!uuid_is_null(nmsg->from_whom.uuid)) {
        log_warn(logger, "Network: refusing %s from the wire\n", verb);
        return NULL;
    }
    json_t *body = NULL;
    if (net_msg_unpack_json(nmsg, &body) != 0 || !json_is_object(body)) {
        json_decref(body);
        return json_object();
    }
    return body;
}

static void _to_identity(char *verb, json_t *body)
{
    generic_msg_t msg = {0};
    msg.type = NET_MESSAGE;
    at_strlcpy(msg.info.net_msg.process, "identity", sizeof(msg.info.net_msg.process));
    msg.info.net_msg.function = verb;
    msg.info.net_msg.encrypt = false;
    net_msg_pack_json(&msg.info.net_msg, body);
    json_decref(body);
    messaging_send("identity", NET_MESSAGE, &msg, false);
    net_msg_free_obj(&msg.info.net_msg);
}

/* "host:port", unbracketed, as Python's '%s:%d' % endpoint. */
static void _ep_text(const net_relay_ep_t *ep, char *out, size_t len)
{
    snprintf(out, len, "%s:%d", ep->host, ep->port);
}

static void _dir_answer(const char *handle, const json_t *entry,
                        const net_relay_ep_t *ep, bool limited)
{
    char where[AT_RELAY_HOST_LEN + 16] = "";
    if (ep != NULL)
        _ep_text(ep, where, sizeof(where));
    json_t *body = json_pack("{s:s, s:O, s:b, s:s}", "handle", handle,
                             "entry", entry != NULL ? entry : json_null(),
                             "limited", limited, "relay", where);
    if (body != NULL)
        _to_identity(NET_ID_DIR_RESULT, body);
}

int net_handle_dir_publish(net_msg_t *nmsg, logger_t *logger)
{
    json_t *body = _local_payload(nmsg, NET_FN_DIR_PUBLISH, logger);
    if (body == NULL)
        return -1;
    json_t *wire = json_object_get(body, "entry");
    at_dir_signed_t e;
    if (at_dir_from_wire(wire, &e) != AT_DIR_OK || at_dir_handle(&e) == NULL) {
        if (e.body != NULL)
            at_dir_free(&e);
        log_warn(logger, "Network: dir_publish: unusable entry\n");
        json_decref(body);
        return -1;
    }
    pthread_mutex_lock(&net_relay.lock);
    if (net_relay.own_entries == NULL)
        net_relay.own_entries = json_object();
    json_object_set(net_relay.own_entries, at_dir_handle(&e), wire);
    pthread_mutex_unlock(&net_relay.lock);
    at_dir_free(&e);
    net_relay_ep_t eps[NET_RELAY_MAX_CLIENTS];
    net_relay_client_t *cs[NET_RELAY_MAX_CLIENTS];
    size_t n = _dir_targets(true, eps, cs, NET_RELAY_MAX_CLIENTS);
    for (size_t i = 0; i < n; i++)
        (void)_dir_ask(&eps[i], cs[i], "dir_publish", NULL, wire);
    json_decref(body);
    return 0;
}

int net_handle_dir_withdraw(net_msg_t *nmsg, logger_t *logger)
{
    json_t *body = _local_payload(nmsg, NET_FN_DIR_WITHDRAW, logger);
    if (body == NULL)
        return -1;
    const char *h = json_string_value(json_object_get(body, "handle"));
    const char *handle = h != NULL ? h : "";
    pthread_mutex_lock(&net_relay.lock);
    if (net_relay.own_entries != NULL)
        json_object_del(net_relay.own_entries, handle);
    pthread_mutex_unlock(&net_relay.lock);
    net_relay_ep_t eps[NET_RELAY_MAX_CLIENTS];
    net_relay_client_t *cs[NET_RELAY_MAX_CLIENTS];
    size_t n = _dir_targets(true, eps, cs, NET_RELAY_MAX_CLIENTS);
    for (size_t i = 0; i < n; i++)
        (void)_dir_ask(&eps[i], cs[i], "dir_withdraw", handle, NULL);
    json_decref(body);
    return 0;
}

static double _mono(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (double)ts.tv_sec + (double)ts.tv_nsec / 1e9;
}

static net_dir_lookup_t *_lookup_find_locked(const char *handle)
{
    for (size_t i = 0; i < NET_DIR_MAX_LOOKUPS; i++)
        if (net_relay.lookups[i].used && strcmp(net_relay.lookups[i].handle, handle) == 0)
            return &net_relay.lookups[i];
    return NULL;
}

int net_handle_dir_lookup(net_msg_t *nmsg, logger_t *logger)
{
    json_t *body = _local_payload(nmsg, NET_FN_DIR_LOOKUP, logger);
    if (body == NULL)
        return -1;
    const char *raw = json_string_value(json_object_get(body, "handle"));
    char handle[AT_DIR_HANDLE_MAX + 1];
    if (at_dir_normalize_handle(raw, handle, sizeof(handle)) != 0) {
        _dir_answer(raw != NULL ? raw : "", NULL, NULL, false);
        json_decref(body);
        return 0;
    }
    json_decref(body);
    net_relay_ep_t eps[NET_RELAY_MAX_CLIENTS];
    net_relay_client_t *cs[NET_RELAY_MAX_CLIENTS];
    size_t n = _dir_targets(false, eps, cs, NET_RELAY_MAX_CLIENTS);
    net_relay_ep_t asked[NET_DIR_MAX_ASKED];
    size_t n_asked = 0;
    for (size_t i = 0; i < n && n_asked < NET_DIR_MAX_ASKED; i++)
        if (_dir_ask(&eps[i], cs[i], "dir_lookup", handle, NULL) == 0)
            asked[n_asked++] = eps[i];
    if (n_asked == 0) {
        _dir_answer(handle, NULL, NULL, false);
        return 0;
    }
    pthread_mutex_lock(&net_relay.lock);
    net_dir_lookup_t *l = _lookup_find_locked(handle);
    for (size_t i = 0; i < NET_DIR_MAX_LOOKUPS && l == NULL; i++)
        if (!net_relay.lookups[i].used)
            l = &net_relay.lookups[i];
    if (l == NULL) {                    /* full: replace the oldest */
        l = &net_relay.lookups[0];
        for (size_t i = 1; i < NET_DIR_MAX_LOOKUPS; i++)
            if (net_relay.lookups[i].since < l->since)
                l = &net_relay.lookups[i];
    }
    memset(l, 0, sizeof(*l));
    l->used = true;
    at_strlcpy(l->handle, handle, sizeof(l->handle));
    memcpy(l->asked, asked, n_asked * sizeof(asked[0]));
    l->n_asked = n_asked;
    l->since = _mono();
    pthread_mutex_unlock(&net_relay.lock);
    return 0;
}

void net_relay_dir_answer(void *arg, const json_t *msg, const char *host, int port)
{
    (void)arg;
    char *text = msg != NULL ? json_dumps(msg, JSON_COMPACT) : NULL;
    if (text == NULL)
        return;
    pthread_mutex_lock(&net_relay.lock);
    if (net_relay.n_dir_answers < NET_RELAY_RECORD_QUEUE) {
        size_t i = net_relay.n_dir_answers++;
        at_strlcpy(net_relay.dir_answers[i].ep.host, host,
                   sizeof(net_relay.dir_answers[i].ep.host));
        net_relay.dir_answers[i].ep.port = port;
        net_relay.dir_answers[i].text = text;
        text = NULL;
    }
    pthread_mutex_unlock(&net_relay.lock);
    free(text);
}

void net_relay_drain_dir(void)
{
    for (;;) {
        pthread_mutex_lock(&net_relay.lock);
        char *text = NULL;
        net_relay_ep_t ep;
        if (net_relay.n_dir_answers > 0) {
            text = net_relay.dir_answers[0].text;
            ep = net_relay.dir_answers[0].ep;
            memmove(&net_relay.dir_answers[0], &net_relay.dir_answers[1],
                    (net_relay.n_dir_answers - 1) * sizeof(net_relay.dir_answers[0]));
            net_relay.n_dir_answers--;
        }
        pthread_mutex_unlock(&net_relay.lock);
        if (text == NULL)
            break;
        json_t *frame = json_loads(text, 0, NULL);
        free(text);
        if (frame == NULL)
            continue;
        const char *op = json_string_value(json_object_get(frame, "op"));
        const char *h = json_string_value(json_object_get(frame, "handle"));
        const char *handle = h != NULL ? h : "";
        const char *reason = json_string_value(json_object_get(frame, "reason"));
        if (op == NULL) {
            json_decref(frame);
            continue;
        }
        pthread_mutex_lock(&net_relay.lock);
        net_dir_lookup_t *l = _lookup_find_locked(handle);
        bool lookup_answer = strcmp(op, "dir_entry") == 0 || strcmp(op, "dir_limited") == 0
            || (strcmp(op, "dir_refused") == 0 && l != NULL && reason != NULL
                && strcmp(reason, "not_registry") == 0);
        if (lookup_answer) {
            size_t k = l != NULL ? l->n_asked : 0;
            for (size_t i = 0; l != NULL && i < l->n_asked; i++)
                if (_ep_eq(&l->asked[i], &ep))
                    k = i;
            if (l == NULL || k == l->n_asked) {     /* nobody asked that relay */
                pthread_mutex_unlock(&net_relay.lock);
                json_decref(frame);
                continue;
            }
            json_t *entry = json_object_get(frame, "entry");
            if (strcmp(op, "dir_entry") == 0 && json_is_object(entry)) {
                memset(l, 0, sizeof(*l));
                pthread_mutex_unlock(&net_relay.lock);
                _dir_answer(handle, entry, &ep, false);
                json_decref(frame);
                continue;
            }
            l->answered[k] = true;
            l->limited |= strcmp(op, "dir_limited") == 0;
            bool all = true;
            for (size_t i = 0; i < l->n_asked; i++)
                all = all && l->answered[i];
            bool limited = l->limited;
            if (all)
                memset(l, 0, sizeof(*l));
            pthread_mutex_unlock(&net_relay.lock);
            if (all)
                _dir_answer(handle, NULL, NULL, limited);
            json_decref(frame);
            continue;
        }
        pthread_mutex_unlock(&net_relay.lock);
        if (strcmp(op, "dir_published") == 0 || strcmp(op, "dir_refused") == 0
            || strcmp(op, "dir_withdrawn") == 0) {
            char where[AT_RELAY_HOST_LEN + 16];
            _ep_text(&ep, where, sizeof(where));
            json_t *seq = json_object_get(frame, "seq");
            json_t *body = json_pack("{s:s, s:s, s:s, s:s, s:I}", "op", op,
                                     "handle", handle, "relay", where,
                                     "reason", reason != NULL ? reason : "",
                                     "seq", json_is_integer(seq)
                                            ? json_integer_value(seq) : (json_int_t)0);
            if (body != NULL)
                _to_identity(NET_ID_DIR_STATUS, body);
        }
        json_decref(frame);
    }
    /* Lookups nobody finished answering. */
    double now = _mono();
    for (;;) {
        char handle[AT_DIR_HANDLE_MAX + 1] = "";
        bool limited = false;
        pthread_mutex_lock(&net_relay.lock);
        for (size_t i = 0; i < NET_DIR_MAX_LOOKUPS && handle[0] == '\0'; i++) {
            net_dir_lookup_t *l = &net_relay.lookups[i];
            if (l->used && now - l->since > NET_DIR_LOOKUP_TIMEOUT_SEC) {
                at_strlcpy(handle, l->handle, sizeof(handle));
                limited = l->limited;
                memset(l, 0, sizeof(*l));
            }
        }
        pthread_mutex_unlock(&net_relay.lock);
        if (handle[0] == '\0')
            break;
        _dir_answer(handle, NULL, NULL, limited);
    }
}

/****************************
 * Area hubs (net_hub.h): identity's publish / withdraw / lookup, and the
 * hubs' answers. Mirrors Python NetworkProcess.handle_hub_* and
 * _drain_relay_hub.
 ****************************/

void net_relay_set_test_hub(net_relay_test_hub_fn fn)
{
    pthread_mutex_lock(&net_relay.lock);
    net_relay.test_hub = fn;
    pthread_mutex_unlock(&net_relay.lock);
}

/* The relays a hub op goes to: as _dir_targets, under the hub test stand-in. */
static size_t _hub_targets(bool own_only, net_relay_ep_t *eps, net_relay_client_t **cs,
                           size_t max)
{
    net_relay_ep_t own[AT_RELAY_MAX];
    size_t n_own = net_relay_own_list(own, AT_RELAY_MAX);
    size_t n = 0;
    pthread_mutex_lock(&net_relay.lock);
    if (net_relay.test_hub != NULL) {
        for (size_t i = 0; i < n_own && n < max; i++) {
            eps[n] = own[i];
            cs[n++] = NULL;
        }
    } else {
        for (size_t i = 0; i < net_relay.n_clients && n < max; i++) {
            bool mine = !own_only;
            for (size_t k = 0; k < n_own && !mine; k++)
                mine = _ep_eq(&own[k], &net_relay.clients[i].ep);
            if (mine && net_relay_client_connected(net_relay.clients[i].client)) {
                eps[n] = net_relay.clients[i].ep;
                cs[n++] = net_relay.clients[i].client;
            }
        }
    }
    pthread_mutex_unlock(&net_relay.lock);
    return n;
}

static int _hub_ask(const net_relay_ep_t *ep, net_relay_client_t *c, const char *op,
                    const char *area, const json_t *card)
{
    net_relay_test_hub_fn fn;
    pthread_mutex_lock(&net_relay.lock);
    fn = net_relay.test_hub;
    pthread_mutex_unlock(&net_relay.lock);
    if (fn != NULL)
        return fn(ep->host, ep->port, op, area, card);
    if (strcmp(op, "hub_publish") == 0)
        return net_relay_client_hub_publish(c, card);
    if (strcmp(op, "hub_withdraw") == 0)
        return net_relay_client_hub_withdraw(c, area);
    return net_relay_client_hub_lookup(c, area);
}

/* @p cards is borrowed. */
static void _hub_answer(const char *area, json_t *cards, bool limited)
{
    json_t *body = json_pack("{s:s, s:O, s:b}", "area", area,
                             "cards", cards != NULL ? cards : json_array(), "limited", limited);
    if (cards == NULL && body != NULL) {
        /* s:O increfed the fresh array; drop the extra reference. */
        json_decref(json_object_get(body, "cards"));
    }
    if (body != NULL)
        _to_identity(NET_ID_HUB_RESULT, body);
}

int net_handle_hub_publish(net_msg_t *nmsg, logger_t *logger)
{
    json_t *body = _local_payload(nmsg, NET_FN_HUB_PUBLISH, logger);
    if (body == NULL)
        return -1;
    json_t *wire = json_object_get(body, "card");
    at_dir_signed_t card;
    const char *area = NULL;
    if (at_dir_from_wire(wire, &card) == AT_DIR_OK)
        area = at_area_card_area(&card);
    if (area == NULL) {
        if (card.body != NULL)
            at_dir_free(&card);
        log_warn(logger, "Network: hub_publish: unusable card\n");
        json_decref(body);
        return -1;
    }
    pthread_mutex_lock(&net_relay.lock);
    if (net_relay.own_cards == NULL)
        net_relay.own_cards = json_object();
    json_object_set(net_relay.own_cards, area, wire);
    pthread_mutex_unlock(&net_relay.lock);
    at_dir_free(&card);
    net_relay_ep_t eps[NET_RELAY_MAX_CLIENTS];
    net_relay_client_t *cs[NET_RELAY_MAX_CLIENTS];
    size_t n = _hub_targets(true, eps, cs, NET_RELAY_MAX_CLIENTS);
    for (size_t i = 0; i < n; i++)
        (void)_hub_ask(&eps[i], cs[i], "hub_publish", NULL, wire);
    json_decref(body);
    return 0;
}

int net_handle_hub_withdraw(net_msg_t *nmsg, logger_t *logger)
{
    json_t *body = _local_payload(nmsg, NET_FN_HUB_WITHDRAW, logger);
    if (body == NULL)
        return -1;
    const char *a = json_string_value(json_object_get(body, "area"));
    const char *area = a != NULL ? a : "";
    pthread_mutex_lock(&net_relay.lock);
    if (net_relay.own_cards != NULL)
        json_object_del(net_relay.own_cards, area);
    pthread_mutex_unlock(&net_relay.lock);
    net_relay_ep_t eps[NET_RELAY_MAX_CLIENTS];
    net_relay_client_t *cs[NET_RELAY_MAX_CLIENTS];
    size_t n = _hub_targets(true, eps, cs, NET_RELAY_MAX_CLIENTS);
    for (size_t i = 0; i < n; i++)
        (void)_hub_ask(&eps[i], cs[i], "hub_withdraw", area, NULL);
    json_decref(body);
    return 0;
}

static int _hub_lookup_find_locked(const char *area)
{
    for (int i = 0; i < NET_HUB_MAX_LOOKUPS; i++)
        if (net_relay.hub_lookups[i].used && strcmp(net_relay.hub_lookups[i].area, area) == 0)
            return i;
    return -1;
}

static void _hub_lookup_clear_locked(int i)
{
    json_decref(net_relay.hub_lookups[i].cards);
    memset(&net_relay.hub_lookups[i], 0, sizeof(net_relay.hub_lookups[i]));
}

int net_handle_hub_lookup(net_msg_t *nmsg, logger_t *logger)
{
    json_t *body = _local_payload(nmsg, NET_FN_HUB_LOOKUP, logger);
    if (body == NULL)
        return -1;
    const char *raw = json_string_value(json_object_get(body, "area"));
    char area[AT_AREA_MAX + 1];
    if (at_area_normalize(raw, area, sizeof(area), AT_AREA_MIN, AT_AREA_MAX) != 0) {
        _hub_answer(raw != NULL ? raw : "", NULL, false);
        json_decref(body);
        return 0;
    }
    json_decref(body);
    pthread_mutex_lock(&net_relay.lock);
    bool in_flight = _hub_lookup_find_locked(area) >= 0;
    pthread_mutex_unlock(&net_relay.lock);
    if (in_flight)
        return 0;                       /* one in flight answers every asker */
    net_relay_ep_t eps[NET_RELAY_MAX_CLIENTS];
    net_relay_client_t *cs[NET_RELAY_MAX_CLIENTS];
    size_t n = _hub_targets(false, eps, cs, NET_RELAY_MAX_CLIENTS);
    net_relay_ep_t asked[NET_DIR_MAX_ASKED];
    size_t n_asked = 0;
    for (size_t i = 0; i < n && n_asked < NET_DIR_MAX_ASKED; i++)
        if (_hub_ask(&eps[i], cs[i], "hub_lookup", area, NULL) == 0)
            asked[n_asked++] = eps[i];
    if (n_asked == 0) {
        _hub_answer(area, NULL, false);
        return 0;
    }
    pthread_mutex_lock(&net_relay.lock);
    int slot = -1;
    for (int i = 0; i < NET_HUB_MAX_LOOKUPS && slot < 0; i++)
        if (!net_relay.hub_lookups[i].used)
            slot = i;
    if (slot < 0) {                     /* full: replace the oldest */
        slot = 0;
        for (int i = 1; i < NET_HUB_MAX_LOOKUPS; i++)
            if (net_relay.hub_lookups[i].since < net_relay.hub_lookups[slot].since)
                slot = i;
        _hub_lookup_clear_locked(slot);
    }
    net_relay.hub_lookups[slot].used = true;
    at_strlcpy(net_relay.hub_lookups[slot].area, area, sizeof(net_relay.hub_lookups[slot].area));
    memcpy(net_relay.hub_lookups[slot].asked, asked, n_asked * sizeof(asked[0]));
    net_relay.hub_lookups[slot].n_asked = n_asked;
    net_relay.hub_lookups[slot].cards = json_array();
    net_relay.hub_lookups[slot].since = _mono();
    pthread_mutex_unlock(&net_relay.lock);
    return 0;
}

void net_relay_hub_answer(void *arg, const json_t *msg, const char *host, int port)
{
    (void)arg;
    char *text = msg != NULL ? json_dumps(msg, JSON_COMPACT) : NULL;
    if (text == NULL)
        return;
    pthread_mutex_lock(&net_relay.lock);
    if (net_relay.n_hub_answers < NET_RELAY_RECORD_QUEUE) {
        size_t i = net_relay.n_hub_answers++;
        at_strlcpy(net_relay.hub_answers[i].ep.host, host,
                   sizeof(net_relay.hub_answers[i].ep.host));
        net_relay.hub_answers[i].ep.port = port;
        net_relay.hub_answers[i].text = text;
        text = NULL;
    }
    pthread_mutex_unlock(&net_relay.lock);
    free(text);
}

void net_relay_drain_hub(void)
{
    for (;;) {
        pthread_mutex_lock(&net_relay.lock);
        char *text = NULL;
        net_relay_ep_t ep;
        if (net_relay.n_hub_answers > 0) {
            text = net_relay.hub_answers[0].text;
            ep = net_relay.hub_answers[0].ep;
            memmove(&net_relay.hub_answers[0], &net_relay.hub_answers[1],
                    (net_relay.n_hub_answers - 1) * sizeof(net_relay.hub_answers[0]));
            net_relay.n_hub_answers--;
        }
        pthread_mutex_unlock(&net_relay.lock);
        if (text == NULL)
            break;
        json_t *frame = json_loads(text, 0, NULL);
        free(text);
        if (frame == NULL)
            continue;
        const char *op = json_string_value(json_object_get(frame, "op"));
        const char *a = json_string_value(json_object_get(frame, "area"));
        const char *area = a != NULL ? a : "";
        const char *reason = json_string_value(json_object_get(frame, "reason"));
        bool not_hub = reason != NULL && strcmp(reason, "not_hub") == 0;
        if (op == NULL) {
            json_decref(frame);
            continue;
        }
        pthread_mutex_lock(&net_relay.lock);
        int li = _hub_lookup_find_locked(area);
        size_t k = NET_DIR_MAX_ASKED;
        for (size_t i = 0; li >= 0 && i < net_relay.hub_lookups[li].n_asked; i++)
            if (_ep_eq(&net_relay.hub_lookups[li].asked[i], &ep)
                && !net_relay.hub_lookups[li].answered[i])
                k = i;
        bool lookup_answer = li >= 0 && k < NET_DIR_MAX_ASKED
            && (strcmp(op, "hub_cards") == 0 || strcmp(op, "hub_limited") == 0
                || (strcmp(op, "hub_refused") == 0 && not_hub));
        if (lookup_answer) {
            typeof(net_relay.hub_lookups[0]) *l = &net_relay.hub_lookups[li];
            l->answered[k] = true;
            l->limited |= strcmp(op, "hub_limited") == 0;
            json_t *cards = json_object_get(frame, "cards");
            if (strcmp(op, "hub_cards") == 0 && json_is_array(cards)) {
                char where[AT_RELAY_HOST_LEN + 16];
                _ep_text(&ep, where, sizeof(where));
                size_t i;
                json_t *c;
                json_array_foreach(cards, i, c) {
                    if (i >= AT_HUB_LOOKUP_MAX)
                        break;
                    if (json_is_object(c))
                        json_array_append_new(l->cards, json_pack("{s:O, s:s}", "card", c,
                                                                  "relay", where));
                }
            }
            bool all = true;
            for (size_t i = 0; i < l->n_asked; i++)
                all = all && l->answered[i];
            json_t *done = NULL;
            bool limited = l->limited;
            char done_area[AT_AREA_MAX + 1] = "";
            if (all) {
                done = json_incref(l->cards);
                at_strlcpy(done_area, l->area, sizeof(done_area));
                _hub_lookup_clear_locked(li);
            }
            pthread_mutex_unlock(&net_relay.lock);
            if (done != NULL) {
                _hub_answer(done_area, done, limited);
                json_decref(done);
            }
            json_decref(frame);
            continue;
        }
        pthread_mutex_unlock(&net_relay.lock);
        if ((strcmp(op, "hub_published") == 0 || strcmp(op, "hub_refused") == 0
             || strcmp(op, "hub_withdrawn") == 0) && !not_hub) {
            char where[AT_RELAY_HOST_LEN + 16];
            _ep_text(&ep, where, sizeof(where));
            json_t *seq = json_object_get(frame, "seq");
            json_t *body = json_pack("{s:s, s:s, s:s, s:s, s:I}", "op", op,
                                     "area", area, "relay", where,
                                     "reason", reason != NULL ? reason : "",
                                     "seq", json_is_integer(seq)
                                            ? json_integer_value(seq) : (json_int_t)0);
            if (body != NULL)
                _to_identity(NET_ID_HUB_STATUS, body);
        }
        json_decref(frame);
    }
    /* Lookups nobody finished answering: answered with what came. */
    double now = _mono();
    for (;;) {
        char area[AT_AREA_MAX + 1] = "";
        bool limited = false;
        json_t *cards = NULL;
        pthread_mutex_lock(&net_relay.lock);
        for (int i = 0; i < NET_HUB_MAX_LOOKUPS && area[0] == '\0'; i++) {
            if (net_relay.hub_lookups[i].used
                && now - net_relay.hub_lookups[i].since > NET_HUB_LOOKUP_TIMEOUT_SEC) {
                at_strlcpy(area, net_relay.hub_lookups[i].area, sizeof(area));
                limited = net_relay.hub_lookups[i].limited;
                cards = json_incref(net_relay.hub_lookups[i].cards);
                _hub_lookup_clear_locked(i);
            }
        }
        pthread_mutex_unlock(&net_relay.lock);
        if (area[0] == '\0')
            break;
        _hub_answer(area, cards, limited);
        json_decref(cards);
    }
}

void net_relay_hub_age_lookups(double seconds)
{
    pthread_mutex_lock(&net_relay.lock);
    for (int i = 0; i < NET_HUB_MAX_LOOKUPS; i++)
        if (net_relay.hub_lookups[i].used)
            net_relay.hub_lookups[i].since -= seconds;
    pthread_mutex_unlock(&net_relay.lock);
}

void net_relay_dir_age_lookups(double seconds)
{
    pthread_mutex_lock(&net_relay.lock);
    for (size_t i = 0; i < NET_DIR_MAX_LOOKUPS; i++)
        if (net_relay.lookups[i].used)
            net_relay.lookups[i].since -= seconds;
    pthread_mutex_unlock(&net_relay.lock);
}

bool net_relay_has_route(const uuid_t peer)
{
    net_relay_ep_t ep;
    return _relay_route_active(peer, &ep);
}

size_t net_relay_route_endpoints(const uuid_t peer, net_relay_ep_t *out,
                                 size_t max)
{
    pthread_mutex_lock(&net_relay.lock);
    net_relay_route_t *r = _route_find_locked(peer, false);
    size_t n = 0;
    for (; r != NULL && n < r->n && n < max; n++)
        out[n] = r->eps[n];
    pthread_mutex_unlock(&net_relay.lock);
    return n;
}

void net_relay_set_test_proc(const process_t *proc)
{
    net_relay.test_proc = proc;
}

void net_relay_set_test_sender(net_relay_test_send_fn fn)
{
    pthread_mutex_lock(&net_relay.lock);
    net_relay.test_send = fn;
    pthread_mutex_unlock(&net_relay.lock);
}

void net_relay_reset_routes(void)
{
    pthread_mutex_lock(&net_relay.lock);
    for (size_t i = 0; i < net_relay.n_routes; i++) {
        free(net_relay.routes[i].last);
        net_relay.routes[i].last = NULL;
    }
    memset(net_relay.routes, 0, sizeof(net_relay.routes));
    net_relay.n_routes = 0;
    net_relay.n_refusals = 0;
    net_relay.n_pins = 0;
    net_relay.n_excluded_uuids = 0;
    net_relay.n_excluded_keys = 0;
    net_relay.n_asked = 0;
    for (size_t i = 0; i < net_relay.n_record_answers; i++)
        free(net_relay.record_answers[i]);
    net_relay.n_record_answers = 0;
    json_decref(net_relay.own_record);
    net_relay.own_record = NULL;
    json_decref(net_relay.own_entries);
    net_relay.own_entries = NULL;
    for (size_t i = 0; i < net_relay.n_dir_answers; i++)
        free(net_relay.dir_answers[i].text);
    net_relay.n_dir_answers = 0;
    memset(net_relay.lookups, 0, sizeof(net_relay.lookups));
    pthread_mutex_unlock(&net_relay.lock);
}

void handle_inbound_relayed(net_thread_ctx_t *ctx, const uint8_t *buf,
                            size_t nbytes, const char *from_uuid)
{
    uuid_t u;
    if (ctx == NULL || buf == NULL || from_uuid == NULL
        || uuid_parse(from_uuid, u) != 0)
        return;
    const public_identity_t *peer = net_find_peer_by_uuid(ctx->proc, u);
    if (peer != NULL) {
        /* A known peer: the ordinary path, keyed on its own address so the
         * lookup there finds the same entry. */
        char addr[ADDR_LEN + 1];
        at_strlcpy(addr, peer->address, sizeof(addr));
        handle_inbound_peer(ctx, (uint8_t *)buf, nbytes, addr);
        return;
    }
    /* A sender we do not know yet: only plaintext can be read (the
     * first-contact hello), and its envelope must name the sender the relay
     * vouched for -- the relay cannot forge `from`, so neither may the frame. */
    net_wire_msg_t wmsg;
    if (net_message_from_wire_fmt(buf, nbytes, NULL, NET_WIRE_JSON, &wmsg) != 0) {
        log_debug(ctx->logger, "Network: unreadable relayed frame from %.8s\n",
                  from_uuid);
        return;
    }
    if (uuid_compare(wmsg.from_whom.uuid, u) != 0) {
        char claimed[UUID_STR_LEN + 1];
        uuid_unparse_lower(wmsg.from_whom.uuid, claimed);
        log_warn(ctx->logger, "Network: relayed frame from %.8s claims to be "
                 "%.8s; dropped\n", from_uuid, claimed);
        net_wire_msg_free(&wmsg);
        return;
    }
    route_to_process(&wmsg, ctx->proc, ctx->queues, ctx->logger);
    net_wire_msg_free(&wmsg);
}

static void *peer_receiver_thread(void *arg)
{
    net_thread_ctx_t *ctx = (net_thread_ctx_t *)arg;
    /* Resolved once per thread rather than per iteration: the value
     * is cached anyway, and hoisting keeps the recv loop a loop. */
    const int poll_ms = net_recv_poll_ms_resolve(NULL, NULL);
    while (!(*ctx->stop))
    {
        uint8_t *buf = NULL;
        size_t nbytes = 0;
        char from_addr[ADDR_LEN + 1] = {0};

        int ret = ctx->transport->recv(ctx->ctx, NET_CHAN_PEER,
                                       &buf, &nbytes,
                                       from_addr, sizeof(from_addr),
                                       poll_ms);
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

    net_inbound_meta_t meta;
    if (net_filters_inbound(ctx, NET_CHAN_BROADCAST, buf, nbytes, from_addr, &meta)
        != NET_FILTER_CONTINUE)
        return;
    inner_buf = meta.inner;
    inner_len = meta.inner_len;

    /* Broadcast messages are unencrypted -- and JSON unconditionally: the
     * broadcast channel IS discovery, so there is no group to consult and the
     * receivers include nodes that hold no group at all
     * (doc/architecture/network-wire-format.md). */
    net_wire_msg_t wmsg;
    if (net_message_from_wire_fmt(inner_buf, inner_len, NULL,
                                  NET_WIRE_JSON, &wmsg) == 0) {
        /* A filter may ask to keep the announcer's self-reported address:
         * cross-cluster discovery does, for a frame a gateway forwarded, where
         * from_addr is the gateway and not the announcer. */
        if (!meta.keep_reported_addr) {
            snprintf(wmsg.from_whom.address, sizeof(wmsg.from_whom.address),
                     "%s", from_addr);
        }
        if (!wmsg.verified && wmsg.function != NULL
            && strcmp(wmsg.function, "group_key_update") == 0)
            log_warn(ctx->logger,
                     "Network: group_key_update arrived UNVERIFIED via "
                     "broadcast-channel (has_signature=%d) — the rotation "
                     "will be ignored\n", (int)wmsg.has_signature);
        route_to_process(&wmsg, ctx->proc, ctx->queues, ctx->logger);
        net_wire_msg_free(&wmsg);
    } else {
        log_error(ctx->logger, "Network: failed to deserialize broadcast from %s\n",
                  from_addr);
    }

    /* Deliver-and-forward: a filter may re-emit the frame once the core has
     * handled it (the gateway's broadcast relay). */
    net_filters_after_deliver(ctx, NET_CHAN_BROADCAST, &meta);
}

static void *broadcast_receiver_thread(void *arg)
{
    net_thread_ctx_t *ctx = (net_thread_ctx_t *)arg;
    /* Resolved once per thread rather than per iteration: the value
     * is cached anyway, and hoisting keeps the recv loop a loop. */
    const int poll_ms = net_recv_poll_ms_resolve(NULL, NULL);
    while (!(*ctx->stop))
    {
        uint8_t *buf = NULL;
        size_t nbytes = 0;
        char from_addr[ADDR_LEN + 1] = {0};

        int ret = ctx->transport->recv(ctx->ctx, NET_CHAN_BROADCAST,
                                       &buf, &nbytes,
                                       from_addr, sizeof(from_addr),
                                       poll_ms);
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
    /* Resolved once per thread rather than per iteration: the value
     * is cached anyway, and hoisting keeps the recv loop a loop. */
    const int poll_ms = net_recv_poll_ms_resolve(NULL, NULL);
    while (!(*ctx->stop))
    {
        uint8_t *buf = NULL;
        size_t nbytes = 0;
        char from_addr[ADDR_LEN + 1] = {0};

        int ret = ctx->transport->recv(ctx->ctx, NET_CHAN_GROUP,
                                       &buf, &nbytes,
                                       from_addr, sizeof(from_addr),
                                       poll_ms);
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

    /* Filters first: a frame for another group is theirs to drop or, on a
     * gateway, forward across legs (the gateway's group forward). */
    net_inbound_meta_t meta;
    if (net_filters_inbound(ctx, NET_CHAN_GROUP, buf, nbytes, from_addr, &meta)
        != NET_FILTER_CONTINUE)
        return;
    inner_buf = meta.inner;
    inner_len = meta.inner_len;

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
        /* The group whose key opened it names the encoding it is in (2.3). */
        if (net_message_from_wire_fmt(plain, plain_len, NULL,
                                      grp->wire_format, &wmsg) == 0) {
            snprintf(wmsg.from_whom.address, sizeof(wmsg.from_whom.address),
                     "%s", from_addr);
            if (!wmsg.verified && wmsg.function != NULL
                && strcmp(wmsg.function, "group_key_update") == 0)
                log_warn(ctx->logger,
                         "Network: group_key_update arrived UNVERIFIED via "
                         "group-channel (has_signature=%d) — the rotation will be "
                         "ignored\\n", (int)wmsg.has_signature);
            /* Gateway boundary, invariant B: the pre-admission handshake is
             * never a group message -- announce is broadcast, accept and
             * history are point-to-point to an unplaced identity -- so a
             * bootstrap verb arriving group-encrypted is either a bug or an
             * attempt to admit across the boundary. */
            if (identity_verb_is_bootstrap(wmsg.function)) {
                boundary_refuse(ctx->logger, "bootstrap_on_group_channel",
                                from_addr,
                                "the pre-admission handshake is never a group "
                                "message");
            } else {
                route_to_process(&wmsg, ctx->proc, ctx->queues, ctx->logger);
            }
            net_wire_msg_free(&wmsg);
        }
    } else {
        /* Name the key we tried, so a fork is legible at a glance instead of
         * looking like ordinary packet loss: compare this fingerprint/epoch with
         * the sender's "group multicast under key" line. */
        char kfp[17] = {0};
        sodium_bin2hex(kfp, sizeof(kfp), grp->encryptor.public, 8);
        log_error(ctx->logger,
                  "Network: group decrypt failed (%d) from %s "
                  "(our key %s… epoch %lld has_private=%d)\n",
                  dec, from_addr, kfp, (long long)grp->key_epoch,
                  sodium_is_zero(grp->encryptor.private,
                                 crypto_box_SECRETKEYBYTES) ? 0 : 1);
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

/* AT → app: emit one peer's latest RTT as PEER_RTT_OBSERVED to AT_MAIN_QUEUE.
 * The main loop (at_route_internal_msgs) forwards it to the app's q_out, where
 * app_events.c decodes it as AT_APP_EVENT_PEER_RTT. Mirrors the route
 * identity_emit_peer_observed takes (id_proc.c). Local IPC only; distinct from
 * broadcast_rtt_update, which fans PEER_RTT_UPDATE to SIBLING processes. */
static int net_emit_rtt_observed(const uuid_t peer_uuid, int rtt_ms)
{
    generic_msg_t msg = {0};
    msg.type = PEER_RTT_OBSERVED;
    msg.size = sizeof(peer_rtt_update_msg_t);
    memcpy(msg.info.peer_rtt_update.peer_uuid, peer_uuid, 16);
    msg.info.peer_rtt_update.rtt_ms = rtt_ms;
    return messaging_send(AT_MAIN_QUEUE, PEER_RTT_OBSERVED, &msg, false);
}

/* AT → app: emit the RTT for every known peer — the proximity half of the
 * roster-pull answer. Snapshot uuid + peer_rtt_ms[] under peers_rwlock, then
 * emit outside it (messaging_send is a syscall; holding the lock across it would
 * block every writer). Mirrors identity_emit_all_peers (id_proc.c). Returns the
 * count emitted. An rtt of 0 means "not yet measured" and crosses as-is — the
 * app ABI reads 0 as unknown. */
static int net_emit_all_rtts(const process_t *proc, logger_t *logger)
{
    if (proc == NULL)
        return 0;
    uuid_t uuids[DEFAULT_MAX_PEERS];
    int    rtts[DEFAULT_MAX_PEERS];
    peers_read_lock(proc);
    size_t n = proc->protocol.num_peers;
    if (n > DEFAULT_MAX_PEERS)
        n = DEFAULT_MAX_PEERS;
    for (size_t i = 0; i < n; i++) {
        memcpy(uuids[i], proc->protocol.peers[i].uuid, sizeof(uuid_t));
        rtts[i] = proc->protocol.peer_rtt_ms[i];
    }
    peers_read_unlock(proc);

    int emitted = 0;
    for (size_t i = 0; i < n; i++) {
        int rc = net_emit_rtt_observed(uuids[i], rtts[i]);
        if (rc == 0)
            emitted++;
        else
            log_debug(logger, "Network: rtt_observed emit returned %d\n", rc);
    }
    return emitted;
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

    /* Resolve the tunables here too, with a logger, so startup states what is
     * in force and where it came from. The consumers call the same resolvers
     * without a logger; the values are cached, so this is the one place a
     * refused override gets reported and an applied one is visible at all. */
    net_knob_source_t annoy_src = KNOB_SRC_DEFAULT,
                      poll_src  = KNOB_SRC_DEFAULT,
                      myst_src  = KNOB_SRC_DEFAULT;
    int annoy_limit = net_annoy_limit_resolve(&annoy_src, logger);
    int poll_ms     = net_recv_poll_ms_resolve(&poll_src, logger);
    int myst_age    = net_mystery_max_age_resolve(&myst_src, logger);
    log_info(logger,
             "Network: annoy limit %d from %s, recv poll %d ms from %s, "
             "mystery max age %d s from %s\n",
             annoy_limit, net_knob_source_name(annoy_src),
             poll_ms, net_knob_source_name(poll_src),
             myst_age, net_knob_source_name(myst_src));

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

    /* Network has no handler table of its own to register; an extension may
     * still want one here, and must have it before the receivers start. */
    at_extensions_register_handlers(proc, "network");

    /* The filters are in place now; refuse a config they cannot honour (the
     * envelope with libat_gateway absent) rather than join a cohort speaking
     * a different wire format. */
    if (net_filters_check_config(net_cfg, logger) != 0) {
        transport->close(tctx);
        if (my_public != NULL) smrt_deref(my_public);
        return -1;
    }

    /* Relays: serve (AT_RELAY) and/or register with our own (AT_USE_RELAY).
     * A failed registration is retried from the loop. */
    net_relay.ctx = &thread_ctx;
    {
        net_relay_ep_t own[AT_RELAY_MAX];
        net_relay_pin_t own_pins[AT_RELAY_MAX];
        size_t n_own = net_relay_own_hints(own, own_pins, AT_RELAY_MAX);
        for (size_t i = 0; i < n_own; i++)
            _relay_pin(&own[i], &own_pins[i]);
    }
    if (net_relay_enabled() && net_relay.server == NULL) {
        net_relay.server = net_relay_server_start(myself->address,
                                                  net_relay_port(), logger);
        if (net_relay.server == NULL) {
            log_error(logger, "Relay: cannot serve on port %d\n",
                      net_relay_port());
        } else {
            net_relay_server_set_identity(net_relay.server, myself);
            net_relay_server_set_distrust(net_relay.server, _relay_distrust, NULL);
            if (net_registry_enabled() && net_relay.registry == NULL) {
                char issuers[AT_REGISTRY_MAX_ISSUERS][2 * 32 + 1];
                size_t n = net_registry_load_issuers(NULL, issuers,
                                                     AT_REGISTRY_MAX_ISSUERS);
                const char *ptrs[AT_REGISTRY_MAX_ISSUERS];
                for (size_t i = 0; i < n; i++)
                    ptrs[i] = issuers[i];
                net_relay.registry = net_registry_new(ptrs, n, net_registry_rate());
                if (net_relay.registry != NULL) {
                    net_registry_set_distrust(net_relay.registry, _relay_distrust, NULL);
                    net_relay_server_set_registry(net_relay.server, net_relay.registry);
                    log_info(logger, "Registry: serving the directory (%zu trusted "
                             "issuer(s))\n", n);
                }
            }
            if (net_hub_enabled() && net_relay.hub == NULL) {
                char areas[AT_HUB_MAX_AREAS][AT_AREA_MAX + 1];
                size_t n = net_hub_areas(areas, AT_HUB_MAX_AREAS);
                const char *ptrs[AT_HUB_MAX_AREAS];
                char listed[AT_HUB_MAX_AREAS * (AT_AREA_MAX + 2) + 1] = "";
                for (size_t i = 0; i < n; i++) {
                    ptrs[i] = areas[i];
                    if (i > 0)
                        strncat(listed, ", ", sizeof(listed) - strlen(listed) - 1);
                    strncat(listed, areas[i], sizeof(listed) - strlen(listed) - 1);
                }
                net_relay.hub = net_hub_new(ptrs, n, net_hub_rate());
                if (net_relay.hub != NULL) {
                    net_hub_set_distrust(net_relay.hub, _relay_distrust, NULL);
                    net_relay_server_set_hub(net_relay.server, net_relay.hub);
                    log_info(logger, "Hub: serving area(s) %s\n", n > 0 ? listed : "(none)");
                }
            }
        }
    }
    _relay_maintain();

    pthread_t peer_thread, bcast_thread, grp_thread;
    pthread_create(&peer_thread,  NULL, peer_receiver_thread,      &thread_ctx);
    pthread_create(&bcast_thread, NULL, broadcast_receiver_thread, &thread_ctx);
    pthread_create(&grp_thread,   NULL, group_receiver_thread,     &thread_ctx);

    char bcast_addr[IPV4_ADDR_LEN] = {0};
    cidr4_to_broadcast(net_cfg->ip4_cidr, bcast_addr);
    log_info(logger, "Network: ready (transport=%s, broadcast=%s port=%d)\n",
             transport->name, bcast_addr, port_num);

    generic_msg_t buf = {0};
    while (keep_running(proc, &pctx.sig_q, logger))
    {
        _relay_maintain();
        net_relay_drain_unreachable();
        net_relay_retry_refused();
        net_relay_drain_records();
        net_relay_drain_dir();
        net_relay_drain_hub();
        /* RECEIVE FIRST, SLEEP ONLY WHEN THERE IS NOTHING TO TAKE. This loop
         * used to sleep a cadence tick and then take exactly ONE message, so
         * the network process drained its queue at one datagram per ~0.5s
         * while every sender writes into an AF_UNIX SOCK_DGRAM queue that
         * holds 10 (net.unix.max_dgram_qlen). A cohort bootstrap bursts far
         * more than 10 through here in well under a second, and messaging_send
         * is non-blocking: everything past the tenth was returned EAGAIN to a
         * caller that mostly discarded it.
         *
         * That is not a fairness detail — it is where the P3.3 staff cohort
         * lost a co-signature. The identity process hands this process each
         * admitted PEER, and peers[] is filled ONLY from those messages. The
         * keeper's queue was full when bob's PEER arrived, so net_proc never
         * learned bob's address, every frame bob sent was deferred as an
         * unknown peer, and the admission came back 1-of-2 with nothing in any
         * log to say why. The keeper had already ACCEPTED bob by then; only
         * the handoff was lost.
         *
         * Draining as fast as messages arrive is also what id_proc's
         * choose_group pump already does (recv, and sleep only on an empty
         * queue). Nothing in this loop is periodic, so there is no work here
         * to starve by looping: when the queue empties we sleep exactly as
         * before. */
        messaging_recv_release(&buf);   /* the previous pass's */
        int err = messaging_recv(&buf);
        if (err == -1 || err == ENOMSG)
        {
            sleep_until(proc, cadence);
            continue;
        }

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
                    /* The requester is a peer, so its group decides the
                     * reply's encoding -- a stats_resp in the wrong format
                     * would be dropped by the very node that asked (2.3). */
                    handle_outbound_stats_req(
                        nmsg, myself, &proc->protocol.group, transport, tctx,
                        port_num,
                        wire_format_for_address(&proc->protocol.group,
                                                nmsg->from_whom.address),
                        logger);
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
                /* App roster pull, RTT half: at_route_extern_msg fans
                 * AT_APP_ROSTER_REQUEST to identity + reputation + network. We
                 * answer with one PEER_RTT_OBSERVED per known peer. The trailing
                 * `continue;` is MANDATORY: without it this verb falls through to
                 * net_encrypt_and_send below and leaks onto the wire. Local IPC
                 * only — an app never learns another node's whole verb surface. */
                if (strcmp(nmsg->function, AT_APP_ROSTER_REQUEST) == 0) {
                    int n = net_emit_all_rtts(proc, logger);
                    log_debug(logger,
                              "Network: rtt roster request -> %d observation(s)\n", n);
                    continue;
                }
                /* Reputation communication cut-off enforcement. rep_proc's
                 * _publish_exclusion feeds an exclude/readmit control message
                 * carrying the peer's address (JSON string). An excluded
                 * address's inbound frames are dropped (reject_message gate in
                 * the ptp/group/any recv loops) and it is skipped as an
                 * outbound target. Mirrors Python netprocess handle_exclude /
                 * handle_readmit. Never leaves on the wire. */
                /* Identity: reach peer {uuid} through relay {relay}. Local
                 * only -- a peer must not be able to reroute this node's
                 * traffic -- so anything carrying a sender is refused. Never
                 * leaves on the wire. Mirrors Python handle_relay_route. */
                if (strcmp(nmsg->function, NET_FN_RELAY_ROUTE) == 0) {
                    (void)net_handle_relay_route(nmsg, logger);
                    continue;
                }
                if (strcmp(nmsg->function, NET_FN_REACH_PUBLISH) == 0) {
                    (void)net_handle_reach_publish(nmsg, logger);
                    continue;
                }
                if (strcmp(nmsg->function, NET_FN_DIR_PUBLISH) == 0) {
                    (void)net_handle_dir_publish(nmsg, logger);
                    continue;
                }
                if (strcmp(nmsg->function, NET_FN_DIR_WITHDRAW) == 0) {
                    (void)net_handle_dir_withdraw(nmsg, logger);
                    continue;
                }
                if (strcmp(nmsg->function, NET_FN_DIR_LOOKUP) == 0) {
                    (void)net_handle_dir_lookup(nmsg, logger);
                    continue;
                }
                if (strcmp(nmsg->function, NET_FN_HUB_PUBLISH) == 0) {
                    (void)net_handle_hub_publish(nmsg, logger);
                    continue;
                }
                if (strcmp(nmsg->function, NET_FN_HUB_WITHDRAW) == 0) {
                    (void)net_handle_hub_withdraw(nmsg, logger);
                    continue;
                }
                if (strcmp(nmsg->function, NET_FN_HUB_LOOKUP) == 0) {
                    (void)net_handle_hub_lookup(nmsg, logger);
                    continue;
                }
                if ((strcmp(nmsg->function, NET_FN_EXCLUDE) == 0 ||
                     strcmp(nmsg->function, NET_FN_READMIT) == 0)
                    && !uuid_is_null(nmsg->from_whom.uuid)) {
                    /* Local only: nobody on the wire excludes for us (it
                     * would gate peers and relays too). rep_proc sends these
                     * with no sender. */
                    log_warn(logger, "Network: refusing %s from the wire\n",
                             nmsg->function);
                    continue;
                }
                if (strcmp(nmsg->function, NET_FN_EXCLUDE) == 0 ||
                    strcmp(nmsg->function, NET_FN_READMIT) == 0) {
                    /* {address, uuid} (either may be empty), or the older bare
                     * address. The uuid gates the peer as a relay client and as
                     * a relay (net_relay_note_exclusion). */
                    json_t *body = NULL;
                    char addr[ADDR_LEN + 1];
                    char ex_uuid[UUID_STR_LEN + 1];
                    addr[0] = '\0';
                    ex_uuid[0] = '\0';
                    if (net_msg_unpack_json(nmsg, &body) == 0 && body != NULL) {
                        const char *a = json_is_object(body)
                            ? json_string_value(json_object_get(body, "address"))
                            : json_string_value(body);
                        const char *u = json_is_object(body)
                            ? json_string_value(json_object_get(body, "uuid")) : NULL;
                        if (a != NULL)
                            snprintf(addr, sizeof(addr), "%s", a);
                        if (u != NULL)
                            at_strlcpy(ex_uuid, u, sizeof(ex_uuid));
                        json_decref(body);
                    }
                    if (ex_uuid[0] != '\0')
                        net_relay_note_exclusion(
                            ex_uuid, strcmp(nmsg->function, NET_FN_EXCLUDE) == 0);
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

            /* Group multicast (Increment 7): an encrypted send to the whole
             * cohort on NET_CHAN_GROUP, signalled by the identity process via
             * nmsg->group_multicast (there is no per-peer to_whom). Checked
             * BEFORE is_broadcast because a group message also carries an empty
             * to_whom.address. */
            bool is_group = nmsg->group_multicast;
            /* No address is a broadcast -- unless we know WHO and how to reach
             * them: a directory holder's entry carries no address, only the
             * relays (identity's relay_route). Python decides broadcast by an
             * absent recipient, never by an empty address. */
            bool is_broadcast = (!is_group && nmsg->to_whom.address[0] == '\0'
                                 && !(!uuid_is_null(nmsg->to_whom.uuid)
                                      && net_relay_has_route(nmsg->to_whom.uuid)));
            if (is_group) {
                wmsg.to_whom.type = RECIPIENT_GROUP;
                log_debug(logger, "Network: group-multicasting %s.%s\n",
                          nmsg->process, nmsg->function);
            } else if (is_broadcast) {
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

            /* Gateway boundary, invariants B and G. Both are gateway-only
             * gates -- address_crosses_gateway is false without child groups,
             * and held_groups_containing can only exceed 1 when we hold more
             * than one group -- so a leaf node takes exactly the historical
             * path. A broadcast is exempt from B: discovery is how a node in
             * OUR domain gets admitted, and it never leaves the segment. */
            if (!is_broadcast && !is_group) {
                if (identity_verb_is_bootstrap(nmsg->function) &&
                    address_crosses_gateway(proc, myself,
                                            nmsg->to_whom.address)) {
                    boundary_refuse(logger, "bootstrap_across_gateway",
                                    nmsg->to_whom.address,
                                    "refusing to send the pre-admission "
                                    "handshake to a cohort we gateway");
                    continue;
                }
                if (held_groups_containing(proc, myself,
                                           nmsg->to_whom.address) > 1) {
                    boundary_refuse(logger, "group_spans_gateway",
                                    nmsg->to_whom.address,
                                    "target is a member of more than one group "
                                    "we hold");
                    continue;
                }
            }

            /* Broadcast is discovery -> JSON; a peer we can place speaks its
             * group's format; one we cannot place gets JSON, which is what
             * makes pre-admission traffic work in a proto cohort (2.3). */
            /* A group multicast rides the cohort's own wire format (that is what
             * handle_inbound_group decodes the decrypted plaintext with). */
            net_wire_format_t send_fmt = is_group
                ? proc->protocol.group.wire_format
                : (is_broadcast
                   ? NET_WIRE_JSON
                   : wire_format_for_address(&proc->protocol.group,
                                             nmsg->to_whom.address));
            int send_ret = net_encrypt_and_send(myself, &proc->protocol.group,
                                                &wmsg, transport, tctx,
                                                port_num, send_fmt, logger);
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

                /* Also surface it to the app (AT_APP_EVENT_PEER_RTT) as the peer
                 * is admitted. Change-driven; the roster pull (net_emit_all_rtts)
                 * re-emits a full view, so a lost live emit self-heals. */
                net_emit_rtt_observed(new_peer->uuid, snapshot_rtt);

                /* Retry deferred encrypted messages with the new peer. Match
                 * by envelope src_uuid when the entry has one (gateway-
                 * forwarded traffic under the routing envelope); otherwise by
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
                            /* The peer is known NOW, so its group answers the
                             * format question that could not be answered when
                             * the frame was deferred
                             * (doc/architecture/network-wire-format.md). A frame
                             * deferred before admission was sent by a peer that
                             * had no group of ours yet, so in practice this
                             * resolves to JSON unless it was already a member. */
                            if (net_message_from_wire_fmt(
                                    plain, plain_len, new_peer,
                                    wire_format_for_address(&proc->protocol.group,
                                                            new_peer->address),
                                    &wmsg) == 0) {
                                route_to_process(&wmsg, proc, queues, logger);
                                log_info(logger, "Network: replayed deferred message from %s\n",
                                         dm->from_addr);
                            }
                            free(plain);
                            net_wire_msg_free(&wmsg);
                            free(dm);             /* slot consumed */
                            deferred_messages[di] = NULL;
                        } else {
                            /* Matched the new peer but still does not decrypt:
                             * unrelated noise from that address, or a frame
                             * under a key that has since rotated. Retained for
                             * the age bound to reclaim (Python's
                             * mystery_handler keeps it and emits the same
                             * counter). */
                            probes_counter("net.mystery", "decrypt_failed", NULL);
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
    messaging_recv_release(&buf);

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

/* DTN is an extension library (src/c/extensions/dtn/, libat_dtn): its runner
 * and transport register themselves when the library loads. */
