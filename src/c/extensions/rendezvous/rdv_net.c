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
 * @file rdv_net.c
 * @brief Rendezvous in the network process: the relay routes and clients, our
 *        own relay server, reachability records, and the network extension
 *        that plugs them into the core loop (network/net_ext.h).
 *
 * FEATURE_SPLIT_PLAN Phase 7b: lifted out of net_proc.c unchanged. The core
 * reaches all of it through the network hooks; the relay readers hand frames
 * back through handle_inbound_relayed (network/net_proc_priv.h).
 */

#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <time.h>
#include <unistd.h>
#include <pthread.h>

#include <jansson.h>
#include <uuid/uuid.h>

#include "processes/processes.h"
#include "utilities/message.h"
#include "utilities/msg_types_priv.h"
#include "utilities/logger.h"
#include "utilities/util.h"
#include "network/network.h"
#include "network/net_message.h"
#include "network/net_proc_priv.h"
#include "network/net_ext.h"
#include "identity/identity.h"
#include "identity/identity_priv.h"
#include "rendezvous/net_relay.h"
#include "rendezvous/net_relay_seeds.h"
#include "rendezvous/net_relay_rosters.h"
#include "rendezvous/net_rendezvous.h"
#include "rendezvous/reach.h"

/* Protocol strings (declared `extern char[]` in rendezvous/net_rendezvous.h). */
/* identity -> network, local IPC: reach peer {uuid} through relay {relay}.
 * Mirror: Python Network.relay_route. */
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
 * FirstContactProtocol.reach_record. */
static char NET_ID_REACH_RECORD[] = "reach_record";

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
} net_relay = { .lock = PTHREAD_MUTEX_INITIALIZER, .retry_sec = NET_RELAY_RETRY_SEC };

static bool _ep_eq(const net_relay_ep_t *a, const net_relay_ep_t *b)
{
    return a->port == b->port && strcmp(a->host, b->host) == 0;
}

/* The services riding the relays (net_rendezvous.h): first contact's directory
 * and area hub. Filled by constructors, then read-only, so unlocked. */
static const net_rdv_service_t *services[NET_RDV_SERVICES_MAX];
static size_t n_services = 0;

int net_rendezvous_service_register(const net_rdv_service_t *svc)
{
    if (svc == NULL || svc->name == NULL || svc->name[0] == '\0') {
        fprintf(stderr, "net_rendezvous_service_register: refusing an unnamed service\n");
        return -1;
    }
    for (size_t i = 0; i < n_services; i++)
        if (strcmp(services[i]->name, svc->name) == 0) {
            fprintf(stderr, "net_rendezvous_service_register: refusing %s: already "
                    "registered\n", svc->name);
            return -1;
        }
    if (n_services >= NET_RDV_SERVICES_MAX) {
        fprintf(stderr, "net_rendezvous_service_register: refusing %s: full\n", svc->name);
        return -1;
    }
    services[n_services++] = svc;
    return 0;
}

size_t net_rendezvous_clients(bool own_only, net_relay_ep_t *eps,
                              net_relay_client_t **cs, size_t max)
{
    net_relay_ep_t own[AT_RELAY_MAX];
    size_t n_own = net_relay_own_list(own, AT_RELAY_MAX);
    size_t n = 0;
    pthread_mutex_lock(&net_relay.lock);
    for (size_t i = 0; i < net_relay.n_clients && n < max; i++) {
        bool mine = !own_only;
        for (size_t k = 0; k < n_own && !mine; k++)
            mine = _ep_eq(&own[k], &net_relay.clients[i].ep);
        if (mine && net_relay_client_connected(net_relay.clients[i].client)) {
            eps[n] = net_relay.clients[i].ep;
            cs[n++] = net_relay.clients[i].client;
        }
    }
    pthread_mutex_unlock(&net_relay.lock);
    return n;
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
 * key belongs to someone it cut off (both recorded by the core,
 * net_is_excluded), or @p uuid is a peer we know under a DIFFERENT key (an
 * impostor). Unknown and neutral pass. Mirrors Python
 * NetworkProcess._is_distrusted. */
bool net_relay_is_distrusted(const char *uuid, const char *pubkey_hex)
{
    if (uuid == NULL)
        return false;
    const char *key = pubkey_hex != NULL ? pubkey_hex : "";
    if (net_is_excluded(uuid, key))
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
            for (size_t i = 0; i < n_services; i++)
                if (services[i]->prefix != NULL && services[i]->on_answer != NULL)
                    net_relay_client_on_op(c, services[i]->prefix, services[i]->on_answer,
                                           services[i]->answer_arg);
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
        /* And whatever the services riding the relay hold here (first
         * contact's directory entries and area cards). */
        for (size_t i = 0; i < n_services; i++)
            if (services[i]->own_registered != NULL)
                services[i]->own_registered(ep, c);
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

/* Reputation cut @p uuid off, or readmitted it: the core records it by uuid and
 * by the key we hold (net_ext.h), and rendezvous's exclusion hook drops the
 * peer at once (_relay_drop_distrusted). The test-facing entry point; the loop
 * goes through net_note_exclusion directly. */
void net_relay_note_exclusion(const char *uuid, bool excluded)
{
    uuid_t u;
    if (uuid == NULL || uuid_parse(uuid, u) != 0)
        return;
    char ul[UUID_STR_LEN + 1], key[crypto_sign_PUBLICKEYBYTES * 2 + 1];
    uuid_unparse_lower(u, ul);
    bool have_key = _peer_key(ul, key, sizeof(key));
    net_note_exclusion(ul, have_key ? key : NULL, excluded);
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
    net_exclusions_reset();
    net_relay.n_asked = 0;
    for (size_t i = 0; i < net_relay.n_record_answers; i++)
        free(net_relay.record_answers[i]);
    net_relay.n_record_answers = 0;
    json_decref(net_relay.own_record);
    net_relay.own_record = NULL;
    pthread_mutex_unlock(&net_relay.lock);
    for (size_t i = 0; i < n_services; i++)
        if (services[i]->reset != NULL)
            services[i]->reset();
}

/****************************
 *  Rendezvous as a network extension (net_ext.h)
 *
 *  FEATURE_SPLIT_PLAN Phase 7a: the core loop names none of this any more; it
 *  calls these through the hooks. The code itself moves out of the core in 7b.
 ****************************/

/* Serve as a relay (AT_RELAY) and/or register with our own (AT_USE_RELAY). A
 * failed registration is retried from the loop. */
static void _rdv_start(net_thread_ctx_t *ctx)
{
    net_relay.ctx = ctx;
    {
        net_relay_ep_t own[AT_RELAY_MAX];
        net_relay_pin_t own_pins[AT_RELAY_MAX];
        size_t n_own = net_relay_own_hints(own, own_pins, AT_RELAY_MAX);
        for (size_t i = 0; i < n_own; i++)
            _relay_pin(&own[i], &own_pins[i]);
    }
    if (net_relay_enabled() && net_relay.server == NULL) {
        net_relay.server = net_relay_server_start(ctx->myself->address,
                                                  net_relay_port(), ctx->logger);
        if (net_relay.server == NULL) {
            log_error(ctx->logger, "Relay: cannot serve on port %d\n",
                      net_relay_port());
        } else {
            net_relay_server_set_identity(net_relay.server, ctx->myself);
            net_relay_server_set_distrust(net_relay.server, _relay_distrust, NULL);
            for (size_t i = 0; i < n_services; i++)
                if (services[i]->server_started != NULL)
                    services[i]->server_started(net_relay.server, ctx);
        }
    }
    _relay_maintain();
}

/* Keep the registrations alive, fail over what relays refused, and hand
 * identity what the relay readers queued. */
static void _rdv_periodic(net_thread_ctx_t *ctx)
{
    (void)ctx;
    _relay_maintain();
    net_relay_drain_unreachable();
    net_relay_retry_refused();
    net_relay_drain_records();
}

/* The local verbs addressed to the network process that rendezvous owns. */
static bool _rdv_local_verb(net_thread_ctx_t *ctx, net_msg_t *nmsg)
{
    /* Identity: reach peer {uuid} through relay {relay}. Local only -- a peer
     * must not be able to reroute this node's traffic -- so anything carrying
     * a sender is refused. Never leaves on the wire. Mirrors Python
     * handle_relay_route. */
    if (strcmp(nmsg->function, NET_FN_RELAY_ROUTE) == 0) {
        (void)net_handle_relay_route(nmsg, ctx->logger);
        return true;
    }
    if (strcmp(nmsg->function, NET_FN_REACH_PUBLISH) == 0) {
        (void)net_handle_reach_publish(nmsg, ctx->logger);
        return true;
    }
    return false;
}

/* A new exclusion is acted on at once: evict the client from the relay we
 * serve, and hang up on a relay we now distrust. */
static void _rdv_exclusion(const char *uuid, bool excluded)
{
    if (excluded)
        _relay_drop_distrusted(uuid);
}

static int _rdv_unicast(const uuid_t peer, const uint8_t *buf, size_t len)
{
    return net_relay_send_to_peer(peer, buf, len);
}

static const net_ext_t rendezvous_net_ext = {
    .name = "rendezvous",
    .start = _rdv_start,
    .periodic = _rdv_periodic,
    .local_verb = _rdv_local_verb,
    .reachable = net_relay_has_route,
    .unicast = _rdv_unicast,
    .exclusion = _rdv_exclusion,
};
NET_EXT_REGISTER(rendezvous, &rendezvous_net_ext)

