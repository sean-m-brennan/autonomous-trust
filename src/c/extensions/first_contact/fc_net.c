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

/* First contact in the network process (fc_net.h): the directory and area-hub
 * clients over the rendezvous relays, and the registry and hub our relay
 * serves. Moved out of net_proc.c's relay block (FEATURE_SPLIT_PLAN Phase 7,
 * R1/R2); the logic is unchanged. Mirrors Python first contact's network half. */

#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <jansson.h>

#include "first_contact/area_card.h"
#include "first_contact/directory.h"
#include "first_contact/fc_net.h"
#include "network/net_ext.h"
#include "first_contact/net_hub.h"
#include "network/net_proc_priv.h"
#include "first_contact/net_registry.h"
#include "rendezvous/net_rendezvous.h"
#include "network/network.h"
#include "processes/processes.h"
#include "utilities/message.h"
#include "utilities/msg_types_priv.h"
#include "utilities/util.h"
#include "utilities/send_retry.h"   /* at_send: keep a refused frame */

/* identity -> network, local IPC: the directory (net_registry.h). Mirror:
 * Python Network.dir_publish / dir_withdraw / dir_lookup. */
char NET_FN_DIR_PUBLISH[] = "dir_publish";
char NET_FN_DIR_WITHDRAW[] = "dir_withdraw";
char NET_FN_DIR_LOOKUP[] = "dir_lookup";
/* network -> identity: a lookup's one outcome, and a registry's word on our
 * publish or withdraw. Mirror: Python FirstContactProtocol.dir_result / dir_status. */
char NET_ID_DIR_RESULT[] = "dir_result";
char NET_ID_DIR_STATUS[] = "dir_status";
/* Area hubs (net_hub.h), the same shape. Mirror: Python Network.hub_* and
 * FirstContactProtocol.hub_result / hub_status. */
char NET_FN_HUB_PUBLISH[] = "hub_publish";
char NET_FN_HUB_WITHDRAW[] = "hub_withdraw";
char NET_FN_HUB_LOOKUP[] = "hub_lookup";
char NET_ID_HUB_RESULT[] = "hub_result";
char NET_ID_HUB_STATUS[] = "hub_status";

/* How many relays one op goes to, and how many answers wait for the loop. */
#define FC_NET_MAX_RELAYS 16
#define FC_NET_ANSWER_QUEUE 32

static struct {
    pthread_mutex_t lock;
    logger_t *logger;               /* the network process's, once it starts */
    /* The directory: our own entries (handle -> wire), refiled at every
     * registration with our relays; registry answers from the readers; and
     * lookups in flight, answered to identity once. Mirrors Python
     * first contact's _own_entries / relay_dir / _dir_lookups. */
    json_t *own_entries;
    net_registry_t *registry;
    struct {
        net_relay_ep_t ep;
        char *text;
    } dir_answers[FC_NET_ANSWER_QUEUE];
    size_t n_dir_answers;
    fc_net_dir_lookup_t lookups[NET_DIR_MAX_LOOKUPS];
    fc_net_test_dir_fn test_dir;
    /* Area hubs, the same shape: our own cards (area -> wire), refiled at
     * every registration; hub answers from the readers; and lookups in
     * flight, answered to identity once with every card any hub held.
     * Mirrors Python first contact's _own_cards / relay_hub / _hub_lookups. */
    json_t *own_cards;
    net_hub_t *hub;
    struct {
        net_relay_ep_t ep;
        char *text;
    } hub_answers[FC_NET_ANSWER_QUEUE];
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
    fc_net_test_hub_fn test_hub;
} fc_net = { .lock = PTHREAD_MUTEX_INITIALIZER };

static bool _ep_eq(const net_relay_ep_t *a, const net_relay_ep_t *b)
{
    return a->port == b->port && strcmp(a->host, b->host) == 0;
}

/****************************
 * The directory (net_registry.h): identity's publish / withdraw / lookup, and
 * the registries' answers. Mirrors Python NetworkProcess.handle_dir_* and
 * _drain_relay_dir.
 ****************************/

void fc_net_set_test_dir(fc_net_test_dir_fn fn)
{
    pthread_mutex_lock(&fc_net.lock);
    fc_net.test_dir = fn;
    pthread_mutex_unlock(&fc_net.lock);
}

/* The relays an op goes to: connected clients (own relays only when
 * @p own_only), or, under a test stand-in, our own list. */
static size_t _dir_targets(bool own_only, net_relay_ep_t *eps, net_relay_client_t **cs,
                           size_t max)
{
    pthread_mutex_lock(&fc_net.lock);
    bool stand_in = fc_net.test_dir != NULL;
    pthread_mutex_unlock(&fc_net.lock);
    if (!stand_in)
        return net_rendezvous_clients(own_only, eps, cs, max);
    net_relay_ep_t own[AT_RELAY_MAX];
    size_t n_own = net_relay_own_list(own, AT_RELAY_MAX);
    size_t n = 0;
    for (size_t i = 0; i < n_own && n < max; i++) {
        eps[n] = own[i];
        cs[n++] = NULL;
    }
    return n;
}

static int _dir_ask(const net_relay_ep_t *ep, net_relay_client_t *c, const char *op,
                    const char *handle, const json_t *entry)
{
    fc_net_test_dir_fn fn;
    pthread_mutex_lock(&fc_net.lock);
    fn = fc_net.test_dir;
    pthread_mutex_unlock(&fc_net.lock);
    if (fn != NULL)
        return fn(ep->host, ep->port, op, handle, entry);
    json_t *req = strcmp(op, "dir_publish") == 0
        ? json_pack("{s:s, s:O}", "op", op, "entry", entry)
        : json_pack("{s:s, s:s}", "op", op, "handle", handle != NULL ? handle : "");
    return net_relay_client_request(c, req);
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
    /* A relay's answer (a directory or hub result or status) arrives once and
     * nothing asks for it again, so a full identity queue keeps it for this
     * process's tick (ISSUES §2.14). One try: this runs on network threads. */
    (void)at_send(NULL, "identity", &msg, verb, "identity", AT_SEND_NOW, NULL,
                  NULL, 0);
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

int fc_net_dir_publish(net_msg_t *nmsg, logger_t *logger)
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
    pthread_mutex_lock(&fc_net.lock);
    if (fc_net.own_entries == NULL)
        fc_net.own_entries = json_object();
    json_object_set(fc_net.own_entries, at_dir_handle(&e), wire);
    pthread_mutex_unlock(&fc_net.lock);
    at_dir_free(&e);
    net_relay_ep_t eps[FC_NET_MAX_RELAYS];
    net_relay_client_t *cs[FC_NET_MAX_RELAYS];
    size_t n = _dir_targets(true, eps, cs, FC_NET_MAX_RELAYS);
    for (size_t i = 0; i < n; i++)
        (void)_dir_ask(&eps[i], cs[i], "dir_publish", NULL, wire);
    json_decref(body);
    return 0;
}

int fc_net_dir_withdraw(net_msg_t *nmsg, logger_t *logger)
{
    json_t *body = _local_payload(nmsg, NET_FN_DIR_WITHDRAW, logger);
    if (body == NULL)
        return -1;
    const char *h = json_string_value(json_object_get(body, "handle"));
    const char *handle = h != NULL ? h : "";
    pthread_mutex_lock(&fc_net.lock);
    if (fc_net.own_entries != NULL)
        json_object_del(fc_net.own_entries, handle);
    pthread_mutex_unlock(&fc_net.lock);
    net_relay_ep_t eps[FC_NET_MAX_RELAYS];
    net_relay_client_t *cs[FC_NET_MAX_RELAYS];
    size_t n = _dir_targets(true, eps, cs, FC_NET_MAX_RELAYS);
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

static fc_net_dir_lookup_t *_lookup_find_locked(const char *handle)
{
    for (size_t i = 0; i < NET_DIR_MAX_LOOKUPS; i++)
        if (fc_net.lookups[i].used && strcmp(fc_net.lookups[i].handle, handle) == 0)
            return &fc_net.lookups[i];
    return NULL;
}

int fc_net_dir_lookup(net_msg_t *nmsg, logger_t *logger)
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
    net_relay_ep_t eps[FC_NET_MAX_RELAYS];
    net_relay_client_t *cs[FC_NET_MAX_RELAYS];
    size_t n = _dir_targets(false, eps, cs, FC_NET_MAX_RELAYS);
    net_relay_ep_t asked[NET_DIR_MAX_ASKED];
    size_t n_asked = 0;
    for (size_t i = 0; i < n && n_asked < NET_DIR_MAX_ASKED; i++)
        if (_dir_ask(&eps[i], cs[i], "dir_lookup", handle, NULL) == 0)
            asked[n_asked++] = eps[i];
    if (n_asked == 0) {
        _dir_answer(handle, NULL, NULL, false);
        return 0;
    }
    pthread_mutex_lock(&fc_net.lock);
    fc_net_dir_lookup_t *l = _lookup_find_locked(handle);
    for (size_t i = 0; i < NET_DIR_MAX_LOOKUPS && l == NULL; i++)
        if (!fc_net.lookups[i].used)
            l = &fc_net.lookups[i];
    if (l == NULL) {                    /* full: replace the oldest */
        l = &fc_net.lookups[0];
        for (size_t i = 1; i < NET_DIR_MAX_LOOKUPS; i++)
            if (fc_net.lookups[i].since < l->since)
                l = &fc_net.lookups[i];
    }
    memset(l, 0, sizeof(*l));
    l->used = true;
    at_strlcpy(l->handle, handle, sizeof(l->handle));
    memcpy(l->asked, asked, n_asked * sizeof(asked[0]));
    l->n_asked = n_asked;
    l->since = _mono();
    pthread_mutex_unlock(&fc_net.lock);
    return 0;
}

void fc_net_dir_answer(void *arg, const json_t *msg, const char *host, int port)
{
    (void)arg;
    const char *op = json_string_value(json_object_get(msg, "op"));
    if (op != NULL && strcmp(op, "dir_refused") == 0)
        log_warn(fc_net.logger, "Relay %s:%d refused directory %s: %s\n", host, port,
                 json_string_value(json_object_get(msg, "handle")),
                 json_string_value(json_object_get(msg, "reason")));
    char *text = msg != NULL ? json_dumps(msg, JSON_COMPACT) : NULL;
    if (text == NULL)
        return;
    pthread_mutex_lock(&fc_net.lock);
    if (fc_net.n_dir_answers < FC_NET_ANSWER_QUEUE) {
        size_t i = fc_net.n_dir_answers++;
        at_strlcpy(fc_net.dir_answers[i].ep.host, host,
                   sizeof(fc_net.dir_answers[i].ep.host));
        fc_net.dir_answers[i].ep.port = port;
        fc_net.dir_answers[i].text = text;
        text = NULL;
    }
    pthread_mutex_unlock(&fc_net.lock);
    free(text);
}

void fc_net_drain_dir(void)
{
    for (;;) {
        pthread_mutex_lock(&fc_net.lock);
        char *text = NULL;
        net_relay_ep_t ep;
        if (fc_net.n_dir_answers > 0) {
            text = fc_net.dir_answers[0].text;
            ep = fc_net.dir_answers[0].ep;
            memmove(&fc_net.dir_answers[0], &fc_net.dir_answers[1],
                    (fc_net.n_dir_answers - 1) * sizeof(fc_net.dir_answers[0]));
            fc_net.n_dir_answers--;
        }
        pthread_mutex_unlock(&fc_net.lock);
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
        pthread_mutex_lock(&fc_net.lock);
        fc_net_dir_lookup_t *l = _lookup_find_locked(handle);
        bool lookup_answer = strcmp(op, "dir_entry") == 0 || strcmp(op, "dir_limited") == 0
            || (strcmp(op, "dir_refused") == 0 && l != NULL && reason != NULL
                && strcmp(reason, "not_registry") == 0);
        if (lookup_answer) {
            size_t k = l != NULL ? l->n_asked : 0;
            for (size_t i = 0; l != NULL && i < l->n_asked; i++)
                if (_ep_eq(&l->asked[i], &ep))
                    k = i;
            if (l == NULL || k == l->n_asked) {     /* nobody asked that relay */
                pthread_mutex_unlock(&fc_net.lock);
                json_decref(frame);
                continue;
            }
            json_t *entry = json_object_get(frame, "entry");
            if (strcmp(op, "dir_entry") == 0 && json_is_object(entry)) {
                memset(l, 0, sizeof(*l));
                pthread_mutex_unlock(&fc_net.lock);
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
            pthread_mutex_unlock(&fc_net.lock);
            if (all)
                _dir_answer(handle, NULL, NULL, limited);
            json_decref(frame);
            continue;
        }
        pthread_mutex_unlock(&fc_net.lock);
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
        pthread_mutex_lock(&fc_net.lock);
        for (size_t i = 0; i < NET_DIR_MAX_LOOKUPS && handle[0] == '\0'; i++) {
            fc_net_dir_lookup_t *l = &fc_net.lookups[i];
            if (l->used && now - l->since > NET_DIR_LOOKUP_TIMEOUT_SEC) {
                at_strlcpy(handle, l->handle, sizeof(handle));
                limited = l->limited;
                memset(l, 0, sizeof(*l));
            }
        }
        pthread_mutex_unlock(&fc_net.lock);
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

void fc_net_set_test_hub(fc_net_test_hub_fn fn)
{
    pthread_mutex_lock(&fc_net.lock);
    fc_net.test_hub = fn;
    pthread_mutex_unlock(&fc_net.lock);
}

/* The relays a hub op goes to: as _dir_targets, under the hub test stand-in. */
static size_t _hub_targets(bool own_only, net_relay_ep_t *eps, net_relay_client_t **cs,
                           size_t max)
{
    pthread_mutex_lock(&fc_net.lock);
    bool stand_in = fc_net.test_hub != NULL;
    pthread_mutex_unlock(&fc_net.lock);
    if (!stand_in)
        return net_rendezvous_clients(own_only, eps, cs, max);
    net_relay_ep_t own[AT_RELAY_MAX];
    size_t n_own = net_relay_own_list(own, AT_RELAY_MAX);
    size_t n = 0;
    for (size_t i = 0; i < n_own && n < max; i++) {
        eps[n] = own[i];
        cs[n++] = NULL;
    }
    return n;
}

static int _hub_ask(const net_relay_ep_t *ep, net_relay_client_t *c, const char *op,
                    const char *area, const json_t *card)
{
    fc_net_test_hub_fn fn;
    pthread_mutex_lock(&fc_net.lock);
    fn = fc_net.test_hub;
    pthread_mutex_unlock(&fc_net.lock);
    if (fn != NULL)
        return fn(ep->host, ep->port, op, area, card);
    json_t *req = strcmp(op, "hub_publish") == 0
        ? json_pack("{s:s, s:O}", "op", op, "card", card)
        : json_pack("{s:s, s:s}", "op", op, "area", area != NULL ? area : "");
    return net_relay_client_request(c, req);
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

int fc_net_hub_publish(net_msg_t *nmsg, logger_t *logger)
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
    pthread_mutex_lock(&fc_net.lock);
    if (fc_net.own_cards == NULL)
        fc_net.own_cards = json_object();
    json_object_set(fc_net.own_cards, area, wire);
    pthread_mutex_unlock(&fc_net.lock);
    at_dir_free(&card);
    net_relay_ep_t eps[FC_NET_MAX_RELAYS];
    net_relay_client_t *cs[FC_NET_MAX_RELAYS];
    size_t n = _hub_targets(true, eps, cs, FC_NET_MAX_RELAYS);
    for (size_t i = 0; i < n; i++)
        (void)_hub_ask(&eps[i], cs[i], "hub_publish", NULL, wire);
    json_decref(body);
    return 0;
}

int fc_net_hub_withdraw(net_msg_t *nmsg, logger_t *logger)
{
    json_t *body = _local_payload(nmsg, NET_FN_HUB_WITHDRAW, logger);
    if (body == NULL)
        return -1;
    const char *a = json_string_value(json_object_get(body, "area"));
    const char *area = a != NULL ? a : "";
    pthread_mutex_lock(&fc_net.lock);
    if (fc_net.own_cards != NULL)
        json_object_del(fc_net.own_cards, area);
    pthread_mutex_unlock(&fc_net.lock);
    net_relay_ep_t eps[FC_NET_MAX_RELAYS];
    net_relay_client_t *cs[FC_NET_MAX_RELAYS];
    size_t n = _hub_targets(true, eps, cs, FC_NET_MAX_RELAYS);
    for (size_t i = 0; i < n; i++)
        (void)_hub_ask(&eps[i], cs[i], "hub_withdraw", area, NULL);
    json_decref(body);
    return 0;
}

static int _hub_lookup_find_locked(const char *area)
{
    for (int i = 0; i < NET_HUB_MAX_LOOKUPS; i++)
        if (fc_net.hub_lookups[i].used && strcmp(fc_net.hub_lookups[i].area, area) == 0)
            return i;
    return -1;
}

static void _hub_lookup_clear_locked(int i)
{
    json_decref(fc_net.hub_lookups[i].cards);
    memset(&fc_net.hub_lookups[i], 0, sizeof(fc_net.hub_lookups[i]));
}

int fc_net_hub_lookup(net_msg_t *nmsg, logger_t *logger)
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
    pthread_mutex_lock(&fc_net.lock);
    bool in_flight = _hub_lookup_find_locked(area) >= 0;
    pthread_mutex_unlock(&fc_net.lock);
    if (in_flight)
        return 0;                       /* one in flight answers every asker */
    net_relay_ep_t eps[FC_NET_MAX_RELAYS];
    net_relay_client_t *cs[FC_NET_MAX_RELAYS];
    size_t n = _hub_targets(false, eps, cs, FC_NET_MAX_RELAYS);
    net_relay_ep_t asked[NET_DIR_MAX_ASKED];
    size_t n_asked = 0;
    for (size_t i = 0; i < n && n_asked < NET_DIR_MAX_ASKED; i++)
        if (_hub_ask(&eps[i], cs[i], "hub_lookup", area, NULL) == 0)
            asked[n_asked++] = eps[i];
    if (n_asked == 0) {
        _hub_answer(area, NULL, false);
        return 0;
    }
    pthread_mutex_lock(&fc_net.lock);
    int slot = -1;
    for (int i = 0; i < NET_HUB_MAX_LOOKUPS && slot < 0; i++)
        if (!fc_net.hub_lookups[i].used)
            slot = i;
    if (slot < 0) {                     /* full: replace the oldest */
        slot = 0;
        for (int i = 1; i < NET_HUB_MAX_LOOKUPS; i++)
            if (fc_net.hub_lookups[i].since < fc_net.hub_lookups[slot].since)
                slot = i;
        _hub_lookup_clear_locked(slot);
    }
    fc_net.hub_lookups[slot].used = true;
    at_strlcpy(fc_net.hub_lookups[slot].area, area, sizeof(fc_net.hub_lookups[slot].area));
    memcpy(fc_net.hub_lookups[slot].asked, asked, n_asked * sizeof(asked[0]));
    fc_net.hub_lookups[slot].n_asked = n_asked;
    fc_net.hub_lookups[slot].cards = json_array();
    fc_net.hub_lookups[slot].since = _mono();
    pthread_mutex_unlock(&fc_net.lock);
    return 0;
}

void fc_net_hub_answer(void *arg, const json_t *msg, const char *host, int port)
{
    (void)arg;
    const char *op = json_string_value(json_object_get(msg, "op"));
    const char *why = json_string_value(json_object_get(msg, "reason"));
    if (op != NULL && strcmp(op, "hub_refused") == 0
        && (why == NULL || strcmp(why, "not_hub") != 0))
        log_warn(fc_net.logger, "Relay %s:%d refused area card %s: %s\n", host, port,
                 json_string_value(json_object_get(msg, "area")), why);
    char *text = msg != NULL ? json_dumps(msg, JSON_COMPACT) : NULL;
    if (text == NULL)
        return;
    pthread_mutex_lock(&fc_net.lock);
    if (fc_net.n_hub_answers < FC_NET_ANSWER_QUEUE) {
        size_t i = fc_net.n_hub_answers++;
        at_strlcpy(fc_net.hub_answers[i].ep.host, host,
                   sizeof(fc_net.hub_answers[i].ep.host));
        fc_net.hub_answers[i].ep.port = port;
        fc_net.hub_answers[i].text = text;
        text = NULL;
    }
    pthread_mutex_unlock(&fc_net.lock);
    free(text);
}

void fc_net_drain_hub(void)
{
    for (;;) {
        pthread_mutex_lock(&fc_net.lock);
        char *text = NULL;
        net_relay_ep_t ep;
        if (fc_net.n_hub_answers > 0) {
            text = fc_net.hub_answers[0].text;
            ep = fc_net.hub_answers[0].ep;
            memmove(&fc_net.hub_answers[0], &fc_net.hub_answers[1],
                    (fc_net.n_hub_answers - 1) * sizeof(fc_net.hub_answers[0]));
            fc_net.n_hub_answers--;
        }
        pthread_mutex_unlock(&fc_net.lock);
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
        pthread_mutex_lock(&fc_net.lock);
        int li = _hub_lookup_find_locked(area);
        size_t k = NET_DIR_MAX_ASKED;
        for (size_t i = 0; li >= 0 && i < fc_net.hub_lookups[li].n_asked; i++)
            if (_ep_eq(&fc_net.hub_lookups[li].asked[i], &ep)
                && !fc_net.hub_lookups[li].answered[i])
                k = i;
        bool lookup_answer = li >= 0 && k < NET_DIR_MAX_ASKED
            && (strcmp(op, "hub_cards") == 0 || strcmp(op, "hub_limited") == 0
                || (strcmp(op, "hub_refused") == 0 && not_hub));
        if (lookup_answer) {
            typeof(fc_net.hub_lookups[0]) *l = &fc_net.hub_lookups[li];
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
            pthread_mutex_unlock(&fc_net.lock);
            if (done != NULL) {
                _hub_answer(done_area, done, limited);
                json_decref(done);
            }
            json_decref(frame);
            continue;
        }
        pthread_mutex_unlock(&fc_net.lock);
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
        pthread_mutex_lock(&fc_net.lock);
        for (int i = 0; i < NET_HUB_MAX_LOOKUPS && area[0] == '\0'; i++) {
            if (fc_net.hub_lookups[i].used
                && now - fc_net.hub_lookups[i].since > NET_HUB_LOOKUP_TIMEOUT_SEC) {
                at_strlcpy(area, fc_net.hub_lookups[i].area, sizeof(area));
                limited = fc_net.hub_lookups[i].limited;
                cards = json_incref(fc_net.hub_lookups[i].cards);
                _hub_lookup_clear_locked(i);
            }
        }
        pthread_mutex_unlock(&fc_net.lock);
        if (area[0] == '\0')
            break;
        _hub_answer(area, cards, limited);
        json_decref(cards);
    }
}

void fc_net_hub_age_lookups(double seconds)
{
    pthread_mutex_lock(&fc_net.lock);
    for (int i = 0; i < NET_HUB_MAX_LOOKUPS; i++)
        if (fc_net.hub_lookups[i].used)
            fc_net.hub_lookups[i].since -= seconds;
    pthread_mutex_unlock(&fc_net.lock);
}

void fc_net_dir_age_lookups(double seconds)
{
    pthread_mutex_lock(&fc_net.lock);
    for (size_t i = 0; i < NET_DIR_MAX_LOOKUPS; i++)
        if (fc_net.lookups[i].used)
            fc_net.lookups[i].since -= seconds;
    pthread_mutex_unlock(&fc_net.lock);
}


/****************************
 *  The services our relay serves (R2): the registry and the hub.
 ****************************/

static bool _fc_distrust(void *arg, const char *uuid, const char *pubkey_hex)
{
    (void)arg;
    return net_relay_is_distrusted(uuid, pubkey_hex);
}

/* A registry op from registrant @p uuid. The reply (new reference). Mirrors
 * Python RelayServer's directory op. */
static json_t *_serve_directory(void *arg, const char *uuid, const char *pub,
                                const char *op, const json_t *req)
{
    (void)arg;
    const char *h = json_string_value(json_object_get(req, "handle"));
    const char *handle = h != NULL ? h : "";
    pthread_mutex_lock(&fc_net.lock);
    net_registry_t *reg = fc_net.registry;
    pthread_mutex_unlock(&fc_net.lock);
    const char *reason = NULL;
    if (reg == NULL)
        reason = "not_registry";
    else if (strcmp(op, "dir_publish") == 0)
        return net_registry_publish(reg, uuid, pub, json_object_get(req, "entry"));
    else if (strcmp(op, "dir_withdraw") == 0)
        return net_registry_withdraw(reg, uuid, pub, handle);
    else if (strcmp(op, "dir_lookup") == 0)
        return net_registry_lookup(reg, uuid, handle);
    else
        reason = "unknown_op";
    return json_pack("{s:s, s:s, s:s}", "op", "dir_refused", "handle", handle,
                     "reason", reason);
}

/* A hub op from registrant @p uuid. The reply (new reference). Mirrors Python
 * RelayServer's area-hub op. */
static json_t *_serve_hub(void *arg, const char *uuid, const char *pub, const char *op,
                          const json_t *req)
{
    (void)arg;
    const char *a = json_string_value(json_object_get(req, "area"));
    const char *area = a != NULL ? a : "";
    pthread_mutex_lock(&fc_net.lock);
    net_hub_t *hub = fc_net.hub;
    pthread_mutex_unlock(&fc_net.lock);
    const char *reason = NULL;
    if (hub == NULL)
        reason = "not_hub";
    else if (strcmp(op, "hub_publish") == 0)
        return net_hub_publish(hub, uuid, pub, json_object_get(req, "card"));
    else if (strcmp(op, "hub_withdraw") == 0)
        return net_hub_withdraw(hub, uuid, pub, area);
    else if (strcmp(op, "hub_lookup") == 0)
        return net_hub_lookup(hub, uuid, area);
    else
        reason = "unknown_op";
    return json_pack("{s:s, s:s, s:s}", "op", "hub_refused", "area", area, "reason", reason);
}

void fc_net_serve_registry(net_relay_server_t *srv, net_registry_t *reg)
{
    pthread_mutex_lock(&fc_net.lock);
    fc_net.registry = reg;
    pthread_mutex_unlock(&fc_net.lock);
    (void)net_relay_server_add_op(srv, "dir_", _serve_directory, NULL);   /* once */
}

void fc_net_serve_hub(net_relay_server_t *srv, net_hub_t *hub)
{
    pthread_mutex_lock(&fc_net.lock);
    fc_net.hub = hub;
    pthread_mutex_unlock(&fc_net.lock);
    (void)net_relay_server_add_op(srv, "hub_", _serve_hub, NULL);          /* once */
}

/* Our relay is up: serve the directory ($AT_REGISTRY) and the hub ($AT_HUB).
 * The op families are always plugged in, so a relay that is neither still
 * says so (not_registry / not_hub) rather than staying silent. */
static void _dir_server_started(net_relay_server_t *srv, net_thread_ctx_t *ctx)
{
    if (net_registry_enabled() && fc_net.registry == NULL) {
        char issuers[AT_REGISTRY_MAX_ISSUERS][2 * 32 + 1];
        size_t n = net_registry_load_issuers(NULL, issuers, AT_REGISTRY_MAX_ISSUERS);
        const char *ptrs[AT_REGISTRY_MAX_ISSUERS];
        for (size_t i = 0; i < n; i++)
            ptrs[i] = issuers[i];
        net_registry_t *reg = net_registry_new(ptrs, n, net_registry_rate());
        if (reg != NULL) {
            net_registry_set_distrust(reg, _fc_distrust, NULL);
            fc_net_serve_registry(srv, reg);
            log_info(ctx->logger, "Registry: serving the directory (%zu trusted "
                     "issuer(s))\n", n);
        }
    }
    fc_net_serve_registry(srv, fc_net.registry);
}

static void _hub_server_started(net_relay_server_t *srv, net_thread_ctx_t *ctx)
{
    if (net_hub_enabled() && fc_net.hub == NULL) {
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
        net_hub_t *hub = net_hub_new(ptrs, n, net_hub_rate());
        if (hub != NULL) {
            net_hub_set_distrust(hub, _fc_distrust, NULL);
            fc_net_serve_hub(srv, hub);
            log_info(ctx->logger, "Hub: serving area(s) %s\n", n > 0 ? listed : "(none)");
        }
    }
    fc_net_serve_hub(srv, fc_net.hub);
}

/* We registered at one of our own relays: file our directory entries and area
 * cards there again, since a registry and a hub hold them in memory. */
static void _dir_own_registered(const net_relay_ep_t *ep, net_relay_client_t *c)
{
    (void)ep;
    pthread_mutex_lock(&fc_net.lock);
    json_t *entries = fc_net.own_entries != NULL ? json_deep_copy(fc_net.own_entries) : NULL;
    pthread_mutex_unlock(&fc_net.lock);
    const char *h;
    json_t *w;
    json_object_foreach(entries, h, w)
        (void)net_relay_client_request(c, json_pack("{s:s, s:O}", "op", "dir_publish",
                                                    "entry", w));
    json_decref(entries);
}

static void _hub_own_registered(const net_relay_ep_t *ep, net_relay_client_t *c)
{
    (void)ep;
    pthread_mutex_lock(&fc_net.lock);
    json_t *cards = fc_net.own_cards != NULL ? json_deep_copy(fc_net.own_cards) : NULL;
    pthread_mutex_unlock(&fc_net.lock);
    const char *a;
    json_t *w;
    json_object_foreach(cards, a, w)
        (void)net_relay_client_request(c, json_pack("{s:s, s:O}", "op", "hub_publish",
                                                    "card", w));
    json_decref(cards);
}

/* The directory's state (net_relay_reset_routes, tests). */
static void _dir_reset(void)
{
    pthread_mutex_lock(&fc_net.lock);
    json_decref(fc_net.own_entries);
    fc_net.own_entries = NULL;
    for (size_t i = 0; i < fc_net.n_dir_answers; i++)
        free(fc_net.dir_answers[i].text);
    fc_net.n_dir_answers = 0;
    memset(fc_net.lookups, 0, sizeof(fc_net.lookups));
    pthread_mutex_unlock(&fc_net.lock);
}

static const net_rdv_service_t directory_service = {
    .name = "directory",
    .prefix = "dir_",
    .on_answer = fc_net_dir_answer,
    .own_registered = _dir_own_registered,
    .server_started = _dir_server_started,
    .reset = _dir_reset,
};
NET_RDV_SERVICE_REGISTER(directory, &directory_service)

static const net_rdv_service_t hub_service = {
    .name = "area_hub",
    .prefix = "hub_",
    .on_answer = fc_net_hub_answer,
    .own_registered = _hub_own_registered,
    .server_started = _hub_server_started,
};
NET_RDV_SERVICE_REGISTER(area_hub, &hub_service)


/****************************
 *  First contact as a network extension (net_ext.h): identity's local verbs
 *  for the directory and the hubs, and handing their answers to identity.
 ****************************/

static void _fc_net_start(net_thread_ctx_t *ctx)
{
    pthread_mutex_lock(&fc_net.lock);
    fc_net.logger = ctx->logger;
    pthread_mutex_unlock(&fc_net.lock);
}

static void _fc_net_periodic(net_thread_ctx_t *ctx)
{
    (void)ctx;
    fc_net_drain_dir();
    fc_net_drain_hub();
}

static bool _fc_net_local_verb(net_thread_ctx_t *ctx, net_msg_t *nmsg)
{
    static const struct {
        const char *verb;
        int (*fn)(net_msg_t *, logger_t *);
    } verbs[] = {
        { NET_FN_DIR_PUBLISH, fc_net_dir_publish },
        { NET_FN_DIR_WITHDRAW, fc_net_dir_withdraw },
        { NET_FN_DIR_LOOKUP, fc_net_dir_lookup },
        { NET_FN_HUB_PUBLISH, fc_net_hub_publish },
        { NET_FN_HUB_WITHDRAW, fc_net_hub_withdraw },
        { NET_FN_HUB_LOOKUP, fc_net_hub_lookup },
    };
    for (size_t i = 0; i < sizeof(verbs) / sizeof(verbs[0]); i++)
        if (strcmp(nmsg->function, verbs[i].verb) == 0) {
            (void)verbs[i].fn(nmsg, ctx != NULL ? ctx->logger : NULL);
            return true;
        }
    return false;
}

static const net_ext_t first_contact_net_ext = {
    .name = "first_contact",
    .start = _fc_net_start,
    .periodic = _fc_net_periodic,
    .local_verb = _fc_net_local_verb,
};
NET_EXT_REGISTER(first_contact, &first_contact_net_ext)
