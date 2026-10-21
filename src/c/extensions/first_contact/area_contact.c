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

#define _GNU_SOURCE
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

#include <jansson.h>

#include "first_contact/area_contact.h"
#include "first_contact/directory_contact.h"
#include "first_contact/fc_shared.h"
#include "first_contact/first_contact.h"
#include "identity/identity_priv.h"
#include "identity/id_proc_priv.h"
#include "first_contact/at_first_contact.h"
#include "config/configuration.h"
#include "first_contact/area_card.h"
#include "network/network.h"
#include "first_contact/fc_net.h"
#include "rendezvous/net_relay_rosters.h"
#include "utilities/logger.h"
#include "utilities/message.h"
#include "utilities/msg_registry.h"
#include "utilities/msg_types_priv.h"
#include "utilities/util.h"
#include "utilities/send_retry.h"   /* at_send: keep a refused event */

#define AREA_LOOKUP_REFS_MAX 16
#define AREA_REFS_PER_LOOKUP 8
#define AREA_INVITES_MAX 256
#define AREA_PUBLISH_REFS_MAX 16

typedef struct {
    bool used;
    char uuid[UUID_STRING_LEN + 1];
    at_dir_signed_t card;
    char relay[AT_FC_RELAY_LEN];
    double at;
    unsigned long order;            /* insertion order: the oldest goes first */
} area_found_t;

typedef struct {
    bool used;
    char area[AT_AREA_MAX + 1];
    char refs[AREA_REFS_PER_LOOKUP][AT_FC_REF_LEN];
    size_t n_refs;
} area_waiting_t;

typedef struct {
    char area[AT_AREA_MAX + 1];
    char ref[AT_FC_REF_LEN];
} area_pubref_t;

static struct {
    pthread_mutex_t lock;
    area_found_t found[AT_AREA_FOUND_MAX];
    unsigned long found_order;
    area_waiting_t waiting[AREA_LOOKUP_REFS_MAX];
    char invites[AREA_INVITES_MAX][AT_CONTACT_NONCE_MAX + 1];
    size_t invites_next;
    area_pubref_t pubrefs[AREA_PUBLISH_REFS_MAX];
    size_t pubrefs_next;
} g_area = { .lock = PTHREAD_MUTEX_INITIALIZER };

/* Mutable names: the handler table keys on them. */
static char AREA_APP_PUBLISH[] = AT_APP_AREA_PUBLISH;
static char AREA_APP_WITHDRAW[] = AT_APP_AREA_WITHDRAW;
static char AREA_APP_LOOKUP[] = AT_APP_AREA_LOOKUP;

void at_area_contact_reset(void)
{
    pthread_mutex_lock(&g_area.lock);
    for (size_t i = 0; i < AT_AREA_FOUND_MAX; i++)
        if (g_area.found[i].used)
            at_dir_free(&g_area.found[i].card);
    memset(g_area.found, 0, sizeof(g_area.found));
    memset(g_area.waiting, 0, sizeof(g_area.waiting));
    memset(g_area.invites, 0, sizeof(g_area.invites));
    memset(g_area.pubrefs, 0, sizeof(g_area.pubrefs));
    g_area.found_order = g_area.invites_next = g_area.pubrefs_next = 0;
    pthread_mutex_unlock(&g_area.lock);
}

void at_area_contact_note_invite(const char *nonce)
{
    if (nonce == NULL || nonce[0] == '\0')
        return;
    pthread_mutex_lock(&g_area.lock);
    at_strlcpy(g_area.invites[g_area.invites_next], nonce, sizeof(g_area.invites[0]));
    g_area.invites_next = (g_area.invites_next + 1) % AREA_INVITES_MAX;
    pthread_mutex_unlock(&g_area.lock);
}

bool at_area_contact_is_invite(const char *nonce)
{
    if (nonce == NULL || nonce[0] == '\0')
        return false;
    bool found = false;
    pthread_mutex_lock(&g_area.lock);
    for (size_t i = 0; i < AREA_INVITES_MAX && !found; i++)
        found = strcmp(g_area.invites[i], nonce) == 0;
    pthread_mutex_unlock(&g_area.lock);
    return found;
}

/* -- events and messages ------------------------------------------------------ */
typedef struct {
    const char *ref, *area, *bucket, *peer_uuid, *name, *relay, *reason, *issuer;
    int64_t seq;
    int32_t count;
} area_ev_t;

static void _emit(const process_t *proc, int32_t kind, area_ev_t e)
{
    generic_msg_t msg = {0};
    msg.type = FIRST_CONTACT_AREA_EVENT;
    fc_area_msg_t *m = AT_MSG_EXT(&msg, fc_area_msg_t);
    m->kind = kind;
    at_strlcpy(m->data.ref, e.ref != NULL ? e.ref : "", sizeof(m->data.ref));
    at_strlcpy(m->data.area, e.area != NULL ? e.area : "", sizeof(m->data.area));
    at_strlcpy(m->data.bucket, e.bucket != NULL ? e.bucket : "", sizeof(m->data.bucket));
    if (e.peer_uuid != NULL && e.peer_uuid[0] != '\0')
        (void)uuid_parse(e.peer_uuid, m->data.peer_uuid);
    at_strlcpy(m->data.name, e.name != NULL ? e.name : "", sizeof(m->data.name));
    at_strlcpy(m->data.relay, e.relay != NULL ? e.relay : "", sizeof(m->data.relay));
    at_strlcpy(m->data.reason, e.reason != NULL ? e.reason : "", sizeof(m->data.reason));
    at_strlcpy(m->data.issuer, e.issuer != NULL ? e.issuer : "", sizeof(m->data.issuer));
    m->data.seq = e.seq;
    m->data.count = e.count;
    if (at_send(proc, AT_MAIN_QUEUE, &msg, "an area event", "the app",
                AT_SEND_NOW, NULL, NULL, 0) != 0)
        log_debug(proc->logger, "Identity: area: could not hand the app event %d\n", kind);
}

/* Local IPC to the network process: {verb} with @p body (stolen). */
static void _to_network(char *verb, json_t *body)
{
    generic_msg_t m = {0};
    m.type = NET_MESSAGE;
    at_strlcpy(m.info.net_msg.process, "network", sizeof(m.info.net_msg.process));
    m.info.net_msg.function = verb;
    m.info.net_msg.encrypt = false;
    net_msg_pack_json(&m.info.net_msg, body);
    json_decref(body);
    (void)identity_send_to_network(NULL, &m, "area hub op", NULL);
    net_msg_free_obj(&m.info.net_msg);
}

static bool _local(const net_msg_t *nmsg)
{
    return uuid_is_null(nmsg->from_whom.uuid);
}

/* -- our own listings ----------------------------------------------------------- */
static int _state_path(char *out, size_t len)
{
    char dir[CFG_PATH_LEN + 1] = {0};
    if (get_data_dir(dir, sizeof(dir)) <= 0)
        return -1;
    int n = snprintf(out, len, "%s/%s", dir, AT_AREA_STATE_FILENAME);
    return (n < 0 || (size_t)n >= len) ? -1 : 0;
}

static json_t *_load_state(void)
{
    char path[CFG_PATH_LEN + 64];
    json_t *st = _state_path(path, sizeof(path)) == 0 ? json_load_file(path, 0, NULL) : NULL;
    if (!json_is_object(st)) {
        json_decref(st);
        return json_object();
    }
    return st;
}

static bool _save_state(const process_t *proc, json_t *state)
{
    char dir[CFG_PATH_LEN + 1] = {0}, path[CFG_PATH_LEN + 64], tmp[CFG_PATH_LEN + 80];
    if (get_data_dir(dir, sizeof(dir)) > 0)
        (void)makedirs(dir, 0755);
    bool ok = _state_path(path, sizeof(path)) == 0
        && (size_t)snprintf(tmp, sizeof(tmp), "%s.tmp", path) < sizeof(tmp)
        && json_dump_file(state, tmp, JSON_SORT_KEYS) == 0
        && rename(tmp, path) == 0;
    if (!ok)
        log_warn(proc->logger, "Identity: area: cannot save %s\n", path);
    return ok;
}

static bool _held_listed(const json_t *held)
{
    json_t *card = json_object_get(held, "card");
    return json_is_object(held) && card != NULL && !json_is_null(card);
}

static size_t _count_listed(const json_t *state)
{
    size_t n = 0;
    const char *area;
    json_t *held;
    json_object_foreach((json_t *)state, area, held)
        n += _held_listed(held) ? 1 : 0;
    return n;
}

bool at_area_contact_listed(const char *area)
{
    if (area == NULL)
        return false;
    json_t *state = _load_state();
    bool yes = _held_listed(json_object_get(state, area));
    json_decref(state);
    return yes;
}

/* Sign a fresh card for @p area from what @p state holds, save it, and hand it
 * to the network. AT_DIR_OK, a signing refusal, or 1 when it was not saved.
 * Mirrors Python _issue. */
static int _issue(const process_t *proc, json_t *state, const char *area, double now,
                  int64_t *seq_out)
{
    json_t *held = json_object_get(state, area);
    json_t *jseq = json_object_get(held, "seq");
    int64_t seq = (json_is_integer(jseq) ? (int64_t)json_integer_value(jseq) : 0) + 1;
    const char *b = json_string_value(json_object_get(held, "bucket"));
    const char *n = json_string_value(json_object_get(held, "name"));
    const identity_t *self = identity_self_identity(proc);
    at_dir_signed_t card;
    int rc = self == NULL ? AT_DIR_MALFORMED
        : at_area_card_create(self, area, b != NULL ? b : "", n != NULL ? n : "", seq, 0,
                              now, &card);
    if (rc != AT_DIR_OK)
        return rc;
    json_object_set_new(held, "seq", json_integer((json_int_t)seq));
    json_object_set_new(held, "card", at_dir_to_wire(&card));
    if (!_save_state(proc, state)) {
        /* A seq not saved could be reissued after a restart and refused as stale. */
        at_dir_free(&card);
        return 1;
    }
    _to_network(NET_FN_HUB_PUBLISH, json_pack("{s:o}", "card", at_dir_to_wire(&card)));
    at_dir_free(&card);
    if (seq_out != NULL)
        *seq_out = seq;
    return AT_DIR_OK;
}

static int _cmp_str(const void *a, const void *b)
{
    return strcmp(*(const char *const *)a, *(const char *const *)b);
}

int at_area_contact_refresh(const process_t *proc)
{
    if (proc == NULL || !at_first_contact_enabled())
        return 0;
    double now = at_dir_contact_now();
    json_t *state = _load_state();
    /* Sorted, as Python's sorted(listed_areas). */
    const char *areas[64];
    size_t na = 0;
    const char *area;
    json_t *held;
    json_object_foreach(state, area, held)
        if (_held_listed(held) && na < 64)
            areas[na++] = area;
    qsort(areas, na, sizeof(areas[0]), _cmp_str);
    int n = 0;
    for (size_t i = 0; i < na; i++) {
        held = json_object_get(state, areas[i]);
        at_dir_signed_t card;
        bool fresh = false;
        if (at_dir_from_wire(json_object_get(held, "card"), &card) == AT_DIR_OK) {
            fresh = (double)at_dir_expiry(&card) - now > AT_AREA_DEFAULT_TTL_SECONDS / 2.0;
            if (fresh)
                _to_network(NET_FN_HUB_PUBLISH, json_pack("{s:o}", "card", at_dir_to_wire(&card)));
            at_dir_free(&card);
        }
        if (fresh) {
            n++;
            continue;
        }
        int rc = _issue(proc, state, areas[i], now, NULL);
        if (rc == AT_DIR_OK)
            n++;
        else if (rc < 0)
            log_warn(proc->logger, "Identity: area: cannot refresh %s\n", areas[i]);
    }
    json_decref(state);
    return n;
}

static void _set_pubref(const char *area, const char *ref)
{
    pthread_mutex_lock(&g_area.lock);
    area_pubref_t *slot = NULL;
    for (size_t i = 0; i < AREA_PUBLISH_REFS_MAX && slot == NULL; i++)
        if (strcmp(g_area.pubrefs[i].area, area) == 0)
            slot = &g_area.pubrefs[i];
    if (slot == NULL) {
        slot = &g_area.pubrefs[g_area.pubrefs_next];
        g_area.pubrefs_next = (g_area.pubrefs_next + 1) % AREA_PUBLISH_REFS_MAX;
    }
    at_strlcpy(slot->area, area, sizeof(slot->area));
    at_strlcpy(slot->ref, ref, sizeof(slot->ref));
    pthread_mutex_unlock(&g_area.lock);
}

static void _get_pubref(const char *area, char *out, size_t len)
{
    out[0] = '\0';
    pthread_mutex_lock(&g_area.lock);
    for (size_t i = 0; i < AREA_PUBLISH_REFS_MAX; i++)
        if (area[0] != '\0' && strcmp(g_area.pubrefs[i].area, area) == 0)
            at_strlcpy(out, g_area.pubrefs[i].ref, len);
    pthread_mutex_unlock(&g_area.lock);
}

static void _refused(const process_t *proc, const char *ref, const char *area,
                     const char *reason)
{
    _emit(proc, AT_APP_EVENT_AREA_REFUSED, (area_ev_t){ .ref = ref, .area = area,
                                                        .reason = reason });
}

bool handle_area_app_publish(const process_t *proc, directory_t *queues,
                                    generic_msg_t *msg)
{
    (void)queues;
    net_msg_t *nmsg = &msg->info.net_msg;
    if (!identity_is_local_app_verb(proc, nmsg))
        return identity_refuse_remote_app_verb(proc, nmsg, AT_APP_AREA_PUBLISH);
    json_t *req = at_fc_app_payload(nmsg);
    const char *r = at_fc_app_ref(req);
    char ref[AT_FC_REF_LEN], area[AT_AREA_MAX + 1] = "", bucket[AT_AREA_BUCKET_MAX + 1] = "";
    at_strlcpy(ref, r != NULL ? r : "", sizeof(ref));
    bool area_ok = at_area_normalize(json_string_value(json_object_get(req, "area")), area,
                                     sizeof(area), AT_AREA_MIN, AT_AREA_MAX) == 0;
    if (!area_ok)
        area[0] = '\0';
    bool bucket_ok = at_area_normalize(json_string_value(json_object_get(req, "bucket")),
                                       bucket, sizeof(bucket), 1, AT_AREA_BUCKET_MAX) == 0;
    json_t *jn = json_object_get(req, "name");
    const char *name = jn == NULL ? "" : json_string_value(jn);
    if (r == NULL || !area_ok || !bucket_ok || strncmp(bucket, area, strlen(area)) != 0
        || !at_area_valid_name(name)) {
        _refused(proc, ref, area, "bad_request");
        json_decref(req);
        return true;
    }
    json_t *state = _load_state();
    if (!_held_listed(json_object_get(state, area)) && _count_listed(state) >= AT_AREA_LISTED_MAX) {
        _refused(proc, ref, area, "full");
        json_decref(state);
        json_decref(req);
        return true;
    }
    json_t *held = json_object_get(state, area);
    if (!json_is_object(held)) {
        held = json_pack("{s:i}", "seq", 0);
        json_object_set_new(state, area, held);
    }
    json_object_set_new(held, "bucket", json_string(bucket));
    json_object_set_new(held, "name", json_string(name));
    json_decref(req);
    _set_pubref(area, ref);
    int64_t seq = 0;
    int rc = _issue(proc, state, area, at_dir_contact_now(), &seq);
    json_decref(state);
    if (rc != AT_DIR_OK) {
        _refused(proc, ref, area, "mint_failed");
        return true;
    }
    log_info(proc->logger, "Identity: area: listing us in %s (seq %lld)\n", area,
             (long long)seq);
    return true;
}

bool handle_area_app_withdraw(const process_t *proc, directory_t *queues,
                                     generic_msg_t *msg)
{
    (void)queues;
    net_msg_t *nmsg = &msg->info.net_msg;
    if (!identity_is_local_app_verb(proc, nmsg))
        return identity_refuse_remote_app_verb(proc, nmsg, AT_APP_AREA_WITHDRAW);
    json_t *req = at_fc_app_payload(nmsg);
    const char *r = at_fc_app_ref(req);
    char ref[AT_FC_REF_LEN], area[AT_AREA_MAX + 1];
    at_strlcpy(ref, r != NULL ? r : "", sizeof(ref));
    if (at_area_normalize(json_string_value(json_object_get(req, "area")), area, sizeof(area),
                          AT_AREA_MIN, AT_AREA_MAX) != 0) {
        _refused(proc, ref, NULL, "bad_request");
        json_decref(req);
        return true;
    }
    json_decref(req);
    json_t *state = _load_state();
    json_t *held = json_object_get(state, area);
    if (json_is_object(held)) {
        /* Keep the seq: a later listing in the same area must still rise. */
        json_object_set_new(held, "card", json_null());
        (void)_save_state(proc, state);
    }
    json_decref(state);
    _set_pubref(area, ref);
    _to_network(NET_FN_HUB_WITHDRAW, json_pack("{s:s}", "area", area));
    return true;
}

bool handle_area_hub_status(const process_t *proc, directory_t *queues, generic_msg_t *msg)
{
    (void)queues;
    net_msg_t *nmsg = &msg->info.net_msg;
    if (!_local(nmsg)) {
        log_warn(proc->logger, "Identity: area: refusing hub_status from the wire\n");
        return true;
    }
    json_t *body = at_fc_app_payload(nmsg);
    const char *op = json_string_value(json_object_get(body, "op"));
    int32_t kind = op == NULL ? 0
        : strcmp(op, "hub_published") == 0 ? AT_APP_EVENT_AREA_PUBLISHED
        : strcmp(op, "hub_refused") == 0 ? AT_APP_EVENT_AREA_REFUSED
        : strcmp(op, "hub_withdrawn") == 0 ? AT_APP_EVENT_AREA_WITHDRAWN : 0;
    if (kind != 0) {
        const char *a = json_string_value(json_object_get(body, "area"));
        char ref[AT_FC_REF_LEN];
        _get_pubref(a != NULL ? a : "", ref, sizeof(ref));
        json_t *seq = json_object_get(body, "seq");
        _emit(proc, kind, (area_ev_t){
            .ref = ref, .area = a, .relay = json_string_value(json_object_get(body, "relay")),
            .reason = json_string_value(json_object_get(body, "reason")),
            .seq = json_is_integer(seq) ? (int64_t)json_integer_value(seq) : 0 });
    }
    json_decref(body);
    return true;
}

/* -- finding people nearby --------------------------------------------------------- */
bool handle_area_app_lookup(const process_t *proc, directory_t *queues,
                                   generic_msg_t *msg)
{
    (void)queues;
    net_msg_t *nmsg = &msg->info.net_msg;
    if (!identity_is_local_app_verb(proc, nmsg))
        return identity_refuse_remote_app_verb(proc, nmsg, AT_APP_AREA_LOOKUP);
    json_t *req = at_fc_app_payload(nmsg);
    const char *ref = at_fc_app_ref(req);
    char area[AT_AREA_MAX + 1];
    if (ref == NULL || at_area_normalize(json_string_value(json_object_get(req, "area")), area,
                                         sizeof(area), AT_AREA_MIN, AT_AREA_MAX) != 0) {
        _refused(proc, ref != NULL ? ref : "", NULL, "bad_request");
        json_decref(req);
        return true;
    }
    bool first = false;
    pthread_mutex_lock(&g_area.lock);
    area_waiting_t *w = NULL;
    for (size_t i = 0; i < AREA_LOOKUP_REFS_MAX && w == NULL; i++)
        if (g_area.waiting[i].used && strcmp(g_area.waiting[i].area, area) == 0)
            w = &g_area.waiting[i];
    for (size_t i = 0; i < AREA_LOOKUP_REFS_MAX && w == NULL; i++)
        if (!g_area.waiting[i].used) {
            w = &g_area.waiting[i];
            memset(w, 0, sizeof(*w));
            w->used = true;
            at_strlcpy(w->area, area, sizeof(w->area));
        }
    if (w != NULL) {
        first = w->n_refs == 0;
        if (w->n_refs < AREA_REFS_PER_LOOKUP)
            at_strlcpy(w->refs[w->n_refs++], ref, sizeof(w->refs[0]));
    }
    pthread_mutex_unlock(&g_area.lock);
    json_decref(req);
    if (w == NULL || first)
        _to_network(NET_FN_HUB_LOOKUP, json_pack("{s:s}", "area", area));
    return true;
}

typedef struct {
    char uuid[UUID_STRING_LEN + 1];
    at_dir_signed_t card;
    char relay[AT_FC_RELAY_LEN];
} area_best_t;

static int _by_uuid(const void *a, const void *b)
{
    return strcmp(((const area_best_t *)a)->uuid, ((const area_best_t *)b)->uuid);
}

static void _remember_found_locked(area_best_t *b, double now)
{
    area_found_t *slot = NULL;
    for (size_t i = 0; i < AT_AREA_FOUND_MAX && slot == NULL; i++)
        if (g_area.found[i].used && strcmp(g_area.found[i].uuid, b->uuid) == 0)
            slot = &g_area.found[i];
    for (size_t i = 0; i < AT_AREA_FOUND_MAX && slot == NULL; i++)
        if (!g_area.found[i].used)
            slot = &g_area.found[i];
    if (slot == NULL) {             /* full: the oldest goes */
        slot = &g_area.found[0];
        for (size_t i = 1; i < AT_AREA_FOUND_MAX; i++)
            if (g_area.found[i].order < slot->order)
                slot = &g_area.found[i];
    }
    if (slot->used)
        at_dir_free(&slot->card);
    slot->used = true;
    slot->order = ++g_area.found_order;
    at_strlcpy(slot->uuid, b->uuid, sizeof(slot->uuid));
    json_t *w = at_dir_to_wire(&b->card);
    (void)at_dir_from_wire(w, &slot->card);
    json_decref(w);
    at_strlcpy(slot->relay, b->relay, sizeof(slot->relay));
    slot->at = now;
}

bool handle_area_hub_result(const process_t *proc, directory_t *queues, generic_msg_t *msg)
{
    (void)queues;
    net_msg_t *nmsg = &msg->info.net_msg;
    if (!_local(nmsg)) {
        log_warn(proc->logger, "Identity: area: refusing hub_result from the wire\n");
        return true;
    }
    json_t *body = at_fc_app_payload(nmsg);
    char area[AT_AREA_MAX + 1];
    if (at_area_normalize(json_string_value(json_object_get(body, "area")), area, sizeof(area),
                          AT_AREA_MIN, AT_AREA_MAX) != 0)
        area[0] = '\0';
    char refs[AREA_REFS_PER_LOOKUP][AT_FC_REF_LEN];
    size_t n_refs = 0;
    pthread_mutex_lock(&g_area.lock);
    for (size_t i = 0; i < AREA_LOOKUP_REFS_MAX; i++)
        if (g_area.waiting[i].used && strcmp(g_area.waiting[i].area, area) == 0) {
            n_refs = g_area.waiting[i].n_refs;
            memcpy(refs, g_area.waiting[i].refs, sizeof(refs));
            memset(&g_area.waiting[i], 0, sizeof(g_area.waiting[i]));
            break;
        }
    pthread_mutex_unlock(&g_area.lock);
    if (n_refs == 0) {
        refs[0][0] = '\0';
        n_refs = 1;
    }
    char me[UUID_STRING_LEN + 1] = "";
    const identity_t *self = identity_self_identity(proc);
    if (self != NULL)
        uuid_unparse_lower(self->uuid, me);
    double now = at_dir_contact_now();
    json_t *items = json_object_get(body, "cards");
    size_t cap = json_array_size(items), n = 0;
    area_best_t *best = calloc(cap > 0 ? cap : 1, sizeof(*best));
    size_t i;
    json_t *item;
    json_array_foreach(items, i, item) {
        if (best == NULL || !json_is_object(item))
            continue;
        at_dir_signed_t card;
        int rc = at_dir_from_wire(json_object_get(item, "card"), &card);
        if (rc == AT_DIR_OK) {
            rc = at_area_card_verify(&card, now);
            if (rc != AT_DIR_OK)
                at_dir_free(&card);
        }
        if (rc != AT_DIR_OK) {
            log_warn(proc->logger, "Identity: area: a card for %s refused\n", area);
            continue;
        }
        char uu[UUID_STRING_LEN + 1];
        at_strlcpy(uu, at_dir_uuid(&card), sizeof(uu));
        for (char *c = uu; *c != '\0'; c++)
            if (*c >= 'A' && *c <= 'Z')
                *c = (char)(*c - 'A' + 'a');
        if (strcmp(at_area_card_area(&card), area) != 0 || strcmp(uu, me) == 0) {
            at_dir_free(&card);
            continue;
        }
        const char *relay = json_string_value(json_object_get(item, "relay"));
        area_best_t *held = NULL;
        for (size_t k = 0; k < n && held == NULL; k++)
            if (strcmp(best[k].uuid, uu) == 0)
                held = &best[k];
        if (held == NULL) {
            held = &best[n++];
            at_strlcpy(held->uuid, uu, sizeof(held->uuid));
        } else if (at_dir_seq(&card) > at_dir_seq(&held->card)) {
            at_dir_free(&held->card);
        } else {
            at_dir_free(&card);
            continue;
        }
        held->card = card;              /* move */
        at_strlcpy(held->relay, relay != NULL ? relay : "", sizeof(held->relay));
    }
    if (n > 1)
        qsort(best, n, sizeof(*best), _by_uuid);
    pthread_mutex_lock(&g_area.lock);
    for (size_t k = 0; k < n; k++)
        _remember_found_locked(&best[k], now);
    pthread_mutex_unlock(&g_area.lock);
    const char *reason = json_is_true(json_object_get(body, "limited")) ? "limited" : "";
    for (size_t r = 0; r < n_refs; r++) {
        for (size_t k = 0; k < n; k++)
            _emit(proc, AT_APP_EVENT_AREA_CARD, (area_ev_t){
                .ref = refs[r], .area = area, .bucket = at_area_card_bucket(&best[k].card),
                .peer_uuid = best[k].uuid, .name = at_area_card_name(&best[k].card),
                .relay = best[k].relay, .seq = at_dir_seq(&best[k].card) });
        _emit(proc, AT_APP_EVENT_AREA_DONE, (area_ev_t){ .ref = refs[r], .area = area,
                                                         .reason = reason, .count = (int32_t)n });
    }
    for (size_t k = 0; k < n; k++)
        at_dir_free(&best[k].card);
    free(best);
    json_decref(body);
    return true;
}

bool at_area_contact_found(const char *uuid, const char *area, at_dir_signed_t *card,
                           char *relay, size_t relay_len)
{
    if (uuid == NULL || area == NULL || card == NULL)
        return false;
    double now = at_dir_contact_now();
    bool have = false;
    pthread_mutex_lock(&g_area.lock);
    for (size_t i = 0; i < AT_AREA_FOUND_MAX && !have; i++) {
        area_found_t *f = &g_area.found[i];
        if (!f->used || strcasecmp(f->uuid, uuid) != 0)
            continue;
        if (now - f->at <= AT_AREA_FOUND_TTL_SECONDS
            && now < (double)at_dir_expiry(&f->card)
            && strcmp(at_area_card_area(&f->card), area) == 0) {
            json_t *w = at_dir_to_wire(&f->card);
            have = at_dir_from_wire(w, card) == AT_DIR_OK;
            json_decref(w);
            if (relay != NULL)
                at_strlcpy(relay, f->relay, relay_len);
        }
        break;
    }
    pthread_mutex_unlock(&g_area.lock);
    return have;
}

/* -- registration -------------------------------------------------------------- */
void at_area_contact_register(process_t *proc)
{
    process_register_handler(proc, AREA_APP_PUBLISH, (handler_ptr_t)handle_area_app_publish);
    process_register_handler(proc, AREA_APP_WITHDRAW, (handler_ptr_t)handle_area_app_withdraw);
    process_register_handler(proc, AREA_APP_LOOKUP, (handler_ptr_t)handle_area_app_lookup);
    process_register_handler(proc, NET_ID_HUB_RESULT, (handler_ptr_t)handle_area_hub_result);
    process_register_handler(proc, NET_ID_HUB_STATUS, (handler_ptr_t)handle_area_hub_status);
}

/* The app may send exactly these verbs, each only to identity. Mirrors
 * Python's area_contact.APP_VERBS in first contact's EXTENSION. */
AT_APP_VERB_REGISTER(area_publish, AT_APP_AREA_PUBLISH, "identity")
AT_APP_VERB_REGISTER(area_withdraw, AT_APP_AREA_WITHDRAW, "identity")
AT_APP_VERB_REGISTER(area_lookup, AT_APP_AREA_LOOKUP, "identity")

/* -- the buckets we are listed under, for rendezvous's roster hints ----------- */

/* A hub serving one of these buckets is preferred among a community's relays
 * (rendezvous/net_relay_rosters.h). Read from the file, not identity's memory: the
 * hints are computed in the network process too. */
static size_t _listed_buckets(char out[][8], size_t max)
{
    char path[CFG_PATH_LEN + 64];
    json_t *state = _state_path(path, sizeof(path)) == 0 ? json_load_file(path, 0, NULL)
                                                         : NULL;
    size_t n = 0;
    const char *area;
    json_t *held;
    json_object_foreach(state, area, held) {
        const char *b = json_string_value(json_object_get(held, "bucket"));
        json_t *card = json_object_get(held, "card");
        if (n < max && b != NULL && b[0] != '\0' && strlen(b) < 8 && card != NULL
            && !json_is_null(card))
            snprintf(out[n++], 8, "%s", b);
    }
    json_decref(state);
    return n;
}

static const net_relay_area_provider_t area_listings = {
    .listed_buckets = _listed_buckets,
    .state_path = _state_path,
};

static void __attribute__((constructor)) _area_provider_register(void)
{
    net_relay_rosters_set_area_provider(&area_listings);
}
