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
#include <time.h>

#include <jansson.h>
#include <sodium.h>

#include "identity/directory_contact.h"
#include "identity/area_contact.h"
#include "identity/fc_shared.h"
#include "identity/first_contact.h"
#include "identity/identity_priv.h"
#include "identity/id_proc_priv.h"
#include "at_first_contact.h"
#include "config/configuration.h"
#include "contacts/contacts.h"
#include "contacts/directory.h"
#include "contacts/area_card.h"
#include "network/network.h"
#include "network/net_relay.h"
#include "utilities/allocation.h"
#include "utilities/logger.h"
#include "utilities/message.h"
#include "utilities/msg_registry.h"
#include "utilities/msg_types_priv.h"
#include "utilities/util.h"

#define DIR_HINT_LEN (AT_RELAY_HOST_LEN + 96)
#define DIR_OUT_MAX 64
#define DIR_LOOKUP_REFS_MAX 64
#define DIR_REFS_PER_LOOKUP 8
#define DIR_INVITES_MAX 256
#define DIR_PUBLISH_REFS_MAX 64

typedef struct {
    bool used;
    char handle[AT_DIR_HANDLE_MAX + 1];
    at_dir_signed_t entry;
    char relay[AT_FC_RELAY_LEN];
    double at;
} dir_found_t;

typedef struct {
    bool used;
    char holder[UUID_STRING_LEN + 1];
    char ref[AT_FC_REF_LEN];
    char nonce[AT_DIR_NONCE_HEX + 1];
    char key[65];
    char handle[AT_DIR_HANDLE_MAX + 1];
    double deadline;
    bool by_area;                   /* found at an area hub, not by handle */
} dir_out_t;

typedef struct {
    bool used;
    char nonce[AT_DIR_NONCE_HEX + 1];
    public_identity_t sender;
    char handle[AT_DIR_HANDLE_MAX + 1];
    char relays[AT_DIR_REQUEST_MAX_RELAYS][DIR_HINT_LEN];
    size_t n_relays;
    double expiry;
    unsigned long order;            /* insertion order: the oldest goes first */
    bool by_area;                   /* asked via an area we are listed in */
} dir_in_t;

typedef struct {
    bool used;
    char handle[AT_DIR_HANDLE_MAX + 1];
    char refs[DIR_REFS_PER_LOOKUP][AT_FC_REF_LEN];
    size_t n_refs;
} dir_waiting_t;

typedef struct {
    char handle[AT_DIR_HANDLE_MAX + 1];
    char ref[AT_FC_REF_LEN];
} dir_pubref_t;

static struct {
    pthread_mutex_t lock;
    dir_found_t found[AT_DIR_FOUND_MAX];
    unsigned long found_next;
    dir_out_t out[DIR_OUT_MAX];
    dir_in_t in[AT_DIR_REQUESTS_IN_MAX];
    unsigned long in_order;
    dir_waiting_t waiting[DIR_LOOKUP_REFS_MAX];
    char invites[DIR_INVITES_MAX][AT_CONTACT_NONCE_MAX + 1];
    size_t invites_next;
    dir_pubref_t pubrefs[DIR_PUBLISH_REFS_MAX];
    size_t pubrefs_next;
} g_dir = { .lock = PTHREAD_MUTEX_INITIALIZER };

/* Seconds added to this node's directory clock: a test seam, so a scenario can
 * let an hour pass between a request and its accept. Set only by the harness
 * between dispatches (at_dir_contact_advance_clock); 0 = wall clock. Cleared by
 * at_dir_contact_reset. Python twin: IdentityProcess._dir_clock_advance. */
static double g_dir_clock_advance = 0.0;

static double _dir_now(void)
{
    return (double)time(NULL) + g_dir_clock_advance;
}

double at_dir_contact_now(void)
{
    return _dir_now();
}

/* Mutable names: the handler table keys on them. */
static char DIR_APP_PUBLISH[] = AT_APP_DIR_PUBLISH;
static char DIR_APP_WITHDRAW[] = AT_APP_DIR_WITHDRAW;
static char DIR_APP_LOOKUP[] = AT_APP_DIR_LOOKUP;
static char DIR_APP_REQUEST[] = AT_APP_FC_REQUEST;
static char DIR_APP_ACCEPT[] = AT_APP_FC_ACCEPT;
static char DIR_APP_DECLINE[] = AT_APP_FC_DECLINE;

void at_dir_contact_reset(void)
{
    pthread_mutex_lock(&g_dir.lock);
    for (size_t i = 0; i < AT_DIR_FOUND_MAX; i++)
        if (g_dir.found[i].used)
            at_dir_free(&g_dir.found[i].entry);
    for (size_t i = 0; i < AT_DIR_REQUESTS_IN_MAX; i++)
        if (g_dir.in[i].used)
            at_fc_free_public(&g_dir.in[i].sender);
    memset(g_dir.found, 0, sizeof(g_dir.found));
    memset(g_dir.out, 0, sizeof(g_dir.out));
    memset(g_dir.in, 0, sizeof(g_dir.in));
    memset(g_dir.waiting, 0, sizeof(g_dir.waiting));
    memset(g_dir.invites, 0, sizeof(g_dir.invites));
    memset(g_dir.pubrefs, 0, sizeof(g_dir.pubrefs));
    g_dir.found_next = g_dir.in_order = 0;
    g_dir.invites_next = g_dir.pubrefs_next = 0;
    pthread_mutex_unlock(&g_dir.lock);
    g_dir_clock_advance = 0.0;
    /* Its area half (identity/area_contact.c) goes with it. */
    at_area_contact_reset();
}

void at_dir_contact_advance_clock(double seconds)
{
    g_dir_clock_advance += seconds;
}

size_t at_dir_contact_held_count(void)
{
    size_t n = 0;
    pthread_mutex_lock(&g_dir.lock);
    for (size_t i = 0; i < AT_DIR_REQUESTS_IN_MAX; i++)
        n += g_dir.in[i].used ? 1 : 0;
    pthread_mutex_unlock(&g_dir.lock);
    return n;
}

void at_dir_contact_outstanding_nonce(const char *holder_uuid, char *out, size_t len)
{
    if (out == NULL || len == 0)
        return;
    out[0] = '\0';
    if (holder_uuid == NULL)
        return;
    pthread_mutex_lock(&g_dir.lock);
    for (size_t i = 0; i < DIR_OUT_MAX; i++)
        if (g_dir.out[i].used && strcasecmp(g_dir.out[i].holder, holder_uuid) == 0) {
            at_strlcpy(out, g_dir.out[i].nonce, len);
            break;
        }
    pthread_mutex_unlock(&g_dir.lock);
}

bool at_dir_contact_is_invite(const char *nonce)
{
    if (nonce == NULL || nonce[0] == '\0')
        return false;
    bool found = false;
    pthread_mutex_lock(&g_dir.lock);
    for (size_t i = 0; i < DIR_INVITES_MAX && !found; i++)
        found = strcmp(g_dir.invites[i], nonce) == 0;
    pthread_mutex_unlock(&g_dir.lock);
    return found;
}

/* -- events and messages ------------------------------------------------------ */
static void _emit(const process_t *proc, int32_t kind, const char *ref,
                  const char *handle, const char *peer_uuid, const char *nickname,
                  const char *relay, const char *reason, int64_t seq)
{
    generic_msg_t msg = {0};
    msg.type = FIRST_CONTACT_DIRECTORY_EVENT;
    fc_directory_msg_t *m = AT_MSG_EXT(&msg, fc_directory_msg_t);
    m->kind = kind;
    at_strlcpy(m->data.ref, ref != NULL ? ref : "", sizeof(m->data.ref));
    at_strlcpy(m->data.handle, handle != NULL ? handle : "", sizeof(m->data.handle));
    if (peer_uuid != NULL && peer_uuid[0] != '\0')
        (void)uuid_parse(peer_uuid, m->data.peer_uuid);
    at_strlcpy(m->data.nickname, nickname != NULL ? nickname : "", sizeof(m->data.nickname));
    at_strlcpy(m->data.relay, relay != NULL ? relay : "", sizeof(m->data.relay));
    at_strlcpy(m->data.reason, reason != NULL ? reason : "", sizeof(m->data.reason));
    m->data.seq = seq;
    if (messaging_send(AT_MAIN_QUEUE, FIRST_CONTACT_DIRECTORY_EVENT, &msg, false) != 0)
        log_debug(proc->logger, "Identity: directory: no main queue for event %d\n", kind);
}

static void _refused(const process_t *proc, const char *ref, const char *handle,
                     const char *reason)
{
    _emit(proc, AT_APP_EVENT_DIR_REFUSED, ref, handle, NULL, NULL, NULL, reason, 0);
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
    (void)identity_send_to_network(NULL, &m, "directory relay op", NULL);
    net_msg_free_obj(&m.info.net_msg);
}

/* A plaintext identity message to @p whom (not yet a peer), from us. */
static void _to_wire(const process_t *proc, char *verb, const public_identity_t *whom,
                     json_t *body)
{
    generic_msg_t m = {0};
    m.type = NET_MESSAGE;
    at_strlcpy(m.info.net_msg.process, "identity", sizeof(m.info.net_msg.process));
    m.info.net_msg.function = verb;
    m.info.net_msg.encrypt = false;
    memcpy(&m.info.net_msg.to_whom, whom, sizeof(public_identity_t));
    (void)identity_own_public_identity(proc, &m.info.net_msg.from_whom);
    at_strlcpy(m.info.net_msg.return_to, "identity", sizeof(m.info.net_msg.return_to));
    net_msg_pack_json(&m.info.net_msg, body);
    json_decref(body);
    (void)identity_send_to_network(proc, &m, "directory request", NULL);
    net_msg_free_obj(&m.info.net_msg);
    at_fc_free_public(&m.info.net_msg.from_whom);
}

static bool _local(const net_msg_t *nmsg)
{
    return uuid_is_null(nmsg->from_whom.uuid);
}

static void _self_uuid(const process_t *proc, char *out)
{
    out[0] = '\0';
    const identity_t *self = identity_self_identity(proc);
    if (self != NULL)
        uuid_unparse_lower(self->uuid, out);
}

static void _lower(char *s)
{
    for (; s != NULL && *s != '\0'; s++)
        if (*s >= 'A' && *s <= 'Z')
            *s = (char)(*s - 'A' + 'a');
}

/* The payload's signed object ({body, sig}), whether it came as an object or
 * as its JSON text. */
static int _signed_from(const json_t *v, at_dir_signed_t *out)
{
    if (json_is_string(v))
        return at_dir_from_text(json_string_value(v), out);
    return at_dir_from_wire(v, out);
}

/* -- our own entries ---------------------------------------------------------- */
static int _state_path(char *out, size_t len)
{
    char dir[CFG_PATH_LEN + 1] = {0};
    if (get_data_dir(dir, sizeof(dir)) <= 0)
        return -1;
    int n = snprintf(out, len, "%s/%s", dir, AT_DIR_STATE_FILENAME);
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
        && json_dump_file(state, tmp, JSON_SORT_KEYS | JSON_INDENT(2)) == 0
        && rename(tmp, path) == 0;
    if (!ok)
        log_warn(proc->logger, "Identity: directory: cannot save %s\n", path);
    return ok;
}

/* An unexpired entry held in @p held ({seq, entry}), into @p out. */
static bool _held_entry(const json_t *held, double now, at_dir_signed_t *out)
{
    if (at_dir_from_wire(json_object_get(held, "entry"), out) != AT_DIR_OK)
        return false;
    json_t *exp = json_object_get(out->body, "expiry");
    if (!json_is_integer(exp) || now >= (double)json_integer_value(exp)) {
        at_dir_free(out);
        return false;
    }
    return true;
}

int at_dir_contact_restore_entries(process_t *proc)
{
    if (proc == NULL || !at_first_contact_enabled())
        return 0;
    json_t *state = _load_state();
    double now = _dir_now();
    int n = 0;
    const char *handle;
    json_t *held;
    json_object_foreach(state, handle, held) {
        at_dir_signed_t e;
        if (!_held_entry(held, now, &e))
            continue;
        _to_network(NET_FN_DIR_PUBLISH, json_pack("{s:o}", "entry", at_dir_to_wire(&e)));
        at_dir_free(&e);
        n++;
    }
    json_decref(state);
    if (n > 0)
        log_info(proc->logger, "Identity: directory: refiling %d entr%s of ours\n",
                 n, n == 1 ? "y" : "ies");
    return n;
}

static bool _is_published(const char *handle)
{
    json_t *state = _load_state();
    at_dir_signed_t e;
    bool yes = _held_entry(json_object_get(state, handle), _dir_now(), &e);
    if (yes)
        at_dir_free(&e);
    json_decref(state);
    return yes;
}

static void _set_pubref(const char *handle, const char *ref)
{
    pthread_mutex_lock(&g_dir.lock);
    dir_pubref_t *slot = NULL;
    for (size_t i = 0; i < DIR_PUBLISH_REFS_MAX && slot == NULL; i++)
        if (strcmp(g_dir.pubrefs[i].handle, handle) == 0)
            slot = &g_dir.pubrefs[i];
    if (slot == NULL) {
        slot = &g_dir.pubrefs[g_dir.pubrefs_next];
        g_dir.pubrefs_next = (g_dir.pubrefs_next + 1) % DIR_PUBLISH_REFS_MAX;
    }
    at_strlcpy(slot->handle, handle, sizeof(slot->handle));
    at_strlcpy(slot->ref, ref, sizeof(slot->ref));
    pthread_mutex_unlock(&g_dir.lock);
}

static void _get_pubref(const char *handle, char *out, size_t len)
{
    out[0] = '\0';
    pthread_mutex_lock(&g_dir.lock);
    for (size_t i = 0; i < DIR_PUBLISH_REFS_MAX; i++)
        if (handle[0] != '\0' && strcmp(g_dir.pubrefs[i].handle, handle) == 0)
            at_strlcpy(out, g_dir.pubrefs[i].ref, len);
    pthread_mutex_unlock(&g_dir.lock);
}

static const char *_REASONS[] = {"", "malformed", "bad_signature", "expired",
                                 "untrusted", "mismatch"};

bool handle_dir_app_publish(const process_t *proc, directory_t *queues, generic_msg_t *msg)
{
    (void)queues;
    net_msg_t *nmsg = &msg->info.net_msg;
    if (!identity_is_local_app_verb(proc, nmsg))
        return identity_refuse_remote_app_verb(proc, nmsg, AT_APP_DIR_PUBLISH);
    json_t *req = at_fc_app_payload(nmsg);
    const char *r = at_fc_app_ref(req);
    if (r == NULL) {
        _refused(proc, "", NULL, "bad_request");
        json_decref(req);
        return true;
    }
    char ref[AT_FC_REF_LEN];
    at_strlcpy(ref, r, sizeof(ref));
    json_t *jv = json_object_get(req, "visibility");
    const char *visibility = jv == NULL ? AT_DIR_VISIBILITY_ANYONE : json_string_value(jv);
    at_dir_signed_t att;
    int rc = _signed_from(json_object_get(req, "attestation"), &att);
    if (rc == AT_DIR_OK) {
        rc = at_dir_attest_verify(&att, NULL, 0, _dir_now());
        if (rc != AT_DIR_OK)
            at_dir_free(&att);
    }
    if (rc != AT_DIR_OK) {
        log_warn(proc->logger, "Identity: directory: app publish refused (%s)\n",
                 _REASONS[-rc]);
        _refused(proc, ref, NULL, _REASONS[-rc]);
        json_decref(req);
        return true;
    }
    char handle[AT_DIR_HANDLE_MAX + 1];
    at_strlcpy(handle, at_dir_handle(&att), sizeof(handle));
    if (visibility == NULL || (strcmp(visibility, AT_DIR_VISIBILITY_ANYONE) != 0
                               && strcmp(visibility, AT_DIR_VISIBILITY_PUBLISHED) != 0)) {
        _refused(proc, ref, handle, "bad_request");
        at_dir_free(&att);
        json_decref(req);
        return true;
    }
    /* Point at the constant, not into req: req is released before the log line. */
    visibility = strcmp(visibility, AT_DIR_VISIBILITY_ANYONE) == 0
               ? AT_DIR_VISIBILITY_ANYONE : AT_DIR_VISIBILITY_PUBLISHED;
    json_t *state = _load_state();
    json_t *jseq = json_object_get(json_object_get(state, handle), "seq");
    int64_t seq = (json_is_integer(jseq) ? (int64_t)json_integer_value(jseq) : 0) + 1;
    at_dir_signed_t entry;
    const identity_t *self = identity_self_identity(proc);
    rc = self == NULL ? AT_DIR_MALFORMED
       : at_dir_create_entry(self, &att, seq, visibility, 0, _dir_now(), &entry);
    at_dir_free(&att);
    json_decref(req);
    if (rc != AT_DIR_OK) {
        _refused(proc, ref, handle, _REASONS[-rc]);
        json_decref(state);
        return true;
    }
    json_object_set_new(state, handle,
                        json_pack("{s:I, s:o}", "seq", (json_int_t)seq,
                                  "entry", at_dir_to_wire(&entry)));
    if (!_save_state(proc, state)) {
        /* A seq not saved could be reissued after a restart and refused as stale. */
        _refused(proc, ref, handle, "mint_failed");
        json_decref(state);
        at_dir_free(&entry);
        return true;
    }
    json_decref(state);
    _set_pubref(handle, ref);
    _to_network(NET_FN_DIR_PUBLISH, json_pack("{s:o}", "entry", at_dir_to_wire(&entry)));
    log_info(proc->logger, "Identity: directory: publishing %s (seq %lld, %s)\n",
             handle, (long long)seq, visibility);
    at_dir_free(&entry);
    return true;
}

bool handle_dir_app_withdraw(const process_t *proc, directory_t *queues, generic_msg_t *msg)
{
    (void)queues;
    net_msg_t *nmsg = &msg->info.net_msg;
    if (!identity_is_local_app_verb(proc, nmsg))
        return identity_refuse_remote_app_verb(proc, nmsg, AT_APP_DIR_WITHDRAW);
    json_t *req = at_fc_app_payload(nmsg);
    const char *r = at_fc_app_ref(req);
    char ref[AT_FC_REF_LEN];
    at_strlcpy(ref, r != NULL ? r : "", sizeof(ref));
    char handle[AT_DIR_HANDLE_MAX + 1];
    if (at_dir_normalize_handle(json_string_value(json_object_get(req, "handle")),
                                handle, sizeof(handle)) != 0) {
        _refused(proc, ref, NULL, "bad_request");
        json_decref(req);
        return true;
    }
    json_decref(req);
    json_t *state = _load_state();
    json_t *held = json_object_get(state, handle);
    if (held != NULL) {
        /* Keep the seq: a later publish of the same handle must still rise. */
        json_t *seq = json_object_get(held, "seq");
        json_object_set_new(state, handle,
                            json_pack("{s:I, s:n}", "seq", json_is_integer(seq)
                                      ? json_integer_value(seq) : (json_int_t)0, "entry"));
        (void)_save_state(proc, state);
    }
    json_decref(state);
    _set_pubref(handle, ref);
    _to_network(NET_FN_DIR_WITHDRAW, json_pack("{s:s}", "handle", handle));
    return true;
}

bool handle_dir_status(const process_t *proc, directory_t *queues, generic_msg_t *msg)
{
    (void)queues;
    net_msg_t *nmsg = &msg->info.net_msg;
    if (!_local(nmsg)) {
        log_warn(proc->logger, "Identity: directory: refusing dir_status from the wire\n");
        return true;
    }
    json_t *body = at_fc_app_payload(nmsg);
    const char *op = json_string_value(json_object_get(body, "op"));
    int32_t kind = op == NULL ? 0
        : strcmp(op, "dir_published") == 0 ? AT_APP_EVENT_DIR_PUBLISHED
        : strcmp(op, "dir_refused") == 0 ? AT_APP_EVENT_DIR_REFUSED
        : strcmp(op, "dir_withdrawn") == 0 ? AT_APP_EVENT_DIR_WITHDRAWN : 0;
    if (kind != 0) {
        const char *h = json_string_value(json_object_get(body, "handle"));
        char ref[AT_FC_REF_LEN];
        _get_pubref(h != NULL ? h : "", ref, sizeof(ref));
        json_t *seq = json_object_get(body, "seq");
        _emit(proc, kind, ref, h, NULL, NULL,
              json_string_value(json_object_get(body, "relay")),
              json_string_value(json_object_get(body, "reason")),
              json_is_integer(seq) ? (int64_t)json_integer_value(seq) : 0);
    }
    json_decref(body);
    return true;
}

/* -- finding someone ------------------------------------------------------------ */
bool handle_dir_app_lookup(const process_t *proc, directory_t *queues, generic_msg_t *msg)
{
    (void)queues;
    net_msg_t *nmsg = &msg->info.net_msg;
    if (!identity_is_local_app_verb(proc, nmsg))
        return identity_refuse_remote_app_verb(proc, nmsg, AT_APP_DIR_LOOKUP);
    json_t *req = at_fc_app_payload(nmsg);
    const char *ref = at_fc_app_ref(req);
    char handle[AT_DIR_HANDLE_MAX + 1];
    if (ref == NULL || at_dir_normalize_handle(json_string_value(json_object_get(req, "handle")),
                                               handle, sizeof(handle)) != 0) {
        _refused(proc, ref != NULL ? ref : "", NULL, "bad_request");
        json_decref(req);
        return true;
    }
    bool first = false;
    pthread_mutex_lock(&g_dir.lock);
    dir_waiting_t *w = NULL;
    for (size_t i = 0; i < DIR_LOOKUP_REFS_MAX && w == NULL; i++)
        if (g_dir.waiting[i].used && strcmp(g_dir.waiting[i].handle, handle) == 0)
            w = &g_dir.waiting[i];
    for (size_t i = 0; i < DIR_LOOKUP_REFS_MAX && w == NULL; i++)
        if (!g_dir.waiting[i].used) {
            w = &g_dir.waiting[i];
            memset(w, 0, sizeof(*w));
            w->used = true;
            at_strlcpy(w->handle, handle, sizeof(w->handle));
        }
    if (w != NULL) {
        first = w->n_refs == 0;
        if (w->n_refs < DIR_REFS_PER_LOOKUP)
            at_strlcpy(w->refs[w->n_refs++], ref, sizeof(w->refs[0]));
    }
    pthread_mutex_unlock(&g_dir.lock);
    json_decref(req);
    if (w == NULL || first)
        _to_network(NET_FN_DIR_LOOKUP, json_pack("{s:s}", "handle", handle));
    return true;
}

bool handle_dir_result(const process_t *proc, directory_t *queues, generic_msg_t *msg)
{
    (void)queues;
    net_msg_t *nmsg = &msg->info.net_msg;
    if (!_local(nmsg)) {
        log_warn(proc->logger, "Identity: directory: refusing dir_result from the wire\n");
        return true;
    }
    json_t *body = at_fc_app_payload(nmsg);
    char handle[AT_DIR_HANDLE_MAX + 1];
    if (at_dir_normalize_handle(json_string_value(json_object_get(body, "handle")),
                                handle, sizeof(handle)) != 0)
        handle[0] = '\0';
    char refs[DIR_REFS_PER_LOOKUP][AT_FC_REF_LEN];
    size_t n_refs = 0;
    pthread_mutex_lock(&g_dir.lock);
    for (size_t i = 0; i < DIR_LOOKUP_REFS_MAX; i++)
        if (g_dir.waiting[i].used && strcmp(g_dir.waiting[i].handle, handle) == 0) {
            n_refs = g_dir.waiting[i].n_refs;
            memcpy(refs, g_dir.waiting[i].refs, sizeof(refs));
            memset(&g_dir.waiting[i], 0, sizeof(g_dir.waiting[i]));
            break;
        }
    pthread_mutex_unlock(&g_dir.lock);
    if (n_refs == 0) {
        refs[0][0] = '\0';
        n_refs = 1;
    }
    const char *reason = json_is_true(json_object_get(body, "limited")) ? "limited" : "";
    json_t *wire = json_object_get(body, "entry");
    at_dir_signed_t entry;
    bool have = false;
    if (json_is_object(wire)) {
        /* Checked HERE: a registry is not trusted to have checked it, nor to
         * answer the handle that was asked. */
        int rc = at_dir_from_wire(wire, &entry);
        if (rc == AT_DIR_OK) {
            rc = at_dir_entry_verify(&entry, NULL, 0, _dir_now());
            if (rc == AT_DIR_OK && strcmp(at_dir_handle(&entry), handle) != 0)
                rc = AT_DIR_MISMATCH;
            if (rc != AT_DIR_OK)
                at_dir_free(&entry);
        }
        if (rc == AT_DIR_OK) {
            have = true;
        } else {
            log_warn(proc->logger, "Identity: directory: entry for %s refused (%s)\n",
                     handle, _REASONS[-rc]);
            reason = "invalid";
        }
    }
    if (!have) {
        for (size_t i = 0; i < n_refs; i++)
            _emit(proc, AT_APP_EVENT_DIR_NOT_FOUND, refs[i], handle, NULL, NULL, NULL,
                  reason, 0);
        json_decref(body);
        return true;
    }
    const char *relay = json_string_value(json_object_get(body, "relay"));
    char uuid[UUID_STRING_LEN + 1], nickname[AT_FC_NICKNAME_LEN];
    at_strlcpy(uuid, at_dir_uuid(&entry), sizeof(uuid));
    _lower(uuid);
    const char *nick = json_string_value(json_object_get(json_object_get(entry.body, "identity"),
                                                         "nickname"));
    at_strlcpy(nickname, nick != NULL ? nick : "", sizeof(nickname));
    pthread_mutex_lock(&g_dir.lock);
    dir_found_t *slot = NULL;
    for (size_t i = 0; i < AT_DIR_FOUND_MAX && slot == NULL; i++)
        if (g_dir.found[i].used && strcmp(g_dir.found[i].handle, handle) == 0)
            slot = &g_dir.found[i];
    if (slot == NULL) {
        slot = &g_dir.found[g_dir.found_next % AT_DIR_FOUND_MAX];
        g_dir.found_next++;
    }
    if (slot->used)
        at_dir_free(&slot->entry);
    slot->used = true;
    at_strlcpy(slot->handle, handle, sizeof(slot->handle));
    slot->entry = entry;            /* move */
    at_strlcpy(slot->relay, relay != NULL ? relay : "", sizeof(slot->relay));
    slot->at = _dir_now();
    pthread_mutex_unlock(&g_dir.lock);
    for (size_t i = 0; i < n_refs; i++)
        _emit(proc, AT_APP_EVENT_DIR_FOUND, refs[i], handle, uuid, nickname,
              relay, "", 0);
    json_decref(body);
    return true;
}

bool handle_dir_app_request(const process_t *proc, directory_t *queues, generic_msg_t *msg)
{
    (void)queues;
    net_msg_t *nmsg = &msg->info.net_msg;
    if (!identity_is_local_app_verb(proc, nmsg))
        return identity_refuse_remote_app_verb(proc, nmsg, AT_APP_FC_REQUEST);
    json_t *req = at_fc_app_payload(nmsg);
    const char *r = at_fc_app_ref(req);
    char handle[AT_DIR_HANDLE_MAX + 1];
    /* Someone an area lookup found (identity/area_contact.c): @c area and
     * @c peer_uuid in place of a handle. Mirrors Python handle_app_request. */
    bool by_area = json_object_get(req, "area") != NULL;
    char area[AT_AREA_MAX + 1] = "", peer[UUID_STRING_LEN + 1] = "";
    if (by_area) {
        if (r == NULL || at_area_normalize(json_string_value(json_object_get(req, "area")),
                                           area, sizeof(area), AT_AREA_MIN, AT_AREA_MAX) != 0) {
            _refused(proc, r != NULL ? r : "", NULL, "bad_request");
            json_decref(req);
            return true;
        }
        snprintf(handle, sizeof(handle), "area:%s", area);
        const char *p = json_string_value(json_object_get(req, "peer_uuid"));
        at_strlcpy(peer, p != NULL ? p : "", sizeof(peer));
    } else if (r == NULL
               || at_dir_normalize_handle(json_string_value(json_object_get(req, "handle")),
                                          handle, sizeof(handle)) != 0) {
        _refused(proc, r != NULL ? r : "", NULL, "bad_request");
        json_decref(req);
        return true;
    }
    char ref[AT_FC_REF_LEN];
    at_strlcpy(ref, r, sizeof(ref));
    json_decref(req);
    /* A copy of what the lookup found, out of the lock. */
    at_dir_signed_t entry;
    char relay[AT_FC_RELAY_LEN] = "";
    bool have = false;
    double now = _dir_now();
    if (by_area)
        have = at_area_contact_found(peer, area, &entry, relay, sizeof(relay));
    pthread_mutex_lock(&g_dir.lock);
    for (size_t i = 0; i < AT_DIR_FOUND_MAX && !have && !by_area; i++) {
        dir_found_t *f = &g_dir.found[i];
        if (f->used && strcmp(f->handle, handle) == 0
            && now - f->at <= AT_DIR_FOUND_TTL_SECONDS
            && now < (double)at_dir_expiry(&f->entry)) {
            json_t *w = at_dir_to_wire(&f->entry);
            have = at_dir_from_wire(w, &entry) == AT_DIR_OK;
            json_decref(w);
            at_strlcpy(relay, f->relay, sizeof(relay));
        }
    }
    pthread_mutex_unlock(&g_dir.lock);
    if (!have) {
        _refused(proc, ref, handle, "unknown_handle");
        return true;
    }
    char me[UUID_STRING_LEN + 1], holder_uuid[UUID_STRING_LEN + 1];
    _self_uuid(proc, me);
    at_strlcpy(holder_uuid, at_dir_uuid(&entry), sizeof(holder_uuid));
    _lower(holder_uuid);
    if (strcmp(holder_uuid, me) == 0) {
        _refused(proc, ref, handle, "bad_request");
        at_dir_free(&entry);
        return true;
    }
    public_identity_t holder;
    if (public_identity_from_json(json_object_get(entry.body, "identity"), &holder) != 0) {
        _refused(proc, ref, handle, "invalid");
        at_dir_free(&entry);
        return true;
    }
    /* The registry relay found the entry, and we are registered there: name it
     * first, so the holder can answer the way the request came. */
    char route[1 + AT_RELAY_MAX][DIR_HINT_LEN];
    size_t n_route = 0;
    if (relay[0] != '\0')
        snprintf(route[n_route++], DIR_HINT_LEN, "%s%s", AT_RELAY_SCHEME, relay);
    n_route += at_fc_own_hints(&route[n_route], AT_RELAY_MAX);
    const char *hints[AT_DIR_REQUEST_MAX_RELAYS];
    net_relay_ep_t seen[1 + AT_RELAY_MAX];
    size_t n_hints = 0, n_seen = 0;
    for (size_t i = 0; i < n_route; i++) {
        net_relay_ep_t ep;
        if (net_relay_parse_hint(route[i], ep.host, sizeof(ep.host), &ep.port, NULL) != 0)
            continue;
        bool dup = false;
        for (size_t k = 0; k < n_seen && !dup; k++)
            dup = seen[k].port == ep.port && strcmp(seen[k].host, ep.host) == 0;
        if (dup)
            continue;
        seen[n_seen++] = ep;
        if (n_hints < AT_DIR_REQUEST_MAX_RELAYS)
            hints[n_hints++] = route[i];
    }
    const identity_t *self = identity_self_identity(proc);
    at_dir_signed_t request;
    if (self == NULL || at_dir_request_create(self, &entry, hints, n_hints, NULL, 0, now,
                                              &request) != AT_DIR_OK) {
        _refused(proc, ref, handle, "mint_failed");
        at_fc_free_public(&holder);
        at_dir_free(&entry);
        return true;
    }
    pthread_mutex_lock(&g_dir.lock);
    dir_out_t *o = NULL;
    for (size_t i = 0; i < DIR_OUT_MAX && o == NULL; i++)
        if (g_dir.out[i].used && strcmp(g_dir.out[i].holder, holder_uuid) == 0)
            o = &g_dir.out[i];
    for (size_t i = 0; i < DIR_OUT_MAX && o == NULL; i++)
        if (!g_dir.out[i].used || g_dir.out[i].deadline <= now)
            o = &g_dir.out[i];
    if (o == NULL) {
        o = &g_dir.out[0];
        for (size_t i = 1; i < DIR_OUT_MAX; i++)
            if (g_dir.out[i].deadline < o->deadline)
                o = &g_dir.out[i];
    }
    memset(o, 0, sizeof(*o));
    o->used = true;
    at_strlcpy(o->holder, holder_uuid, sizeof(o->holder));
    at_strlcpy(o->ref, ref, sizeof(o->ref));
    at_strlcpy(o->nonce, at_dir_request_nonce(&request), sizeof(o->nonce));
    at_strlcpy(o->key, at_dir_key(&entry), sizeof(o->key));
    at_strlcpy(o->handle, handle, sizeof(o->handle));
    o->deadline = (double)at_dir_expiry(&request);
    o->by_area = by_area;
    pthread_mutex_unlock(&g_dir.lock);
    at_fc_send_route_hints(holder.uuid, hints, n_hints > 0 ? 1 : 0);
    _to_wire(proc, ID_FC_REQUEST, &holder, at_dir_to_wire(&request));
    log_info(proc->logger, "Identity: directory: asked %s (%.8s) to become a contact\n",
             handle, holder_uuid);
    _emit(proc, AT_APP_EVENT_DIR_REQUEST_SENT, ref, handle, holder_uuid, holder.nickname,
          NULL, "", 0);
    at_dir_free(&request);
    at_dir_free(&entry);
    at_fc_free_public(&holder);
    return true;
}

/* -- being asked ------------------------------------------------------------------ */
bool handle_dir_contact_request(const process_t *proc, directory_t *queues, generic_msg_t *msg)
{
    (void)queues;
    net_msg_t *nmsg = &msg->info.net_msg;
    const public_identity_t *sender = &nmsg->from_whom;
    if (!at_fc_has_sender(sender)) {
        log_warn(proc->logger, "Identity: directory: contact request with no sender "
                 "identity; ignoring\n");
        return true;
    }
    json_t *payload = NULL;
    at_dir_signed_t request;
    int rc = net_msg_unpack_json(nmsg, &payload) == 0
           ? _signed_from(payload, &request) : AT_DIR_MALFORMED;
    json_decref(payload);
    double now = _dir_now();
    if (rc == AT_DIR_OK) {
        rc = at_dir_request_verify(&request, now);
        if (rc != AT_DIR_OK)
            at_dir_free(&request);
    }
    if (rc != AT_DIR_OK) {
        log_warn(proc->logger, "Identity: directory: contact request refused (%s)\n",
                 _REASONS[-rc]);
        return true;
    }
    char me[UUID_STRING_LEN + 1], from[UUID_STRING_LEN + 1], to[UUID_STRING_LEN + 1],
         who[UUID_STRING_LEN + 1];
    _self_uuid(proc, me);
    uuid_unparse_lower(sender->uuid, who);
    at_strlcpy(from, at_dir_request_from(&request), sizeof(from));
    at_strlcpy(to, at_dir_request_to(&request), sizeof(to));
    _lower(from);
    _lower(to);
    const char *why = NULL;
    if (strcmp(from, who) != 0
        || strcasecmp(at_dir_key(&request), (const char *)sender->signature.public_hex) != 0)
        why = "not signed by its sender";
    else if (strcmp(to, me) != 0 || strcmp(from, me) == 0)
        why = "not addressed to us";
    else if (json_object_get(request.body, "area") != NULL) {
        if (!at_area_contact_listed(json_string_value(json_object_get(request.body, "area"))))
            why = "via an area where we are not listed";
    } else if (!_is_published(at_dir_handle(&request)))
        why = "for a handle we do not publish";
    if (why != NULL) {
        log_warn(proc->logger, "Identity: directory: contact request %s; ignoring\n", why);
        at_dir_free(&request);
        return true;
    }
    char data_dir[CFG_PATH_LEN + 1] = {0};
    bool known = false;
    if (get_data_dir(data_dir, sizeof(data_dir)) > 0) {
        contacts_t store;
        contacts_init(&store);
        (void)contacts_load(data_dir, &store);
        known = contacts_get(&store, who) != NULL;
        contacts_free(&store);
    }
    if (known) {
        log_info(proc->logger, "Identity: directory: %s asked again, but is already a "
                 "contact\n", sender->nickname);
        at_dir_free(&request);
        return true;
    }
    pthread_mutex_lock(&g_dir.lock);
    for (size_t i = 0; i < AT_DIR_REQUESTS_IN_MAX; i++) {
        dir_in_t *d = &g_dir.in[i];
        if (d->used && (d->expiry <= now || uuid_compare(d->sender.uuid, sender->uuid) == 0)) {
            at_fc_free_public(&d->sender);
            memset(d, 0, sizeof(*d));
        }
    }
    dir_in_t *slot = NULL;
    for (size_t i = 0; i < AT_DIR_REQUESTS_IN_MAX && slot == NULL; i++)
        if (!g_dir.in[i].used)
            slot = &g_dir.in[i];
    if (slot == NULL) {             /* full: the oldest goes */
        slot = &g_dir.in[0];
        for (size_t i = 1; i < AT_DIR_REQUESTS_IN_MAX; i++)
            if (g_dir.in[i].order < slot->order)
                slot = &g_dir.in[i];
        at_fc_free_public(&slot->sender);
    }
    memset(slot, 0, sizeof(*slot));
    slot->used = true;
    slot->order = ++g_dir.in_order;
    at_strlcpy(slot->nonce, at_dir_request_nonce(&request), sizeof(slot->nonce));
    slot->sender = *sender;
    slot->sender.operator_key_binding = NULL;
    slot->sender.operator_key_binding_len = 0;
    /* Borrowed from the envelope: keep none of its heap. */
    slot->sender.zta_credential = NULL;
    slot->sender.zta_credential_len = 0;
    slot->sender.num_zta_credentials = 0;
    const char *req_area = json_string_value(json_object_get(request.body, "area"));
    slot->by_area = req_area != NULL;
    if (slot->by_area)
        snprintf(slot->handle, sizeof(slot->handle), "area:%s", req_area);
    else
        at_strlcpy(slot->handle, at_dir_handle(&request), sizeof(slot->handle));
    json_t *rv = json_object_get(request.body, "relays");
    for (size_t i = 0; i < json_array_size(rv) && slot->n_relays < AT_DIR_REQUEST_MAX_RELAYS; i++)
        at_strlcpy(slot->relays[slot->n_relays++], json_string_value(json_array_get(rv, i)),
                   DIR_HINT_LEN);
    slot->expiry = (double)at_dir_expiry(&request);
    char nonce[AT_DIR_NONCE_HEX + 1], handle[AT_DIR_HANDLE_MAX + 1];
    at_strlcpy(nonce, slot->nonce, sizeof(nonce));
    at_strlcpy(handle, slot->handle, sizeof(handle));
    pthread_mutex_unlock(&g_dir.lock);
    log_info(proc->logger, "Identity: directory: %s asks to become a contact (via %s)\n",
             sender->nickname, handle);
    _emit(proc, AT_APP_EVENT_DIR_CONTACT_REQUEST, nonce, handle, who, sender->nickname,
          NULL, "", 0);
    at_dir_free(&request);
    return true;
}

/* Take the held request the app's ref names, into @p out; refused (and false)
 * when there is none, or it expired. */
static bool _take_in(const process_t *proc, net_msg_t *nmsg, char *ref, size_t ref_len,
                     dir_in_t *out)
{
    json_t *req = at_fc_app_payload(nmsg);
    const char *r = json_string_value(json_object_get(req, "ref"));
    at_strlcpy(ref, r != NULL ? r : "", ref_len);
    json_decref(req);
    bool found = false;
    pthread_mutex_lock(&g_dir.lock);
    for (size_t i = 0; i < AT_DIR_REQUESTS_IN_MAX && !found; i++)
        if (g_dir.in[i].used && ref[0] != '\0' && strcmp(g_dir.in[i].nonce, ref) == 0) {
            *out = g_dir.in[i];
            memset(&g_dir.in[i], 0, sizeof(g_dir.in[i]));
            found = true;
        }
    pthread_mutex_unlock(&g_dir.lock);
    if (!found || out->expiry <= _dir_now()) {
        if (found)
            at_fc_free_public(&out->sender);
        _refused(proc, ref, NULL, "unknown_request");
        return false;
    }
    return true;
}

bool handle_dir_app_accept(const process_t *proc, directory_t *queues, generic_msg_t *msg)
{
    (void)queues;
    net_msg_t *nmsg = &msg->info.net_msg;
    if (!identity_is_local_app_verb(proc, nmsg))
        return identity_refuse_remote_app_verb(proc, nmsg, AT_APP_FC_ACCEPT);
    char ref[AT_FC_REF_LEN];
    dir_in_t held;
    if (!_take_in(proc, nmsg, ref, sizeof(ref), &held))
        return true;
    char hints[AT_RELAY_MAX][DIR_HINT_LEN];
    size_t n = at_fc_own_hints(hints, AT_RELAY_MAX);
    const char *ptrs[AT_RELAY_MAX];
    for (size_t i = 0; i < n; i++)
        ptrs[i] = hints[i];
    char nonce[33];
    at_fc_new_nonce(nonce);
    char *blob = NULL;
    const identity_t *self = identity_self_identity(proc);
    if (self == NULL
        || at_create_invitation(self, ptrs, n, (long)time(NULL) + AT_DIR_ACCEPT_INVITATION_TTL,
                                nonce, &blob) != 0 || blob == NULL) {
        log_error(proc->logger, "Identity: directory: could not mint an invitation\n");
        _refused(proc, ref, NULL, "mint_failed");
        free(blob);
        at_fc_free_public(&held.sender);
        return true;
    }
    /* The hello this invitation brings back reports under the request's ref,
     * and records a directory-provenance contact. */
    at_fc_remember_minted(nonce, ref);
    if (held.by_area) {
        at_area_contact_note_invite(nonce);
    } else {
        pthread_mutex_lock(&g_dir.lock);
        at_strlcpy(g_dir.invites[g_dir.invites_next], nonce, sizeof(g_dir.invites[0]));
        g_dir.invites_next = (g_dir.invites_next + 1) % DIR_INVITES_MAX;
        pthread_mutex_unlock(&g_dir.lock);
    }
    const char *rptrs[AT_DIR_REQUEST_MAX_RELAYS];
    for (size_t i = 0; i < held.n_relays; i++)
        rptrs[i] = held.relays[i];
    at_fc_send_route_hints(held.sender.uuid, rptrs, held.n_relays);
    _to_wire(proc, ID_FC_ACCEPT, &held.sender,
             json_pack("{s:s, s:s}", "nonce", ref, "invitation", blob));
    free(blob);
    char who[UUID_STRING_LEN + 1];
    uuid_unparse_lower(held.sender.uuid, who);
    log_info(proc->logger, "Identity: directory: accepted %s\n", held.sender.nickname);
    _emit(proc, AT_APP_EVENT_DIR_ACCEPTED, ref, held.handle, who, held.sender.nickname,
          NULL, "", 0);
    at_fc_free_public(&held.sender);
    return true;
}

bool handle_dir_app_decline(const process_t *proc, directory_t *queues, generic_msg_t *msg)
{
    (void)queues;
    net_msg_t *nmsg = &msg->info.net_msg;
    if (!identity_is_local_app_verb(proc, nmsg))
        return identity_refuse_remote_app_verb(proc, nmsg, AT_APP_FC_DECLINE);
    char ref[AT_FC_REF_LEN];
    dir_in_t held;
    if (!_take_in(proc, nmsg, ref, sizeof(ref), &held))
        return true;
    /* Nothing goes back: the requester learns nothing silence would not tell. */
    char who[UUID_STRING_LEN + 1];
    uuid_unparse_lower(held.sender.uuid, who);
    _emit(proc, AT_APP_EVENT_DIR_DECLINED, ref, held.handle, who, held.sender.nickname,
          NULL, "", 0);
    at_fc_free_public(&held.sender);
    return true;
}

bool handle_dir_contact_accept(const process_t *proc, directory_t *queues, generic_msg_t *msg)
{
    net_msg_t *nmsg = &msg->info.net_msg;
    const public_identity_t *holder = &nmsg->from_whom;
    if (!at_fc_has_sender(holder)) {
        log_warn(proc->logger, "Identity: directory: accept with no sender identity; "
                 "ignoring\n");
        return true;
    }
    char uuid[UUID_STRING_LEN + 1];
    uuid_unparse_lower(holder->uuid, uuid);
    double now = _dir_now();
    dir_out_t out;
    bool found = false;
    pthread_mutex_lock(&g_dir.lock);
    for (size_t i = 0; i < DIR_OUT_MAX && !found; i++)
        if (g_dir.out[i].used && strcmp(g_dir.out[i].holder, uuid) == 0) {
            out = g_dir.out[i];
            found = true;
        }
    pthread_mutex_unlock(&g_dir.lock);
    if (!found || out.deadline <= now) {
        log_warn(proc->logger, "Identity: directory: accept from %.8s, to whom no request "
                 "is outstanding; ignoring\n", uuid);
        return true;
    }
    json_t *payload = at_fc_app_payload(nmsg);
    const char *nonce = json_string_value(json_object_get(payload, "nonce"));
    if (strcasecmp((const char *)holder->signature.public_hex, out.key) != 0
        || nonce == NULL || strcmp(nonce, out.nonce) != 0) {
        log_warn(proc->logger, "Identity: directory: accept from %.8s does not answer our "
                 "request (key or nonce); ignoring\n", uuid);
        json_decref(payload);
        return true;
    }
    const char *b = json_string_value(json_object_get(payload, "invitation"));
    char *blob = b != NULL ? strdup(b) : NULL;
    json_decref(payload);
    at_invitation_t inv;
    public_identity_t inviter;
    if (blob == NULL || at_invitation_decode(blob, &inv) != AT_INVITE_OK) {
        log_warn(proc->logger, "Identity: directory: accept from %.8s carries a bad "
                 "invitation\n", uuid);
        free(blob);
        return true;
    }
    if (at_invitation_verify(&inv, &inviter) != AT_INVITE_OK) {
        log_warn(proc->logger, "Identity: directory: accept from %.8s carries a bad "
                 "invitation\n", uuid);
        at_invitation_free(&inv);
        free(blob);
        return true;
    }
    bool ok = uuid_compare(inviter.uuid, holder->uuid) == 0
        && strcasecmp((const char *)inviter.signature.public_hex, out.key) == 0
        /* The invitation keeps its own (wall) clock, as Python's is_expired(). */
        && !at_invitation_is_expired(&inv, (double)time(NULL));
    at_invitation_free(&inv);
    if (!ok) {
        log_warn(proc->logger, "Identity: directory: accept from %.8s carries an invitation "
                 "that is not its own, or has expired; ignoring\n", uuid);
        at_fc_free_public(&inviter);
        free(blob);
        return true;
    }
    pthread_mutex_lock(&g_dir.lock);
    for (size_t i = 0; i < DIR_OUT_MAX; i++)
        if (g_dir.out[i].used && strcmp(g_dir.out[i].holder, uuid) == 0)
            memset(&g_dir.out[i], 0, sizeof(g_dir.out[i]));
    pthread_mutex_unlock(&g_dir.lock);
    (void)at_first_contact_initiate_prov(proc, queues, blob, NULL, out.ref,
                                         out.by_area ? AT_PROV_AREA : AT_PROV_DIRECTORY, NULL);
    at_fc_emit_hello_sent(proc, out.ref, &inviter);
    at_fc_free_public(&inviter);
    free(blob);
    return true;
}

/* -- registration -------------------------------------------------------------- */
void at_dir_contact_register(process_t *proc)
{
    process_register_handler(proc, DIR_APP_PUBLISH, (handler_ptr_t)handle_dir_app_publish);
    process_register_handler(proc, DIR_APP_WITHDRAW, (handler_ptr_t)handle_dir_app_withdraw);
    process_register_handler(proc, DIR_APP_LOOKUP, (handler_ptr_t)handle_dir_app_lookup);
    process_register_handler(proc, DIR_APP_REQUEST, (handler_ptr_t)handle_dir_app_request);
    process_register_handler(proc, DIR_APP_ACCEPT, (handler_ptr_t)handle_dir_app_accept);
    process_register_handler(proc, DIR_APP_DECLINE, (handler_ptr_t)handle_dir_app_decline);
    process_register_handler(proc, NET_ID_DIR_RESULT, (handler_ptr_t)handle_dir_result);
    process_register_handler(proc, NET_ID_DIR_STATUS, (handler_ptr_t)handle_dir_status);
    process_register_handler(proc, ID_FC_REQUEST, (handler_ptr_t)handle_dir_contact_request);
    process_register_handler(proc, ID_FC_ACCEPT, (handler_ptr_t)handle_dir_contact_accept);
}

/* The app may send exactly these verbs, each only to identity. Mirrors
 * Python's directory_contact.APP_VERBS in first contact's EXTENSION. */
AT_APP_VERB_REGISTER(dir_publish, AT_APP_DIR_PUBLISH, "identity")
AT_APP_VERB_REGISTER(dir_withdraw, AT_APP_DIR_WITHDRAW, "identity")
AT_APP_VERB_REGISTER(dir_lookup, AT_APP_DIR_LOOKUP, "identity")
AT_APP_VERB_REGISTER(fc_request, AT_APP_FC_REQUEST, "identity")
AT_APP_VERB_REGISTER(fc_accept, AT_APP_FC_ACCEPT, "identity")
AT_APP_VERB_REGISTER(fc_decline, AT_APP_FC_DECLINE, "identity")
