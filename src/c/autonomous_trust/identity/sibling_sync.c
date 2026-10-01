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

/** @file Pairing one's own devices and syncing their address books (C twin
 *  of identity/sibling_sync.py). See sibling_sync.h. */

#define _GNU_SOURCE
#include "identity/sibling_sync.h"

#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <time.h>
#include <sys/stat.h>

#include <jansson.h>
#include <uuid/uuid.h>

#include "config/configuration.h"
#include "contacts/contacts.h"
#include "contacts/device.h"
#include "contacts/siblings.h"
#include "contacts/sync.h"
#include "identity/device_contact.h"
#include "identity/fc_shared.h"
#include "identity/first_contact.h"
#include "identity/id_proc_priv.h"
#include "identity/identity_priv.h"
#include "network/net_relay.h"
#include "processes/extension.h"
#include "utilities/logger.h"
#include "utilities/message.h"
#include "utilities/msg_types_priv.h"   /* net_msg_pack_json */
#include "utilities/util.h"

#define PAIR_MAX 16
#define HINT_LEN (AT_RELAY_HOST_LEN + 96)

typedef struct {
    bool used;
    uuid_t uuid;
    char nickname[NAME_LEN + 1];
    char ref[AT_FC_REF_LEN];
    at_fc_role_t role;
    double deadline;
    char hints[AT_SIBLING_HINTS_MAX][HINT_LEN];
    size_t n_hints;
} pairing_t;

/* What was last pushed (or taken): per contact its version, per tombstone
 * its time. Python sibling_sync._versions / proc._sync_seen. */
typedef struct {
    char kind;                          /* 'c' contact, 't' tombstone */
    char uuid[UUID_STRING_LEN + 1];
    double v;
} seen_t;

/* One node's baseline. Keyed by the node, as Python keeps it on the process:
 * a process hosts one node, but a test harness hosts several. */
typedef struct {
    bool used;
    char owner[UUID_STRING_LEN + 1];
    seen_t *seen;
    size_t n_seen;
} track_t;

#define TRACK_MAX 8

static struct {
    pthread_mutex_t lock;
    pairing_t pending[PAIR_MAX];
    track_t track[TRACK_MAX];
} sib_state = { .lock = PTHREAD_MUTEX_INITIALIZER };

/* @p proc's baseline, or NULL (@p create: take a slot, evicting the first).
 * Call with sib_state.lock held. */
static track_t *_track_slot(const process_t *proc, bool create)
{
    const identity_t *self = identity_self_identity(proc);
    char me[UUID_STRING_LEN + 1] = "";
    if (self != NULL)
        uuid_unparse_lower(self->uuid, me);
    for (size_t i = 0; i < TRACK_MAX; i++)
        if (sib_state.track[i].used && strcmp(sib_state.track[i].owner, me) == 0)
            return &sib_state.track[i];
    if (!create)
        return NULL;
    track_t *t = &sib_state.track[0];
    for (size_t i = 0; i < TRACK_MAX; i++)
        if (!sib_state.track[i].used) {
            t = &sib_state.track[i];
            break;
        }
    free(t->seen);
    memset(t, 0, sizeof(*t));
    t->used = true;
    at_strlcpy(t->owner, me, sizeof(t->owner));
    return t;
}

static char FN_CONTACTS_SYNC[] = "contacts_sync";
static char FN_APP_SIBLING_LIST[] = AT_APP_SIBLING_LIST;
static char FN_APP_SIBLING_REMOVE[] = AT_APP_SIBLING_REMOVE;

void at_sibling_sync_reset(void)
{
    pthread_mutex_lock(&sib_state.lock);
    memset(sib_state.pending, 0, sizeof(sib_state.pending));
    for (size_t i = 0; i < TRACK_MAX; i++)
        free(sib_state.track[i].seen);
    memset(sib_state.track, 0, sizeof(sib_state.track));
    pthread_mutex_unlock(&sib_state.lock);
}

static double _now(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    return (double)ts.tv_sec + (double)ts.tv_nsec / 1e9;
}

/* -- the files ------------------------------------------------------------- */

static bool _data_dir(char *dir, size_t len)
{
    return get_data_dir(dir, len) > 0;
}

static void _load_siblings(at_siblings_t *sib)
{
    char dir[CFG_PATH_LEN + 1] = {0};
    if (_data_dir(dir, sizeof(dir)))
        at_siblings_load(dir, sib);
    else
        at_siblings_init(sib);
}

static void _save_siblings(const process_t *proc, const at_siblings_t *sib)
{
    char dir[CFG_PATH_LEN + 1] = {0};
    if (!_data_dir(dir, sizeof(dir)) || at_siblings_save(sib, dir) != 0)
        log_warn(proc->logger, "Identity: could not persist the sibling list\n");
}

static bool _load_store(contacts_t *store, char *dir, size_t len)
{
    contacts_init(store);
    if (!_data_dir(dir, len))
        return false;
    (void)contacts_load(dir, store);
    return true;
}

bool at_sibling_is(const char *uuid)
{
    static struct {
        pthread_mutex_t lock;
        char path[CFG_PATH_LEN + 64];
        struct timespec mtime;
        bool loaded;
        char (*uuids)[UUID_STRING_LEN + 1];
        size_t count;
    } cache = { .lock = PTHREAD_MUTEX_INITIALIZER };
    char dir[CFG_PATH_LEN + 1] = {0};
    if (uuid == NULL || !_data_dir(dir, sizeof(dir)))
        return false;
    char path[CFG_PATH_LEN + 64];
    snprintf(path, sizeof(path), "%s/%s", dir, AT_SIBLINGS_FILENAME);
    struct stat st;
    bool present = stat(path, &st) == 0;
    pthread_mutex_lock(&cache.lock);
    bool stale = !cache.loaded || strcmp(cache.path, path) != 0
        || (present && (st.st_mtim.tv_sec != cache.mtime.tv_sec
                        || st.st_mtim.tv_nsec != cache.mtime.tv_nsec))
        || (!present && cache.count > 0);
    if (stale) {
        free(cache.uuids);
        cache.uuids = NULL;
        cache.count = 0;
        at_strlcpy(cache.path, path, sizeof(cache.path));
        memset(&cache.mtime, 0, sizeof(cache.mtime));
        if (present) {
            cache.mtime = st.st_mtim;
            at_siblings_t sib;
            at_siblings_load(dir, &sib);
            if (sib.count > 0)
                cache.uuids = calloc(sib.count, sizeof(*cache.uuids));
            for (size_t i = 0; cache.uuids != NULL && i < sib.count; i++)
                at_strlcpy(cache.uuids[cache.count++], sib.devices[i].uuid,
                           sizeof(cache.uuids[0]));
            at_siblings_free(&sib);
        }
        cache.loaded = true;
    }
    bool found = false;
    for (size_t i = 0; i < cache.count && !found; i++)
        found = strcmp(cache.uuids[i], uuid) == 0;
    pthread_mutex_unlock(&cache.lock);
    return found;
}

/* -- sending ----------------------------------------------------------------- */

static void _send(char *verb, const public_identity_t *to,
                  const public_identity_t *self, json_t *body)
{
    generic_msg_t msg = {0};
    msg.type = NET_MESSAGE;
    at_strlcpy(msg.info.net_msg.process, "identity", sizeof(msg.info.net_msg.process));
    msg.info.net_msg.function = verb;
    msg.info.net_msg.encrypt = true;
    memcpy(&msg.info.net_msg.to_whom, to, sizeof(public_identity_t));
    memcpy(&msg.info.net_msg.from_whom, self, sizeof(public_identity_t));
    at_strlcpy(msg.info.net_msg.return_to, "identity", sizeof(msg.info.net_msg.return_to));
    net_msg_pack_json(&msg.info.net_msg, body);
    (void)identity_send_to_network(NULL, &msg, "contacts sync", NULL);
    net_msg_free_obj(&msg.info.net_msg);
}

/* Route @p uuid through the relay hints in @p hints, then our own relays. */
static void _route(const uuid_t uuid, const char *const *hints, size_t n)
{
    const char *route[2 * AT_RELAY_MAX];
    size_t m = 0;
    for (size_t i = 0; i < n && m < AT_RELAY_MAX; i++)
        if (hints[i] != NULL
            && strncmp(hints[i], AT_RELAY_SCHEME, strlen(AT_RELAY_SCHEME)) == 0)
            route[m++] = hints[i];
    char own[AT_RELAY_MAX][HINT_LEN];
    size_t n_own = at_fc_own_hints(own, AT_RELAY_MAX);
    size_t theirs = m;
    for (size_t i = 0; i < n_own && m < 2 * AT_RELAY_MAX; i++) {
        char h_host[AT_RELAY_HOST_LEN], o_host[AT_RELAY_HOST_LEN];
        int h_port = 0, o_port = 0;
        bool dup = false;
        if (net_relay_parse_endpoint(own[i], o_host, sizeof(o_host), &o_port) == 0)
            for (size_t j = 0; j < theirs && !dup; j++)
                dup = net_relay_parse_endpoint(route[j], h_host, sizeof(h_host), &h_port) == 0
                      && h_port == o_port && strcmp(h_host, o_host) == 0;
        if (!dup)
            route[m++] = own[i];
    }
    at_fc_send_route_hints(uuid, route, m < AT_RELAY_MAX ? m : AT_RELAY_MAX);
}

static void _admit(const process_t *proc, directory_t *queues,
                   const public_identity_t *who, const char *const *hints, size_t n)
{
    (void)identity_admit_direct_peer((process_t *)proc, queues, who);
    _route(who->uuid, hints, n);
}

/* Every sibling that is a peer now, as its peers[] entry. */
static size_t _sibling_peers(const process_t *proc, const at_siblings_t *sib,
                             public_identity_t *out, size_t max)
{
    size_t n = 0;
    for (size_t i = 0; i < sib->count && n < max; i++) {
        uuid_t u;
        if (uuid_parse(sib->devices[i].uuid, u) == 0
            && identity_find_peer_pub(proc, u, &out[n]))
            n++;
    }
    return n;
}

/* -- change tracking ------------------------------------------------------- */

static seen_t *_versions(const contacts_t *store, size_t *n)
{
    size_t total = store->count + store->tombstones_count;
    seen_t *v = calloc(total ? total : 1, sizeof(*v));
    *n = 0;
    if (v == NULL)
        return NULL;
    for (size_t i = 0; i < store->count; i++) {
        v[*n].kind = 'c';
        uuid_unparse_lower(store->items[i].identity.uuid, v[*n].uuid);
        v[(*n)++].v = contact_version(&store->items[i]);
    }
    for (size_t i = 0; i < store->tombstones_count; i++) {
        v[*n].kind = 't';
        at_strlcpy(v[*n].uuid, store->tombstones[i].uuid, sizeof(v[0].uuid));
        v[(*n)++].v = store->tombstones[i].at;
    }
    return v;
}

static const seen_t *_seen_find(const seen_t *s, size_t n, char kind, const char *uuid)
{
    for (size_t i = 0; i < n; i++)
        if (s[i].kind == kind && strcmp(s[i].uuid, uuid) == 0)
            return &s[i];
    return NULL;
}

/* Take @p store's versions as @p proc's baseline (replace) or fold them into
 * it (only when it has one). */
static void _track(const process_t *proc, const contacts_t *store, bool replace)
{
    size_t n = 0;
    seen_t *now = _versions(store, &n);
    if (now == NULL)
        return;
    pthread_mutex_lock(&sib_state.lock);
    track_t *t = _track_slot(proc, replace);
    if (t != NULL && (replace || t->seen == NULL)) {
        free(t->seen);
        t->seen = now;
        t->n_seen = n;
        now = NULL;
    } else if (t != NULL) {
        for (size_t i = 0; i < n; i++) {
            seen_t *hit = (seen_t *)_seen_find(t->seen, t->n_seen,
                                               now[i].kind, now[i].uuid);
            if (hit != NULL) {
                hit->v = now[i].v;
                continue;
            }
            seen_t *grown = realloc(t->seen, (t->n_seen + 1) * sizeof(*grown));
            if (grown == NULL)
                break;
            t->seen = grown;
            t->seen[t->n_seen++] = now[i];
        }
    }
    pthread_mutex_unlock(&sib_state.lock);
    free(now);
}

static bool _tracking(const process_t *proc)
{
    pthread_mutex_lock(&sib_state.lock);
    bool yes = _track_slot(proc, false) != NULL;
    pthread_mutex_unlock(&sib_state.lock);
    return yes;
}

static int _send_payload(const process_t *proc, const public_identity_t *to, size_t n_to,
                         json_t *payload)
{
    public_identity_t self;
    memset(&self, 0, sizeof(self));
    if (payload == NULL || n_to == 0 || identity_own_public_identity(proc, &self) != 0) {
        json_decref(payload);
        return 0;
    }
    for (size_t i = 0; i < n_to; i++)
        _send(FN_CONTACTS_SYNC, &to[i], &self, payload);
    json_decref(payload);
    at_fc_free_public(&self);
    return (int)n_to;
}

int at_sibling_send_full(const process_t *proc, const public_identity_t *only, bool reply)
{
    if (proc == NULL)
        return 0;
    char dir[CFG_PATH_LEN + 1] = {0};
    contacts_t store;
    _load_store(&store, dir, sizeof(dir));
    json_t *payload = at_sync_build(&store, NULL, 0);
    if (payload != NULL && reply)
        json_object_set_new(payload, "reply", json_true());
    if (!_tracking(proc))
        _track(proc, &store, true);
    contacts_free(&store);
    public_identity_t peers[AT_CONTACT_DEVICES_MAX];
    size_t n = 0;
    if (only != NULL) {
        peers[n++] = *only;
    } else {
        at_siblings_t sib;
        _load_siblings(&sib);
        n = _sibling_peers(proc, &sib, peers, AT_CONTACT_DEVICES_MAX);
        at_siblings_free(&sib);
    }
    int sent = _send_payload(proc, peers, n, payload);
    for (size_t i = 0; only == NULL && i < n; i++)
        at_fc_free_public(&peers[i]);
    return sent;
}

int at_sibling_push_changes(const process_t *proc)
{
    if (proc == NULL)
        return 0;
    char dir[CFG_PATH_LEN + 1] = {0};
    contacts_t store;
    _load_store(&store, dir, sizeof(dir));
    size_t n_now = 0;
    seen_t *now = _versions(&store, &n_now);
    if (now == NULL) {
        contacts_free(&store);
        return 0;
    }
    /* The changed uuids, sorted and unique (Python: sorted({...})). */
    const char **changed = calloc(n_now ? n_now : 1, sizeof(char *));
    size_t n_changed = 0;
    pthread_mutex_lock(&sib_state.lock);
    track_t *t = _track_slot(proc, false);
    bool had = t != NULL;
    if (t == NULL)
        t = _track_slot(proc, true);
    for (size_t i = 0; had && changed != NULL && i < n_now; i++) {
        const seen_t *b = _seen_find(t->seen, t->n_seen, now[i].kind, now[i].uuid);
        if (b != NULL && !(b->v < now[i].v) && !(b->v > now[i].v))
            continue;
        bool dup = false;
        for (size_t j = 0; j < n_changed && !dup; j++)
            dup = strcmp(changed[j], now[i].uuid) == 0;
        if (!dup)
            changed[n_changed++] = now[i].uuid;
    }
    free(t->seen);
    t->seen = now;
    t->n_seen = n_now;
    pthread_mutex_unlock(&sib_state.lock);
    int sent = 0;
    if (had && n_changed > 0) {
        at_siblings_t sib;
        _load_siblings(&sib);
        public_identity_t peers[AT_CONTACT_DEVICES_MAX];
        size_t n = _sibling_peers(proc, &sib, peers, AT_CONTACT_DEVICES_MAX);
        at_siblings_free(&sib);
        if (n > 0)
            sent = _send_payload(proc, peers, n, at_sync_build(&store, changed, n_changed));
        for (size_t i = 0; i < n; i++)
            at_fc_free_public(&peers[i]);
    }
    free(changed);          /* its strings live in `now`, now the baseline */
    contacts_free(&store);
    return sent;
}

/* -- pairing ----------------------------------------------------------------- */

bool at_sibling_can_pair(const process_t *proc)
{
    at_dir_signed_t cert;
    if (at_device_own_cert(proc, &cert) != 0)
        return false;
    at_dir_free(&cert);
    return true;
}

void at_sibling_refuse(const process_t *proc, directory_t *queues,
                       const public_identity_t *peer, const char *ref,
                       at_fc_role_t role, bool drop)
{
    if (drop)
        (void)identity_remove_direct_peer((process_t *)proc, queues, peer->uuid);
    char u[UUID_STRING_LEN + 1];
    uuid_unparse_lower(peer->uuid, u);
    log_info(proc->logger, "Identity: first contact: %s is not a sibling; pairing "
             "refused\n", peer->nickname[0] != '\0' ? peer->nickname : u);
    at_fc_emit_event(proc, AT_APP_EVENT_FC_REFUSED, ref, peer,
                     AT_FC_REASON_NOT_SIBLING, role);
}

int at_sibling_expire(const process_t *proc, directory_t *queues, double now)
{
    pairing_t late[PAIR_MAX];
    size_t n = 0;
    pthread_mutex_lock(&sib_state.lock);
    for (size_t i = 0; i < PAIR_MAX; i++)
        if (sib_state.pending[i].used && sib_state.pending[i].deadline <= now) {
            late[n++] = sib_state.pending[i];
            memset(&sib_state.pending[i], 0, sizeof(sib_state.pending[i]));
        }
    pthread_mutex_unlock(&sib_state.lock);
    for (size_t i = 0; i < n; i++) {
        public_identity_t who;
        memset(&who, 0, sizeof(who));
        uuid_copy(who.uuid, late[i].uuid);
        at_strlcpy(who.nickname, late[i].nickname, sizeof(who.nickname));
        public_identity_t peer;
        bool is_peer = identity_find_peer_pub(proc, late[i].uuid, &peer);
        if (is_peer)
            at_fc_free_public(&peer);
        at_sibling_refuse(proc, queues, &who, late[i].ref, late[i].role, is_peer);
    }
    return (int)n;
}

void at_sibling_begin(const process_t *proc, directory_t *queues,
                      const public_identity_t *peer, const char *ref,
                      at_fc_role_t role, const char *const *hints, size_t n_hints)
{
    double now = _now();
    (void)at_sibling_expire(proc, queues, now);
    pthread_mutex_lock(&sib_state.lock);
    pairing_t *slot = NULL;
    for (size_t i = 0; i < PAIR_MAX && slot == NULL; i++)
        if (sib_state.pending[i].used
            && uuid_compare(sib_state.pending[i].uuid, peer->uuid) == 0)
            slot = &sib_state.pending[i];
    for (size_t i = 0; i < PAIR_MAX && slot == NULL; i++)
        if (!sib_state.pending[i].used)
            slot = &sib_state.pending[i];
    if (slot == NULL) {
        slot = &sib_state.pending[0];
        for (size_t i = 1; i < PAIR_MAX; i++)
            if (sib_state.pending[i].deadline < slot->deadline)
                slot = &sib_state.pending[i];
    }
    memset(slot, 0, sizeof(*slot));
    slot->used = true;
    uuid_copy(slot->uuid, peer->uuid);
    at_strlcpy(slot->nickname, peer->nickname, sizeof(slot->nickname));
    at_strlcpy(slot->ref, ref != NULL ? ref : "", sizeof(slot->ref));
    slot->role = role;
    slot->deadline = now + AT_SIBLING_PAIR_WAIT_SECONDS;
    for (size_t i = 0; i < n_hints && slot->n_hints < AT_SIBLING_HINTS_MAX; i++)
        if (hints[i] != NULL && hints[i][0] != '\0')
            at_strlcpy(slot->hints[slot->n_hints++], hints[i], HINT_LEN);
    pthread_mutex_unlock(&sib_state.lock);
    (void)at_device_push_own_cert(proc, peer);
}

bool at_sibling_on_device_cert(const process_t *proc, directory_t *queues,
                               const public_identity_t *sender, const json_t *cert_wire)
{
    pairing_t entry;
    bool found = false;
    pthread_mutex_lock(&sib_state.lock);
    for (size_t i = 0; i < PAIR_MAX && !found; i++)
        if (sib_state.pending[i].used
            && uuid_compare(sib_state.pending[i].uuid, sender->uuid) == 0) {
            entry = sib_state.pending[i];
            memset(&sib_state.pending[i], 0, sizeof(sib_state.pending[i]));
            found = true;
        }
    pthread_mutex_unlock(&sib_state.lock);
    if (!found)
        return false;
    if (entry.deadline <= _now()) {
        at_sibling_refuse(proc, queues, sender, entry.ref, entry.role, true);
        return true;
    }
    at_dir_signed_t cert, own;
    memset(&cert, 0, sizeof(cert));
    memset(&own, 0, sizeof(own));
    bool have_own = at_device_own_cert(proc, &own) == 0;
    at_siblings_t sib;
    _load_siblings(&sib);
    int rc = at_dir_from_wire(cert_wire, &cert) != AT_DIR_OK
                 ? (have_own ? AT_DEVICE_MALFORMED : AT_DEVICE_UNKNOWN_OPERATOR)
                 : at_siblings_add(&sib, sender, &cert, have_own ? &own : NULL);
    at_dir_free(&cert);
    at_dir_free(&own);
    if (rc != AT_DEVICE_OK) {
        log_info(proc->logger, "Identity: first contact: pairing with %s refused (%s)\n",
                 sender->nickname, at_device_reason(rc));
        at_siblings_free(&sib);
        at_sibling_refuse(proc, queues, sender, entry.ref, entry.role, true);
        return true;
    }
    char u[UUID_STRING_LEN + 1];
    uuid_unparse_lower(sender->uuid, u);
    const char *hints[AT_SIBLING_HINTS_MAX];
    for (size_t i = 0; i < entry.n_hints; i++)
        hints[i] = entry.hints[i];
    at_siblings_set_hints(&sib, u, hints, entry.n_hints);
    _save_siblings(proc, &sib);
    at_siblings_free(&sib);
    _route(sender->uuid, hints, entry.n_hints);
    at_fc_push_own_record(proc, sender);
    log_info(proc->logger, "Identity: first contact: paired with %s, another device "
             "of ours\n", sender->nickname);
    at_fc_emit_event(proc, AT_APP_EVENT_FC_SIBLING_PAIRED, entry.ref, sender,
                     AT_FC_REASON_NONE, entry.role);
    (void)at_sibling_send_full(proc, sender, false);
    return true;
}

/* -- receiving a sibling's book ------------------------------------------------- */

static bool _is_sibling(const at_siblings_t *sib, const public_identity_t *who)
{
    char u[UUID_STRING_LEN + 1];
    uuid_unparse_lower(who->uuid, u);
    const at_contact_device_t *dev = at_siblings_get(sib, u);
    if (dev == NULL)
        return false;
    public_identity_t pub;
    if (at_contact_device_identity(dev, &pub) != 0)
        return false;
    bool same = strcasecmp((const char *)pub.signature.public_hex,
                           (const char *)who->signature.public_hex) == 0;
    at_fc_free_public(&pub);
    return same;
}

/* One device of @p c as a public identity: index 0 is the first. */
static bool _device_identity(const contact_t *c, size_t d, public_identity_t *out)
{
    memset(out, 0, sizeof(*out));
    if (d == 0) {
        *out = c->identity;
        out->operator_key_binding = NULL;
        out->operator_key_binding_len = 0;
        return true;
    }
    return at_contact_device_identity(&c->devices[d - 1], out) == 0;
}

void at_sibling_apply_changes(const process_t *proc, directory_t *queues,
                              contacts_t *store, contacts_t *before,
                              const at_sync_change_t *ch, size_t n, int32_t origin)
{
    public_identity_t self;
    memset(&self, 0, sizeof(self));
    bool have_self = identity_own_public_identity(proc, &self) == 0;
    for (size_t k = 0; k < n; k++) {
        if (ch[k].action == AT_SYNC_ADDED || ch[k].action == AT_SYNC_UPDATED) {
            contact_t *c = contacts_get_first(store, ch[k].uuid);
            if (c == NULL)
                continue;
            if (ch[k].action == AT_SYNC_ADDED) {
                for (size_t d = 0; d <= c->devices_count; d++) {
                    public_identity_t who;
                    if (!_device_identity(c, d, &who))
                        continue;
                    if (!(have_self && uuid_compare(who.uuid, self.uuid) == 0))
                        _admit(proc, queues, &who, (const char *const *)c->rendezvous,
                               c->rendezvous_count);
                    if (d > 0)
                        at_fc_free_public(&who);
                }
                /* They know our sibling, not this device: say it is one of ours. */
                (void)at_device_announce_contact(proc, c);
            }
            at_fc_emit_contact(proc, AT_APP_EVENT_FC_CONTACT, "", c, false, origin);
        } else if (ch[k].action == AT_SYNC_REMOVED) {
            contact_t *gone = contacts_get_first(before, ch[k].uuid);
            if (gone == NULL)
                continue;
            bool dropped = false;
            for (size_t d = 0; d <= gone->devices_count; d++) {
                public_identity_t who;
                if (!_device_identity(gone, d, &who))
                    continue;
                if (identity_remove_direct_peer((process_t *)proc, queues, who.uuid) == 0)
                    dropped = true;
                if (d > 0)
                    at_fc_free_public(&who);
            }
            at_fc_emit_contact(proc, AT_APP_EVENT_FC_REMOVED, "", gone, dropped, origin);
        }
    }
    if (have_self)
        at_fc_free_public(&self);
}

bool handle_contacts_sync(const process_t *proc, directory_t *queues, generic_msg_t *msg)
{
    net_msg_t *nmsg = &msg->info.net_msg;
    const public_identity_t *sender = &nmsg->from_whom;
    at_siblings_t sib;
    _load_siblings(&sib);
    if (!at_fc_has_sender(sender) || !_is_sibling(&sib, sender)) {
        char u[UUID_STRING_LEN + 1];
        uuid_unparse_lower(sender->uuid, u);
        log_debug(proc->logger, "Identity: address book from %.8s, not a sibling; "
                  "ignored\n", u);
        at_siblings_free(&sib);
        return true;
    }
    json_t *payload = at_fc_app_payload(nmsg);
    char dir[CFG_PATH_LEN + 1] = {0};
    contacts_t store, before;
    _load_store(&store, dir, sizeof(dir));
    contacts_init(&before);
    (void)contacts_load(dir, &before);
    const char *exclude[AT_CONTACT_DEVICES_MAX + 1];
    char me[UUID_STRING_LEN + 1] = "";
    const identity_t *self = identity_self_identity(proc);
    if (self != NULL)
        uuid_unparse_lower(self->uuid, me);
    size_t n_ex = 0;
    exclude[n_ex++] = me;
    for (size_t i = 0; i < sib.count && n_ex < AT_CONTACT_DEVICES_MAX + 1; i++)
        exclude[n_ex++] = sib.devices[i].uuid;
    at_sync_change_t *ch = NULL;
    size_t n = 0;
    bool valid = at_sync_merge(&store, payload, _now(), exclude, n_ex, &ch, &n) == 0;
    if (!valid) {
        log_warn(proc->logger, "Identity: address book from %s refused (not a sync "
                 "payload)\n", sender->nickname);
    } else if (n > 0) {
        if (contacts_save(&store, dir) != 0)
            log_warn(proc->logger, "Identity: could not persist the contacts store\n");
        /* What we just took is not ours to push back. */
        if (_tracking(proc))
            _track(proc, &store, false);
        at_sibling_apply_changes(proc, queues, &store, &before, ch, n,
                                 AT_FC_ORIGIN_SIBLING);
        log_info(proc->logger, "Identity: first contact: %zu address-book change(s) "
                 "from %s\n", n, sender->nickname);
    }
    free(ch);
    bool reply = valid && json_is_true(json_object_get(payload, "reply"));
    json_decref(payload);
    contacts_free(&store);
    contacts_free(&before);
    at_siblings_free(&sib);
    if (reply)
        (void)at_sibling_send_full(proc, sender, false);
    return true;
}

/* -- startup, reachability ------------------------------------------------------ */

int at_sibling_restore(process_t *proc)
{
    if (proc == NULL || !at_first_contact_enabled())
        return 0;
    char dir[CFG_PATH_LEN + 1] = {0};
    contacts_t store;
    _load_store(&store, dir, sizeof(dir));
    _track(proc, &store, true);
    contacts_free(&store);
    at_siblings_t sib;
    _load_siblings(&sib);
    int restored = 0;
    for (size_t i = 0; i < sib.count; i++) {
        public_identity_t who;
        if (at_contact_device_identity(&sib.devices[i], &who) != 0)
            continue;
        const char *hints[AT_SIBLING_HINTS_MAX];
        for (size_t h = 0; h < sib.reach[i].n_hints; h++)
            hints[h] = sib.reach[i].hints[h];
        _admit(proc, NULL, &who, hints, sib.reach[i].n_hints);
        at_fc_push_own_record(proc, &who);
        (void)at_sibling_send_full(proc, &who, true);
        at_fc_free_public(&who);
        restored++;
    }
    at_siblings_free(&sib);
    if (restored > 0)
        log_info(proc->logger, "Identity: first contact: reconnecting %d sibling "
                 "device(s)\n", restored);
    return restored;
}

bool at_sibling_apply_record(const process_t *proc, const at_reach_record_t *rec)
{
    const char *ru = at_reach_uuid(rec), *rk = at_reach_key(rec);
    if (ru == NULL || rk == NULL)
        return false;
    at_siblings_t sib;
    _load_siblings(&sib);
    const at_contact_device_t *dev = at_siblings_get(&sib, ru);
    if (dev == NULL) {
        at_siblings_free(&sib);
        return false;
    }
    public_identity_t pub;
    bool same = at_contact_device_identity(dev, &pub) == 0
                && strcasecmp((const char *)pub.signature.public_hex, rk) == 0;
    if (!same) {
        log_warn(proc->logger, "Identity: first contact: record for sibling %.8s is "
                 "signed by another key; refused\n", ru);
        at_siblings_free(&sib);
        return true;
    }
    at_sibling_reach_t *r = at_siblings_reach(&sib, ru);
    if (at_reach_seq(rec) <= r->reach_seq) {
        at_fc_free_public(&pub);
        at_siblings_free(&sib);
        return true;
    }
    r->reach_seq = at_reach_seq(rec);
    /* The record's relays and endpoints ahead of what we had, deduplicated. */
    const char *merged[AT_SIBLING_HINTS_MAX];
    char keep[AT_SIBLING_HINTS_MAX][AT_SIBLING_HINT_LEN];
    size_t n = 0;
    json_t *lists[2] = {at_reach_relays(rec), at_reach_endpoints(rec)};
    for (int l = 0; l < 2; l++)
        for (size_t i = 0; lists[l] != NULL && i < json_array_size(lists[l])
                           && n < AT_SIBLING_HINTS_MAX; i++) {
            const char *h = json_string_value(json_array_get(lists[l], i));
            bool dup = h == NULL || h[0] == '\0';
            for (size_t j = 0; j < n && !dup; j++)
                dup = strcmp(keep[j], h) == 0;
            if (!dup)
                at_strlcpy(keep[n++], h, sizeof(keep[0]));
        }
    for (size_t i = 0; i < r->n_hints && n < AT_SIBLING_HINTS_MAX; i++) {
        bool dup = false;
        for (size_t j = 0; j < n && !dup; j++)
            dup = strcmp(keep[j], r->hints[i]) == 0;
        if (!dup)
            at_strlcpy(keep[n++], r->hints[i], sizeof(keep[0]));
    }
    for (size_t i = 0; i < n; i++)
        merged[i] = keep[i];
    at_siblings_set_hints(&sib, ru, merged, n);
    _save_siblings(proc, &sib);
    _route(pub.uuid, merged, n);
    at_fc_free_public(&pub);
    at_siblings_free(&sib);
    return true;
}

/* -- app verbs ------------------------------------------------------------------ */

bool handle_app_sibling_list(const process_t *proc, directory_t *queues, generic_msg_t *msg)
{
    (void)queues;
    net_msg_t *nmsg = &msg->info.net_msg;
    if (!identity_is_local_app_verb(proc, nmsg))
        return identity_refuse_remote_app_verb(proc, nmsg, AT_APP_SIBLING_LIST);
    json_t *req = at_fc_app_payload(nmsg);
    const char *ref = at_fc_app_ref(req);
    if (ref == NULL) {
        at_fc_emit_event(proc, AT_APP_EVENT_FC_REFUSED, "", NULL,
                         AT_FC_REASON_BAD_REQUEST, AT_FC_ROLE_NONE);
        json_decref(req);
        return true;
    }
    at_siblings_t sib;
    _load_siblings(&sib);
    for (size_t i = 0; i < sib.count; i++) {
        const char *nick = json_string_value(json_object_get(sib.devices[i].identity,
                                                             "nickname"));
        at_fc_emit_sibling(proc, AT_APP_EVENT_FC_SIBLING, ref, sib.devices[i].uuid,
                           nick, sib.devices[i].added_at, false, 0);
    }
    at_fc_emit_sibling(proc, AT_APP_EVENT_FC_SIBLINGS_DONE, ref, NULL, NULL, 0.0,
                       false, (int32_t)sib.count);
    at_siblings_free(&sib);
    json_decref(req);
    return true;
}

bool handle_app_sibling_remove(const process_t *proc, directory_t *queues,
                               generic_msg_t *msg)
{
    net_msg_t *nmsg = &msg->info.net_msg;
    if (!identity_is_local_app_verb(proc, nmsg))
        return identity_refuse_remote_app_verb(proc, nmsg, AT_APP_SIBLING_REMOVE);
    json_t *req = at_fc_app_payload(nmsg);
    const char *ref = at_fc_app_ref(req);
    if (ref == NULL) {
        at_fc_emit_event(proc, AT_APP_EVENT_FC_REFUSED, "", NULL,
                         AT_FC_REASON_BAD_REQUEST, AT_FC_ROLE_NONE);
        json_decref(req);
        return true;
    }
    const char *peer = json_string_value(json_object_get(req, "peer"));
    at_siblings_t sib;
    _load_siblings(&sib);
    const at_contact_device_t *dev = peer != NULL ? at_siblings_get(&sib, peer) : NULL;
    if (dev == NULL) {
        public_identity_t who;
        memset(&who, 0, sizeof(who));
        if (peer != NULL)
            (void)uuid_parse(peer, who.uuid);
        at_fc_emit_event(proc, AT_APP_EVENT_FC_REFUSED, ref, peer != NULL ? &who : NULL,
                         AT_FC_REASON_UNKNOWN_CONTACT, AT_FC_ROLE_NONE);
        at_siblings_free(&sib);
        json_decref(req);
        return true;
    }
    char u[UUID_STRING_LEN + 1], nick[NAME_LEN + 1] = "";
    at_strlcpy(u, dev->uuid, sizeof(u));
    const char *n = json_string_value(json_object_get(dev->identity, "nickname"));
    if (n != NULL)
        at_strlcpy(nick, n, sizeof(nick));
    (void)at_siblings_remove(&sib, u);
    _save_siblings(proc, &sib);
    at_siblings_free(&sib);
    uuid_t uu;
    bool dropped = uuid_parse(u, uu) == 0
                   && identity_remove_direct_peer((process_t *)proc, queues, uu) == 0;
    log_info(proc->logger, "Identity: first contact: unpaired %.8s\n", u);
    at_fc_emit_sibling(proc, AT_APP_EVENT_FC_SIBLING_REMOVED, ref, u, nick, 0.0,
                       dropped, 0);
    json_decref(req);
    return true;
}

void at_sibling_sync_register(process_t *proc)
{
    process_register_handler(proc, FN_CONTACTS_SYNC, (handler_ptr_t)handle_contacts_sync);
    process_register_handler(proc, FN_APP_SIBLING_LIST,
                             (handler_ptr_t)handle_app_sibling_list);
    process_register_handler(proc, FN_APP_SIBLING_REMOVE,
                             (handler_ptr_t)handle_app_sibling_remove);
}

/* The app may send these verbs, each only to identity. Python's
 * sibling_sync.APP_VERBS. */
AT_APP_VERB_REGISTER(sibling_list, AT_APP_SIBLING_LIST, "identity")
AT_APP_VERB_REGISTER(sibling_remove, AT_APP_SIBLING_REMOVE, "identity")
