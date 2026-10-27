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

#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include <jansson.h>
#include <sodium.h>
#include <uuid/uuid.h>

#include "identity/anchored_cohort.h"
#include "identity/id_proc_priv.h"
#include "identity/join_policy.h"
#include "config/configuration.h"
#include "structures/map.h"
#include "structures/data.h"
#include "utilities/msg_types.h"
#include "utilities/msg_types_priv.h"
#include "utilities/logger.h"

char ID_COHORT_INVITE[] = "anchored_cohort_invite";
char ID_COHORT_REPLY[]  = "anchored_cohort_reply";

/* What this node holds, under one lock. The lock is never held across a send
 * or an anchor judgement (id_ext.h calls the hooks with no lock held). */
static struct {
    pthread_mutex_t lock;
    bool initialized;
    bool held;
    group_t group;
    /* Coordinator: member uuid -> when it was invited (floating_pt data), for
     * members that have not answered the current invitation. */
    map_t pending;
    /* Coordinator: member uuid -> the member set it refused (string). */
    map_t refused;
} cs = { .lock = PTHREAD_MUTEX_INITIALIZER };

static bool (*g_anchor_fn)(const process_t *, const public_identity_t *);
static double (*g_clock)(void);

static void _ensure(void)
{
    if (cs.initialized)
        return;
    map_init(&cs.pending);
    map_init(&cs.refused);
    cs.initialized = true;
}

static double _now(void)
{
    return g_clock != NULL ? g_clock() : (double)time(NULL);
}

static void _drop_group_locked(void)
{
    if (cs.held && cs.group.address_map.items != NULL)
        map_free(&cs.group.address_map);
    sodium_memzero(&cs.group, sizeof(cs.group));
    cs.held = false;
}

/* A deep copy of @p src into @p dst (zeroed first), through its canonical
 * form: the address map is the only allocation, and the round trip is the
 * one the wire already exercises. */
static bool _copy_group(const group_t *src, group_t *dst)
{
    memset(dst, 0, sizeof(*dst));
    json_t *j = NULL;
    if (group_to_json(src, &j) != 0 || j == NULL)
        return false;
    bool ok = group_from_json(j, dst) == 0;
    json_decref(j);
    return ok;
}

static bool _owns_private(const group_t *g)
{
    return !sodium_is_zero(g->encryptor.private, crypto_box_SECRETKEYBYTES);
}

static bool _is_member(const group_t *g, const char *key)
{
    data_t *d = NULL;
    return map_get((map_t *)&g->address_map, (map_key_t)key, &d) == 0;
}

static int _cmp_str(const void *a, const void *b)
{
    return strcmp((const char *)a, (const char *)b);
}

/* The member uuids of @p g, sorted, into @p out (each UUID_STRING_LEN + 1);
 * returns how many (at most @p max). */
static size_t _members(const group_t *g, char (*out)[UUID_STRING_LEN + 1],
                       size_t max)
{
    size_t n = 0;
    map_key_t key;
    data_t *val;
    map_entries_for_each((map_t *)&g->address_map, key, val)
    {
        (void)val;
        if (n < max)
            snprintf(out[n++], UUID_STRING_LEN + 1, "%s", key);
    }
    map_end_for_each
    qsort(out, n, UUID_STRING_LEN + 1, _cmp_str);
    return n;
}

/* The sorted member set of @p g as one comma-joined string. */
static void _member_set(const group_t *g, char *out, size_t cap)
{
    char (*m)[UUID_STRING_LEN + 1] = calloc(DEFAULT_MAX_PEERS, UUID_STRING_LEN + 1);
    out[0] = '\0';
    if (m == NULL)
        return;
    size_t n = _members(g, m, DEFAULT_MAX_PEERS);
    size_t used = 0;
    for (size_t i = 0; i < n && used + UUID_STRING_LEN + 2 < cap; i++)
        used += (size_t)snprintf(out + used, cap - used, "%s%s",
                                 i ? "," : "", m[i]);
    free(m);
}

#define COHORT_SET_LEN (DEFAULT_MAX_PEERS * (UUID_STRING_LEN + 1) + 1)

static bool _policy(at_join_policy_t *p)
{
    identity_get_join_policy(p);
    return p->enabled;
}

static bool _is_anchor(const process_t *proc, const public_identity_t *peer)
{
    return g_anchor_fn != NULL ? g_anchor_fn(proc, peer)
                               : identity_is_anchored(proc, peer);
}

/* A copy of the held peer @p key, or false. */
static bool _peer_by_uuid(const process_t *proc, const char *key,
                          public_identity_t *out)
{
    bool found = false;
    peers_read_lock(proc);
    for (size_t i = 0; i < proc->protocol.num_peers && !found; i++) {
        char pk[UUID_STRING_LEN + 1];
        uuid_unparse_lower(proc->protocol.peers[i].uuid, pk);
        if (strcmp(pk, key) == 0) {
            *out = proc->protocol.peers[i];
            found = true;
        }
    }
    peers_read_unlock(proc);
    return found;
}

/* ---- persistence and publication ----------------------------------------- */

static void _persist(const process_t *proc, const group_t *g)
{
    char dir[CFG_PATH_LEN + 1] = {0};
    if (get_cfg_dir(dir, sizeof(dir)) < 0)
        return;
    char path[CFG_PATH_LEN + 64];
    snprintf(path, sizeof(path), "%s/%s", dir, AT_COHORT_FILE);
    if (g == NULL) {
        (void)unlink(path);
        return;
    }
    json_t *j = NULL;
    if (group_to_json(g, &j) != 0 || j == NULL)
        return;
    if (json_dump_file(j, path, JSON_INDENT(2)) != 0)
        log_warn(proc->logger, "Identity: could not persist the anchored cohort\n");
    json_decref(j);
}

/* Tell reputation which cohort this node holds (ANCHORED_COHORT). */
static void _publish(const process_t *proc, const group_t *g)
{
    generic_msg_t out;
    memset(&out, 0, sizeof(out));
    out.type = ANCHORED_COHORT;
    out.size = sizeof(anchored_cohort_msg_t);
    anchored_cohort_msg_t *m = &out.info.anchored_cohort;
    if (g != NULL) {
        m->held = true;
        uuid_copy(m->group_uuid, g->uuid);
        char (*keys)[UUID_STRING_LEN + 1] =
            calloc(AT_COHORT_MAX_MEMBERS, UUID_STRING_LEN + 1);
        if (keys != NULL) {
            size_t n = _members(g, keys, AT_COHORT_MAX_MEMBERS);
            for (size_t i = 0; i < n; i++)
                if (uuid_parse(keys[i], m->members[m->n_members]) == 0)
                    m->n_members++;
            free(keys);
        }
    }
    (void)identity_send_to(proc, "reputation", &out, "the anchored cohort", "");
}

/* Hold @p g (NULL: none), persist and publish. Takes cs.lock. */
static void _set(const process_t *proc, const group_t *g, const char *reason)
{
    pthread_mutex_lock(&cs.lock);
    _ensure();
    _drop_group_locked();
    group_t snap;
    bool have = false;
    if (g != NULL && _copy_group(g, &cs.group)) {
        cs.held = true;
        have = _copy_group(&cs.group, &snap);
    }
    pthread_mutex_unlock(&cs.lock);
    _persist(proc, have ? &snap : NULL);
    _publish(proc, have ? &snap : NULL);
    char u[UUID_STRING_LEN + 1] = "-";
    size_t n = 0;
    if (have) {
        uuid_unparse_lower(snap.uuid, u);
        n = map_size(&snap.address_map);
    }
    log_info(proc->logger, "Identity: anchored cohort %.8s: %s (%zu member(s))\n",
             u, reason, n);
    if (have)
        map_free(&snap.address_map);
}

/* ---- sending --------------------------------------------------------------- */

static void _send(const process_t *proc, char *function, json_t *payload,
                  const public_identity_t *to)
{
    generic_msg_t m = {0};
    m.type = NET_MESSAGE;
    strncpy(m.info.net_msg.process, "identity", PROC_NAME_LEN);
    m.info.net_msg.function = function;
    m.info.net_msg.encrypt = true;
    memcpy(&m.info.net_msg.to_whom, to, sizeof(public_identity_t));
    strncpy(m.info.net_msg.return_to, "identity", PROC_NAME_LEN);
    net_msg_pack_json(&m.info.net_msg, payload);
    (void)identity_send_to_network(proc, &m, function, to->nickname);
    net_msg_free_obj(&m.info.net_msg);
}

/* Send every other member the held cohort's canonical form, and start its
 * reply clock. */
static void _invite_all(const process_t *proc)
{
    const identity_t *self = identity_self_identity(proc);
    if (self == NULL)
        return;
    char me[UUID_STRING_LEN + 1];
    uuid_unparse_lower(self->uuid, me);
    pthread_mutex_lock(&cs.lock);
    if (!cs.held) {
        pthread_mutex_unlock(&cs.lock);
        return;
    }
    json_t *payload = NULL;
    (void)group_to_json(&cs.group, &payload);
    char (*keys)[UUID_STRING_LEN + 1] = calloc(DEFAULT_MAX_PEERS, UUID_STRING_LEN + 1);
    size_t n = keys != NULL ? _members(&cs.group, keys, DEFAULT_MAX_PEERS) : 0;
    map_free(&cs.pending);
    map_init(&cs.pending);
    double present = _now();
    for (size_t i = 0; i < n; i++)
        if (strcmp(keys[i], me) != 0)
            map_set(&cs.pending, (map_key_t)keys[i], floating_pt_dbl_data(present));
    pthread_mutex_unlock(&cs.lock);
    for (size_t i = 0; payload != NULL && i < n; i++) {
        public_identity_t peer;
        if (strcmp(keys[i], me) != 0 && _peer_by_uuid(proc, keys[i], &peer))
            _send(proc, ID_COHORT_INVITE, payload, &peer);
    }
    json_decref(payload);
    free(keys);
}

/* ---- forming and coordinating ------------------------------------------- */

/* The primary group's members this node counts as anchors, as held public
 * identities sorted by uuid, into @p out; returns how many. */
static size_t _cohort_anchors(const process_t *proc, const char *me,
                              public_identity_t *out, size_t max)
{
    public_identity_t *peers = calloc(DEFAULT_MAX_PEERS, sizeof(*peers));
    if (peers == NULL)
        return 0;
    size_t n = 0;
    peers_read_lock(proc);
    for (size_t i = 0; i < proc->protocol.num_peers && n < DEFAULT_MAX_PEERS; i++) {
        char pk[UUID_STRING_LEN + 1];
        uuid_unparse_lower(proc->protocol.peers[i].uuid, pk);
        if (strcmp(pk, me) != 0 && _is_member(&proc->protocol.group, pk))
            peers[n++] = proc->protocol.peers[i];
    }
    peers_read_unlock(proc);
    size_t k = 0;
    for (size_t i = 0; i < n && k < max; i++)     /* judged with no lock held */
        if (_is_anchor(proc, &peers[i]))
            out[k++] = peers[i];
    free(peers);
    for (size_t i = 1; i < k; i++)                /* insertion sort by uuid */
        for (size_t j = i; j > 0 && uuid_compare(out[j - 1].uuid, out[j].uuid) > 0; j--) {
            public_identity_t t = out[j];
            out[j] = out[j - 1];
            out[j - 1] = t;
        }
    return k;
}

/* Whether @p me is the lowest-uuid member of the cohort held. cs.lock held. */
static bool _is_coordinator_locked(const char *me)
{
    if (!cs.held)
        return false;
    char low[UUID_STRING_LEN + 1] = {0};
    map_key_t key;
    data_t *val;
    map_entries_for_each(&cs.group.address_map, key, val)
    {
        (void)val;
        if (low[0] == '\0' || strcmp(key, low) < 0)
            snprintf(low, sizeof(low), "%s", key);
    }
    map_end_for_each
    return strcmp(low, me) == 0;
}

/* Drop @p key from the cohort held. cs.lock held. */
static void _drop_member_locked(const char *key)
{
    map_remove(&cs.pending, (map_key_t)key);
    map_remove(&cs.group.address_map, (map_key_t)key);
}

/* Rotate the held cohort's key, then persist, publish and re-invite. */
static void _rotate(const process_t *proc, const char *reason)
{
    pthread_mutex_lock(&cs.lock);
    group_t snap;
    bool ok = cs.held && group_rotate_key(&cs.group) >= 0
              && _copy_group(&cs.group, &snap);
    pthread_mutex_unlock(&cs.lock);
    if (!ok) {
        log_warn(proc->logger, "Identity: could not rotate the anchored cohort key\n");
        return;
    }
    _set(proc, &snap, reason);
    map_free(&snap.address_map);
    _invite_all(proc);
}

static void _coordinate(const process_t *proc, const char *me,
                        const public_identity_t *anchors, size_t n_anchors)
{
    pthread_mutex_lock(&cs.lock);
    bool changed = false;
    /* Who would join, then the membership offered; a peer is never offered
     * the membership it refused. */
    bool *add = calloc(n_anchors > 0 ? n_anchors : 1, sizeof(bool));
    char *offer = calloc(1, COHORT_SET_LEN);
    if (add == NULL || offer == NULL) {
        pthread_mutex_unlock(&cs.lock);
        free(add);
        free(offer);
        return;
    }
    for (int pass = 0; pass < 2; pass++) {
        group_t probe;
        if (!_copy_group(&cs.group, &probe))
            break;
        for (size_t i = 0; i < n_anchors; i++) {
            char k[UUID_STRING_LEN + 1];
            uuid_unparse_lower(anchors[i].uuid, k);
            if (pass == 0)
                add[i] = !_is_member(&cs.group, k);
            if (add[i])
                group_add_address(&probe, k, anchors[i].address);
        }
        _member_set(&probe, offer, COHORT_SET_LEN);
        map_free(&probe.address_map);
        for (size_t i = 0; i < n_anchors; i++) {
            if (!add[i])
                continue;
            char k[UUID_STRING_LEN + 1];
            uuid_unparse_lower(anchors[i].uuid, k);
            data_t *d = NULL;
            string_t was = NULL;
            if (map_get(&cs.refused, (map_key_t)k, &d) == 0
                && data_string_ptr(d, &was) == 0 && strcmp(was, offer) == 0)
                add[i] = false;
        }
    }
    for (size_t i = 0; i < n_anchors; i++) {
        if (!add[i])
            continue;
        char k[UUID_STRING_LEN + 1];
        uuid_unparse_lower(anchors[i].uuid, k);
        group_add_address(&cs.group, k, anchors[i].address);
        changed = true;
    }
    free(add);
    free(offer);
    /* Members that never answered. */
    double present = _now();
    char (*late)[UUID_STRING_LEN + 1] = calloc(DEFAULT_MAX_PEERS, UUID_STRING_LEN + 1);
    size_t n_late = 0;
    map_key_t key;
    data_t *val;
    map_entries_for_each(&cs.pending, key, val)
    {
        double since = present;
        (void)data_floating_pt_dbl(val, &since);
        if (late != NULL && n_late < DEFAULT_MAX_PEERS
            && present - since >= AT_COHORT_REPLY_TIMEOUT)
            snprintf(late[n_late++], UUID_STRING_LEN + 1, "%s", key);
    }
    map_end_for_each
    for (size_t i = 0; i < n_late; i++) {
        _drop_member_locked(late[i]);
        changed = true;
    }
    free(late);
    (void)me;
    pthread_mutex_unlock(&cs.lock);
    if (changed)
        _rotate(proc, "membership changed");
}

void identity_anchored_cohort_tick(const process_t *proc)
{
    at_join_policy_t policy;
    if (proc == NULL || !_policy(&policy) || uuid_is_null(proc->protocol.group.uuid))
        return;
    const identity_t *self = identity_self_identity(proc);
    if (self == NULL)
        return;
    char me[UUID_STRING_LEN + 1];
    uuid_unparse_lower(self->uuid, me);
    public_identity_t *anchors = calloc(DEFAULT_MAX_PEERS, sizeof(*anchors));
    if (anchors == NULL)
        return;
    size_t n = _cohort_anchors(proc, me, anchors, DEFAULT_MAX_PEERS);
    pthread_mutex_lock(&cs.lock);
    _ensure();
    bool held = cs.held;
    bool coordinator = _is_coordinator_locked(me);
    pthread_mutex_unlock(&cs.lock);
    if (held) {
        if (coordinator)
            _coordinate(proc, me, anchors, n);
        free(anchors);
        return;
    }
    if (n < (size_t)policy.anchored_cohort_min) {
        free(anchors);
        return;
    }
    char low[UUID_STRING_LEN + 1];
    uuid_unparse_lower(anchors[0].uuid, low);   /* sorted: the lowest anchor */
    if (strcmp(low, me) < 0) {
        free(anchors);
        return;                                 /* the lowest uuid forms it */
    }
    group_t g;
    memset(&g, 0, sizeof(g));               /* group_init sets only some fields */
    if (group_init(NULL, (char *)self->address, &g) != 0) {
        free(anchors);
        return;
    }
    group_add_address(&g, me, self->address);
    for (size_t i = 0; i < n; i++) {
        char k[UUID_STRING_LEN + 1];
        uuid_unparse_lower(anchors[i].uuid, k);
        group_add_address(&g, k, anchors[i].address);
    }
    g.created = _now();
    g.wire_format = proc->protocol.group.wire_format;
    free(anchors);
    _set(proc, &g, "formed");
    map_free(&g.address_map);
    sodium_memzero(&g, sizeof(g));
    _invite_all(proc);
}

void identity_anchored_cohort_load(const process_t *proc)
{
    at_join_policy_t policy;
    if (proc == NULL || !_policy(&policy))
        return;
    char dir[CFG_PATH_LEN + 1] = {0};
    if (get_cfg_dir(dir, sizeof(dir)) < 0)
        return;
    char path[CFG_PATH_LEN + 64];
    snprintf(path, sizeof(path), "%s/%s", dir, AT_COHORT_FILE);
    if (access(path, R_OK) != 0)
        return;
    json_error_t jerr;
    json_t *j = json_load_file(path, 0, &jerr);
    group_t g;
    memset(&g, 0, sizeof(g));
    if (j == NULL || group_from_json(j, &g) != 0) {
        log_warn(proc->logger, "Identity: could not load the anchored cohort\n");
        json_decref(j);
        return;
    }
    json_decref(j);
    _set(proc, &g, "restored");
    map_free(&g.address_map);
    sodium_memzero(&g, sizeof(g));
}

/* ---- the verbs ------------------------------------------------------------- */

static void _reply(const process_t *proc, const group_t *g, bool accepted,
                   const public_identity_t *to)
{
    char u[UUID_STRING_LEN + 1];
    uuid_unparse_lower(g->uuid, u);
    json_t *arr = json_pack("[s, I, b]", u, (json_int_t)g->key_epoch, accepted);
    if (arr == NULL)
        return;
    _send(proc, ID_COHORT_REPLY, arr, to);
    json_decref(arr);
}

/* An invitation to, or an update of, an anchored cohort. Mirrors Python
 * handle_anchored_cohort_invite. */
static bool handle_anchored_cohort_invite(const process_t *proc,
                                          directory_t *queues, generic_msg_t *msg)
{
    (void)queues;
    net_msg_t *nmsg = &msg->info.net_msg;
    if (nmsg->function == NULL || strcmp(nmsg->function, ID_COHORT_INVITE) != 0)
        return false;
    at_join_policy_t policy;
    if (!_policy(&policy))
        return true;                            /* not ours to answer */
    const identity_t *self = identity_self_identity(proc);
    json_t *payload = NULL;
    if (self == NULL || net_msg_unpack_json(nmsg, &payload) != 0 || payload == NULL)
        return true;
    group_t g;
    memset(&g, 0, sizeof(g));
    int rc = group_from_json(payload, &g);
    json_decref(payload);
    if (rc != 0) {
        if (g.address_map.items != NULL)
            map_free(&g.address_map);
        log_warn(proc->logger, "Identity: unreadable anchored cohort invite\n");
        return true;
    }
    char me[UUID_STRING_LEN + 1], sender[UUID_STRING_LEN + 1];
    uuid_unparse_lower(self->uuid, me);
    uuid_unparse_lower(nmsg->from_whom.uuid, sender);

    pthread_mutex_lock(&cs.lock);
    _ensure();
    bool same = cs.held && uuid_compare(cs.group.uuid, g.uuid) == 0;
    bool other = cs.held && !same;
    bool stale = same && g.key_epoch <= cs.group.key_epoch;
    pthread_mutex_unlock(&cs.lock);
    if (stale) {
        map_free(&g.address_map);
        return true;                            /* a replay or a stale update */
    }
    const char *why = NULL;
    if (other)
        why = "holds another anchored cohort";
    else if (!_is_member(&g, me) || !_is_member(&g, sender))
        why = "not listed with its sender";
    else if (!_owns_private(&g))
        why = "carries no key";
    else {
        char (*keys)[UUID_STRING_LEN + 1] = calloc(DEFAULT_MAX_PEERS, UUID_STRING_LEN + 1);
        size_t n = keys != NULL ? _members(&g, keys, DEFAULT_MAX_PEERS) : 0;
        for (size_t i = 0; i < n && why == NULL; i++) {
            public_identity_t peer;
            if (strcmp(keys[i], me) == 0)
                continue;
            if (!_peer_by_uuid(proc, keys[i], &peer) || !_is_anchor(proc, &peer))
                why = "lists a member not an anchor here";
        }
        free(keys);
    }
    bool accepted = why == NULL;
    if (accepted) {
        char reason[48];
        snprintf(reason, sizeof(reason), same ? "updated to epoch %lld" : "joined",
                 (long long)g.key_epoch);
        pthread_mutex_lock(&cs.lock);
        map_free(&cs.pending);
        map_init(&cs.pending);
        pthread_mutex_unlock(&cs.lock);
        _set(proc, &g, reason);
    } else {
        char gu[UUID_STRING_LEN + 1];
        uuid_unparse_lower(g.uuid, gu);
        log_info(proc->logger, "Identity: anchored cohort %.8s from %s refused: %s\n",
                 gu, nmsg->from_whom.nickname, why);
        if (same) {
            char reason[96];
            snprintf(reason, sizeof(reason), "left (%s)", why);
            _set(proc, NULL, reason);
        }
    }
    _reply(proc, &g, accepted, &nmsg->from_whom);
    map_free(&g.address_map);
    sodium_memzero(&g, sizeof(g));
    return true;
}

/* A member's answer to the coordinator's invitation. Mirrors Python
 * handle_anchored_cohort_reply. */
static bool handle_anchored_cohort_reply(const process_t *proc,
                                         directory_t *queues, generic_msg_t *msg)
{
    (void)queues;
    net_msg_t *nmsg = &msg->info.net_msg;
    if (nmsg->function == NULL || strcmp(nmsg->function, ID_COHORT_REPLY) != 0)
        return false;
    const identity_t *self = identity_self_identity(proc);
    json_t *payload = NULL;
    if (self == NULL || net_msg_unpack_json(nmsg, &payload) != 0 || payload == NULL)
        return true;
    const char *gu = json_string_value(json_array_get(payload, 0));
    json_t *j_epoch = json_array_get(payload, 1);
    json_t *j_ok = json_array_get(payload, 2);
    uuid_t group_uuid;
    bool readable = gu != NULL && uuid_parse(gu, group_uuid) == 0
                    && json_is_integer(j_epoch) && json_is_boolean(j_ok);
    int64_t epoch = readable ? (int64_t)json_integer_value(j_epoch) : 0;
    bool accepted = readable && json_is_true(j_ok);
    json_decref(payload);
    if (!readable)
        return true;
    char me[UUID_STRING_LEN + 1], sender[UUID_STRING_LEN + 1];
    uuid_unparse_lower(self->uuid, me);
    uuid_unparse_lower(nmsg->from_whom.uuid, sender);
    pthread_mutex_lock(&cs.lock);
    _ensure();
    if (!cs.held || uuid_compare(cs.group.uuid, group_uuid) != 0
        || !_is_member(&cs.group, sender) || epoch != cs.group.key_epoch) {
        pthread_mutex_unlock(&cs.lock);
        return true;                            /* not ours, or superseded */
    }
    map_remove(&cs.pending, (map_key_t)sender);
    bool drop = !accepted && _is_coordinator_locked(me);
    if (drop) {
        char *set = calloc(1, COHORT_SET_LEN);
        if (set != NULL) {
            _member_set(&cs.group, set, COHORT_SET_LEN);
            map_set(&cs.refused, (map_key_t)sender, string_data(set, strlen(set)));
            free(set);
        }
        _drop_member_locked(sender);
    }
    pthread_mutex_unlock(&cs.lock);
    if (drop)
        _rotate(proc, "a member refused");
    return true;
}

void identity_anchored_cohort_register(process_t *proc)
{
    process_register_handler(proc, ID_COHORT_INVITE,
                             (handler_ptr_t)handle_anchored_cohort_invite);
    process_register_handler(proc, ID_COHORT_REPLY,
                             (handler_ptr_t)handle_anchored_cohort_reply);
}

bool identity_anchored_cohort_held(group_t *out)
{
    pthread_mutex_lock(&cs.lock);
    bool ok = cs.held && out != NULL && _copy_group(&cs.group, out);
    pthread_mutex_unlock(&cs.lock);
    return ok;
}

void identity_anchored_cohort_release(group_t *g)
{
    if (g == NULL)
        return;
    if (g->address_map.items != NULL)
        map_free(&g->address_map);
    sodium_memzero(g, sizeof(*g));
}

void identity_anchored_cohort_reset(void)
{
    pthread_mutex_lock(&cs.lock);
    _ensure();
    _drop_group_locked();
    map_free(&cs.pending);
    map_init(&cs.pending);
    map_free(&cs.refused);
    map_init(&cs.refused);
    pthread_mutex_unlock(&cs.lock);
}

void identity_anchored_cohort_set_anchor_fn(
    bool (*fn)(const process_t *proc, const public_identity_t *peer))
{
    g_anchor_fn = fn;
}

void identity_anchored_cohort_set_clock(double (*clock)(void))
{
    g_clock = clock;
}
