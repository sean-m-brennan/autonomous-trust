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

#include <stdio.h>
#include <string.h>
#include <pthread.h>
#include <time.h>

#include "fleet/fleet_gate.h"
#include "config/configuration.h"
#include "identity/identity.h"
#include "identity/id_proc_priv.h"   /* identity_self_identity, identity_copy_held_message */
#include "network/net_message.h"
#include "utilities/msg_types_priv.h"   /* net_msg_pack_json */
#include "reputation/reputation.h"   /* REP_PROTO_LOCAL_QUERY / _RESP */
#include "structures/map.h"
#include "utilities/send_retry.h"
#include "utilities/util.h"

/* A reputation answer is used for this long before it is asked for again. */
#define FLEET_GATE_REP_TTL_SEC 60
#define FLEET_GATE_REP_CACHE   64
#define FLEET_GATE_HELD        32

typedef struct {
    uuid_t uuid;
    double score;
    bool found;
    bool asked;          /* a query is out and no answer yet */
    time_t at;
} rep_entry_t;

typedef struct {
    generic_msg_t msg;
    fleet_gate_handler_fn handler;
} held_t;

/* Per process: fleet and config each run in their own. */
static struct {
    pthread_mutex_t lock;
    bool lock_ready;
    rep_entry_t rep[FLEET_GATE_REP_CACHE];
    size_t num_rep;
    held_t held[FLEET_GATE_HELD];
    size_t num_held;
    double bar;          /* < 0: not read yet */
} gate = { .bar = -1.0 };

static void _lock(void)
{
    if (!gate.lock_ready) {
        pthread_mutex_init(&gate.lock, NULL);
        gate.lock_ready = true;
    }
    pthread_mutex_lock(&gate.lock);
}

static void _unlock(void)
{
    pthread_mutex_unlock(&gate.lock);
}

/* -- the group ----------------------------------------------------------- */

bool fleet_gate_is_self(const process_t *proc, const uuid_t uuid)
{
    const identity_t *self = identity_self_identity(proc);
    return self != NULL && uuid_compare(self->uuid, uuid) == 0;
}

static bool _in_address_map(const process_t *proc, const uuid_t uuid)
{
    map_t *amap = (map_t *)&proc->protocol.group.address_map;
    if (amap->items == NULL)
        return false;
    char key[UUID_STRING_LEN + 1];
    uuid_unparse_lower(uuid, key);
    data_t *value = NULL;
    return map_get(amap, key, &value) == 0;
}

size_t fleet_gate_group_size(const process_t *proc)
{
    map_t *amap = (map_t *)&proc->protocol.group.address_map;
    size_t n = amap->items == NULL ? 0 : map_size(amap);
    const identity_t *self = identity_self_identity(proc);
    if (self == NULL || !_in_address_map(proc, self->uuid))
        n++;
    return n;
}

size_t fleet_gate_quorum(size_t group_size)
{
    return group_size / 2;
}

bool fleet_gate_member(const process_t *proc, const uuid_t uuid,
                       uint8_t pk_out[crypto_sign_PUBLICKEYBYTES],
                       bool *operator_bound_out)
{
    const identity_t *self = identity_self_identity(proc);
    if (self != NULL && uuid_compare(self->uuid, uuid) == 0) {
        memcpy(pk_out, self->signature.public, crypto_sign_PUBLICKEYBYTES);
        if (operator_bound_out != NULL)
            *operator_bound_out = self->operator_bound;
        return true;
    }
    if (!_in_address_map(proc, uuid))
        return false;
    bool found = false;
    peers_read_lock((process_t *)proc);
    for (size_t i = 0; i < proc->protocol.num_peers && !found; i++) {
        const public_identity_t *p = &proc->protocol.peers[i];
        if (uuid_compare(p->uuid, uuid) != 0)
            continue;
        memcpy(pk_out, p->signature.public, crypto_sign_PUBLICKEYBYTES);
        if (operator_bound_out != NULL)
            *operator_bound_out = p->operator_bound;
        found = true;
    }
    peers_read_unlock((process_t *)proc);
    return found;
}

size_t fleet_gate_members(const process_t *proc, public_identity_t **out)
{
    *out = NULL;
    peers_read_lock((process_t *)proc);
    size_t n = proc->protocol.num_peers, count = 0;
    public_identity_t *list = calloc(n > 0 ? n : 1, sizeof(public_identity_t));
    for (size_t i = 0; list != NULL && i < n; i++)
        if (_in_address_map(proc, proc->protocol.peers[i].uuid)
            && !fleet_gate_is_self(proc, proc->protocol.peers[i].uuid))
            memcpy(&list[count++], &proc->protocol.peers[i], sizeof(public_identity_t));
    peers_read_unlock((process_t *)proc);
    *out = list;
    return count;
}

/* -- reputation ---------------------------------------------------------- */

double fleet_gate_min_reputation(void)
{
    _lock();
    if (gate.bar < 0.0) {
        gate.bar = FLEET_DEFAULT_MIN_REPUTATION;
        char dir[CFG_PATH_LEN + 1] = {0};
        char path[CFG_PATH_LEN + 32] = {0};
        if (get_cfg_dir(dir, sizeof(dir)) >= 0 && dir[0] != '\0'
            && path_join(path, sizeof(path), dir, FLEET_GATE_CFG_NAME ".cfg.json") >= 0) {
            json_error_t err;
            json_t *cfg = json_load_file(path, 0, &err);
            json_t *bar = cfg != NULL ? json_object_get(cfg, "min_proposer_reputation") : NULL;
            if (json_is_number(bar))
                gate.bar = json_number_value(bar);
            json_decref(cfg);
        }
    }
    double bar = gate.bar;
    _unlock();
    return bar;
}

void fleet_gate_set_min_reputation(double bar)
{
    _lock();
    gate.bar = bar;
    _unlock();
}

/* Caller holds the lock. */
static rep_entry_t *_rep_entry(const uuid_t uuid, bool create)
{
    for (size_t i = 0; i < gate.num_rep; i++)
        if (uuid_compare(gate.rep[i].uuid, uuid) == 0)
            return &gate.rep[i];
    if (!create)
        return NULL;
    size_t at = gate.num_rep;
    if (at == FLEET_GATE_REP_CACHE) {
        at = 0;     /* full: replace the oldest answer */
        for (size_t i = 1; i < gate.num_rep; i++)
            if (gate.rep[i].at < gate.rep[at].at)
                at = i;
    } else {
        gate.num_rep++;
    }
    memset(&gate.rep[at], 0, sizeof(gate.rep[at]));
    uuid_copy(gate.rep[at].uuid, uuid);
    return &gate.rep[at];
}

void fleet_gate_set_reputation(const uuid_t uuid, double score, bool found)
{
    _lock();
    rep_entry_t *e = _rep_entry(uuid, true);
    e->score = score;
    e->found = found;
    e->asked = false;
    e->at = time(NULL);
    _unlock();
}

static void _ask_reputation(const process_t *proc, const uuid_t uuid)
{
    char u[UUID_STRING_LEN + 1];
    uuid_unparse_lower(uuid, u);
    json_t *query = json_pack("{s:s, s:s}", "peer_uuid", u, "return_process", proc->name);
    if (query == NULL)
        return;
    generic_msg_t msg = {0};
    msg.type = NET_MESSAGE;
    at_strlcpy(msg.info.net_msg.process, "reputation", sizeof(msg.info.net_msg.process));
    msg.info.net_msg.function = REP_PROTO_LOCAL_QUERY;
    if (net_msg_pack_json(&msg.info.net_msg, query) == 0)
        (void)at_send(proc, "reputation", &msg, "a reputation query", "reputation",
                      0, NULL, NULL, 0);
    json_decref(query);
    net_msg_free_obj(&msg.info.net_msg);
}

/* PASS/REFUSE from the cache, or PENDING after asking. */
static fleet_gate_t _reputation(const process_t *proc, const uuid_t uuid, double bar,
                                double *score_out)
{
    time_t now = time(NULL);
    bool ask = false;
    fleet_gate_t verdict = FLEET_GATE_PENDING;
    _lock();
    rep_entry_t *e = _rep_entry(uuid, false);
    if (e != NULL && !e->asked && now - e->at <= FLEET_GATE_REP_TTL_SEC) {
        *score_out = e->found ? e->score : 0.0;
        verdict = (e->found && fleet_check_reputation_threshold(e->score, bar))
                  ? FLEET_GATE_PASS : FLEET_GATE_REFUSE;
    } else {
        /* Asked and not answered: ask again once the answer is overdue. */
        e = _rep_entry(uuid, true);
        ask = !e->asked || now - e->at > FLEET_GATE_REP_TTL_SEC;
        if (ask) {
            e->asked = true;
            e->at = now;
        }
    }
    _unlock();
    if (ask)
        _ask_reputation(proc, uuid);
    return verdict;
}

/* -- the proposer -------------------------------------------------------- */

fleet_gate_t fleet_gate_proposer(const process_t *proc, const uuid_t signer,
                                 fleet_gate_verify_fn verify, const void *prop,
                                 char *why, size_t why_len)
{
    char u[UUID_STRING_LEN + 1];
    uuid_unparse_lower(signer, u);
    uint8_t pk[crypto_sign_PUBLICKEYBYTES];
    bool bound = false;
    if (!fleet_gate_member(proc, signer, pk, &bound)) {
        snprintf(why, why_len, "signer %.8s is not a member of our group", u);
        return FLEET_GATE_REFUSE;
    }
    if (verify(prop, pk) != 0) {
        snprintf(why, why_len, "the signature does not verify under the key we hold "
                 "for %.8s", u);
        return FLEET_GATE_REFUSE;
    }
    if (!bound) {
        snprintf(why, why_len, "signer %.8s is not operator-bound", u);
        return FLEET_GATE_REFUSE;
    }
    /* A node holds no reputation for itself: the others judge its proposal. */
    if (fleet_gate_is_self(proc, signer))
        return FLEET_GATE_PASS;
    double bar = fleet_gate_min_reputation();
    double score = 0.0;
    fleet_gate_t verdict = _reputation(proc, signer, bar, &score);
    if (verdict == FLEET_GATE_REFUSE)
        snprintf(why, why_len, "signer %.8s has reputation %.3f, below our bar %.3f", u,
                 score, bar);
    else if (verdict == FLEET_GATE_PENDING)
        snprintf(why, why_len, "waiting for the reputation of %.8s", u);
    return verdict;
}

/* -- grants -------------------------------------------------------------- */

static void _put_be64(uint8_t *out, int64_t v)
{
    uint64_t u = (uint64_t)v;
    for (int i = 7; i >= 0; i--) {
        out[i] = (uint8_t)(u & 0xff);
        u >>= 8;
    }
}

size_t fleet_gate_grant_signable(const char *kind, const uuid_t proposal_uuid,
                                 int64_t id1, int64_t id2,
                                 const uint8_t hash[32], uint8_t *buf, size_t len)
{
    static const char tag[] = "at-fleet-grant-v1";
    size_t klen = strlen(kind);
    size_t need = sizeof(tag) + klen + 1 + sizeof(uuid_t) + 16 + 32;
    if (len < need)
        return 0;
    size_t off = 0;
    memcpy(buf + off, tag, sizeof(tag));            /* includes the NUL */
    off += sizeof(tag);
    memcpy(buf + off, kind, klen + 1);
    off += klen + 1;
    memcpy(buf + off, proposal_uuid, sizeof(uuid_t));
    off += sizeof(uuid_t);
    _put_be64(buf + off, id1);
    off += 8;
    _put_be64(buf + off, id2);
    off += 8;
    memcpy(buf + off, hash, 32);
    off += 32;
    return off;
}

json_t *fleet_gate_sign_grant(const process_t *proc, const char *kind,
                              const uuid_t proposal_uuid, int64_t id1, int64_t id2,
                              const uint8_t hash[32])
{
    const identity_t *self = identity_self_identity(proc);
    if (self == NULL)
        return NULL;
    uint8_t msg[128];
    size_t n = fleet_gate_grant_signable(kind, proposal_uuid, id1, id2, hash, msg,
                                         sizeof(msg));
    uint8_t sig[crypto_sign_BYTES];
    if (n == 0 || crypto_sign_detached(sig, NULL, msg, n, self->signature.private) != 0)
        return NULL;
    char sig_hex[crypto_sign_BYTES * 2 + 1];
    sodium_bin2hex(sig_hex, sizeof(sig_hex), sig, sizeof(sig));
    char granter[UUID_STRING_LEN + 1], prop[UUID_STRING_LEN + 1];
    uuid_unparse_lower(self->uuid, granter);
    uuid_unparse_lower(proposal_uuid, prop);
    return json_pack("{s:s, s:I, s:I, s:s, s:s}", "granter", granter, "id1",
                     (json_int_t)id1, "id2", (json_int_t)id2, "proposal_uuid", prop,
                     "signature", sig_hex);
}

bool fleet_gate_grant_valid(const process_t *proc, const json_t *grant,
                            const char *kind, const uuid_t proposal_uuid,
                            int64_t id1, int64_t id2, const uint8_t hash[32],
                            uuid_t granter_out)
{
    if (!json_is_object(grant))
        return false;
    const char *granter = json_string_value(json_object_get(grant, "granter"));
    const char *prop = json_string_value(json_object_get(grant, "proposal_uuid"));
    const char *sig_hex = json_string_value(json_object_get(grant, "signature"));
    json_t *j1 = json_object_get(grant, "id1"), *j2 = json_object_get(grant, "id2");
    uuid_t g, p;
    if (granter == NULL || prop == NULL || sig_hex == NULL || !json_is_integer(j1)
        || !json_is_integer(j2) || uuid_parse(granter, g) != 0 || uuid_parse(prop, p) != 0
        || uuid_compare(p, proposal_uuid) != 0 || json_integer_value(j1) != id1
        || json_integer_value(j2) != id2)
        return false;
    uint8_t sig[crypto_sign_BYTES];
    size_t sig_len = 0;
    if (strlen(sig_hex) != 2 * crypto_sign_BYTES
        || sodium_hex2bin(sig, sizeof(sig), sig_hex, strlen(sig_hex), NULL, &sig_len,
                          NULL) != 0 || sig_len != sizeof(sig))
        return false;
    uint8_t pk[crypto_sign_PUBLICKEYBYTES];
    if (!fleet_gate_member(proc, g, pk, NULL))
        return false;
    uint8_t msg[128];
    size_t n = fleet_gate_grant_signable(kind, proposal_uuid, id1, id2, hash, msg,
                                         sizeof(msg));
    if (n == 0 || crypto_sign_verify_detached(sig, msg, n, pk) != 0)
        return false;
    uuid_copy(granter_out, g);
    return true;
}

size_t fleet_gate_count_grants(const process_t *proc, const json_t *grants,
                               const char *kind, const uuid_t proposal_uuid,
                               const uuid_t proposer, int64_t id1, int64_t id2,
                               const uint8_t hash[32])
{
    if (!json_is_array(grants))
        return 0;
    size_t n = json_array_size(grants);
    uuid_t *seen = calloc(n > 0 ? n : 1, sizeof(uuid_t));
    if (seen == NULL)
        return 0;
    size_t count = 0;
    for (size_t i = 0; i < n; i++) {
        uuid_t g;
        if (!fleet_gate_grant_valid(proc, json_array_get(grants, i), kind, proposal_uuid,
                                    id1, id2, hash, g)
            || uuid_compare(g, proposer) == 0)
            continue;
        bool dup = false;
        for (size_t k = 0; k < count && !dup; k++)
            dup = uuid_compare(seen[k], g) == 0;
        if (!dup)
            uuid_copy(seen[count++], g);
    }
    free(seen);
    return count;
}

/* -- held messages ------------------------------------------------------- */

void fleet_gate_hold(const process_t *proc, const generic_msg_t *msg,
                     fleet_gate_handler_fn handler)
{
    generic_msg_t copy;
    if (!identity_copy_held_message(msg, &copy)) {
        log_warn(proc->logger, "%s: could not hold a message for a reputation "
                 "answer (out of memory); it is lost\n", proc->name);
        return;
    }
    _lock();
    if (gate.num_held == FLEET_GATE_HELD) {
        _unlock();
        log_warn(proc->logger, "%s: %d messages already wait for a reputation "
                 "answer; one more is dropped\n", proc->name, FLEET_GATE_HELD);
        messaging_recv_release(&copy);
        return;
    }
    gate.held[gate.num_held].msg = copy;
    gate.held[gate.num_held].handler = handler;
    gate.num_held++;
    _unlock();
}

size_t fleet_gate_held(void)
{
    _lock();
    size_t n = gate.num_held;
    _unlock();
    return n;
}

bool fleet_gate_handle_rep_reply(const process_t *proc, directory_t *queues,
                                 generic_msg_t *msg)
{
    /* Local IPC only: a peer must not state reputations for us. */
    if (!uuid_is_null(msg->info.net_msg.from_whom.uuid))
        return true;
    json_t *body = NULL;
    if (net_msg_unpack_json(&msg->info.net_msg, &body) != 0 || body == NULL)
        return true;
    const char *u = json_string_value(json_object_get(body, "peer_uuid"));
    uuid_t uuid;
    if (u != NULL && uuid_parse(u, uuid) == 0)
        fleet_gate_set_reputation(uuid, json_number_value(json_object_get(body, "score")),
                                  json_is_true(json_object_get(body, "found")));
    json_decref(body);

    /* Run what was waiting. A message still waiting is held again by its
     * handler. */
    _lock();
    size_t n = gate.num_held;
    held_t *batch = NULL;
    if (n > 0 && (batch = malloc(n * sizeof(held_t))) != NULL) {
        memcpy(batch, gate.held, n * sizeof(held_t));
        gate.num_held = 0;
    }
    _unlock();
    if (batch == NULL)
        return true;
    for (size_t i = 0; i < n; i++) {
        (void)batch[i].handler(proc, queues, &batch[i].msg);
        messaging_recv_release(&batch[i].msg);
    }
    free(batch);
    return true;
}

void fleet_gate_reset(void)
{
    _lock();
    for (size_t i = 0; i < gate.num_held; i++)
        messaging_recv_release(&gate.held[i].msg);
    gate.num_held = 0;
    gate.num_rep = 0;
    gate.bar = -1.0;
    _unlock();
}
