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

/* Live replication, the requestor's side (RD_12.6_LIVE_REPLICATION_PLAN.md
 * sections 3.3-3.7). The C twin of Python `replication/live.py`.
 *
 * Through the negotiation result hook (negotiation/neg_ext.h): when a result
 * of a replayable capability arrives, draw once against the declared
 * probability; a sampled result's score is held while one other capable
 * peer, drawn uniformly, runs the same task as a replica. Agreement
 * corroborates both. Disagreement between two committed traces goes to the
 * bisection game, settled by re-executing one step with this node's own step
 * contract; anything else is released to the ordinary arms. A held score is
 * released by the hold deadline, twice the commit timeout from the draw.
 *
 * The hook decides under the negotiation lock and acts from its periodic
 * pass, so where Python starts the replica at once, this starts it on the
 * next pass. */

#include "at_replication.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <time.h>

#include <jansson.h>
#include <sodium.h>
#include <uuid/uuid.h>

#include "negotiation/neg_certified.h"   /* at_cert_verifier_seed */
#include "negotiation/neg_ext.h"
#include "negotiation/neg_replay.h"
#include "negotiation/negotiation.h"     /* NEG_PROTO_REPLAY_* */
#include "utilities/msg_types_priv.h"      /* net_msg_unpack_json */
#include "processes/capabilities.h"      /* find_capability */
#include "processes/extension.h"
#include "replication/adjudication.h"
#include "replication/bisection.h"
#include "replication/replication.h"
#include "replication/sampling.h"
#include "utilities/util.h"              /* at_strlcpy */

#define REPL_GROUPS_MAX 8
#define REPL_TOMBSTONES 64
#define REPL_TEXT_MAX   (CAP_RESULT_LEN * 4 + 1)

enum { PH_FREE = 0, PH_DISPATCH, PH_REPLICA, PH_ADJUDICATE, PH_CHALLENGE,
       PH_REVEAL };

typedef struct {
    bool   have;
    bool   arrived;     /* its result is in */
    uuid_t task;
    uuid_t executor;
    char   result[REPL_TEXT_MAX];
    bool   has_result;
    char  *certificate_json;
    char  *prediction_json;
    char   root[AT_REPL_HASH_HEX_LEN + 1];
    int    len;
    /* the reveal at k, heap strings, NULL when absent */
    bool   revealed;
    char  *prev, *pre, *state;
    char   digest[AT_REPL_HASH_HEX_LEN + 1];
} repl_side_t;

typedef struct {
    int    phase;
    char   cap[CAP_NAMELEN + 1];
    char   kwargs_json[TASK_KWARGS_LEN];
    double issued_at;
    double deadline;
    repl_side_t side[2];
    at_repl_session_t session;
    int    round, index;
    bool   owed[2];
} repl_group_t;

static struct {
    pthread_mutex_t lock;
    bool model_loaded;
    at_replication_model_t model;
    repl_group_t groups[REPL_GROUPS_MAX];
    uuid_t tombstones[REPL_TOMBSTONES];
    int next_tomb;
} R = { .lock = PTHREAD_MUTEX_INITIALIZER };

static double _now(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (double)ts.tv_sec + (double)ts.tv_nsec / 1e9;
}

/* Twice the commit timeout, read as the reputation process reads it. */
static double _hold_seconds(void)
{
    const char *raw = getenv("AT_REP_COMMIT_TIMEOUT_SEC");
    double commit = raw != NULL && raw[0] != '\0' ? atof(raw) : 15.0;
    return 2.0 * (commit > 0.0 ? commit : 15.0);
}

/* Caller holds R.lock. */
static const at_replication_model_t *_model_locked(void)
{
    if (!R.model_loaded)
    {
        char err[256] = {0};
        if (!at_replication_model_load_env(&R.model, err, sizeof(err)))
        {
            fprintf(stderr, "replication: declaration rejected, live replication "
                    "stays OFF: %s\n", err);
            at_replication_model_parse(NULL, &R.model, NULL, 0);
            R.model.default_prob = 0.0;
            R.model.num_caps = 0;
        }
        R.model_loaded = true;
    }
    return &R.model;
}

static void _side_free(repl_side_t *s)
{
    free(s->certificate_json);
    free(s->prediction_json);
    free(s->prev);
    free(s->pre);
    free(s->state);
    memset(s, 0, sizeof(*s));
}

/* Not _dup: the Windows CRT declares _dup(int) in io.h. */
static char *_str_dup(const char *s)
{
    return s != NULL ? strdup(s) : NULL;
}

static void _side_from(repl_side_t *s, const neg_result_info_t *info)
{
    _side_free(s);
    s->have = true;
    s->arrived = true;
    uuid_copy(s->task, info->task);
    uuid_copy(s->executor, info->executor);
    if (info->result != NULL)
    {
        size_t n = info->result_len < sizeof(s->result) - 1
            ? info->result_len : sizeof(s->result) - 1;
        memcpy(s->result, info->result, n);
        s->result[n] = '\0';
        s->has_result = true;
    }
    s->certificate_json = _str_dup(info->certificate_json);
    s->prediction_json = _str_dup(info->prediction_json);
    if (info->trace_root != NULL)
        at_strlcpy(s->root, info->trace_root, sizeof(s->root));
    s->len = info->trace_root != NULL ? info->trace_len : 0;
}

static void _info_of(const repl_group_t *g, const repl_side_t *s,
                     neg_result_info_t *info)
{
    memset(info, 0, sizeof(*info));
    info->task = s->task;
    info->executor = s->executor;
    info->capability = g->cap;
    info->kwargs_json = g->kwargs_json;
    info->issued_at = g->issued_at;
    info->result = s->has_result ? s->result : NULL;
    info->result_len = s->has_result ? strlen(s->result) : 0;
    info->certificate_json = s->certificate_json;
    info->prediction_json = s->prediction_json;
}

/* Caller holds R.lock. */
static void _tomb(const uuid_t task)
{
    uuid_copy(R.tombstones[R.next_tomb], task);
    R.next_tomb = (R.next_tomb + 1) % REPL_TOMBSTONES;
}

static bool _tombed(const uuid_t task)
{
    for (int i = 0; i < REPL_TOMBSTONES; i++)
        if (!uuid_is_null(R.tombstones[i]) && uuid_compare(R.tombstones[i], task) == 0)
            return true;
    return false;
}

static void _free_group_locked(repl_group_t *g)
{
    for (int i = 0; i < 2; i++)
    {
        if (g->side[i].have)
            _tomb(g->side[i].task);
        _side_free(&g->side[i]);
    }
    memset(g, 0, sizeof(*g));
}

/* ---- the hook ----------------------------------------------------------- */

static neg_result_verdict_t _on_result(const process_t *proc,
                                       const neg_result_info_t *info)
{
    (void)proc;
    neg_result_verdict_t out = NEG_RESULT_LEAVE;
    pthread_mutex_lock(&R.lock);
    for (int i = 0; i < REPL_GROUPS_MAX; i++)
    {
        repl_group_t *g = &R.groups[i];
        if (g->phase == PH_REPLICA && g->side[1].have
            && uuid_compare(g->side[1].task, info->task) == 0)
        {
            _side_from(&g->side[1], info);
            g->phase = PH_ADJUDICATE;
            out = NEG_RESULT_CONSUME;
            goto done;
        }
    }
    if (_tombed(info->task))
    {
        out = NEG_RESULT_CONSUME;      /* a late replica result */
        goto done;
    }
    {
        const at_replication_model_t *m = _model_locked();
        double prob = at_replication_live_prob_for(m, info->capability);
        if (prob <= 0.0 || !at_replication_should_replicate(prob, at_cert_verifier_seed(), NULL))
            goto done;
        for (int i = 0; i < REPL_GROUPS_MAX; i++)
        {
            repl_group_t *g = &R.groups[i];
            if (g->phase != PH_FREE)
                continue;
            memset(g, 0, sizeof(*g));
            g->phase = PH_DISPATCH;
            at_strlcpy(g->cap, info->capability, sizeof(g->cap));
            if (info->kwargs_json != NULL)
                at_strlcpy(g->kwargs_json, info->kwargs_json, sizeof(g->kwargs_json));
            g->issued_at = info->issued_at;
            g->deadline = _now() + _hold_seconds();
            _side_from(&g->side[0], info);
            out = NEG_RESULT_HOLD;
            break;
        }
    }
done:
    pthread_mutex_unlock(&R.lock);
    return out;
}

/* ---- acting (unlocked by the negotiation process) ------------------------ */

static void _hex_digest(const char *text, char out[AT_REPL_HASH_HEX_LEN + 1])
{
    unsigned char d[32];
    crypto_generichash(d, sizeof(d), (const unsigned char *)text, strlen(text), NULL, 0);
    sodium_bin2hex(out, AT_REPL_HASH_HEX_LEN + 1, d, sizeof(d));
}

/* Release side @p i of @p g with @p verdict (or for the ordinary arms when
 * @p have_verdict is false), and propose an attestation for an OUTVOTED one.
 * Caller holds R.lock; the group stays intact until the caller frees it. */
static void _release_side_locked(const process_t *proc, repl_group_t *g, int i,
                                 bool have_verdict, at_repl_verdict_t verdict)
{
    repl_side_t *s = &g->side[i];
    if (!s->have || !s->arrived)
        return;
    neg_result_info_t info;
    _info_of(g, s, &info);
    double score = 0.0;
    const char *channel = NULL;
    bool scored = have_verdict && at_replication_verify(verdict, &score, &channel);
    negotiation_release_held(proc, &info, scored, score, channel);
    if (scored && verdict == AT_REPL_OUTVOTED)
    {
        char task[UUID_STRING_LEN + 1];
        uuid_unparse_lower(s->task, task);
        int k = at_repl_session_divergence(&g->session);
        const char *claimed = k >= 0 && g->session.have[i][k] ? g->session.digests[i][k]
            : s->root;
        /* "AT-REPLICATION\0task|k|claimed|cap", as Python's _attest: the
         * NUL separator means hashing bytes, not a C string. */
        static const char tag[] = "AT-REPLICATION";
        char text[sizeof(tag) + 256];
        memcpy(text, tag, sizeof(tag));          /* with its NUL */
        int n = k >= 0
            ? snprintf(text + sizeof(tag), sizeof(text) - sizeof(tag), "%s|%d|%s|%s",
                       task, k, claimed, g->cap)
            : snprintf(text + sizeof(tag), sizeof(text) - sizeof(tag), "%s||%s|%s",
                       task, claimed, g->cap);
        if (n < 0 || (size_t)n >= sizeof(text) - sizeof(tag))
            return;
        unsigned char d[32];
        crypto_generichash(d, sizeof(d), (const unsigned char *)text,
                           sizeof(tag) + (size_t)n, NULL, 0);
        char evidence[AT_REPL_HASH_HEX_LEN + 1], scope[AT_REPL_HASH_HEX_LEN + 1];
        sodium_bin2hex(evidence, sizeof(evidence), d, sizeof(d));
        _hex_digest(task, scope);
        negotiation_propose_attestation(proc, s->executor, score, channel, g->cap,
                                        evidence, scope);
    }
}

static const char *_truth_ctx_kwargs;
static int _truth_ctx_k;
static char _truth_buf[NEG_REPLAY_STATE_MAX + 1];

/* Re-execute step k with this node's own step contract (D3). */
static const char *_truth(const char *pre, void *ctx)
{
    const capability_replay_t *r = ctx;
    _truth_buf[0] = '\0';
    if (_truth_ctx_k == 0)
        return r->init(_truth_ctx_kwargs, _truth_buf, sizeof(_truth_buf)) == 0
            ? _truth_buf : NULL;
    if (pre == NULL)
        return NULL;
    return r->step(pre, _truth_ctx_k, _truth_buf, sizeof(_truth_buf)) == 1
        ? _truth_buf : NULL;
}

static const capability_replay_t *_local_replay(const char *cap)
{
    capability_t *c = find_capability(cap);
    return c != NULL ? c->replay : NULL;
}

/* Ask the next question, or the reveal once the session is done. Caller
 * holds R.lock (sending does not take the negotiation lock). */
static void _advance_locked(const process_t *proc, repl_group_t *g)
{
    int at = 0;
    bool owe[2] = {false, false};
    const char *verb;
    g->round++;
    if (at_repl_session_pending(&g->session, &at, owe))
    {
        g->phase = PH_CHALLENGE;
        g->index = at;
        verb = NEG_PROTO_REPLAY_CHALLENGE;
    }
    else
    {
        g->phase = PH_REVEAL;
        g->index = at_repl_session_divergence(&g->session);
        owe[0] = owe[1] = true;
        verb = NEG_PROTO_REPLAY_REVEAL;
    }
    for (int i = 0; i < 2; i++)
    {
        g->owed[i] = owe[i];
        if (!owe[i])
            continue;
        char task[UUID_STRING_LEN + 1], payload[160];
        uuid_unparse_lower(g->side[i].task, task);
        snprintf(payload, sizeof(payload), "{\"task\":\"%s\",\"round\":%d,\"index\":%d}",
                 task, g->round, g->index);
        (void)negotiation_send_replay(proc, verb, g->side[i].executor, payload);
    }
}

/* Two results in: agree, game, or the ordinary arms. Caller holds R.lock. */
static void _adjudicate_locked(const process_t *proc, repl_group_t *g)
{
    at_repl_result_t res[2];
    for (int i = 0; i < 2; i++)
    {
        memset(&res[i], 0, sizeof(res[i]));
        snprintf(res[i].peer, sizeof(res[i].peer), "%c", 'a' + i);
        const char *t = g->side[i].has_result ? g->side[i].result : "";
        char *end = NULL;
        double v = strtod(t, &end);
        res[i].is_number = t[0] != '\0' && end != NULL && *end == '\0';
        res[i].num = v;
        at_strlcpy(res[i].text, t, sizeof(res[i].text));
    }
    at_repl_verdict_t v[2];
    at_replication_adjudicate(res, 2, at_replication_tolerance_for(&R.model, g->cap), v);
    if (v[0] == AT_REPL_CORROBORATED && v[1] == AT_REPL_CORROBORATED)
    {
        _release_side_locked(proc, g, 0, true, AT_REPL_CORROBORATED);
        _release_side_locked(proc, g, 1, true, AT_REPL_CORROBORATED);
        _free_group_locked(g);
        return;
    }
    const capability_replay_t *replay = _local_replay(g->cap);
    if (v[0] == AT_REPL_DISPUTE && replay != NULL && g->side[0].len > 0
        && g->side[1].len > 0
        && at_repl_session_init(&g->session, g->side[0].len, g->side[0].root,
                                g->side[1].len, g->side[1].root)
        && g->session.disputed)
    {
        _advance_locked(proc, g);
        return;
    }
    /* No commitment, no step contract, or results that differ over agreeing
     * traces: the ordinary arms score both. */
    _release_side_locked(proc, g, 0, false, AT_REPL_DISPUTE);
    _release_side_locked(proc, g, 1, false, AT_REPL_DISPUTE);
    _free_group_locked(g);
}

static void _settle_game_locked(const process_t *proc, repl_group_t *g)
{
    int max_bytes = 4096;
    (void)at_replication_replay_for(&R.model, g->cap, NULL, &max_bytes);
    at_repl_reveal_t rv[2];
    for (int i = 0; i < 2; i++)
    {
        rv[i].prev = g->side[i].prev;
        rv[i].pre = g->side[i].pre;
        rv[i].state = g->side[i].state;
    }
    const capability_replay_t *replay = _local_replay(g->cap);
    _truth_ctx_kwargs = g->kwargs_json;
    _truth_ctx_k = g->index;
    at_repl_verdict_t v[2];
    if (replay == NULL
        || !at_repl_settle(&g->session, rv, _truth, (void *)replay,
                           (size_t)max_bytes, v))
    {
        _release_side_locked(proc, g, 0, false, AT_REPL_DISPUTE);
        _release_side_locked(proc, g, 1, false, AT_REPL_DISPUTE);
    }
    else
    {
        _release_side_locked(proc, g, 0, true, v[0]);
        _release_side_locked(proc, g, 1, true, v[1]);
    }
    _free_group_locked(g);
}

/* One side went quiet mid-game (D10): re-run the whole computation and
 * settle the side that answered alone; the silent side is not scored. */
static void _settle_silence_locked(const process_t *proc, repl_group_t *g, int live)
{
    const capability_replay_t *replay = _local_replay(g->cap);
    if (replay != NULL)
    {
        neg_trace_t t = {0};
        char result[CAP_RESULT_LEN + 1];
        char root[NEG_REPLAY_HASH_HEX_LEN + 1] = {0};
        if (neg_replay_run(replay, g->kwargs_json, &t, result, sizeof(result)) == 0
            && neg_trace_digest(&t, t.n - 1, root))
        {
            bool ok = t.n == g->side[live].len && strcmp(root, g->side[live].root) == 0;
            _release_side_locked(proc, g, live, true,
                                 ok ? AT_REPL_CORROBORATED : AT_REPL_OUTVOTED);
        }
        else
            _release_side_locked(proc, g, live, false, AT_REPL_DISPUTE);
        neg_trace_free(&t);
    }
    else
        _release_side_locked(proc, g, live, false, AT_REPL_DISPUTE);
    _free_group_locked(g);
}

/* Both this and the result hook run on the negotiation loop's one thread,
 * so holding R.lock while the core takes its own state lock (and the hook
 * taking R.lock under that one) cannot cross. */
static void _periodic(const process_t *proc)
{
    double now = _now();
    pthread_mutex_lock(&R.lock);
    for (int gi = 0; gi < REPL_GROUPS_MAX; gi++)
    {
        repl_group_t *g = &R.groups[gi];
        switch (g->phase)
        {
        case PH_DISPATCH:
        {
            uuid_t task, peer;
            if (negotiation_start_replica(proc, g->cap, g->kwargs_json,
                                          g->side[0].executor, at_cert_verifier_seed(),
                                          task, peer) == 0)
            {
                memset(&g->side[1], 0, sizeof(g->side[1]));
                g->side[1].have = true;
                uuid_copy(g->side[1].task, task);
                uuid_copy(g->side[1].executor, peer);
                g->phase = PH_REPLICA;
            }
            else
            {
                /* No replica peer: nothing is held. */
                _release_side_locked(proc, g, 0, false, AT_REPL_DISPUTE);
                _free_group_locked(g);
            }
            break;
        }
        case PH_ADJUDICATE:
            _adjudicate_locked(proc, g);
            break;
        case PH_REPLICA:
            if (now >= g->deadline)
            {
                _release_side_locked(proc, g, 0, false, AT_REPL_DISPUTE);
                _free_group_locked(g);
            }
            break;
        case PH_CHALLENGE:
        case PH_REVEAL:
            if (now >= g->deadline)
            {
                if (g->owed[0] != g->owed[1])
                    _settle_silence_locked(proc, g, g->owed[0] ? 1 : 0);
                else
                {
                    _release_side_locked(proc, g, 0, false, AT_REPL_DISPUTE);
                    _release_side_locked(proc, g, 1, false, AT_REPL_DISPUTE);
                    _free_group_locked(g);
                }
            }
            break;
        default:
            break;
        }
    }
    pthread_mutex_unlock(&R.lock);
}

/* An executor's answer to one of our challenges or reveals. */
static bool _handle_replay_response(const process_t *proc, directory_t *queues,
                                    generic_msg_t *msg)
{
    (void)queues;
    net_msg_t *nmsg = &msg->info.net_msg;
    json_t *j = NULL;
    if (!nmsg->verified || nmsg->obj == NULL || nmsg->len == 0
        || net_msg_unpack_json(nmsg, &j) != 0 || !json_is_object(j))
    {
        json_decref(j);
        return true;
    }
    const char *task = json_string_value(json_object_get(j, "task"));
    uuid_t tu;
    if (task == NULL || uuid_parse(task, tu) != 0)
    {
        json_decref(j);
        return true;
    }
    pthread_mutex_lock(&R.lock);
    for (int gi = 0; gi < REPL_GROUPS_MAX; gi++)
    {
        repl_group_t *g = &R.groups[gi];
        if (g->phase != PH_CHALLENGE && g->phase != PH_REVEAL)
            continue;
        int i = -1;
        for (int s = 0; s < 2; s++)
            if (g->side[s].have && uuid_compare(g->side[s].task, tu) == 0
                && uuid_compare(g->side[s].executor, nmsg->from_whom.uuid) == 0)
                i = s;
        if (i < 0)
            continue;
        if (!g->owed[i]
            || json_integer_value(json_object_get(j, "round")) != g->round
            || !json_is_integer(json_object_get(j, "index"))
            || json_integer_value(json_object_get(j, "index")) != g->index)
            break;
        if (g->phase == PH_CHALLENGE)
        {
            const char *d = json_string_value(json_object_get(j, "digest"));
            if (d == NULL)
                break;
            at_strlcpy(g->side[i].digest, d, sizeof(g->side[i].digest));
        }
        else
        {
            json_t *rv = json_object_get(j, "reveal");
            if (!json_is_object(rv))
                break;
            free(g->side[i].prev);
            free(g->side[i].pre);
            free(g->side[i].state);
            g->side[i].prev = _str_dup(json_string_value(json_object_get(rv, "prev")));
            g->side[i].pre = _str_dup(json_string_value(json_object_get(rv, "pre")));
            g->side[i].state = _str_dup(json_string_value(json_object_get(rv, "state")));
        }
        g->owed[i] = false;
        if (g->owed[0] || g->owed[1])
            break;
        if (g->phase == PH_CHALLENGE)
        {
            int at = 0;
            bool owe[2];
            (void)at_repl_session_pending(&g->session, &at, owe);
            if (!at_repl_session_answer(&g->session, g->index,
                                        owe[0] ? g->side[0].digest : NULL,
                                        owe[1] ? g->side[1].digest : NULL))
            {
                /* A malformed digest is no answer: the deadline decides. */
                for (int s = 0; s < 2; s++)
                    g->owed[s] = owe[s] && strlen(g->side[s].digest) != AT_REPL_HASH_HEX_LEN;
                break;
            }
            _advance_locked(proc, g);
        }
        else
            _settle_game_locked(proc, g);
        break;
    }
    pthread_mutex_unlock(&R.lock);
    json_decref(j);
    return true;
}

static void _reset(void)
{
    pthread_mutex_lock(&R.lock);
    for (int i = 0; i < REPL_GROUPS_MAX; i++)
    {
        _side_free(&R.groups[i].side[0]);
        _side_free(&R.groups[i].side[1]);
        memset(&R.groups[i], 0, sizeof(R.groups[i]));
    }
    memset(R.tombstones, 0, sizeof(R.tombstones));
    R.next_tomb = 0;
    R.model_loaded = false;
    pthread_mutex_unlock(&R.lock);
}

static int _register_handlers(process_t *proc, const char *proc_name)
{
    if (strcmp(proc_name, "negotiation") == 0)
        process_register_handler(proc, NEG_PROTO_REPLAY_RESPONSE,
                                 (handler_ptr_t)_handle_replay_response);
    return 0;
}

static const neg_result_hook_t replication_hook = {
    .name = "replication", .on_result = _on_result, .periodic = _periodic };
NEG_RESULT_HOOK_REGISTER(replication, &replication_hook)

static const at_extension_t replication_ext = {
    .name = "replication", .register_handlers = _register_handlers, .reset = _reset };
AT_EXTENSION_REGISTER(replication_live, &replication_ext)

void at_replication_live_link(void) {}
