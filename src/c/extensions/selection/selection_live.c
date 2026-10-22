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

/* Selective assignment in a running negotiation process: the C twin of Python
 * selection/hooks.py (RD_12.7_SELECTIVE_ASSIGNMENT_PLAN.md sections 0, 3).
 *
 * Through the selection hook (negotiation/neg_ext.h): the requestor draws a
 * task's invitees or a probe's target, re-draws after a decline, and joins
 * every scored result into its log; the peer checks the coin on every
 * invitation it admits and audits the draws an index gap shows it was not
 * shown. The hooks run under the negotiation lock, so audit queries are
 * queued and sent from the periodic pass. Every finding is logged and
 * counted per requestor, and nothing else happens (section 0.2).
 *
 * State is per negotiation process, because the conformance runner hosts
 * several nodes in one program. */

#include "at_selection.h"

#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <jansson.h>
#include <uuid/uuid.h>

#include "bootstrap/bootstrap_capabilities.h"
#include "config/configuration.h"
#include "negotiation/neg_ext.h"
#include "processes/extension.h"
#include "selection/selection.h"
#include "utilities/msg_types_priv.h"      /* net_msg_unpack_json */
#include "utilities/util.h"

#define SEL_PROCS_MAX 16
#define SEL_PENDING_MAX 64
#define SEL_FINDINGS_MAX 64
#define ESTIMATE_SECONDS 300.0

typedef struct {
    unsigned char peer[16];
    long index;
} sel_query_t;

typedef struct {
    char requestor[37];
    char reason[32];
    long count;
} sel_finding_t;

typedef struct {
    const process_t   *proc;
    bool               have_req;
    at_sel_requestor_t req;
    at_sel_peer_t      peer;
    sel_query_t        pending[SEL_PENDING_MAX];
    size_t             n_pending;
    sel_finding_t      findings[SEL_FINDINGS_MAX];
    size_t             n_findings;
    double             estimated_at;
    /* conformance: a fixed model, root and directory instead of the env's */
    bool               configured;
    at_selection_model_t model;
    unsigned char      root[AT_SEL_LINK_BYTES];
    char               cfg_dir[512];
} sel_proc_t;

static struct {
    pthread_mutex_t lock;
    sel_proc_t procs[SEL_PROCS_MAX];
    bool model_loaded;
    at_selection_model_t model;
} S = { .lock = PTHREAD_MUTEX_INITIALIZER };

static double _now(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (double)ts.tv_sec + (double)ts.tv_nsec / 1e9;
}

static const at_selection_model_t *_env_model_locked(void)
{
    if (!S.model_loaded)
    {
        char err[256] = {0};
        if (!at_selection_load_env(&S.model, err, sizeof(err)))
        {
            fprintf(stderr, "selection: $AT_SELECTION: %s; selecting nothing\n", err);
            at_selection_parse(NULL, &S.model, NULL, 0);
        }
        S.model_loaded = true;
    }
    return &S.model;
}

static sel_proc_t *_proc_locked(const process_t *proc, bool create)
{
    sel_proc_t *free_slot = NULL;
    for (int i = 0; i < SEL_PROCS_MAX; i++)
    {
        if (S.procs[i].proc == proc)
            return &S.procs[i];
        if (S.procs[i].proc == NULL && free_slot == NULL)
            free_slot = &S.procs[i];
    }
    if (!create || free_slot == NULL)
        return NULL;
    memset(free_slot, 0, sizeof(*free_slot));
    free_slot->proc = proc;
    return free_slot;
}

static const at_selection_model_t *_model_of(const sel_proc_t *sp)
{
    return sp != NULL && sp->configured ? &sp->model : _env_model_locked();
}

static at_sel_requestor_t *_requestor_locked(sel_proc_t *sp)
{
    if (sp->have_req)
        return &sp->req;
    char dir[512] = {0};
    if (sp->configured)
        at_strlcpy(dir, sp->cfg_dir, sizeof(dir));
    else if (get_cfg_dir(dir, sizeof(dir)) < 0)
        return NULL;
    if (at_sel_requestor_open(&sp->req, _model_of(sp), "negotiation", dir,
                              sp->configured ? sp->root : NULL) != 0)
        return NULL;
    sp->have_req = true;
    return &sp->req;
}

static void _finding_locked(sel_proc_t *sp, const char *requestor, const char *reason)
{
    fprintf(stderr, "selection: requestor %.8s, draw finding: %s\n", requestor, reason);
    for (size_t i = 0; i < sp->n_findings; i++)
        if (strcmp(sp->findings[i].requestor, requestor) == 0
            && strcmp(sp->findings[i].reason, reason) == 0)
        {
            sp->findings[i].count++;
            return;
        }
    if (sp->n_findings == SEL_FINDINGS_MAX)
        return;
    sel_finding_t *f = &sp->findings[sp->n_findings++];
    at_strlcpy(f->requestor, requestor, sizeof(f->requestor));
    at_strlcpy(f->reason, reason, sizeof(f->reason));
    f->count = 1;
}

static bool _is_probe_cap(const char *cap)
{
    for (int i = 0; i < BOOTSTRAP_CAPABILITY_COUNT; i++)
        if (strcmp(BOOTSTRAP_CAPABILITY_NAMES[i], cap) == 0)
            return true;
    return false;
}

/* 'p' probe, 't' task, 0 not drawn. Mirrors Python hooks._purpose. */
static char _purpose(const at_selection_model_t *m, const char *cap, bool addressed)
{
    if (!m->declared)
        return 0;
    if (addressed)
        return _is_probe_cap(cap) && m->has_probe ? 'p' : 0;
    if (_is_probe_cap(cap))
        return 0;
    return at_selection_selects(m, cap) ? 't' : 0;
}

static int _by_uuid(const void *a, const void *b)
{
    return strcmp((const char *)a, (const char *)b);
}

/* Sort the candidates by uuid string, draw among them, and map the choice
 * back to the core's order. */
static bool _decide_locked(sel_proc_t *sp, const char *task, const char *cap, char purpose,
                           const neg_candidates_t *cands, const bool *exclude,
                           long redraw_of, int k, double floor, bool *selected,
                           char *draw_json, size_t draw_len)
{
    at_sel_requestor_t *r = _requestor_locked(sp);
    if (r == NULL)
        return false;
    size_t n = 0;
    typedef struct { char uuid[37]; size_t at; } ent_t;
    ent_t *ents = calloc(cands->n ? cands->n : 1, sizeof(*ents));
    char (*uuids)[37] = calloc(cands->n ? cands->n : 1, sizeof(*uuids));
    double *w = calloc(cands->n ? cands->n : 1, sizeof(*w));
    bool *sel = calloc(cands->n ? cands->n : 1, sizeof(*sel));
    bool ok = false;
    if (ents == NULL || uuids == NULL || w == NULL || sel == NULL)
        goto out;
    for (size_t i = 0; i < cands->n; i++)
    {
        if (exclude != NULL && exclude[i])
            continue;
        uuid_unparse_lower(cands->uuid[i], ents[n].uuid);
        ents[n++].at = i;
    }
    if (n == 0)
        goto out;
    qsort(ents, n, sizeof(*ents), _by_uuid);
    long total = r->probe_total;
    for (size_t i = 0; i < n; i++)
    {
        at_strlcpy(uuids[i], ents[i].uuid, sizeof(uuids[i]));
        w[i] = purpose == 'p' ? at_sel_ucb_bonus(at_sel_probe_count(r, uuids[i]), total)
                              : 1.0 + (double)cands->tier[ents[i].at];
    }
    if (at_sel_decide(r, task, cap, uuids, w, n, k, floor, purpose == 'p', redraw_of,
                      sel, draw_json, draw_len) != 0)
        goto out;
    for (size_t i = 0; i < cands->n; i++)
        selected[i] = false;
    for (size_t i = 0; i < n; i++)
        selected[ents[i].at] = sel[i];
    ok = true;
out:
    free(ents);
    free(uuids);
    free(w);
    free(sel);
    return ok;
}

/* ---- requestor side ------------------------------------------------------- */

static bool _select(const process_t *proc, const char *task_uuid, const char *capability,
                    const neg_candidates_t *cands, const unsigned char *target,
                    bool *selected, char *draw_json, size_t draw_len)
{
    pthread_mutex_lock(&S.lock);
    sel_proc_t *sp = _proc_locked(proc, true);
    const at_selection_model_t *m = _model_of(sp);
    char purpose = _purpose(m, capability, target != NULL);
    bool ok = false;
    if (sp != NULL && purpose != 0)
    {
        const at_sel_policy_t *pol = at_selection_policy_for(m, capability);
        ok = _decide_locked(sp, task_uuid, capability, purpose, cands, NULL, 0,
                            purpose == 'p' ? 1 : pol->k,
                            purpose == 'p' ? m->probe_floor : pol->floor,
                            selected, draw_json, draw_len);
    }
    pthread_mutex_unlock(&S.lock);
    return ok;
}

static bool _on_decline(const process_t *proc, const char *task_uuid, const char *capability,
                        const unsigned char *peer, const neg_candidates_t *cands,
                        bool *selected, char *draw_json, size_t draw_len)
{
    pthread_mutex_lock(&S.lock);
    bool ok = false;
    sel_proc_t *sp = _proc_locked(proc, false);
    const at_selection_model_t *m = _model_of(sp);
    at_sel_requestor_t *r = sp != NULL && m->declared ? _requestor_locked(sp) : NULL;
    char who[37];
    uuid_unparse_lower(peer, who);
    at_sel_record_t *rec = r != NULL ? at_sel_record_decline(r, task_uuid, who) : NULL;
    bool *exclude = rec != NULL ? calloc(cands->n ? cands->n : 1, sizeof(*exclude)) : NULL;
    if (exclude != NULL)
    {
        for (size_t i = 0; i < cands->n; i++)
        {
            char u[37];
            uuid_unparse_lower(cands->uuid[i], u);
            exclude[i] = at_sel_asked(r, task_uuid, u);
        }
        bool probe = rec->probe;
        long redraw_of = rec->index;
        double floor = probe ? m->probe_floor : at_selection_policy_for(m, capability)->floor;
        ok = _decide_locked(sp, task_uuid, capability, probe ? 'p' : 't', cands, exclude,
                            redraw_of, 1, floor, selected, draw_json, draw_len);
        free(exclude);
    }
    pthread_mutex_unlock(&S.lock);
    return ok;
}

static void _on_score(const process_t *proc, const char *task_uuid,
                      const unsigned char *executor, double score)
{
    pthread_mutex_lock(&S.lock);
    sel_proc_t *sp = _proc_locked(proc, false);
    if (sp != NULL && sp->have_req)
    {
        char who[37];
        uuid_unparse_lower(executor, who);
        (void)at_sel_record_outcome(&sp->req, task_uuid, who, score);
    }
    pthread_mutex_unlock(&S.lock);
}

/* ---- peer side --------------------------------------------------------------- */

static void _on_invitation(const process_t *proc, const unsigned char *requestor,
                           const char *draw_json)
{
    json_error_t jerr;
    json_t *draw = json_loads(draw_json, 0, &jerr);
    char who[37];
    uuid_unparse_lower(requestor, who);
    long gap[AT_SEL_AUDIT_MAX_PER_GAP];
    size_t n_gap = 0;
    pthread_mutex_lock(&S.lock);
    sel_proc_t *sp = _proc_locked(proc, true);
    if (sp != NULL)
    {
        const char *finding = draw != NULL ? at_sel_check_draw(&sp->peer, who, draw, gap, &n_gap)
                                           : "malformed";
        if (finding != NULL)
            _finding_locked(sp, who, finding);
        for (size_t i = 0; i < n_gap && sp->n_pending < SEL_PENDING_MAX; i++)
        {
            memcpy(sp->pending[sp->n_pending].peer, requestor, 16);
            sp->pending[sp->n_pending++].index = gap[i];
        }
    }
    pthread_mutex_unlock(&S.lock);
    json_decref(draw);
}

/* ---- the audit verbs ------------------------------------------------------------ */

static bool _handle_audit_query(const process_t *proc, directory_t *queues, generic_msg_t *msg)
{
    (void)queues;
    net_msg_t *nmsg = &msg->info.net_msg;
    if (!nmsg->verified)
        return true;
    json_t *j = NULL;
    if (nmsg->obj == NULL || nmsg->len == 0 || net_msg_unpack_json(nmsg, &j) != 0
        || !json_is_object(j) || !json_is_integer(json_object_get(j, "index")))
    {
        json_decref(j);
        return true;
    }
    long index = (long)json_integer_value(json_object_get(j, "index"));
    json_decref(j);
    char asker[37];
    uuid_unparse_lower(nmsg->from_whom.uuid, asker);
    pthread_mutex_lock(&S.lock);
    sel_proc_t *sp = _proc_locked(proc, true);
    at_sel_requestor_t *r = NULL;
    if (sp != NULL && (sp->have_req || _model_of(sp)->declared))
        r = _requestor_locked(sp);
    json_t *answer = r != NULL ? at_sel_audit_answer(r, index, asker)
                               : json_pack("{s:I, s:s}", "index", (json_int_t)index,
                                           "status", "unknown");
    pthread_mutex_unlock(&S.lock);
    char *text = json_dumps(answer, JSON_COMPACT | JSON_SORT_KEYS);
    json_decref(answer);
    if (text != NULL)
        (void)negotiation_send_replay(proc, AT_SEL_AUDIT_REPLY, nmsg->from_whom.uuid, text);
    free(text);
    return true;
}

static bool _handle_audit_reply(const process_t *proc, directory_t *queues, generic_msg_t *msg)
{
    (void)queues;
    net_msg_t *nmsg = &msg->info.net_msg;
    if (!nmsg->verified)
        return true;
    json_t *j = NULL;
    if (nmsg->obj == NULL || nmsg->len == 0 || net_msg_unpack_json(nmsg, &j) != 0
        || !json_is_object(j))
    {
        json_decref(j);
        return true;
    }
    char who[37];
    uuid_unparse_lower(nmsg->from_whom.uuid, who);
    pthread_mutex_lock(&S.lock);
    sel_proc_t *sp = _proc_locked(proc, true);
    if (sp != NULL)
    {
        const char *finding = at_sel_check_answer(&sp->peer, who, j);
        if (finding != NULL)
            _finding_locked(sp, who, finding);
    }
    pthread_mutex_unlock(&S.lock);
    json_decref(j);
    return true;
}

static void _periodic(const process_t *proc)
{
    sel_query_t out[SEL_PENDING_MAX];
    size_t n_out = 0;
    pthread_mutex_lock(&S.lock);
    sel_proc_t *sp = _proc_locked(proc, false);
    if (sp != NULL)
    {
        memcpy(out, sp->pending, sp->n_pending * sizeof(*out));
        n_out = sp->n_pending;
        sp->n_pending = 0;
        if (sp->have_req)
        {
            at_sel_requestor_flush(&sp->req, false);
            double now = _now();
            if (now - sp->estimated_at >= ESTIMATE_SECONDS)
            {
                sp->estimated_at = now;
                json_t *est = at_sel_estimate(sp->req.records, sp->req.rec_n);
                const char *cap;
                json_t *e;
                json_object_foreach(est, cap, e)
                {
                    json_t *v = json_object_get(e, "value");
                    fprintf(stderr, "selection: %s over %lld decisions: value logged %.3f "
                                    "uniform %.3f greedy %.3f\n", cap,
                            (long long)json_integer_value(json_object_get(e, "decisions")),
                            json_real_value(json_object_get(v, "logged")),
                            json_real_value(json_object_get(v, "uniform")),
                            json_real_value(json_object_get(v, "greedy")));
                }
                json_decref(est);
            }
        }
    }
    pthread_mutex_unlock(&S.lock);
    for (size_t i = 0; i < n_out; i++)
    {
        char payload[64];
        snprintf(payload, sizeof(payload), "{\"index\":%ld}", out[i].index);
        (void)negotiation_send_replay(proc, AT_SEL_AUDIT_QUERY, out[i].peer, payload);
    }
}

/* ---- the conformance and test surface --------------------------------------------- */

int at_selection_configure(const process_t *proc, const void *model_ptr,
                           const unsigned char *root, const char *cfg_dir)
{
    const at_selection_model_t *model = model_ptr;
    pthread_mutex_lock(&S.lock);
    sel_proc_t *sp = _proc_locked(proc, true);
    int rc = -1;
    if (sp != NULL)
    {
        if (sp->have_req)
            at_sel_requestor_close(&sp->req);
        sp->have_req = false;
        sp->configured = true;
        sp->model = *model;
        memcpy(sp->root, root, AT_SEL_LINK_BYTES);
        at_strlcpy(sp->cfg_dir, cfg_dir, sizeof(sp->cfg_dir));
        rc = 0;
    }
    pthread_mutex_unlock(&S.lock);
    return rc;
}

long at_selection_finding_count(const process_t *proc, const char *requestor, const char *reason)
{
    long n = 0;
    pthread_mutex_lock(&S.lock);
    sel_proc_t *sp = _proc_locked(proc, false);
    for (size_t i = 0; sp != NULL && i < sp->n_findings; i++)
        if ((requestor == NULL || strcmp(sp->findings[i].requestor, requestor) == 0)
            && (reason == NULL || strcmp(sp->findings[i].reason, reason) == 0))
            n += sp->findings[i].count;
    pthread_mutex_unlock(&S.lock);
    return n;
}

json_t *at_selection_log_json(const process_t *proc)
{
    json_t *arr = json_array();
    pthread_mutex_lock(&S.lock);
    sel_proc_t *sp = _proc_locked(proc, false);
    for (size_t i = 0; sp != NULL && sp->have_req && i < sp->req.rec_n; i++)
        json_array_append_new(arr, at_sel_record_to_json(sp->req.records[i]));
    pthread_mutex_unlock(&S.lock);
    return arr;
}

static void _reset(void)
{
    pthread_mutex_lock(&S.lock);
    for (int i = 0; i < SEL_PROCS_MAX; i++)
    {
        if (S.procs[i].have_req)
            at_sel_requestor_close(&S.procs[i].req);
        at_sel_peer_free(&S.procs[i].peer);
        memset(&S.procs[i], 0, sizeof(S.procs[i]));
    }
    S.model_loaded = false;
    pthread_mutex_unlock(&S.lock);
}

/* The registry keeps the verb names it is given, so they need storage of
 * their own (the core's verbs are extern char arrays for the same reason). */
static char audit_query_verb[] = AT_SEL_AUDIT_QUERY;
static char audit_reply_verb[] = AT_SEL_AUDIT_REPLY;

static int _register_handlers(process_t *proc, const char *proc_name)
{
    if (strcmp(proc_name, "negotiation") == 0)
    {
        process_register_handler(proc, audit_query_verb, (handler_ptr_t)_handle_audit_query);
        process_register_handler(proc, audit_reply_verb, (handler_ptr_t)_handle_audit_reply);
    }
    return 0;
}

static const neg_select_hook_t selection_hook = {
    .name = "selection", .select = _select, .on_decline = _on_decline,
    .on_invitation = _on_invitation, .on_score = _on_score, .periodic = _periodic };
NEG_SELECT_HOOK_REGISTER(selection, &selection_hook)

static const at_extension_t selection_ext = {
    .name = "selection", .register_handlers = _register_handlers, .reset = _reset };
AT_EXTENSION_REGISTER(selection_live, &selection_ext)

void at_selection_live_link(void) {}
