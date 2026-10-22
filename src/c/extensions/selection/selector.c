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

/* The requestor's chain and decision log, the peer's audit, and the doubly
 * robust estimator: the C twin of Python selection/selector.py, the check
 * half of hooks.py, and estimate.py (RD_12.7_SELECTIVE_ASSIGNMENT_PLAN.md
 * sections 0.1-0.2, 3.6-3.7). The two files a requestor keeps,
 * selection-<proc>.json (chain, next index, probe counts; written before a
 * link is used) and selection-log-<proc>.json (the bounded log; flushed on a
 * slow timer), have Python's shape, so either runtime reads the other's. */

#include "selection/selection.h"

#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include <sodium.h>

#include "utilities/util.h"     /* at_strlcpy */

#define FLUSH_SECONDS 5.0
#define POLICY_VERSION 1

static double _now(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (double)ts.tv_sec + (double)ts.tv_nsec / 1e9;
}

static const char *_kind_name(at_sel_kind_t k)
{
    return k == AT_SEL_CATEGORICAL ? "categorical"
         : k == AT_SEL_BERNOULLI ? "bernoulli" : "all";
}

/* Write @p doc to @p path through a temporary file and a rename, so a reader
 * sees the old file or the new one, never a torn one (the atomic-write rule
 * the Python side's atomic_write follows). */
static int _atomic_dump(const json_t *doc, const char *path)
{
    char tmp[600];
    int n = snprintf(tmp, sizeof(tmp), "%s.%ld.tmp", path, (long)getpid());
    if (n < 0 || (size_t)n >= sizeof(tmp))
        return -1;
    FILE *f = fopen(tmp, "w");
    if (f == NULL)
        return -1;
    int rc = json_dumpf(doc, f, JSON_COMPACT | JSON_SORT_KEYS);
    rc |= fflush(f);
    rc |= fsync(fileno(f));
    rc |= fclose(f);
    if (rc != 0 || rename(tmp, path) != 0)
    {
        unlink(tmp);
        return -1;
    }
    return 0;
}

/* ---- records ---------------------------------------------------------------- */

void at_sel_record_free(at_sel_record_t *rec)
{
    if (rec == NULL)
        return;
    free(rec->rows);
    free(rec);
}

json_t *at_sel_record_to_json(const at_sel_record_t *rec)
{
    json_t *eligible = json_array();
    json_t *weights = json_array();
    json_t *outcome = json_object();
    for (size_t i = 0; i < rec->n; i++)
    {
        const at_sel_row_t *r = &rec->rows[i];
        json_array_append_new(eligible, json_pack("{s:s, s:f, s:b}", "peer", r->peer,
                                                  "propensity", r->propensity,
                                                  "selected", r->selected));
        json_array_append_new(weights, json_real(r->weight));
        if (r->outcome == AT_SEL_OUT_SCORE)
            json_object_set_new(outcome, r->peer, json_real(r->score));
        else if (r->outcome == AT_SEL_OUT_DECLINED)
            json_object_set_new(outcome, r->peer, json_string("declined"));
    }
    return json_pack("{s:I, s:s, s:s, s:s, s:s, s:i, s:s, s:s, s:b, s:b, s:o, s:f,"
                     " s:o, s:o, s:o, s:o}",
                     "index", (json_int_t)rec->index, "head", rec->head,
                     "link", rec->link, "task", rec->task,
                     "capability", rec->capability, "policy", POLICY_VERSION,
                     "purpose", rec->probe ? "probe" : "task",
                     "kind", _kind_name(rec->kind), "degraded", rec->degraded,
                     "fallback", rec->fallback,
                     "k", rec->k > 0 ? json_integer(rec->k) : json_null(),
                     "floor", rec->floor, "weights", weights, "eligible", eligible,
                     "outcome", outcome,
                     "redraw_of", rec->redraw_of > 0 ? json_integer(rec->redraw_of)
                                                     : json_null());
}

at_sel_record_t *at_sel_record_from_json(const json_t *j)
{
    json_t *elig = json_object_get(j, "eligible");
    json_t *weights = json_object_get(j, "weights");
    json_t *outcome = json_object_get(j, "outcome");
    if (!json_is_object(j) || !json_is_array(elig) || !json_is_integer(json_object_get(j, "index")))
        return NULL;
    at_sel_record_t *rec = calloc(1, sizeof(*rec));
    if (rec == NULL)
        return NULL;
    rec->n = json_array_size(elig);
    rec->rows = calloc(rec->n ? rec->n : 1, sizeof(*rec->rows));
    if (rec->rows == NULL)
    {
        free(rec);
        return NULL;
    }
    rec->index = (long)json_integer_value(json_object_get(j, "index"));
    const char *s;
    if ((s = json_string_value(json_object_get(j, "head"))) != NULL)
        at_strlcpy(rec->head, s, sizeof(rec->head));
    if ((s = json_string_value(json_object_get(j, "link"))) != NULL)
        at_strlcpy(rec->link, s, sizeof(rec->link));
    if ((s = json_string_value(json_object_get(j, "task"))) != NULL)
        at_strlcpy(rec->task, s, sizeof(rec->task));
    if ((s = json_string_value(json_object_get(j, "capability"))) != NULL)
        at_strlcpy(rec->capability, s, sizeof(rec->capability));
    s = json_string_value(json_object_get(j, "purpose"));
    rec->probe = s != NULL && strcmp(s, "probe") == 0;
    s = json_string_value(json_object_get(j, "kind"));
    rec->kind = s == NULL ? AT_SEL_ALL
              : strcmp(s, "categorical") == 0 ? AT_SEL_CATEGORICAL
              : strcmp(s, "bernoulli") == 0 ? AT_SEL_BERNOULLI : AT_SEL_ALL;
    rec->degraded = json_is_true(json_object_get(j, "degraded"));
    rec->fallback = json_is_true(json_object_get(j, "fallback"));
    json_t *k = json_object_get(j, "k");
    rec->k = json_is_integer(k) ? (int)json_integer_value(k) : 0;
    rec->floor = json_number_value(json_object_get(j, "floor"));
    json_t *rd = json_object_get(j, "redraw_of");
    rec->redraw_of = json_is_integer(rd) ? (long)json_integer_value(rd) : 0;
    for (size_t i = 0; i < rec->n; i++)
    {
        json_t *row = json_array_get(elig, i);
        at_sel_row_t *r = &rec->rows[i];
        if ((s = json_string_value(json_object_get(row, "peer"))) != NULL)
            at_strlcpy(r->peer, s, sizeof(r->peer));
        r->propensity = json_number_value(json_object_get(row, "propensity"));
        r->selected = json_is_true(json_object_get(row, "selected"));
        r->weight = json_number_value(json_array_get(weights, i));
        json_t *out = json_object_get(outcome, r->peer);
        if (json_is_number(out))
        {
            r->outcome = AT_SEL_OUT_SCORE;
            r->score = json_number_value(out);
        }
        else if (json_is_string(out))
            r->outcome = AT_SEL_OUT_DECLINED;
    }
    return rec;
}

/* ---- the requestor ------------------------------------------------------------ */

static int _write_chain(at_sel_requestor_t *r)
{
    char root[AT_SEL_HEX_LEN + 1], prev[AT_SEL_HEX_LEN + 1];
    at_sel_hex(r->chain->root, AT_SEL_LINK_BYTES, root);
    if (r->has_prev_root)
        at_sel_hex(r->prev_root, AT_SEL_LINK_BYTES, prev);
    json_t *counts = json_object();
    for (size_t i = 0; i < r->probe_n; i++)
        json_object_set_new(counts, r->probe_peer[i], json_integer(r->probe_count[i]));
    json_t *doc = json_pack("{s:i, s:s, s:I, s:o, s:o, s:I}", "version", 1,
                            "root", root, "next", (json_int_t)r->next_index,
                            "prev_root", r->has_prev_root ? json_string(prev) : json_null(),
                            "probe_counts", counts,
                            "probe_total", (json_int_t)r->probe_total);
    int rc = doc != NULL ? _atomic_dump(doc, r->chain_path) : -1;
    json_decref(doc);
    return rc;
}

static int _probe_slot(at_sel_requestor_t *r, const char *peer)
{
    for (size_t i = 0; i < r->probe_n; i++)
        if (strcmp(r->probe_peer[i], peer) == 0)
            return (int)i;
    if (r->probe_n == r->probe_cap)
    {
        size_t cap = r->probe_cap ? r->probe_cap * 2 : 16;
        char (*pp)[37] = realloc(r->probe_peer, cap * sizeof(*pp));
        if (pp == NULL)
            return -1;
        r->probe_peer = pp;
        long *pc = realloc(r->probe_count, cap * sizeof(*pc));
        if (pc == NULL)
            return -1;
        r->probe_count = pc;
        r->probe_cap = cap;
    }
    at_strlcpy(r->probe_peer[r->probe_n], peer, 37);
    r->probe_count[r->probe_n] = 0;
    return (int)r->probe_n++;
}

long at_sel_probe_count(const at_sel_requestor_t *r, const char *peer)
{
    for (size_t i = 0; i < r->probe_n; i++)
        if (strcmp(r->probe_peer[i], peer) == 0)
            return r->probe_count[i];
    return 0;
}

double at_sel_ucb_bonus(long count, long total)
{
    return sqrt(2.0 * log((double)(total + 2)) / (double)(count + 1));
}

static void _push(at_sel_requestor_t *r, at_sel_record_t *rec)
{
    size_t bound = (size_t)r->model.log_records;
    if (r->rec_n == bound)
    {
        at_sel_record_free(r->records[0]);
        memmove(&r->records[0], &r->records[1], (bound - 1) * sizeof(*r->records));
        r->rec_n--;
    }
    r->records[r->rec_n++] = rec;
    r->dirty = true;
}

int at_sel_requestor_open(at_sel_requestor_t *r, const at_selection_model_t *model,
                          const char *proc_name, const char *cfg_dir,
                          const unsigned char *root)
{
    memset(r, 0, sizeof(*r));
    r->model = *model;
    r->next_index = 1;
    snprintf(r->chain_path, sizeof(r->chain_path), "%s/selection-%s.json", cfg_dir, proc_name);
    snprintf(r->log_path, sizeof(r->log_path), "%s/selection-log-%s.json", cfg_dir, proc_name);
    r->chain = malloc(sizeof(*r->chain));
    r->records = calloc((size_t)model->log_records, sizeof(*r->records));
    if (r->chain == NULL || r->records == NULL)
    {
        at_sel_requestor_close(r);
        return -1;
    }
    json_error_t jerr;
    json_t *state = json_load_file(r->chain_path, 0, &jerr);
    unsigned char seed[AT_SEL_LINK_BYTES];
    if (state != NULL
        && at_sel_unhex(json_string_value(json_object_get(state, "root")), seed, sizeof(seed)) == 0)
    {
        at_sel_chain_init(r->chain, seed);
        r->next_index = (long)json_integer_value(json_object_get(state, "next"));
        if (r->next_index < 1)
            r->next_index = 1;
        r->has_prev_root = at_sel_unhex(json_string_value(json_object_get(state, "prev_root")),
                                        r->prev_root, AT_SEL_LINK_BYTES) == 0;
        const char *peer;
        json_t *v;
        json_object_foreach(json_object_get(state, "probe_counts"), peer, v)
        {
            int slot = _probe_slot(r, peer);
            if (slot >= 0)
                r->probe_count[slot] = (long)json_integer_value(v);
        }
        r->probe_total = (long)json_integer_value(json_object_get(state, "probe_total"));
    }
    else
    {
        if (root != NULL)
            memcpy(seed, root, sizeof(seed));
        else
            randombytes_buf(seed, sizeof(seed));
        at_sel_chain_init(r->chain, seed);
        (void)_write_chain(r);
    }
    json_decref(state);

    json_t *log = json_load_file(r->log_path, 0, &jerr);
    json_t *recs = json_object_get(log, "records");
    for (size_t i = 0; i < json_array_size(recs); i++)
    {
        at_sel_record_t *rec = at_sel_record_from_json(json_array_get(recs, i));
        if (rec != NULL)
            _push(r, rec);
    }
    json_decref(log);
    r->dirty = false;
    return 0;
}

void at_sel_requestor_close(at_sel_requestor_t *r)
{
    for (size_t i = 0; r->records != NULL && i < r->rec_n; i++)
        at_sel_record_free(r->records[i]);
    free(r->records);
    free(r->chain);
    free(r->probe_peer);
    free(r->probe_count);
    memset(r, 0, sizeof(*r));
}

void at_sel_requestor_flush(at_sel_requestor_t *r, bool force)
{
    double now = _now();
    if (!r->dirty || (!force && now - r->last_flush < FLUSH_SECONDS))
        return;
    json_t *arr = json_array();
    for (size_t i = 0; i < r->rec_n; i++)
        json_array_append_new(arr, at_sel_record_to_json(r->records[i]));
    json_t *doc = json_pack("{s:i, s:o}", "version", 1, "records", arr);
    if (doc != NULL && _atomic_dump(doc, r->log_path) == 0)
    {
        r->dirty = false;
        r->last_flush = now;
    }
    json_decref(doc);
}

int at_sel_decide(at_sel_requestor_t *r, const char *task, const char *capability,
                  char (*peers)[37], const double *weights, size_t n, int k,
                  double floor, bool probe, long redraw_of, bool *selected,
                  char *draw_json, size_t draw_len)
{
    if (r->next_index > AT_SEL_CHAIN_LENGTH)
    {
        memcpy(r->prev_root, r->chain->root, AT_SEL_LINK_BYTES);
        r->has_prev_root = true;
        unsigned char seed[AT_SEL_LINK_BYTES];
        randombytes_buf(seed, sizeof(seed));
        at_sel_chain_init(r->chain, seed);
        r->next_index = 1;
    }
    long index = r->next_index++;
    if (_write_chain(r) != 0)
        return -1;      /* never use a link the file does not record as spent */
    unsigned char link[AT_SEL_LINK_BYTES];
    at_sel_chain_link(r->chain, index, link);

    at_sel_record_t *rec = calloc(1, sizeof(*rec));
    double *inclusion = calloc(n ? n : 1, sizeof(*inclusion));
    if (rec == NULL || inclusion == NULL
        || (rec->rows = calloc(n ? n : 1, sizeof(*rec->rows))) == NULL)
    {
        free(inclusion);
        at_sel_record_free(rec);
        return -1;
    }
    if (at_sel_draw(weights, n, k, floor, at_sel_seed_of(link), selected, inclusion,
                    &rec->kind, &rec->degraded, &rec->fallback) != 0)
    {
        free(inclusion);
        at_sel_record_free(rec);
        return -1;
    }
    rec->index = index;
    at_sel_hex(r->chain->head, AT_SEL_LINK_BYTES, rec->head);
    at_sel_hex(link, AT_SEL_LINK_BYTES, rec->link);
    at_strlcpy(rec->task, task, sizeof(rec->task));
    at_strlcpy(rec->capability, capability, sizeof(rec->capability));
    rec->probe = probe;
    rec->k = k;
    rec->floor = floor;
    rec->redraw_of = redraw_of;
    rec->n = n;
    for (size_t i = 0; i < n; i++)
    {
        at_strlcpy(rec->rows[i].peer, peers[i], sizeof(rec->rows[i].peer));
        rec->rows[i].propensity = inclusion[i];
        rec->rows[i].weight = weights[i];
        rec->rows[i].selected = selected[i];
    }
    free(inclusion);

    json_t *field = json_pack("{s:s, s:I, s:s}", "head", rec->head,
                              "index", (json_int_t)index, "link", rec->link);
    if (r->has_prev_root)
    {
        char prev[AT_SEL_HEX_LEN + 1];
        at_sel_hex(r->prev_root, AT_SEL_LINK_BYTES, prev);
        json_object_set_new(field, "prev_root", json_string(prev));
    }
    char *text = json_dumps(field, JSON_COMPACT | JSON_SORT_KEYS);
    json_decref(field);
    if (text == NULL || strlen(text) >= draw_len)
    {
        free(text);
        at_sel_record_free(rec);
        return -1;
    }
    at_strlcpy(draw_json, text, draw_len);
    free(text);

    if (probe)
    {
        for (size_t i = 0; i < n; i++)
            if (selected[i])
            {
                int slot = _probe_slot(r, peers[i]);
                if (slot >= 0)
                    r->probe_count[slot]++;
            }
        r->probe_total++;
        (void)_write_chain(r);
    }
    _push(r, rec);
    return 0;
}

static at_sel_record_t *_selecting(const at_sel_requestor_t *r, const char *task,
                                   const char *peer, size_t *pos)
{
    for (size_t i = r->rec_n; i > 0; i--)
    {
        at_sel_record_t *rec = r->records[i - 1];
        if (strcmp(rec->task, task) != 0)
            continue;
        for (size_t p = 0; p < rec->n; p++)
            if (rec->rows[p].selected && strcmp(rec->rows[p].peer, peer) == 0)
            {
                *pos = p;
                return rec;
            }
    }
    return NULL;
}

at_sel_record_t *at_sel_record_decline(at_sel_requestor_t *r, const char *task,
                                       const char *peer)
{
    size_t pos;
    at_sel_record_t *rec = _selecting(r, task, peer, &pos);
    if (rec != NULL)
    {
        rec->rows[pos].outcome = AT_SEL_OUT_DECLINED;
        r->dirty = true;
    }
    return rec;
}

bool at_sel_record_outcome(at_sel_requestor_t *r, const char *task,
                           const char *peer, double score)
{
    size_t pos;
    at_sel_record_t *rec = _selecting(r, task, peer, &pos);
    if (rec == NULL)
        return false;
    rec->rows[pos].outcome = AT_SEL_OUT_SCORE;
    rec->rows[pos].score = score;
    r->dirty = true;
    return true;
}

bool at_sel_asked(const at_sel_requestor_t *r, const char *task, const char *peer)
{
    size_t pos;
    return _selecting(r, task, peer, &pos) != NULL;
}

const at_sel_record_t *at_sel_record_at(const at_sel_requestor_t *r, long index)
{
    for (size_t i = 0; i < r->rec_n; i++)
        if (r->records[i]->index == index)
            return r->records[i];
    return NULL;
}

json_t *at_sel_audit_row(const at_sel_record_t *rec, size_t pos)
{
    const at_sel_row_t *row = &rec->rows[pos];
    json_t *out = json_pack("{s:I, s:b, s:f, s:b}", "position", (json_int_t)pos,
                            "eligible", 1, "propensity", row->propensity,
                            "selected", row->selected);
    if (rec->kind == AT_SEL_ALL)
    {
        json_object_set_new(out, "draw_at", json_null());
        json_object_set_new(out, "lo", json_real(0.0));
        json_object_set_new(out, "hi", json_real(1.0));
        return out;
    }
    double *w = calloc(rec->n, sizeof(*w));
    double *p = calloc(rec->n, sizeof(*p));
    if (w == NULL || p == NULL)
    {
        free(w);
        free(p);
        json_decref(out);
        return NULL;
    }
    for (size_t i = 0; i < rec->n; i++)
        w[i] = rec->rows[i].weight;
    (void)at_sel_propensities(w, rec->n, rec->floor, p);
    double lo = 0.0;
    for (size_t i = 0; i < pos; i++)
        lo += p[i];
    if (rec->kind == AT_SEL_CATEGORICAL)
    {
        json_object_set_new(out, "draw_at", json_integer(0));
        json_object_set_new(out, "lo", json_real(lo));
        json_object_set_new(out, "hi", json_real(lo + p[pos]));
    }
    else if (rec->fallback && row->selected)
    {
        json_object_set_new(out, "draw_at", json_integer((json_int_t)rec->n));
        json_object_set_new(out, "lo", json_real(lo));
        json_object_set_new(out, "hi", json_real(lo + p[pos]));
    }
    else
    {
        double pi = (double)rec->k * p[pos];
        pi = pi < rec->floor ? rec->floor : pi;
        pi = pi > 1.0 ? 1.0 : pi;
        json_object_set_new(out, "draw_at", json_integer((json_int_t)pos));
        json_object_set_new(out, "lo", json_real(0.0));
        json_object_set_new(out, "hi", json_real(pi));
    }
    free(w);
    free(p);
    return out;
}

json_t *at_sel_audit_answer(const at_sel_requestor_t *r, long index, const char *asker)
{
    const at_sel_record_t *rec = at_sel_record_at(r, index);
    if (rec == NULL || index >= r->next_index)
        return json_pack("{s:I, s:s}", "index", (json_int_t)index, "status", "unknown");
    json_t *row = json_null();
    for (size_t i = 0; i < rec->n; i++)
        if (strcmp(rec->rows[i].peer, asker) == 0)
        {
            json_decref(row);
            row = at_sel_audit_row(rec, i);
            if (row == NULL)
                row = json_null();
            break;
        }
    return json_pack("{s:I, s:s, s:s, s:s, s:s, s:I, s:o}", "index", (json_int_t)index,
                     "status", "ok", "head", rec->head, "link", rec->link,
                     "task", rec->task, "eligible_count", (json_int_t)rec->n, "row", row);
}

/* ---- the peer's audit ------------------------------------------------------------ */

void at_sel_peer_free(at_sel_peer_t *p)
{
    for (size_t i = 0; i < p->n; i++)
        free(p->seen[i].indices);
    free(p->seen);
    memset(p, 0, sizeof(*p));
}

static at_sel_seen_t *_seen(const at_sel_peer_t *p, const char *requestor)
{
    for (size_t i = 0; i < p->n; i++)
        if (strcmp(p->seen[i].requestor, requestor) == 0)
            return &p->seen[i];
    return NULL;
}

static bool _has_index(const at_sel_seen_t *s, long index)
{
    for (size_t i = 0; i < s->n_indices; i++)
        if (s->indices[i] == index)
            return true;
    return false;
}

static bool _int_of(const json_t *v, long *out)
{
    if (!json_is_integer(v))
        return false;
    *out = (long)json_integer_value(v);
    return true;
}

const char *at_sel_check_draw(at_sel_peer_t *p, const char *requestor,
                              const json_t *draw, long *gap, size_t *n_gap)
{
    *n_gap = 0;
    unsigned char head[AT_SEL_LINK_BYTES], link[AT_SEL_LINK_BYTES], prev[AT_SEL_LINK_BYTES];
    long index = 0;
    json_t *jprev = json_object_get(draw, "prev_root");
    bool has_prev = jprev != NULL && !json_is_null(jprev);
    if (!json_is_object(draw)
        || at_sel_unhex(json_string_value(json_object_get(draw, "head")), head, sizeof(head)) != 0
        || !_int_of(json_object_get(draw, "index"), &index)
        || at_sel_unhex(json_string_value(json_object_get(draw, "link")), link, sizeof(link)) != 0
        || (has_prev && at_sel_unhex(json_string_value(jprev), prev, sizeof(prev)) != 0))
        return "malformed";

    const char *finding = NULL;
    at_sel_seen_t *seen = _seen(p, requestor);
    if (seen != NULL && sodium_memcmp(seen->head, head, sizeof(head)) != 0)
    {
        if (!(has_prev && at_sel_verify_rotation(seen->head, prev)))
            finding = "head_changed";
        memcpy(seen->head, head, sizeof(head));
        seen->known_index = 0;
        seen->n_indices = 0;
    }
    if (seen == NULL)
    {
        if (p->n == p->cap)
        {
            size_t cap = p->cap ? p->cap * 2 : 8;
            at_sel_seen_t *grown = realloc(p->seen, cap * sizeof(*grown));
            if (grown == NULL)
                return finding;
            p->seen = grown;
            p->cap = cap;
        }
        seen = &p->seen[p->n++];
        memset(seen, 0, sizeof(*seen));
        at_strlcpy(seen->requestor, requestor, sizeof(seen->requestor));
        memcpy(seen->head, head, sizeof(head));
    }
    if (seen->known_index > 0 && index <= seen->known_index)
    {
        if (_has_index(seen, index))
            return finding;
        return finding != NULL ? finding : "index_not_increasing";
    }
    if (!at_sel_verify_link(head, index, link, seen->known_index, seen->known_link))
        return finding != NULL ? finding : "bad_link";
    if (seen->known_index > 0 && index > seen->known_index + 1)
    {
        long from = index - AT_SEL_AUDIT_MAX_PER_GAP;
        if (from < seen->known_index + 1)
            from = seen->known_index + 1;
        for (long i = from; i < index; i++)
            gap[(*n_gap)++] = i;
    }
    seen->known_index = index;
    memcpy(seen->known_link, link, sizeof(link));
    if (seen->n_indices == seen->cap_indices)
    {
        size_t cap = seen->cap_indices ? seen->cap_indices * 2 : 16;
        long *grown = realloc(seen->indices, cap * sizeof(*grown));
        if (grown == NULL)
            return finding;
        seen->indices = grown;
        seen->cap_indices = cap;
    }
    seen->indices[seen->n_indices++] = index;
    return finding;
}

const char *at_sel_check_answer(const at_sel_peer_t *p, const char *requestor,
                                const json_t *answer)
{
    const char *status = json_string_value(json_object_get(answer, "status"));
    if (status == NULL || strcmp(status, "ok") != 0)
        return "audit_unknown";
    long index = 0, draw_at = -1;
    unsigned char head[AT_SEL_LINK_BYTES], link[AT_SEL_LINK_BYTES];
    double lo = 0.0, hi = 0.0;
    bool selected = false;
    json_t *row = json_object_get(answer, "row");
    if (!_int_of(json_object_get(answer, "index"), &index)
        || at_sel_unhex(json_string_value(json_object_get(answer, "link")), link, sizeof(link)) != 0
        || at_sel_unhex(json_string_value(json_object_get(answer, "head")), head, sizeof(head)) != 0)
        return "audit_malformed";
    if (row != NULL && !json_is_null(row))
    {
        json_t *jsel = json_object_get(row, "selected");
        json_t *jat = json_object_get(row, "draw_at");
        if (!json_is_object(row) || jsel == NULL)
            return "audit_malformed";
        selected = json_is_true(jsel);
        if (jat != NULL && !json_is_null(jat))
        {
            json_t *jlo = json_object_get(row, "lo"), *jhi = json_object_get(row, "hi");
            if (!_int_of(jat, &draw_at) || !json_is_number(jlo) || !json_is_number(jhi)
                || draw_at < 0 || draw_at > (1L << 20))
                return "audit_malformed";
            lo = json_number_value(jlo);
            hi = json_number_value(jhi);
        }
    }
    const at_sel_seen_t *seen = _seen(p, requestor);
    if (seen == NULL || sodium_memcmp(seen->head, head, sizeof(head)) != 0
        || !at_sel_verify_link(head, index, link, 0, NULL))
        return "audit_bad_link";
    if (row == NULL || json_is_null(row))
        return NULL;
    if (draw_at >= 0)
    {
        at_splitmix64_t rng;
        at_splitmix64_init(&rng, at_sel_seed_of(link));
        double u = 0.0;
        for (long i = 0; i <= draw_at; i++)
            u = at_sel_unit(&rng);
        if ((lo <= u && u < hi) != selected)
            return "audit_inconsistent";
    }
    if (selected && !_has_index(seen, index))
        return "audit_selected_uninvited";
    return NULL;
}

/* ---- the estimator ------------------------------------------------------------------ */

typedef struct {
    char   peer[37];
    double sum;
    long   count;
} _rhat_t;

static double _rhat_of(const _rhat_t *m, size_t n, const char *peer, double prior)
{
    for (size_t i = 0; i < n; i++)
        if (strcmp(m[i].peer, peer) == 0)
            return (m[i].sum + AT_SEL_PRIOR_STRENGTH * prior)
                 / ((double)m[i].count + AT_SEL_PRIOR_STRENGTH);
    return prior;
}

static double _decision_value(int policy, const at_sel_record_t *rec,
                              const _rhat_t *m, size_t nm, double prior)
{
    double *rhat = calloc(rec->n ? rec->n : 1, sizeof(*rhat));
    if (rhat == NULL)
        return 0.0;
    for (size_t i = 0; i < rec->n; i++)
        rhat[i] = _rhat_of(m, nm, rec->rows[i].peer, prior);
    size_t best = 0;
    for (size_t i = 1; i < rec->n; i++)
        if (rhat[i] > rhat[best])
            best = i;
    double num = 0.0, den = 0.0;
    for (size_t i = 0; i < rec->n; i++)
    {
        const at_sel_row_t *row = &rec->rows[i];
        double pi = policy == 0 ? row->propensity
                  : policy == 1 ? 1.0 : (i == best ? 1.0 : 0.0);
        double term = rhat[i];
        if (row->selected && row->outcome == AT_SEL_OUT_SCORE && row->propensity > 0.0)
            term += (row->score - rhat[i]) / row->propensity;
        num += pi * term;
        den += pi;
    }
    free(rhat);
    return den > 0.0 ? num / den : 0.0;
}

json_t *at_sel_estimate(at_sel_record_t *const *records, size_t n)
{
    /* records arrive in index order (the log's insertion order) */
    _rhat_t *m = NULL;
    size_t nm = 0, cap = 0;
    double total = 0.0;
    long count = 0;
    for (size_t r = 0; r < n; r++)
    {
        const at_sel_record_t *rec = records[r];
        if (!rec->probe)
            continue;
        for (size_t i = 0; i < rec->n; i++)
        {
            const at_sel_row_t *row = &rec->rows[i];
            if (!row->selected || row->outcome != AT_SEL_OUT_SCORE)
                continue;
            size_t at = nm;
            for (size_t j = 0; j < nm; j++)
                if (strcmp(m[j].peer, row->peer) == 0)
                    at = j;
            if (at == nm)
            {
                if (nm == cap)
                {
                    cap = cap ? cap * 2 : 16;
                    _rhat_t *grown = realloc(m, cap * sizeof(*grown));
                    if (grown == NULL)
                    {
                        free(m);
                        return json_object();
                    }
                    m = grown;
                }
                memset(&m[nm], 0, sizeof(m[nm]));
                at_strlcpy(m[nm].peer, row->peer, sizeof(m[nm].peer));
                nm++;
            }
            m[at].sum += row->score;
            m[at].count++;
            total += row->score;
            count++;
        }
    }
    double prior = count > 0 ? total / (double)count : AT_SEL_NEUTRAL;

    static const char *const names[3] = { "logged", "uniform", "greedy" };
    json_t *out = json_object();
    for (size_t r = 0; r < n; r++)
    {
        const at_sel_record_t *rec = records[r];
        long observed = 0;
        for (size_t i = 0; i < rec->n; i++)
            if (rec->rows[i].selected && rec->rows[i].outcome == AT_SEL_OUT_SCORE)
                observed++;
        if (observed == 0)
            continue;
        json_t *entry = json_object_get(out, rec->capability);
        if (entry == NULL)
        {
            entry = json_pack("{s:I, s:I, s:{s:f, s:f, s:f}}", "decisions", (json_int_t)0,
                              "observed", (json_int_t)0, "value",
                              "logged", 0.0, "uniform", 0.0, "greedy", 0.0);
            json_object_set_new(out, rec->capability, entry);
        }
        json_object_set_new(entry, "decisions",
                            json_integer(json_integer_value(json_object_get(entry, "decisions")) + 1));
        json_object_set_new(entry, "observed",
                            json_integer(json_integer_value(json_object_get(entry, "observed")) + observed));
        json_t *value = json_object_get(entry, "value");
        for (int p = 0; p < 3; p++)
            json_object_set_new(value, names[p],
                                json_real(json_real_value(json_object_get(value, names[p]))
                                          + _decision_value(p, rec, m, nm, prior)));
    }
    free(m);

    const char *cap_name;
    json_t *entry;
    json_object_foreach(out, cap_name, entry)
    {
        (void)cap_name;
        double d = (double)json_integer_value(json_object_get(entry, "decisions"));
        json_t *value = json_object_get(entry, "value");
        for (int p = 0; p < 3; p++)
            json_object_set_new(value, names[p],
                                json_real(json_real_value(json_object_get(value, names[p])) / d));
        double logged = json_real_value(json_object_get(value, "logged"));
        json_object_set_new(entry, "regret",
                            json_pack("{s:f, s:f}",
                                      "uniform", json_real_value(json_object_get(value, "uniform")) - logged,
                                      "greedy", json_real_value(json_object_get(value, "greedy")) - logged));
    }
    return out;
}
