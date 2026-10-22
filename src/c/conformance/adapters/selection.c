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

/*
 * C adapter for the `selection` conformance protocol (R+D.md §12.7;
 * RD_12.7_SELECTIVE_ASSIGNMENT_PLAN.md). Non-message-driven, like
 * replication: a declaration (fixtures.selection), a chain root
 * (fixtures.root) and a list of events, evaluated in order against one
 * requestor and one auditing peer. Mirrors the Python adapter
 * conformance/harness/python/adapters/selection.py, whose docstring lists the
 * events.
 */

#include "selection.h"

#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include <jansson.h>

#include "selection/selection.h"

#define SEL_TOL 1e-12

/* Python's _close: numbers within tolerance (an integer equals the same
 * real), booleans and strings exactly, objects key for key, arrays in
 * order. */
static bool _close(const json_t *a, const json_t *b)
{
    if (json_is_boolean(a) || json_is_boolean(b))
        return json_is_boolean(a) && json_is_boolean(b) && json_is_true(a) == json_is_true(b);
    if (json_is_number(a) && json_is_number(b))
        return fabs(json_number_value(a) - json_number_value(b)) <= SEL_TOL;
    if (json_is_object(a) && json_is_object(b))
    {
        if (json_object_size(a) != json_object_size(b))
            return false;
        const char *k;
        json_t *v;
        json_object_foreach((json_t *)a, k, v)
            if (!_close(v, json_object_get(b, k)))
                return false;
        return true;
    }
    if (json_is_array(a) && json_is_array(b))
    {
        if (json_array_size(a) != json_array_size(b))
            return false;
        for (size_t i = 0; i < json_array_size(a); i++)
            if (!_close(json_array_get(a, i), json_array_get(b, i)))
                return false;
        return true;
    }
    if (a == NULL || b == NULL)
        return a == b || (a == NULL && json_is_null(b)) || (b == NULL && json_is_null(a));
    return json_equal((json_t *)a, (json_t *)b);
}

/* Every key @p want names matches in @p actual. */
static bool _subset(const json_t *actual, const json_t *want)
{
    if (json_is_object(want))
    {
        if (!json_is_object(actual))
            return false;
        const char *k;
        json_t *v;
        json_object_foreach((json_t *)want, k, v)
        {
            json_t *a = json_object_get(actual, k);
            if (a == NULL || !_subset(a, v))
                return false;
        }
        return true;
    }
    return _close(actual, want);
}

static bool _expect(const json_t *ev, const char *name, json_t *actual, int index,
                    char *err, size_t errlen)
{
    json_t *want = json_object_get(ev, name);
    bool ok = want == NULL || _close(actual, want);
    if (!ok)
    {
        char *a = json_dumps(actual, JSON_COMPACT | JSON_ENCODE_ANY);
        char *w = json_dumps(want, JSON_COMPACT | JSON_ENCODE_ANY);
        snprintf(err, errlen, "event %d: %s=%.200s, expected %.200s", index, name,
                 a ? a : "?", w ? w : "?");
        free(a);
        free(w);
    }
    json_decref(actual);
    return ok;
}

static const char *_kind(at_sel_kind_t k)
{
    return k == AT_SEL_CATEGORICAL ? "categorical" : k == AT_SEL_BERNOULLI ? "bernoulli" : "all";
}

static double *_weights(const json_t *arr, size_t *n)
{
    *n = json_array_size(arr);
    double *w = calloc(*n ? *n : 1, sizeof(*w));
    for (size_t i = 0; w != NULL && i < *n; i++)
        w[i] = json_number_value(json_array_get(arr, i));
    return w;
}

static int _k(const json_t *spec)
{
    json_t *k = json_object_get(spec, "k");
    return json_is_integer(k) ? (int)json_integer_value(k) : 0;
}

static json_t *_bools_to_indices(const bool *sel, size_t n)
{
    json_t *arr = json_array();
    for (size_t i = 0; i < n; i++)
        if (sel[i])
            json_array_append_new(arr, json_integer((json_int_t)i));
    return arr;
}

static json_t *_doubles(const double *v, size_t n)
{
    json_t *arr = json_array();
    for (size_t i = 0; i < n; i++)
        json_array_append_new(arr, json_real(v[i]));
    return arr;
}

static json_t *_finding(const char *f)
{
    return f != NULL ? json_string(f) : json_null();
}

/* The requestor's draw `index` as an invitation field, with `tamper`
 * applied. */
static json_t *_draw_field(const at_sel_requestor_t *r, long index, const json_t *tamper)
{
    const at_sel_record_t *rec = at_sel_record_at(r, index);
    if (rec == NULL)
        return NULL;
    json_t *f = json_pack("{s:s, s:I, s:s}", "head", rec->head, "index", (json_int_t)rec->index,
                          "link", rec->link);
    if (json_is_object(tamper))
        json_object_update(f, (json_t *)tamper);
    return f;
}

static int _event(const at_selection_model_t *model, at_sel_requestor_t *r, at_sel_peer_t *peer,
                  const unsigned char *root, int index, const json_t *ev, char *err, size_t errlen)
{
#define EXPECT(name, actual) do { if (!_expect(ev, name, actual, index, err, errlen)) return -1; } while (0)
    json_t *spec;
    if ((spec = json_object_get(ev, "declare")) != NULL)
    {
        at_selection_model_t m;
        EXPECT("refused", json_boolean(!at_selection_parse(spec, &m, NULL, 0)));
    }
    else if ((spec = json_object_get(ev, "policy")) != NULL)
    {
        const char *cap = json_string_value(spec);
        const at_sel_policy_t *p = at_selection_policy_for(model, cap);
        EXPECT("k", p->k > 0 ? json_integer(p->k) : json_null());
        EXPECT("floor", json_real(p->floor));
        EXPECT("selects", json_boolean(at_selection_selects(model, cap)));
    }
    else if ((spec = json_object_get(ev, "propensities")) != NULL)
    {
        size_t n;
        double *w = _weights(json_object_get(spec, "weights"), &n);
        double *p = calloc(n ? n : 1, sizeof(*p));
        if (w == NULL || p == NULL)
        {
            free(w);
            free(p);
            return -1;
        }
        bool deg = at_sel_propensities(w, n, json_number_value(json_object_get(spec, "floor")), p);
        json_t *probs = _doubles(p, n);
        free(w);
        free(p);
        EXPECT("probs", probs);
        EXPECT("degraded", json_boolean(deg));
    }
    else if ((spec = json_object_get(ev, "draw")) != NULL)
    {
        size_t n;
        double *w = _weights(json_object_get(spec, "weights"), &n);
        bool *sel = calloc(n ? n : 1, sizeof(*sel));
        double *inc = calloc(n ? n : 1, sizeof(*inc));
        at_sel_kind_t kind;
        bool deg, fb;
        int rc = w && sel && inc
            ? at_sel_draw(w, n, _k(spec), json_number_value(json_object_get(spec, "floor")),
                          (uint64_t)json_integer_value(json_object_get(spec, "seed")),
                          sel, inc, &kind, &deg, &fb)
            : -1;
        json_t *jsel = rc == 0 ? _bools_to_indices(sel, n) : NULL;
        json_t *jinc = rc == 0 ? _doubles(inc, n) : NULL;
        free(w);
        free(sel);
        free(inc);
        if (rc != 0)
            return -1;
        EXPECT("selected", jsel);
        EXPECT("inclusion", jinc);
        EXPECT("kind", json_string(_kind(kind)));
        EXPECT("fallback", json_boolean(fb));
        EXPECT("degraded", json_boolean(deg));
    }
    else if ((spec = json_object_get(ev, "link")) != NULL)
    {
        at_sel_chain_t *c = malloc(sizeof(*c));
        if (c == NULL)
            return -1;
        at_sel_chain_init(c, root);
        unsigned char link[AT_SEL_LINK_BYTES];
        char hex[AT_SEL_HEX_LEN + 1];
        at_sel_chain_link(c, (long)json_integer_value(spec), link);
        free(c);
        at_sel_hex(link, sizeof(link), hex);
        EXPECT("hex", json_string(hex));
    }
    else if (json_object_get(ev, "head") != NULL)
    {
        at_sel_chain_t *c = malloc(sizeof(*c));
        if (c == NULL)
            return -1;
        at_sel_chain_init(c, root);
        char hex[AT_SEL_HEX_LEN + 1];
        at_sel_hex(c->head, AT_SEL_LINK_BYTES, hex);
        free(c);
        EXPECT("hex", json_string(hex));
    }
    else if ((spec = json_object_get(ev, "verify")) != NULL)
    {
        at_sel_chain_t *c = malloc(sizeof(*c));
        if (c == NULL)
            return -1;
        at_sel_chain_init(c, root);
        unsigned char link[AT_SEL_LINK_BYTES] = {0}, known[AT_SEL_LINK_BYTES] = {0};
        json_t *of = json_object_get(spec, "link_of");
        if (of != NULL)
            at_sel_chain_link(c, (long)json_integer_value(of), link);
        else
            (void)at_sel_unhex(json_string_value(json_object_get(spec, "link")), link, sizeof(link));
        long ki = (long)json_integer_value(json_object_get(spec, "known_index"));
        if (ki > 0)
            at_sel_chain_link(c, ki, known);
        bool ok = at_sel_verify_link(c->head, (long)json_integer_value(json_object_get(spec, "index")),
                                     link, ki, known);
        free(c);
        EXPECT("ok", json_boolean(ok));
    }
    else if ((spec = json_object_get(ev, "decide")) != NULL)
    {
        json_t *jpeers = json_object_get(spec, "peers");
        size_t n = json_array_size(jpeers), nw;
        char (*peers)[37] = calloc(n ? n : 1, sizeof(*peers));
        bool *sel = calloc(n ? n : 1, sizeof(*sel));
        double *w = _weights(json_object_get(spec, "weights"), &nw);
        char draw_json[512];
        const char *purpose = json_string_value(json_object_get(spec, "purpose"));
        int rc = -1;
        if (peers != NULL && sel != NULL && w != NULL && nw == n)
        {
            for (size_t i = 0; i < n; i++)
                snprintf(peers[i], sizeof(peers[i]), "%s", json_string_value(json_array_get(jpeers, i)));
            rc = at_sel_decide(r, json_string_value(json_object_get(spec, "task")),
                               json_string_value(json_object_get(spec, "capability")), peers, w, n,
                               _k(spec), json_number_value(json_object_get(spec, "floor")),
                               purpose != NULL && strcmp(purpose, "probe") == 0, 0, sel,
                               draw_json, sizeof(draw_json));
        }
        json_t *chosen = json_array();
        for (size_t i = 0; rc == 0 && i < n; i++)
            if (sel[i])
                json_array_append_new(chosen, json_string(peers[i]));
        free(peers);
        free(sel);
        free(w);
        if (rc != 0)
        {
            json_decref(chosen);
            snprintf(err, errlen, "event %d: decide failed", index);
            return -1;
        }
        EXPECT("selected", chosen);
        EXPECT("index", json_integer((json_int_t)(r->next_index - 1)));
    }
    else if ((spec = json_object_get(ev, "decline")) != NULL)
    {
        EXPECT("recorded", json_boolean(at_sel_record_decline(
                   r, json_string_value(json_object_get(spec, "task")),
                   json_string_value(json_object_get(spec, "peer"))) != NULL));
    }
    else if ((spec = json_object_get(ev, "outcome")) != NULL)
    {
        EXPECT("recorded", json_boolean(at_sel_record_outcome(
                   r, json_string_value(json_object_get(spec, "task")),
                   json_string_value(json_object_get(spec, "peer")),
                   json_number_value(json_object_get(spec, "score")))));
    }
    else if ((spec = json_object_get(ev, "audit")) != NULL)
    {
        json_t *answer = at_sel_audit_answer(r, (long)json_integer_value(json_object_get(spec, "index")),
                                             json_string_value(json_object_get(spec, "asker")));
        json_t *want = json_object_get(ev, "answer");
        bool ok = want == NULL || _subset(answer, want);
        if (!ok)
        {
            char *a = json_dumps(answer, JSON_COMPACT);
            snprintf(err, errlen, "event %d: answer=%.300s", index, a ? a : "?");
            free(a);
        }
        json_decref(answer);
        if (!ok)
            return -1;
    }
    else if ((spec = json_object_get(ev, "check_draw")) != NULL)
    {
        json_t *field = json_object_get(spec, "draw");
        field = field != NULL ? json_incref(field)
                              : _draw_field(r, (long)json_integer_value(json_object_get(spec, "index")),
                                            json_object_get(spec, "tamper"));
        const char *who = json_string_value(json_object_get(spec, "requestor"));
        long gap[AT_SEL_AUDIT_MAX_PER_GAP];
        size_t n_gap = 0;
        const char *finding = at_sel_check_draw(peer, who ? who : "R", field, gap, &n_gap);
        json_decref(field);
        json_t *jgap = json_array();
        for (size_t i = 0; i < n_gap; i++)
            json_array_append_new(jgap, json_integer(gap[i]));
        EXPECT("finding", _finding(finding));
        EXPECT("gap", jgap);
    }
    else if ((spec = json_object_get(ev, "check_answer")) != NULL)
    {
        json_t *answer = at_sel_audit_answer(r, (long)json_integer_value(json_object_get(spec, "index")),
                                             json_string_value(json_object_get(spec, "asker")));
        const char *k;
        json_t *v;
        json_object_foreach(json_object_get(spec, "tamper"), k, v)
        {
            json_t *row = json_object_get(answer, "row");
            if (strcmp(k, "row") == 0 && json_is_object(v) && json_is_object(row))
                json_object_update(row, v);
            else
                json_object_set(answer, k, v);
        }
        const char *who = json_string_value(json_object_get(spec, "requestor"));
        const char *finding = at_sel_check_answer(peer, who ? who : "R", answer);
        json_decref(answer);
        EXPECT("finding", _finding(finding));
    }
    else if ((spec = json_object_get(ev, "estimate")) != NULL)
    {
        json_t *recs = json_object_get(spec, "records");
        json_t *result;
        if (json_is_array(recs))
        {
            size_t n = json_array_size(recs);
            at_sel_record_t **list = calloc(n ? n : 1, sizeof(*list));
            for (size_t i = 0; list != NULL && i < n; i++)
                list[i] = at_sel_record_from_json(json_array_get(recs, i));
            result = list != NULL ? at_sel_estimate(list, n) : json_object();
            for (size_t i = 0; list != NULL && i < n; i++)
                at_sel_record_free(list[i]);
            free(list);
        }
        else
            result = at_sel_estimate(r->records, r->rec_n);
        EXPECT("result", result);
    }
    else
    {
        snprintf(err, errlen, "event %d: unrecognised event", index);
        return -1;
    }
    return 0;
#undef EXPECT
}

void at_selection_conformance_run(const at_case_t *c, at_case_result_t *out)
{
    if (strcmp(c->kind, "scenario") != 0)
    {
        at_case_result_set_skip(out, "C selection adapter only handles kind:scenario");
        return;
    }
    struct timespec t0, t1;
    clock_gettime(CLOCK_MONOTONIC, &t0);
    char err[768] = {0};
    int rc = -1;
    json_t *fixtures = json_object_get(c->data, "fixtures");
    json_t *decl = json_object_get(fixtures, "selection");
    at_selection_model_t model;
    json_t *empty = json_pack("{s:i}", "version", 1);
    bool parsed = at_selection_parse(decl != NULL ? decl : empty, &model, err, sizeof(err));
    json_decref(empty);
    unsigned char root[AT_SEL_LINK_BYTES] = {0};
    const char *root_hex = json_string_value(json_object_get(fixtures, "root"));
    char dir[] = "/tmp/at-conf-selection-XXXXXX";
    at_sel_requestor_t req;
    at_sel_peer_t peer = {0};
    bool opened = false;
    if (!parsed)
        goto done;
    if (root_hex != NULL && at_sel_unhex(root_hex, root, sizeof(root)) != 0)
    {
        snprintf(err, sizeof(err), "fixtures.root is not 32 bytes of hex");
        goto done;
    }
    if (mkdtemp(dir) == NULL || at_sel_requestor_open(&req, &model, "negotiation", dir, root) != 0)
    {
        snprintf(err, sizeof(err), "cannot open a requestor");
        goto done;
    }
    opened = true;
    json_t *events = json_object_get(fixtures, "events");
    size_t i;
    json_t *ev;
    rc = 0;
    json_array_foreach(events, i, ev)
        if ((rc = _event(&model, &req, &peer, root, (int)i + 1, ev, err, sizeof(err))) != 0)
            break;
done:
    if (opened)
    {
        char path[600];
        snprintf(path, sizeof(path), "%s", req.chain_path);
        unlink(path);
        snprintf(path, sizeof(path), "%s", req.log_path);
        unlink(path);
        at_sel_requestor_close(&req);
        rmdir(dir);
    }
    at_sel_peer_free(&peer);
    clock_gettime(CLOCK_MONOTONIC, &t1);
    int ms = (int)((t1.tv_sec - t0.tv_sec) * 1000 + (t1.tv_nsec - t0.tv_nsec) / 1000000);
    if (rc == 0)
        at_case_result_set_pass(out, ms);
    else
        at_case_result_set_fail(out, ms, "assertion", err[0] ? err : "selection scenario failed");
}
