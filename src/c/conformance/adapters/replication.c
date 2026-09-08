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
 * Non-message-driven, like the physics, calibration and prequential adapters:
 * the scenario carries a declaration (fixtures.replication) and a list of
 * events; this loads the declaration into this runtime's sampler and evaluates
 * each event in order. The decision is one SplitMix64 draw against a
 * probability, so what is pinned is that the two runtimes compute the SAME
 * draw and fall the same way -- a task one replicates and the other skips would
 * let a peer's exposure depend on which implementation was watching (R+D.md
 * §12.6; doc/verification_oracle.md build-order step 6).
 */

#include "replication.h"

#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <jansson.h>

#include "replication/adjudication.h"
#include "replication/bisection.h"
#include "replication/replication.h"
#include "replication/sampling.h"

/* Draw comparison tolerance. The draw is exact power-of-two-scaled integer
 * arithmetic, so this is tight; it exists only so a pinned literal need not
 * carry all 17 digits. Mirrors the Python adapter's TOL. */
#define AT_REPL_TOL 1e-12

/* Build one result value the way the adjudicator compares it: a JSON number
 * becomes numeric, everything else a canonical string, and the two never agree
 * (Python's 42 == "42" is false). Mirrors the Python adapter passing the raw
 * value to adjudicate(), whose _agree keeps numbers and non-numbers apart. */
static void _fill_result(at_repl_result_t *r, const char *peer, json_t *value)
{
    memset(r, 0, sizeof(*r));
    snprintf(r->peer, sizeof(r->peer), "%s", peer ? peer : "");
    if (json_is_number(value))
    {
        r->is_number = true;
        r->num = json_number_value(value);
    }
    else if (json_is_string(value))
    {
        r->is_number = false;
        snprintf(r->text, sizeof(r->text), "%s", json_string_value(value));
    }
    else
    {
        /* bool/null/array/object: a compact canonical form, structural like
         * Python's ==. Scenarios keep to numbers and strings; this is the
         * honest fallback rather than a silent miscompare. */
        r->is_number = false;
        char *t = value ? json_dumps(value, JSON_COMPACT | JSON_SORT_KEYS)
                        : NULL;
        if (t != NULL)
        {
            snprintf(r->text, sizeof(r->text), "%s", t);
            free(t);
        }
    }
}

/* Shared verdict/score assertion for the adjudicate and bisect events. Every
 * named peer must match its computed verdict, and the scored peers must be
 * EXACTLY those the `scores` map names -- a verdict that maps to no score must
 * be absent, which is what pins the dispute/single case. */
static int _check_vs(json_t *event, int index, const char *const *peers,
                     const at_repl_verdict_t *verdicts, size_t n,
                     char *err, size_t err_len)
{
    json_t *want_v = json_object_get(event, "verdicts");
    if (json_is_object(want_v))
    {
        if (json_object_size(want_v) != n)
        {
            snprintf(err, err_len,
                     "event %d: verdicts names %zu peers, expected %zu",
                     index, json_object_size(want_v), n);
            return -1;
        }
        for (size_t i = 0; i < n; i++)
        {
            const char *got = at_replication_verdict_str(verdicts[i]);
            const char *w = json_string_value(json_object_get(want_v, peers[i]));
            if (w == NULL || strcmp(got, w) != 0)
            {
                snprintf(err, err_len,
                         "event %d: %.63s verdict=%s, expected %.63s",
                         index, peers[i], got, w ? w : "(unset)");
                return -1;
            }
        }
    }

    json_t *want_s = json_object_get(event, "scores");
    if (json_is_object(want_s))
    {
        size_t scored = 0;
        for (size_t i = 0; i < n; i++)
        {
            double sc;
            const char *ch;
            if (!at_replication_verify(verdicts[i], &sc, &ch))
                continue;
            scored++;
            json_t *wj = json_object_get(want_s, peers[i]);
            if (!json_is_array(wj) || json_array_size(wj) != 2)
            {
                snprintf(err, err_len,
                         "event %d: %.63s scored (%.2f,%.63s) but not in "
                         "expected scores", index, peers[i], sc, ch);
                return -1;
            }
            double ws = json_number_value(json_array_get(wj, 0));
            const char *wc = json_string_value(json_array_get(wj, 1));
            if (fabs(sc - ws) > AT_REPL_TOL || wc == NULL
                || strcmp(ch, wc) != 0)
            {
                snprintf(err, err_len,
                         "event %d: %.63s score=(%.17g,%.40s), expected "
                         "(%.17g,%.40s)", index, peers[i], sc, ch, ws,
                         wc ? wc : "(null)");
                return -1;
            }
        }
        if (scored != json_object_size(want_s))
        {
            snprintf(err, err_len,
                     "event %d: %zu scored, expected %zu", index, scored,
                     json_object_size(want_s));
            return -1;
        }
    }
    return 0;
}

static int _run_adjudicate(const at_replication_model_t *model, json_t *event,
                           int index, char *err, size_t err_len)
{
    json_t *spec = json_object_get(event, "adjudicate");
    const char *cap = json_string_value(json_object_get(spec, "capability"));
    json_t *tol_j = json_object_get(spec, "tolerance");
    double tol = json_is_number(tol_j)
                     ? json_number_value(tol_j)
                     : at_replication_tolerance_for(model, cap);

    json_t *results = json_object_get(spec, "results");
    size_t n = json_is_array(results) ? json_array_size(results) : 0;
    if (n > 32)
    {
        snprintf(err, err_len, "event %d: too many results (%zu)", index, n);
        return -1;
    }
    at_repl_result_t rs[32];
    for (size_t i = 0; i < n; i++)
    {
        json_t *r = json_array_get(results, i);
        _fill_result(&rs[i], json_string_value(json_object_get(r, "peer")),
                     json_object_get(r, "value"));
    }
    at_repl_verdict_t verdicts[32];
    at_replication_adjudicate(rs, n, tol, verdicts);

    const char *peers[32];
    for (size_t i = 0; i < n; i++)
        peers[i] = rs[i].peer;
    return _check_vs(event, index, peers, verdicts, n, err, err_len);
}

/* Extract a JSON array of string tokens into a borrowed const char* array
 * (pointers into the live JSON). Returns the count, capped at AT_REPL_MAX_STEPS. */
static size_t _string_array(json_t *arr, const char **out, size_t cap)
{
    size_t n = json_is_array(arr) ? json_array_size(arr) : 0;
    if (n > cap)
        n = cap;
    for (size_t i = 0; i < n; i++)
        out[i] = json_string_value(json_array_get(arr, i));
    return n;
}

static int _run_bisect(json_t *event, int index, char *err, size_t err_len)
{
    json_t *spec = json_object_get(event, "bisect");
    json_t *traces = json_object_get(spec, "traces");
    if (!json_is_object(traces) || json_object_size(traces) != 2)
    {
        snprintf(err, err_len,
                 "event %d: bisect needs exactly two traces", index);
        return -1;
    }
    /* the two executors, in the object's own order (verdicts are per-peer and
     * order-independent, but the peers[] must line up with the verdicts[]). */
    const char *peer_a = NULL;
    const char *peer_b = NULL;
    json_t *trace_a = NULL;
    json_t *trace_b = NULL;
    const char *key;
    json_t *val;
    json_object_foreach(traces, key, val)
    {
        if (peer_a == NULL) { peer_a = key; trace_a = val; }
        else                { peer_b = key; trace_b = val; }
    }

    const char *sa[AT_REPL_MAX_STEPS];
    const char *sb[AT_REPL_MAX_STEPS];
    const char *ref[AT_REPL_MAX_STEPS];
    size_t na = _string_array(trace_a, sa, AT_REPL_MAX_STEPS);
    size_t nb = _string_array(trace_b, sb, AT_REPL_MAX_STEPS);
    size_t nref = _string_array(json_object_get(spec, "reference"), ref,
                                AT_REPL_MAX_STEPS);

    int k = -1;
    bool diverged = false;
    at_repl_verdict_t va, vb;
    if (!at_replication_bisect_adjudicate(sa, na, sb, nb, ref, nref,
                                          &k, &diverged, &va, &vb))
    {
        snprintf(err, err_len, "event %d: bisect failed (trace too long?)",
                 index);
        return -1;
    }

    json_t *want_k = json_object_get(event, "divergence_index");
    if (want_k != NULL)
    {
        /* null pins "never diverged"; an integer pins the step. */
        if (json_is_null(want_k))
        {
            if (diverged)
            {
                snprintf(err, err_len,
                         "event %d: divergence_index=%d, expected null",
                         index, k);
                return -1;
            }
        }
        else
        {
            int wk = (int)json_integer_value(want_k);
            if (!diverged)
            {
                snprintf(err, err_len,
                         "event %d: divergence_index=none, expected %d",
                         index, wk);
                return -1;
            }
            if (k != wk)
            {
                snprintf(err, err_len,
                         "event %d: divergence_index=%d, expected %d",
                         index, k, wk);
                return -1;
            }
        }
    }

    json_t *want_roots = json_object_get(event, "roots");
    if (json_is_object(want_roots))
    {
        const char *rk;
        json_t *rv;
        json_object_foreach(want_roots, rk, rv)
        {
            const char **states = (strcmp(rk, peer_a) == 0) ? sa
                                : (strcmp(rk, peer_b) == 0) ? sb : NULL;
            size_t ns = (states == sa) ? na : (states == sb) ? nb : 0;
            char root[AT_REPL_HASH_HEX_LEN + 1];
            const char *want = json_string_value(rv);
            if (states == NULL || !at_replication_commit_root(states, ns, root))
            {
                snprintf(err, err_len,
                         "event %d: roots names %.40s, not a trace or empty",
                         index, rk);
                return -1;
            }
            if (want == NULL || strcmp(root, want) != 0)
            {
                snprintf(err, err_len,
                         "event %d: root[%.20s]=%.16s..., expected %.16s...",
                         index, rk, root, want ? want : "(null)");
                return -1;
            }
        }
    }

    const char *peers[2] = {peer_a, peer_b};
    at_repl_verdict_t verdicts[2] = {va, vb};
    return _check_vs(event, index, peers, verdicts, 2, err, err_len);
}

void at_replication_conformance_run(const at_case_t *c, at_case_result_t *out)
{
    if (strcmp(c->kind, "scenario") != 0)
    {
        char detail[160];
        snprintf(detail, sizeof(detail),
                 "C replication adapter only handles kind:scenario (got %s)",
                 c->kind);
        at_case_result_set_skip(out, detail);
        return;
    }

    struct timespec t0, t1;
    clock_gettime(CLOCK_MONOTONIC, &t0);
    char err[512] = {0};
    int rc = -1;

    json_t *fixtures = json_object_get(c->data, "fixtures");
    json_t *decl = fixtures ? json_object_get(fixtures, "replication") : NULL;
    if (!json_is_object(decl))
    {
        snprintf(err, sizeof(err),
                 "replication scenario needs fixtures.replication");
        goto done;
    }

    char *decl_text = json_dumps(decl, JSON_COMPACT);
    if (decl_text == NULL)
    {
        snprintf(err, sizeof(err), "cannot re-encode fixtures.replication");
        goto done;
    }
    at_replication_model_t model;
    char model_err[512] = {0};
    bool parsed = at_replication_model_parse(decl_text, &model, model_err,
                                             sizeof(model_err));
    free(decl_text);
    if (!parsed)
    {
        snprintf(err, sizeof(err), "fixtures.replication rejected: %s",
                 model_err);
        goto done;
    }

    json_t *events = fixtures ? json_object_get(fixtures, "events") : NULL;
    size_t i;
    json_t *event;
    json_array_foreach(events, i, event)
    {
        int index = (int)i + 1;
        json_t *sample = json_object_get(event, "sample");
        json_t *prob_field = json_object_get(event, "prob");
        json_t *cap_field = json_object_get(event, "capability");

        if (json_is_object(sample))
        {
            const char *cap =
                json_string_value(json_object_get(sample, "capability"));
            json_t *seed_j = json_object_get(sample, "seed");
            if (!json_is_integer(seed_j))
            {
                snprintf(err, sizeof(err), "event %d: sample needs a seed",
                         index);
                goto done;
            }
            uint64_t seed = (uint64_t)json_integer_value(seed_j);
            json_t *ovr = json_object_get(sample, "prob");
            double prob = json_is_number(ovr)
                              ? json_number_value(ovr)
                              : at_replication_prob_for(&model, cap);
            double draw = 0.0;
            bool decision =
                at_replication_should_replicate(prob, seed, &draw);

            json_t *want_rep = json_object_get(event, "replicate");
            if (want_rep != NULL)
            {
                bool expected = json_is_true(want_rep);
                if (decision != expected)
                {
                    snprintf(err, sizeof(err),
                             "event %d: replicate=%s, expected %s "
                             "(prob=%g, seed=%llu, draw=%.17g)",
                             index, decision ? "True" : "False",
                             expected ? "True" : "False", prob,
                             (unsigned long long)seed, draw);
                    goto done;
                }
            }
            json_t *want_draw = json_object_get(event, "draw");
            if (json_is_number(want_draw))
            {
                double w = json_number_value(want_draw);
                if (fabs(draw - w) > AT_REPL_TOL)
                {
                    snprintf(err, sizeof(err),
                             "event %d: draw=%.17g, expected %.17g",
                             index, draw, w);
                    goto done;
                }
            }
            json_t *want_ep = json_object_get(event, "effective_prob");
            if (json_is_number(want_ep))
            {
                double w = json_number_value(want_ep);
                if (fabs(prob - w) > AT_REPL_TOL)
                {
                    snprintf(err, sizeof(err),
                             "event %d: effective_prob=%.17g, expected %.17g",
                             index, prob, w);
                    goto done;
                }
            }
        }
        else if (json_is_object(json_object_get(event, "adjudicate")))
        {
            if (_run_adjudicate(&model, event, index, err, sizeof(err)) != 0)
                goto done;
        }
        else if (json_is_object(json_object_get(event, "bisect")))
        {
            if (_run_bisect(event, index, err, sizeof(err)) != 0)
                goto done;
        }
        else if (json_is_number(prob_field) && json_is_string(cap_field))
        {
            const char *cap = json_string_value(cap_field);
            double want = json_number_value(prob_field);
            double actual = at_replication_prob_for(&model, cap);
            if (fabs(actual - want) > AT_REPL_TOL)
            {
                snprintf(err, sizeof(err),
                         "event %d: prob_for('%s')=%.17g, expected %.17g",
                         index, cap ? cap : "(null)", actual, want);
                goto done;
            }
        }
        else
        {
            snprintf(err, sizeof(err), "event %d: unrecognised event", index);
            goto done;
        }
    }
    rc = 0;

done:
    clock_gettime(CLOCK_MONOTONIC, &t1);
    int ms = (int)((t1.tv_sec - t0.tv_sec) * 1000
                   + (t1.tv_nsec - t0.tv_nsec) / 1000000);
    if (rc == 0)
        at_case_result_set_pass(out, ms);
    else
        at_case_result_set_fail(out, ms, "AssertionError", err);
}
