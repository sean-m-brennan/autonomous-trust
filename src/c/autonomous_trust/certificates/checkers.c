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

#include <math.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "certificates/checkers.h"
#include "certificates/drat.h"
#include "certificates/rng.h"
#include "utilities/util.h"   /* at_strlcpy */

/****************************
 * Coercion helpers
 *
 * A failure to coerce OUR inputs is INDETERMINATE; a failure to coerce the
 * PEER's answer or witness is INVALID. The callers make that distinction, so
 * these only report whether the shape was usable.
 ****************************/

typedef struct
{
    double *v;
    int     n;
} vec_t;

typedef struct
{
    double *v;     /* row-major, rows*cols */
    int     rows;
    int     cols;
} mat_t;

static void _vec_free(vec_t *v) { free(v->v); v->v = NULL; v->n = 0; }
static void _mat_free(mat_t *m) { free(m->v); m->v = NULL; m->rows = m->cols = 0; }

static void _say(char *buf, size_t len, const char *fmt, ...)
    __attribute__((format(printf, 3, 4)));

static void _say(char *buf, size_t len, const char *fmt, ...)
{
    if (buf == NULL || len == 0)
        return;
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, len, fmt, ap);
    va_end(ap);
}

static bool _is_num(json_t *j)
{
    return json_is_real(j) || json_is_integer(j);
}

static double _num(json_t *j)
{
    return json_is_real(j) ? json_real_value(j)
                           : (double)json_integer_value(j);
}

static bool _get_vec(json_t *j, vec_t *out)
{
    out->v = NULL;
    out->n = 0;
    if (!json_is_array(j))
        return false;
    size_t n = json_array_size(j);
    if (n == 0 || n > AT_CERT_MAX_DIM)
        return false;
    out->v = calloc(n, sizeof(double));
    if (out->v == NULL)
        return false;
    for (size_t i = 0; i < n; i++)
    {
        json_t *item = json_array_get(j, i);
        if (json_is_boolean(item) || !_is_num(item))
        {
            _vec_free(out);
            return false;
        }
        double d = _num(item);
        if (!isfinite(d))
        {
            _vec_free(out);
            return false;
        }
        out->v[i] = d;
    }
    out->n = (int)n;
    return true;
}

static bool _get_mat(json_t *j, mat_t *out)
{
    out->v = NULL;
    out->rows = out->cols = 0;
    if (!json_is_array(j))
        return false;
    size_t rows = json_array_size(j);
    if (rows == 0 || rows > AT_CERT_MAX_DIM)
        return false;
    json_t *first = json_array_get(j, 0);
    if (!json_is_array(first))
        return false;
    size_t cols = json_array_size(first);
    if (cols == 0 || cols > AT_CERT_MAX_DIM)
        return false;
    if (rows * cols > (size_t)AT_CERT_MAX_ELEMENTS)
        return false;
    out->v = calloc(rows * cols, sizeof(double));
    if (out->v == NULL)
        return false;
    for (size_t r = 0; r < rows; r++)
    {
        json_t *row = json_array_get(j, r);
        if (!json_is_array(row) || json_array_size(row) != cols)
        {
            _mat_free(out);
            return false;              /* ragged */
        }
        for (size_t c = 0; c < cols; c++)
        {
            json_t *item = json_array_get(row, c);
            if (json_is_boolean(item) || !_is_num(item))
            {
                _mat_free(out);
                return false;
            }
            double d = _num(item);
            if (!isfinite(d))
            {
                _mat_free(out);
                return false;
            }
            out->v[r * cols + c] = d;
        }
    }
    out->rows = (int)rows;
    out->cols = (int)cols;
    return true;
}

/* Pull a named field out of the peer's answer, tolerating a bare value. */
static json_t *_answer_field(json_t *answer, const char *key)
{
    if (json_is_object(answer))
        return json_object_get(answer, key);
    return answer;
}

static double _dot(const double *a, const double *b, int n)
{
    double total = 0.0;
    for (int i = 0; i < n; i++)
        total += a[i] * b[i];
    return total;
}

/* Canonical text form of a graph node or job id, so the two runtimes compare
 * the same things. Python compares decoded JSON values, where 1 == 1.0; a
 * real that is integral is therefore rendered as an integer here, or the two
 * would disagree about whether a path visits the node it says it does. */
static bool _node_key(json_t *j, char *buf, size_t len)
{
    if (json_is_string(j))
    {
        at_strlcpy(buf, json_string_value(j), len);
        return true;
    }
    if (json_is_integer(j))
    {
        snprintf(buf, len, "%lld", (long long)json_integer_value(j));
        return true;
    }
    if (json_is_real(j))
    {
        double d = json_real_value(j);
        /* An INTEGRAL real renders as an integer, because Python compares the
         * decoded values where 1 == 1.0 -- without this the two runtimes would
         * disagree about whether a path visits the node it names. The test is
         * exact equality on purpose (not a tolerance), spelled as a difference
         * against zero because the strict build refuses `==` on doubles. */
        long long truncated = (long long)d;
        if (isfinite(d) && fabs(d - (double)truncated) <= 0.0)
            snprintf(buf, len, "%lld", truncated);
        else
            snprintf(buf, len, "%.17g", d);
        return true;
    }
    if (json_is_true(j) || json_is_false(j))
        return false;                  /* a bool is not an identifier */
    return false;
}

/****************************
 * Linear algebra
 ****************************/

/* Freivalds' check: A(Br) == Cr for a random r, in O(n^2).
 *
 * The one row of the table needing no witness from the peer at all — the
 * certificate is the VERIFIER's randomness, not the prover's data, which is
 * why the seed must come from the requestor and must not be derivable from the
 * matrices (rng.h). One-sided: a correct product passes every round, a wrong
 * one survives a round with probability at most 1/2, so `repetitions` rounds
 * bound the false-accept rate at 2^-k. It is the only checker here that is
 * probabilistic rather than exact, and the one whose exact alternative —
 * recomputing the product — costs more than the work being verified. */
static at_cert_verdict_t _check_matrix_product(json_t *inputs, json_t *answer,
                                               json_t *certificate,
                                               const at_cert_capability_t *decl,
                                               uint64_t seed,
                                               char *reason, size_t reason_len)
{
    (void)certificate;
    mat_t a = {0}, b = {0}, c = {0};
    at_cert_verdict_t out = AT_CERT_INDETERMINATE;

    if (!_get_mat(json_object_get(inputs, "a"), &a))
    {
        _say(reason, reason_len, "input a is not a usable matrix");
        goto done;
    }
    if (!_get_mat(json_object_get(inputs, "b"), &b))
    {
        _say(reason, reason_len, "input b is not a usable matrix");
        goto done;
    }
    if (a.cols != b.rows)
    {
        _say(reason, reason_len, "input a columns do not match input b rows");
        goto done;
    }
    if (!_get_mat(_answer_field(answer, "c"), &c))
    {
        _say(reason, reason_len, "answer is not a matrix");
        out = AT_CERT_INVALID;
        goto done;
    }
    if (c.rows != a.rows || c.cols != b.cols)
    {
        _say(reason, reason_len, "answer is %dx%d but A*B is %dx%d",
             c.rows, c.cols, a.rows, b.cols);
        out = AT_CERT_INVALID;
        goto done;
    }

    at_splitmix64_t rng;
    at_splitmix64_init(&rng, seed);
    double *r = calloc((size_t)b.cols, sizeof(double));
    double *br = calloc((size_t)b.rows, sizeof(double));
    double *abr = calloc((size_t)a.rows, sizeof(double));
    double *cr = calloc((size_t)c.rows, sizeof(double));
    if (r == NULL || br == NULL || abr == NULL || cr == NULL)
    {
        free(r); free(br); free(abr); free(cr);
        _say(reason, reason_len, "cannot allocate the challenge vectors");
        goto done;
    }
    out = AT_CERT_VALID;
    for (int round = 0; round < decl->repetitions && out == AT_CERT_VALID; round++)
    {
        for (int i = 0; i < b.cols; i++)
            r[i] = at_splitmix64_pm1(&rng);
        for (int i = 0; i < b.rows; i++)
            br[i] = _dot(&b.v[(size_t)i * b.cols], r, b.cols);
        for (int i = 0; i < a.rows; i++)
            abr[i] = _dot(&a.v[(size_t)i * a.cols], br, a.cols);
        for (int i = 0; i < c.rows; i++)
            cr[i] = _dot(&c.v[(size_t)i * c.cols], r, c.cols);
        for (int i = 0; i < a.rows; i++)
        {
            if (fabs(abr[i] - cr[i]) > decl->tolerance)
            {
                _say(reason, reason_len,
                     "Freivalds round %d: row %d differs by %g",
                     round, i, fabs(abr[i] - cr[i]));
                out = AT_CERT_INVALID;
                break;
            }
        }
    }
    free(r); free(br); free(abr); free(cr);

done:
    _mat_free(&a); _mat_free(&b); _mat_free(&c);
    return out;
}

/* Residual check: ||A x - b||_inf <= tolerance. One matrix-vector product
 * against a solve. No witness beyond the solution itself, which is the point:
 * the answer certifies itself, and the interface only had to promise to return
 * x rather than a claim about x. */
static at_cert_verdict_t _check_linear_solve(json_t *inputs, json_t *answer,
                                             json_t *certificate,
                                             const at_cert_capability_t *decl,
                                             uint64_t seed,
                                             char *reason, size_t reason_len)
{
    (void)certificate; (void)seed;
    mat_t a = {0};
    vec_t b = {0}, x = {0};
    at_cert_verdict_t out = AT_CERT_INDETERMINATE;

    if (!_get_mat(json_object_get(inputs, "a"), &a))
    {
        _say(reason, reason_len, "input a is not a usable matrix");
        goto done;
    }
    if (!_get_vec(json_object_get(inputs, "b"), &b))
    {
        _say(reason, reason_len, "input b is not a usable vector");
        goto done;
    }
    if (a.rows != b.n)
    {
        _say(reason, reason_len, "input a rows do not match input b");
        goto done;
    }
    if (!_get_vec(_answer_field(answer, "x"), &x))
    {
        _say(reason, reason_len, "answer is not a vector");
        out = AT_CERT_INVALID;
        goto done;
    }
    if (x.n != a.cols)
    {
        _say(reason, reason_len, "answer has %d entries, A has %d columns",
             x.n, a.cols);
        out = AT_CERT_INVALID;
        goto done;
    }
    double worst = 0.0;
    for (int i = 0; i < a.rows; i++)
    {
        double residual = fabs(_dot(&a.v[(size_t)i * a.cols], x.v, a.cols) - b.v[i]);
        if (residual > worst)
            worst = residual;
    }
    if (worst > decl->tolerance)
    {
        _say(reason, reason_len,
             "residual norm %g exceeds the declared tolerance %g",
             worst, decl->tolerance);
        out = AT_CERT_INVALID;
    }
    else
        out = AT_CERT_VALID;

done:
    _mat_free(&a); _vec_free(&b); _vec_free(&x);
    return out;
}

/* Linear programming, in the canonical primal form
 *
 *     minimise  c.x   subject to   A x >= b,  x >= 0
 *
 * Two things can be certified, and the certificate says which:
 *
 *   {"dual": y}    Optimality. Weak duality gives c.x >= b.y for any feasible
 *                  pair, so a feasible x and a dual-feasible y whose
 *                  objectives MEET proves both optimal. That is the whole
 *                  proof — no re-solving, no trusting the solver, linear in
 *                  the size of the problem.
 *   {"farkas": y}  Infeasibility. By Farkas' lemma the system has no solution
 *                  exactly when some y >= 0 has A'y <= 0 and b.y > 0. A peer
 *                  answering "infeasible" is otherwise making the one claim
 *                  that cannot be checked by inspecting an answer, because
 *                  there is no answer to inspect. */
static at_cert_verdict_t _check_lp(json_t *inputs, json_t *answer,
                                   json_t *certificate,
                                   const at_cert_capability_t *decl,
                                   uint64_t seed,
                                   char *reason, size_t reason_len)
{
    (void)seed;
    mat_t a = {0};
    vec_t b = {0}, c = {0}, x = {0}, y = {0};
    at_cert_verdict_t out = AT_CERT_INDETERMINATE;
    const double tol = decl->tolerance;

    if (!_get_mat(json_object_get(inputs, "a"), &a))
    {
        _say(reason, reason_len, "input a is not a usable matrix");
        goto done;
    }
    if (!_get_vec(json_object_get(inputs, "b"), &b) ||
        !_get_vec(json_object_get(inputs, "c"), &c))
    {
        _say(reason, reason_len, "inputs b and c must both be vectors");
        goto done;
    }
    if (a.rows != b.n)
    {
        _say(reason, reason_len, "input a rows do not match input b");
        goto done;
    }
    if (a.cols != c.n)
    {
        _say(reason, reason_len, "input a columns do not match input c");
        goto done;
    }

    json_t *infeasible = json_is_object(answer)
        ? json_object_get(answer, "infeasible") : NULL;
    if (json_is_true(infeasible))
    {
        if (!_get_vec(json_object_get(certificate, "farkas"), &y))
        {
            _say(reason, reason_len,
                 "infeasibility claimed without a Farkas witness");
            out = AT_CERT_INVALID;
            goto done;
        }
        if (y.n != a.rows)
        {
            _say(reason, reason_len,
                 "Farkas certificate length does not match A rows");
            out = AT_CERT_INVALID;
            goto done;
        }
        out = AT_CERT_VALID;
        for (int i = 0; i < y.n; i++)
        {
            if (y.v[i] < -tol)
            {
                _say(reason, reason_len,
                     "Farkas certificate entry %d is negative", i);
                out = AT_CERT_INVALID;
                goto done;
            }
        }
        for (int j = 0; j < a.cols; j++)
        {
            double col = 0.0;
            for (int i = 0; i < a.rows; i++)
                col += a.v[(size_t)i * a.cols + j] * y.v[i];
            if (col > tol)
            {
                _say(reason, reason_len,
                     "Farkas certificate violates (A' y)[%d] <= 0 by %g", j, col);
                out = AT_CERT_INVALID;
                goto done;
            }
        }
        double by = _dot(b.v, y.v, b.n);
        if (by <= tol)
        {
            _say(reason, reason_len,
                 "Farkas certificate has b.y = %g, which does not exceed zero",
                 by);
            out = AT_CERT_INVALID;
        }
        goto done;
    }

    if (!_get_vec(_answer_field(answer, "x"), &x))
    {
        _say(reason, reason_len, "answer is not a primal solution");
        out = AT_CERT_INVALID;
        goto done;
    }
    if (x.n != a.cols)
    {
        _say(reason, reason_len, "answer length does not match A columns");
        out = AT_CERT_INVALID;
        goto done;
    }
    for (int j = 0; j < x.n; j++)
    {
        if (x.v[j] < -tol)
        {
            _say(reason, reason_len, "primal solution entry %d is negative", j);
            out = AT_CERT_INVALID;
            goto done;
        }
    }
    for (int i = 0; i < a.rows; i++)
    {
        double ax = _dot(&a.v[(size_t)i * a.cols], x.v, a.cols);
        if (ax < b.v[i] - tol)
        {
            _say(reason, reason_len,
                 "primal solution violates constraint %d by %g", i, b.v[i] - ax);
            out = AT_CERT_INVALID;
            goto done;
        }
    }
    if (!decl->require_optimal)
    {
        out = AT_CERT_VALID;
        goto done;
    }
    if (!_get_vec(json_object_get(certificate, "dual"), &y))
    {
        _say(reason, reason_len, "optimality claimed without a dual");
        out = AT_CERT_INVALID;
        goto done;
    }
    if (y.n != a.rows)
    {
        _say(reason, reason_len, "dual certificate length does not match A rows");
        out = AT_CERT_INVALID;
        goto done;
    }
    for (int i = 0; i < y.n; i++)
    {
        if (y.v[i] < -tol)
        {
            _say(reason, reason_len, "dual entry %d is negative", i);
            out = AT_CERT_INVALID;
            goto done;
        }
    }
    for (int j = 0; j < a.cols; j++)
    {
        double col = 0.0;
        for (int i = 0; i < a.rows; i++)
            col += a.v[(size_t)i * a.cols + j] * y.v[i];
        if (col > c.v[j] + tol)
        {
            _say(reason, reason_len,
                 "dual violates (A' y)[%d] <= c[%d] by %g", j, j, col - c.v[j]);
            out = AT_CERT_INVALID;
            goto done;
        }
    }
    {
        double gap = fabs(_dot(c.v, x.v, c.n) - _dot(b.v, y.v, b.n));
        if (gap > tol)
        {
            _say(reason, reason_len,
                 "duality gap %g exceeds the declared tolerance %g", gap, tol);
            out = AT_CERT_INVALID;
        }
        else
            out = AT_CERT_VALID;
    }

done:
    _mat_free(&a); _vec_free(&b); _vec_free(&c); _vec_free(&x); _vec_free(&y);
    return out;
}

/****************************
 * Combinatorial
 ****************************/

#define NODE_KEY_LEN 96

typedef struct
{
    char   u[NODE_KEY_LEN];
    char   v[NODE_KEY_LEN];
    double w;
} edge_t;

/* Read [[u, v, w], ...] into a heap array, keeping the CHEAPEST parallel edge
 * (the only one a shortest path would use, and the only one the potential has
 * to admit) or SUMMING capacities for a flow. */
static edge_t *_get_edges(json_t *j, int *n_out, bool sum_parallel)
{
    *n_out = 0;
    if (!json_is_array(j) || json_array_size(j) == 0)
        return NULL;
    size_t n = json_array_size(j);
    if (n > (size_t)AT_CERT_MAX_DIM * 4)
        return NULL;
    edge_t *edges = calloc(n, sizeof(edge_t));
    if (edges == NULL)
        return NULL;
    int count = 0;
    for (size_t i = 0; i < n; i++)
    {
        json_t *e = json_array_get(j, i);
        if (!json_is_array(e) || json_array_size(e) != 3)
        {
            free(edges);
            return NULL;
        }
        edge_t cur;
        memset(&cur, 0, sizeof(cur));
        json_t *w = json_array_get(e, 2);
        if (!_node_key(json_array_get(e, 0), cur.u, sizeof(cur.u)) ||
            !_node_key(json_array_get(e, 1), cur.v, sizeof(cur.v)) ||
            json_is_boolean(w) || !_is_num(w) || !isfinite(_num(w)))
        {
            free(edges);
            return NULL;
        }
        cur.w = _num(w);
        int found = -1;
        for (int k = 0; k < count; k++)
        {
            if (strcmp(edges[k].u, cur.u) == 0 && strcmp(edges[k].v, cur.v) == 0)
            {
                found = k;
                break;
            }
        }
        if (found < 0)
            edges[count++] = cur;
        else if (sum_parallel)
            edges[found].w += cur.w;
        else if (cur.w < edges[found].w)
            edges[found].w = cur.w;
    }
    *n_out = count;
    return edges;
}

/* A path, plus a feasible potential proving it is shortest.
 *
 * The optimality half is where a naive interface goes wrong. "The path, plus
 * an admissible lower bound" is the standard phrasing, but a bound the peer
 * merely ASSERTS certifies nothing — a peer returning a detour can assert a
 * bound equal to its own cost and call itself optimal. What is checkable is
 * the bound's own witness: a feasible POTENTIAL, the LP dual of shortest path.
 * Node prices pi with pi[v] - pi[u] <= w(u,v) on every edge make
 * pi[target] - pi[source] a valid lower bound on ANY source-target path,
 * verifiable in one pass over the edges. A path whose cost meets that bound is
 * optimal, and no assertion is taken on trust. */
static at_cert_verdict_t _check_path(json_t *inputs, json_t *answer,
                                     json_t *certificate,
                                     const at_cert_capability_t *decl,
                                     uint64_t seed,
                                     char *reason, size_t reason_len)
{
    (void)seed;
    int n_edges = 0;
    edge_t *edges = _get_edges(json_object_get(inputs, "edges"), &n_edges, false);
    at_cert_verdict_t out = AT_CERT_INDETERMINATE;
    char source[NODE_KEY_LEN] = {0}, target[NODE_KEY_LEN] = {0};

    if (edges == NULL)
    {
        _say(reason, reason_len, "input edges are not a usable edge list");
        return AT_CERT_INDETERMINATE;
    }
    if (!_node_key(json_object_get(inputs, "source"), source, sizeof(source)) ||
        !_node_key(json_object_get(inputs, "target"), target, sizeof(target)))
    {
        _say(reason, reason_len, "inputs must name a source and a target");
        goto done;
    }

    json_t *path = _answer_field(answer, "path");
    if (!json_is_array(path) || json_array_size(path) == 0)
    {
        _say(reason, reason_len, "answer is not a path");
        out = AT_CERT_INVALID;
        goto done;
    }
    size_t plen = json_array_size(path);
    if (plen > (size_t)AT_CERT_MAX_DIM * 4)
    {
        _say(reason, reason_len, "answer path is too long");
        out = AT_CERT_INVALID;
        goto done;
    }
    char first[NODE_KEY_LEN] = {0}, last[NODE_KEY_LEN] = {0};
    if (!_node_key(json_array_get(path, 0), first, sizeof(first)) ||
        !_node_key(json_array_get(path, plen - 1), last, sizeof(last)))
    {
        _say(reason, reason_len, "path endpoints are not identifiers");
        out = AT_CERT_INVALID;
        goto done;
    }
    if (strcmp(first, source) != 0 || strcmp(last, target) != 0)
    {
        _say(reason, reason_len, "path runs %s -> %s, not %s -> %s",
             first, last, source, target);
        out = AT_CERT_INVALID;
        goto done;
    }

    double cost = 0.0;
    for (size_t i = 0; i + 1 < plen; i++)
    {
        char u[NODE_KEY_LEN] = {0}, v[NODE_KEY_LEN] = {0};
        if (!_node_key(json_array_get(path, i), u, sizeof(u)) ||
            !_node_key(json_array_get(path, i + 1), v, sizeof(v)))
        {
            _say(reason, reason_len, "path contains a non-identifier");
            out = AT_CERT_INVALID;
            goto done;
        }
        int found = -1;
        for (int k = 0; k < n_edges; k++)
        {
            if (strcmp(edges[k].u, u) == 0 && strcmp(edges[k].v, v) == 0)
            {
                found = k;
                break;
            }
        }
        if (found < 0)
        {
            _say(reason, reason_len, "path uses a non-existent edge (%s, %s)",
                 u, v);
            out = AT_CERT_INVALID;
            goto done;
        }
        cost += edges[found].w;
    }

    if (!decl->require_optimal)
    {
        out = AT_CERT_VALID;
        goto done;
    }

    json_t *potential = json_object_get(certificate, "potential");
    if (!json_is_object(potential) || json_object_size(potential) == 0)
    {
        _say(reason, reason_len,
             "optimality claimed without a feasible potential; a bare lower "
             "bound is an assertion, not a witness");
        out = AT_CERT_INVALID;
        goto done;
    }
    const double tol = decl->tolerance;
    for (int k = 0; k < n_edges; k++)
    {
        json_t *ju = json_object_get(potential, edges[k].u);
        json_t *jv = json_object_get(potential, edges[k].v);
        if (ju == NULL || jv == NULL || json_is_boolean(ju) ||
            json_is_boolean(jv) || !_is_num(ju) || !_is_num(jv) ||
            !isfinite(_num(ju)) || !isfinite(_num(jv)))
        {
            _say(reason, reason_len,
                 "potential omits or mistypes an endpoint of edge (%s, %s), "
                 "so it bounds nothing", edges[k].u, edges[k].v);
            out = AT_CERT_INVALID;
            goto done;
        }
        if (_num(jv) - _num(ju) > edges[k].w + tol)
        {
            _say(reason, reason_len,
                 "potential is infeasible on edge (%s, %s): %g > %g",
                 edges[k].u, edges[k].v, _num(jv) - _num(ju), edges[k].w);
            out = AT_CERT_INVALID;
            goto done;
        }
    }
    json_t *ps = json_object_get(potential, source);
    json_t *pt = json_object_get(potential, target);
    if (ps == NULL || pt == NULL || !_is_num(ps) || !_is_num(pt))
    {
        _say(reason, reason_len, "potential omits the source or the target");
        out = AT_CERT_INVALID;
        goto done;
    }
    {
        double lower = _num(pt) - _num(ps);
        if (cost > lower + tol)
        {
            _say(reason, reason_len,
                 "path costs %g but the potential proves a lower bound of only "
                 "%g, so optimality is not established", cost, lower);
            out = AT_CERT_INVALID;
        }
        else
            out = AT_CERT_VALID;
    }

done:
    free(edges);
    return out;
}

/* A feasible flow, plus a cut whose capacity meets its value.
 *
 * Max-flow min-cut: any s-t cut's capacity bounds any s-t flow's value, so a
 * flow and a cut that agree are simultaneously maximum and minimum. Both
 * halves are checked — feasibility (capacity and conservation) and optimality
 * (the cut) — because a feasible flow alone certifies only that the peer
 * returned A flow. */
static at_cert_verdict_t _check_flow(json_t *inputs, json_t *answer,
                                     json_t *certificate,
                                     const at_cert_capability_t *decl,
                                     uint64_t seed,
                                     char *reason, size_t reason_len)
{
    (void)seed;
    int n_edges = 0;
    edge_t *edges = _get_edges(json_object_get(inputs, "edges"), &n_edges, true);
    double *flow = NULL;
    char (*nodes)[NODE_KEY_LEN] = NULL;
    double *net = NULL;
    at_cert_verdict_t out = AT_CERT_INDETERMINATE;
    char source[NODE_KEY_LEN] = {0}, sink[NODE_KEY_LEN] = {0};

    if (edges == NULL)
    {
        _say(reason, reason_len, "input edges are not a usable edge list");
        return AT_CERT_INDETERMINATE;
    }
    if (!_node_key(json_object_get(inputs, "source"), source, sizeof(source)) ||
        !_node_key(json_object_get(inputs, "sink"), sink, sizeof(sink)))
    {
        _say(reason, reason_len, "inputs must name a source and a sink");
        goto done;
    }
    if (strcmp(source, sink) == 0)
    {
        _say(reason, reason_len, "source and sink are the same node");
        goto done;
    }

    flow = calloc((size_t)n_edges, sizeof(double));
    nodes = calloc((size_t)n_edges * 2, sizeof(*nodes));
    net = calloc((size_t)n_edges * 2, sizeof(double));
    if (flow == NULL || nodes == NULL || net == NULL)
    {
        _say(reason, reason_len, "cannot allocate the flow tables");
        goto done;
    }

    json_t *raw = _answer_field(answer, "flow");
    if (!json_is_array(raw))
    {
        _say(reason, reason_len, "answer carries no flow assignment");
        out = AT_CERT_INVALID;
        goto done;
    }
    const double tol = decl->tolerance;
    size_t i;
    json_t *entry;
    json_array_foreach(raw, i, entry)
    {
        if (!json_is_array(entry) || json_array_size(entry) != 3)
        {
            _say(reason, reason_len, "flow entries must be [u, v, f]");
            out = AT_CERT_INVALID;
            goto done;
        }
        char u[NODE_KEY_LEN] = {0}, v[NODE_KEY_LEN] = {0};
        json_t *jf = json_array_get(entry, 2);
        if (!_node_key(json_array_get(entry, 0), u, sizeof(u)) ||
            !_node_key(json_array_get(entry, 1), v, sizeof(v)) ||
            json_is_boolean(jf) || !_is_num(jf) || !isfinite(_num(jf)))
        {
            _say(reason, reason_len, "flow value must be a finite number");
            out = AT_CERT_INVALID;
            goto done;
        }
        int found = -1;
        for (int k = 0; k < n_edges; k++)
        {
            if (strcmp(edges[k].u, u) == 0 && strcmp(edges[k].v, v) == 0)
            {
                found = k;
                break;
            }
        }
        if (found < 0)
        {
            _say(reason, reason_len, "flow on a non-existent edge (%s, %s)", u, v);
            out = AT_CERT_INVALID;
            goto done;
        }
        flow[found] += _num(jf);
    }
    for (int k = 0; k < n_edges; k++)
    {
        if (flow[k] < -tol || flow[k] > edges[k].w + tol)
        {
            _say(reason, reason_len,
                 "flow %g on edge (%s, %s) is outside [0, %g]",
                 flow[k], edges[k].u, edges[k].v, edges[k].w);
            out = AT_CERT_INVALID;
            goto done;
        }
    }

    int n_nodes = 0;
    for (int k = 0; k < n_edges; k++)
    {
        const char *ends[2] = {edges[k].u, edges[k].v};
        for (int e = 0; e < 2; e++)
        {
            int found = -1;
            for (int m = 0; m < n_nodes; m++)
            {
                if (strcmp(nodes[m], ends[e]) == 0)
                {
                    found = m;
                    break;
                }
            }
            if (found < 0)
            {
                at_strlcpy(nodes[n_nodes], ends[e], NODE_KEY_LEN);
                found = n_nodes++;
            }
            net[found] += (e == 0) ? -flow[k] : flow[k];
        }
    }
    double value = 0.0;
    for (int m = 0; m < n_nodes; m++)
    {
        if (strcmp(nodes[m], source) == 0)
        {
            value = -net[m];
            continue;
        }
        if (strcmp(nodes[m], sink) == 0)
            continue;
        if (fabs(net[m]) > tol)
        {
            _say(reason, reason_len, "flow is not conserved at %s: net %g",
                 nodes[m], net[m]);
            out = AT_CERT_INVALID;
            goto done;
        }
    }
    {
        json_t *claimed = json_is_object(answer)
            ? json_object_get(answer, "value") : NULL;
        if (claimed != NULL && !json_is_boolean(claimed) && _is_num(claimed))
        {
            if (fabs(_num(claimed) - value) > tol)
            {
                _say(reason, reason_len,
                     "claimed value %g does not match the flow out of the "
                     "source, %g", _num(claimed), value);
                out = AT_CERT_INVALID;
                goto done;
            }
        }
    }

    if (!decl->require_optimal)
    {
        out = AT_CERT_VALID;
        goto done;
    }
    json_t *cut = json_object_get(certificate, "cut");
    if (!json_is_array(cut))
    {
        _say(reason, reason_len, "optimality claimed without a cut witness");
        out = AT_CERT_INVALID;
        goto done;
    }
    bool has_source = false, has_sink = false;
    json_array_foreach(cut, i, entry)
    {
        char key[NODE_KEY_LEN] = {0};
        if (!_node_key(entry, key, sizeof(key)))
            continue;
        if (strcmp(key, source) == 0)
            has_source = true;
        if (strcmp(key, sink) == 0)
            has_sink = true;
    }
    if (!has_source)
    {
        _say(reason, reason_len, "the cut does not contain the source");
        out = AT_CERT_INVALID;
        goto done;
    }
    if (has_sink)
    {
        _say(reason, reason_len, "the cut contains the sink");
        out = AT_CERT_INVALID;
        goto done;
    }
    {
        double cut_capacity = 0.0;
        for (int k = 0; k < n_edges; k++)
        {
            bool u_in = false, v_in = false;
            json_array_foreach(cut, i, entry)
            {
                char key[NODE_KEY_LEN] = {0};
                if (!_node_key(entry, key, sizeof(key)))
                    continue;
                if (strcmp(key, edges[k].u) == 0)
                    u_in = true;
                if (strcmp(key, edges[k].v) == 0)
                    v_in = true;
            }
            if (u_in && !v_in)
                cut_capacity += edges[k].w;
        }
        if (fabs(cut_capacity - value) > tol)
        {
            _say(reason, reason_len,
                 "cut capacity %g does not meet the flow value %g, so "
                 "maximality is not established", cut_capacity, value);
            out = AT_CERT_INVALID;
        }
        else
            out = AT_CERT_VALID;
    }

done:
    free(edges); free(flow); free(nodes); free(net);
    return out;
}

/* Start times, plus the makespan they achieve.
 *
 * Feasibility is three linear passes — non-negative starts, precedences
 * respected, and no instant with more jobs running than there are machines.
 * The capacity test only has to examine job START times: occupancy changes
 * only when something starts, so if no start instant is over capacity, no
 * instant is.
 *
 * The makespan in the certificate is checked against the schedule rather than
 * trusted. A peer that under-reports its own makespan is claiming a better
 * schedule than it produced, which is the failure mode worth catching. */
typedef struct
{
    char   id[NODE_KEY_LEN];
    double duration;
    double start;
    bool   scheduled;
} job_t;

static at_cert_verdict_t _check_schedule(json_t *inputs, json_t *answer,
                                         json_t *certificate,
                                         const at_cert_capability_t *decl,
                                         uint64_t seed,
                                         char *reason, size_t reason_len)
{
    (void)seed;
    json_t *jobs_in = json_object_get(inputs, "jobs");
    if (!json_is_array(jobs_in) || json_array_size(jobs_in) == 0 ||
        json_array_size(jobs_in) > (size_t)AT_CERT_MAX_DIM)
    {
        _say(reason, reason_len, "inputs must carry a usable job list");
        return AT_CERT_INDETERMINATE;
    }
    int n_jobs = (int)json_array_size(jobs_in);
    job_t *jobs = calloc((size_t)n_jobs, sizeof(job_t));
    if (jobs == NULL)
        return AT_CERT_INDETERMINATE;
    at_cert_verdict_t out = AT_CERT_INDETERMINATE;

    size_t i;
    json_t *item;
    json_array_foreach(jobs_in, i, item)
    {
        json_t *dur = json_is_object(item) ? json_object_get(item, "duration") : NULL;
        /* Keyed by the id AS TEXT: start times arrive as a JSON object, whose
         * keys are strings by construction, so an integer job id would never
         * match its own start and every schedule would read as missing one. */
        if (!json_is_object(item) ||
            !_node_key(json_object_get(item, "id"), jobs[i].id, NODE_KEY_LEN) ||
            json_is_boolean(dur) || !_is_num(dur) || !isfinite(_num(dur)) ||
            _num(dur) < 0)
        {
            _say(reason, reason_len, "a job has no usable id and duration");
            goto done;
        }
        jobs[i].duration = _num(dur);
    }
    json_t *jcap = json_object_get(inputs, "capacity");
    int capacity = 1;
    if (jcap != NULL)
    {
        if (json_is_boolean(jcap) || !json_is_integer(jcap) ||
            json_integer_value(jcap) < 1)
        {
            _say(reason, reason_len, "capacity must be a positive integer");
            goto done;
        }
        capacity = (int)json_integer_value(jcap);
    }

    json_t *starts = _answer_field(answer, "start");
    if (!json_is_object(starts) || json_object_size(starts) == 0)
    {
        _say(reason, reason_len, "answer carries no start times");
        out = AT_CERT_INVALID;
        goto done;
    }
    const double tol = decl->tolerance;
    const char *key;
    json_t *val;
    json_object_foreach(starts, key, val)
    {
        if (json_is_boolean(val) || !_is_num(val) || !isfinite(_num(val)))
        {
            _say(reason, reason_len, "start time for %s is not a finite number",
                 key);
            out = AT_CERT_INVALID;
            goto done;
        }
        int found = -1;
        for (int k = 0; k < n_jobs; k++)
        {
            if (strcmp(jobs[k].id, key) == 0)
            {
                found = k;
                break;
            }
        }
        if (found < 0)
        {
            _say(reason, reason_len, "answer schedules an unknown job %s", key);
            out = AT_CERT_INVALID;
            goto done;
        }
        jobs[found].start = _num(val);
        jobs[found].scheduled = true;
    }
    for (int k = 0; k < n_jobs; k++)
    {
        if (!jobs[k].scheduled)
        {
            _say(reason, reason_len, "no start time for job %s", jobs[k].id);
            out = AT_CERT_INVALID;
            goto done;
        }
        if (jobs[k].start < -tol)
        {
            _say(reason, reason_len, "job %s starts before zero", jobs[k].id);
            out = AT_CERT_INVALID;
            goto done;
        }
    }

    json_t *precedences = json_object_get(inputs, "precedences");
    if (precedences != NULL && !json_is_null(precedences))
    {
        if (!json_is_array(precedences))
        {
            _say(reason, reason_len,
                 "precedences must be a list of [before, after]");
            goto done;
        }
        json_array_foreach(precedences, i, item)
        {
            char before[NODE_KEY_LEN] = {0}, after[NODE_KEY_LEN] = {0};
            if (!json_is_array(item) || json_array_size(item) != 2 ||
                !_node_key(json_array_get(item, 0), before, NODE_KEY_LEN) ||
                !_node_key(json_array_get(item, 1), after, NODE_KEY_LEN))
            {
                _say(reason, reason_len,
                     "precedences must be [before, after] pairs");
                goto done;
            }
            int bi = -1, ai = -1;
            for (int k = 0; k < n_jobs; k++)
            {
                if (strcmp(jobs[k].id, before) == 0) bi = k;
                if (strcmp(jobs[k].id, after) == 0)  ai = k;
            }
            if (bi < 0 || ai < 0)
            {
                _say(reason, reason_len, "a precedence names an unknown job");
                goto done;
            }
            if (jobs[ai].start < jobs[bi].start + jobs[bi].duration - tol)
            {
                _say(reason, reason_len,
                     "job %s starts at %g, before %s finishes at %g",
                     jobs[ai].id, jobs[ai].start, jobs[bi].id,
                     jobs[bi].start + jobs[bi].duration);
                out = AT_CERT_INVALID;
                goto done;
            }
        }
    }

    for (int k = 0; k < n_jobs; k++)
    {
        int running = 0;
        for (int m = 0; m < n_jobs; m++)
        {
            if ((jobs[m].start <= jobs[k].start + tol &&
                 jobs[k].start + tol < jobs[m].start + jobs[m].duration - tol) ||
                /* A zero-duration job occupies only its own instant, so it
                 * is counted at that instant alone. Durations are validated
                 * non-negative above, so `<= 0.0` is exactly "is zero" and
                 * avoids the `==` the strict build refuses. */
                (jobs[m].duration <= 0.0 &&
                 fabs(jobs[m].start - jobs[k].start) <= tol))
                running++;
        }
        if (running > capacity)
        {
            _say(reason, reason_len,
                 "%d jobs run at t=%g but capacity is %d", running,
                 jobs[k].start, capacity);
            out = AT_CERT_INVALID;
            goto done;
        }
    }

    double makespan = 0.0;
    for (int k = 0; k < n_jobs; k++)
    {
        double end = jobs[k].start + jobs[k].duration;
        if (end > makespan)
            makespan = end;
    }
    {
        json_t *claimed = json_object_get(certificate, "makespan");
        if (claimed != NULL && !json_is_boolean(claimed) && _is_num(claimed) &&
            fabs(_num(claimed) - makespan) > tol)
        {
            _say(reason, reason_len,
                 "claimed makespan %g does not match the schedule, which "
                 "finishes at %g", _num(claimed), makespan);
            out = AT_CERT_INVALID;
            goto done;
        }
        json_t *deadline = json_object_get(inputs, "deadline");
        if (deadline != NULL && !json_is_boolean(deadline) && _is_num(deadline) &&
            makespan > _num(deadline) + tol)
        {
            _say(reason, reason_len,
                 "schedule finishes at %g, past the deadline %g",
                 makespan, _num(deadline));
            out = AT_CERT_INVALID;
            goto done;
        }
    }
    out = AT_CERT_VALID;

done:
    free(jobs);
    return out;
}

/****************************
 * SAT
 ****************************/

/* A satisfying assignment, or a DRAT refutation.
 *
 * The asymmetry is why this row is in the table. SAT is certified in one line
 * — exhibit the assignment, evaluate the clauses — while UNSAT admits no such
 * object and is exactly the answer a lying peer gives for free. drat.c supplies
 * the other half. */
static at_cert_verdict_t _check_sat(json_t *inputs, json_t *answer,
                                    json_t *certificate,
                                    const at_cert_capability_t *decl,
                                    uint64_t seed,
                                    char *reason, size_t reason_len)
{
    (void)seed;
    json_t *cnf = json_object_get(inputs, "cnf");
    if (!json_is_array(cnf) || json_array_size(cnf) == 0)
    {
        _say(reason, reason_len, "inputs must carry a non-empty CNF");
        return AT_CERT_INDETERMINATE;
    }
    json_t *claim = _answer_field(answer, "sat");
    if (claim == NULL || !json_is_boolean(claim))
    {
        _say(reason, reason_len,
             "answer does not state whether the formula is satisfiable");
        return AT_CERT_INVALID;
    }

    if (json_is_true(claim))
    {
        json_t *assignment = json_object_get(certificate, "assignment");
        if (!json_is_array(assignment))
        {
            _say(reason, reason_len,
                 "satisfiability claimed without an assignment");
            return AT_CERT_INVALID;
        }
        size_t n = json_array_size(assignment);
        long long *lits = (n > 0) ? calloc(n, sizeof(long long)) : NULL;
        if (n > 0 && lits == NULL)
            return AT_CERT_INDETERMINATE;
        for (size_t i = 0; i < n; i++)
        {
            json_t *item = json_array_get(assignment, i);
            if (!json_is_integer(item) || json_integer_value(item) == 0)
            {
                free(lits);
                _say(reason, reason_len,
                     "assignment must be non-zero integer literals");
                return AT_CERT_INVALID;
            }
            lits[i] = json_integer_value(item);
            for (size_t j = 0; j < i; j++)
            {
                if (lits[j] == -lits[i])
                {
                    _say(reason, reason_len,
                         "assignment sets both %lld and %lld",
                         (long long)lits[i], (long long)-lits[i]);
                    free(lits);
                    return AT_CERT_INVALID;
                }
            }
        }
        size_t ci;
        json_t *clause;
        json_array_foreach(cnf, ci, clause)
        {
            if (!json_is_array(clause))
            {
                free(lits);
                _say(reason, reason_len, "each CNF clause must be a list");
                return AT_CERT_INDETERMINATE;
            }
            bool satisfied = false;
            size_t li;
            json_t *lit;
            json_array_foreach(clause, li, lit)
            {
                if (!json_is_integer(lit))
                    continue;
                for (size_t k = 0; k < n; k++)
                {
                    if (lits[k] == json_integer_value(lit))
                    {
                        satisfied = true;
                        break;
                    }
                }
                if (satisfied)
                    break;
            }
            if (!satisfied)
            {
                free(lits);
                _say(reason, reason_len,
                     "assignment leaves clause %zu unsatisfied", ci);
                return AT_CERT_INVALID;
            }
        }
        free(lits);
        return AT_CERT_VALID;
    }

    json_t *proof = json_object_get(certificate, "proof");
    if (!json_is_array(proof))
    {
        _say(reason, reason_len,
             "unsatisfiability claimed without a refutation; \"I searched and "
             "found nothing\" is not a witness");
        return AT_CERT_INVALID;
    }
    char why[AT_CERT_ERR_LEN] = {0};
    at_drat_result_t rc = at_drat_check(cnf, proof, decl->max_proof_len,
                                        why, sizeof(why));
    if (rc == AT_DRAT_VALID)
        return AT_CERT_VALID;
    /* A malformed proof is the PEER's blob, not our inputs: a failed
     * certificate, not something we were unable to check. */
    _say(reason, reason_len, "%s%s",
         rc == AT_DRAT_MALFORMED ? "malformed refutation: " : "", why);
    return AT_CERT_INVALID;
}

/****************************
 * Estimation
 ****************************/

/* Whiteness of the innovation sequence.
 *
 * The one row of the table yielding a BOUND rather than a proof, and worth
 * being plain about. A well-behaved estimator leaves innovations that are
 * serially uncorrelated; correlation at short lags means the filter is
 * mis-specified or the reported sequence was not produced by the filter
 * claimed. Neither is a contradiction, so this verdict is weaker in kind than
 * the others here — but it is the standard test, and an estimator that fails
 * it is not delivering what it says it is. */
static at_cert_verdict_t _check_state_estimation(json_t *inputs, json_t *answer,
                                                 json_t *certificate,
                                                 const at_cert_capability_t *decl,
                                                 uint64_t seed,
                                                 char *reason, size_t reason_len)
{
    (void)inputs; (void)certificate; (void)seed;
    vec_t seq = {0};
    if (!_get_vec(_answer_field(answer, "innovations"), &seq))
    {
        _say(reason, reason_len, "answer carries no innovation sequence");
        return AT_CERT_INVALID;
    }
    at_cert_verdict_t out = AT_CERT_VALID;
    if (seq.n <= decl->max_lag + 1)
    {
        _say(reason, reason_len, "sequence of %d is too short for %d lags",
             seq.n, decl->max_lag);
        out = AT_CERT_INDETERMINATE;
        goto done;
    }
    double mean = 0.0;
    for (int i = 0; i < seq.n; i++)
        mean += seq.v[i];
    mean /= (double)seq.n;
    for (int i = 0; i < seq.n; i++)
        seq.v[i] -= mean;
    double denom = 0.0;
    for (int i = 0; i < seq.n; i++)
        denom += seq.v[i] * seq.v[i];
    if (denom <= 0.0)
    {
        _say(reason, reason_len, "the sequence is constant, so it has no spectrum");
        out = AT_CERT_INDETERMINATE;
        goto done;
    }
    for (int lag = 1; lag <= decl->max_lag; lag++)
    {
        double numer = 0.0;
        for (int i = 0; i + lag < seq.n; i++)
            numer += seq.v[i] * seq.v[i + lag];
        double rho = numer / denom;
        if (fabs(rho) > decl->bound)
        {
            _say(reason, reason_len,
                 "innovations correlate at lag %d (rho = %g, bound %g), so the "
                 "sequence is not white", lag, rho, decl->bound);
            out = AT_CERT_INVALID;
            goto done;
        }
    }

done:
    _vec_free(&seq);
    return out;
}

/****************************
 * Dispatch
 ****************************/

static const struct
{
    const char *kind;
    at_cert_checker_fn fn;
} CHECKER_TABLE[] = {
    {"lp",               _check_lp},
    {"sat",              _check_sat},
    {"path",             _check_path},
    {"linear_solve",     _check_linear_solve},
    {"matrix_product",   _check_matrix_product},
    {"schedule",         _check_schedule},
    {"flow",             _check_flow},
    {"state_estimation", _check_state_estimation},
};

at_cert_checker_fn at_cert_checker_for(const char *kind)
{
    if (kind == NULL || kind[0] == '\0')
        return NULL;
    for (size_t i = 0; i < sizeof(CHECKER_TABLE) / sizeof(CHECKER_TABLE[0]); i++)
    {
        if (strcmp(CHECKER_TABLE[i].kind, kind) == 0)
            return CHECKER_TABLE[i].fn;
    }
    return NULL;
}

bool at_cert_self_certifying(const char *kind)
{
    if (kind == NULL)
        return false;
    return strcmp(kind, "matrix_product") == 0 ||
           strcmp(kind, "linear_solve") == 0 ||
           strcmp(kind, "state_estimation") == 0;
}
