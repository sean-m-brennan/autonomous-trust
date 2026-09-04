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

#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "certificates/drat.h"

/* One clause: a heap array of non-zero literals. `lits` is NULL for the empty
 * clause, which is legitimate and is what a refutation ends on. */
typedef struct
{
    int *lits;
    int  n;
} clause_t;

typedef struct
{
    clause_t *items;
    int       n;
    int       cap;
} clause_set_t;

/* Variable assignment during propagation: 0 unset, 1 true, -1 false, indexed
 * by variable. Grown to fit the largest variable seen. */
typedef struct
{
    signed char *val;
    int          cap;
} assign_t;

static void _fail(char *buf, size_t len, const char *fmt, ...)
    __attribute__((format(printf, 3, 4)));

static void _fail(char *buf, size_t len, const char *fmt, ...)
{
    if (buf == NULL || len == 0)
        return;
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, len, fmt, ap);
    va_end(ap);
}

static void _clause_free(clause_t *c)
{
    free(c->lits);
    c->lits = NULL;
    c->n = 0;
}

static void _set_free(clause_set_t *set)
{
    for (int i = 0; i < set->n; i++)
        _clause_free(&set->items[i]);
    free(set->items);
    set->items = NULL;
    set->n = set->cap = 0;
}

static bool _set_push(clause_set_t *set, int *lits, int n)
{
    if (set->n >= AT_DRAT_MAX_CLAUSES)
        return false;
    if (set->n == set->cap)
    {
        int cap = set->cap == 0 ? 64 : set->cap * 2;
        clause_t *grown = realloc(set->items, (size_t)cap * sizeof(*grown));
        if (grown == NULL)
            return false;
        set->items = grown;
        set->cap = cap;
    }
    set->items[set->n].lits = lits;
    set->items[set->n].n = n;
    set->n++;
    return true;
}

static void _set_remove(clause_set_t *set, int idx)
{
    _clause_free(&set->items[idx]);
    for (int i = idx; i + 1 < set->n; i++)
        set->items[i] = set->items[i + 1];
    set->n--;
}

/* Coerce one JSON clause to a de-duplicated literal array.
 * Returns  1 on success, 0 for a TAUTOLOGY (contains l and -l, so it
 * constrains nothing and every step may skip it), -1 if malformed. */
static int _normalise(json_t *clause, int **out, int *out_n)
{
    *out = NULL;
    *out_n = 0;
    if (!json_is_array(clause))
        return -1;
    size_t n = json_array_size(clause);
    if (n > AT_DRAT_MAX_CLAUSES)
        return -1;
    int *lits = (n > 0) ? calloc(n, sizeof(int)) : NULL;
    if (n > 0 && lits == NULL)
        return -1;
    int count = 0;
    for (size_t i = 0; i < n; i++)
    {
        json_t *item = json_array_get(clause, i);
        if (!json_is_integer(item))
        {
            free(lits);
            return -1;
        }
        long long v = json_integer_value(item);
        if (v == 0 || v > INT32_MAX || v < INT32_MIN)
        {
            /* DIMACS terminates a clause with 0; inside a JSON list it is not
             * a literal, and dropping it would silently shorten the clause,
             * which changes what the proof proves. */
            free(lits);
            return -1;
        }
        int lit = (int)v;
        bool dup = false;
        for (int j = 0; j < count; j++)
        {
            if (lits[j] == -lit)
            {
                free(lits);
                return 0;              /* tautology */
            }
            if (lits[j] == lit)
                dup = true;
        }
        if (!dup)
            lits[count++] = lit;
    }
    *out = lits;
    *out_n = count;
    return 1;
}

static bool _assign_fit(assign_t *a, int var)
{
    if (var < a->cap)
        return true;
    int cap = a->cap == 0 ? 64 : a->cap;
    while (cap <= var)
        cap *= 2;
    signed char *grown = realloc(a->val, (size_t)cap);
    if (grown == NULL)
        return false;
    memset(grown + a->cap, 0, (size_t)(cap - a->cap));
    a->val = grown;
    a->cap = cap;
    return true;
}

/* Unit-propagate to fixpoint. True if a conflict was reached. */
static bool _propagate(const clause_set_t *set, assign_t *a)
{
    bool changed = true;
    while (changed)
    {
        changed = false;
        for (int ci = 0; ci < set->n; ci++)
        {
            const clause_t *c = &set->items[ci];
            int unassigned = 0;
            int last = 0;
            bool satisfied = false;
            for (int li = 0; li < c->n; li++)
            {
                int lit = c->lits[li];
                int var = lit > 0 ? lit : -lit;
                signed char v = (var < a->cap) ? a->val[var] : 0;
                if (v == 0)
                {
                    unassigned++;
                    last = lit;
                    if (unassigned > 1)
                        break;   /* two free literals: no unit, no conflict */
                }
                else if ((v > 0) == (lit > 0))
                {
                    satisfied = true;
                    break;
                }
            }
            if (satisfied || unassigned > 1)
                continue;
            if (unassigned == 0)
                return true;                   /* every literal false */
            int var = last > 0 ? last : -last;
            if (!_assign_fit(a, var))
                return false;
            a->val[var] = (last > 0) ? 1 : -1;
            changed = true;
        }
    }
    return false;
}

/* True when `lits` is implied by `set` via unit propagation. */
static bool _is_rup(const clause_set_t *set, const int *lits, int n)
{
    assign_t a = {NULL, 0};
    bool conflict = false;
    for (int i = 0; i < n; i++)
    {
        int lit = lits[i];
        int var = lit > 0 ? lit : -lit;
        if (!_assign_fit(&a, var))
        {
            free(a.val);
            return false;
        }
        signed char want = (lit > 0) ? -1 : 1;   /* falsify the literal */
        if (a.val[var] != 0 && a.val[var] != want)
        {
            /* Asserts a literal and its negation: a tautology, vacuously
             * implied. _normalise screens these out of the formula, so this
             * only fires on a resolvent built by hand below. */
            free(a.val);
            return true;
        }
        a.val[var] = want;
    }
    conflict = _propagate(set, &a);
    free(a.val);
    return conflict;
}

/* True when `lits` may be added: RUP, or RAT on its first literal. */
static bool _is_rat(const clause_set_t *set, const int *lits, int n)
{
    if (_is_rup(set, lits, n))
        return true;
    if (n == 0)
        /* The empty clause has no pivot, so RAT does not apply: the only way
         * to end a refutation is for it to be genuinely implied. */
        return false;

    int pivot = lits[0];
    for (int ci = 0; ci < set->n; ci++)
    {
        const clause_t *c = &set->items[ci];
        bool has_neg = false;
        for (int li = 0; li < c->n; li++)
        {
            if (c->lits[li] == -pivot)
            {
                has_neg = true;
                break;
            }
        }
        if (!has_neg)
            continue;

        int cap = n + c->n;
        int *res = calloc((size_t)(cap > 0 ? cap : 1), sizeof(int));
        if (res == NULL)
            return false;
        int rn = 0;
        for (int i = 0; i < n; i++)
        {
            if (lits[i] != pivot)
                res[rn++] = lits[i];
        }
        bool tautology = false;
        for (int li = 0; li < c->n && !tautology; li++)
        {
            int lit = c->lits[li];
            if (lit == -pivot)
                continue;
            bool dup = false;
            for (int j = 0; j < rn; j++)
            {
                if (res[j] == -lit)
                {
                    tautology = true;
                    break;
                }
                if (res[j] == lit)
                    dup = true;
            }
            if (!tautology && !dup)
                res[rn++] = lit;
        }
        bool ok = tautology || _is_rup(set, res, rn);
        free(res);
        if (!ok)
            return false;
    }
    return true;
}

static int _cmp_int(const void *a, const void *b)
{
    int x = *(const int *)a, y = *(const int *)b;
    return (x > y) - (x < y);
}

/* Delete ONE clause matching `lits` as a set. Deleting every duplicate would
 * strip clauses the proof still relies on, and a checker that drops a clause
 * the solver kept can reject a valid proof. */
static void _delete_one(clause_set_t *set, const int *lits, int n)
{
    int *key = (n > 0) ? malloc((size_t)n * sizeof(int)) : NULL;
    if (n > 0 && key == NULL)
        return;
    if (n > 0)
    {
        memcpy(key, lits, (size_t)n * sizeof(int));
        qsort(key, (size_t)n, sizeof(int), _cmp_int);
    }
    for (int ci = 0; ci < set->n; ci++)
    {
        if (set->items[ci].n != n)
            continue;
        int *other = (n > 0) ? malloc((size_t)n * sizeof(int)) : NULL;
        if (n > 0 && other == NULL)
            break;
        if (n > 0)
        {
            memcpy(other, set->items[ci].lits, (size_t)n * sizeof(int));
            qsort(other, (size_t)n, sizeof(int), _cmp_int);
        }
        bool same = (n == 0) || memcmp(key, other, (size_t)n * sizeof(int)) == 0;
        free(other);
        if (same)
        {
            _set_remove(set, ci);
            break;
        }
    }
    free(key);
}

at_drat_result_t at_drat_check(json_t *formula, json_t *proof,
                               int max_proof_len,
                               char *reason, size_t reason_len)
{
    if (reason != NULL && reason_len > 0)
        reason[0] = '\0';
    if (!json_is_array(formula) || !json_is_array(proof))
    {
        _fail(reason, reason_len, "formula and proof must both be arrays");
        return AT_DRAT_MALFORMED;
    }

    clause_set_t set = {NULL, 0, 0};
    at_drat_result_t out = AT_DRAT_INVALID;
    bool derived_empty = false;

    size_t idx;
    json_t *item;
    json_array_foreach(formula, idx, item)
    {
        int *lits = NULL, n = 0;
        int rc = _normalise(item, &lits, &n);
        if (rc < 0)
        {
            _fail(reason, reason_len,
                  "formula clause %zu is not a list of non-zero integers", idx);
            out = AT_DRAT_MALFORMED;
            goto done;
        }
        if (rc == 0)
            continue;                     /* a tautology constrains nothing */
        if (!_set_push(&set, lits, n))
        {
            free(lits);
            _fail(reason, reason_len, "formula exceeds %d clauses",
                  AT_DRAT_MAX_CLAUSES);
            out = AT_DRAT_MALFORMED;
            goto done;
        }
    }

    int steps = 0;
    json_array_foreach(proof, idx, item)
    {
        steps++;
        if (steps > max_proof_len)
        {
            _fail(reason, reason_len, "proof exceeds the declared %d steps",
                  max_proof_len);
            out = AT_DRAT_MALFORMED;
            goto done;
        }
        if (json_is_object(item))
        {
            json_t *target = json_object_get(item, "d");
            if (target == NULL)
            {
                _fail(reason, reason_len,
                      "a proof step object must carry \"d\"");
                out = AT_DRAT_MALFORMED;
                goto done;
            }
            int *lits = NULL, n = 0;
            int rc = _normalise(target, &lits, &n);
            if (rc < 0)
            {
                _fail(reason, reason_len, "deletion step %zu is malformed", idx);
                out = AT_DRAT_MALFORMED;
                goto done;
            }
            if (rc == 1)
                _delete_one(&set, lits, n);
            free(lits);
            continue;
        }

        int *lits = NULL, n = 0;
        int rc = _normalise(item, &lits, &n);
        if (rc < 0)
        {
            _fail(reason, reason_len,
                  "proof step %zu is not a list of non-zero integers", idx);
            out = AT_DRAT_MALFORMED;
            goto done;
        }
        if (rc == 0)
        {
            free(lits);
            continue;                     /* adding a tautology is a no-op */
        }
        if (!_is_rat(&set, lits, n))
        {
            _fail(reason, reason_len,
                  "lemma at step %zu is neither RUP nor RAT against the "
                  "clauses derived before it", idx);
            free(lits);
            out = AT_DRAT_INVALID;
            goto done;
        }
        if (!_set_push(&set, lits, n))
        {
            free(lits);
            _fail(reason, reason_len, "proof grows the formula past %d clauses",
                  AT_DRAT_MAX_CLAUSES);
            out = AT_DRAT_MALFORMED;
            goto done;
        }
        if (n == 0)
            derived_empty = true;
    }

    if (!derived_empty)
    {
        /* The single most important check here. A proof of a hundred sound
         * lemmas that never reaches the empty clause has proved nothing about
         * satisfiability, and accepting it would let a peer claim UNSAT by
         * emitting arbitrary valid inferences. */
        _fail(reason, reason_len, "the proof never derives the empty clause");
        out = AT_DRAT_INVALID;
        goto done;
    }
    out = AT_DRAT_VALID;

done:
    _set_free(&set);
    return out;
}
