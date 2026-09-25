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

#include <jansson.h>

#include "physics/physics.h"
#include "utilities/util.h"   /* at_strlcpy */

#define AT_PHYSICS_ENV "AT_PHYSICS"

/* Cap on the number of conflicts fed to the exhaustive search. Minimal hitting
 * set is NP-hard in general and the enumeration branches on every conflict;
 * real conflict sets here are a handful, so the cap guards against a
 * pathological window rather than a normal limit. Past it the verdict narrows
 * to the singleton test (see _diagnose), which can turn a REFUTED into an
 * IMPLICATED but never the reverse — an overloaded window costs evidence
 * rather than manufacturing it. */
#define AT_PHYS_MAX_CONFLICTS 16

/* Room for the hitting sets of AT_PHYS_MAX_CONFLICTS conflicts. Bounded by the
 * product of the conflict sizes; the enumeration stops writing (and the
 * diagnosis falls back) if it would overflow. */
#define AT_PHYS_MAX_DIAGNOSES 256

static void _err(char *buf, size_t len, const char *fmt, ...)
    __attribute__((format(printf, 3, 4)));

static void _err(char *buf, size_t len, const char *fmt, ...)
{
    if (buf == NULL || len == 0)
        return;
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, len, fmt, ap);
    va_end(ap);
}

/****************************
 * Declaration parsing
 ****************************/

static bool _num_field(json_t *obj, const char *key, double *out)
{
    json_t *v = json_object_get(obj, key);
    if (v == NULL || json_is_null(v))
        return false;
    if (json_is_real(v))
        *out = json_real_value(v);
    else if (json_is_integer(v))
        *out = (double)json_integer_value(v);
    else
        return false;
    return true;
}

static int _quantity_index(const at_physics_model_t *model, const char *name)
{
    for (int i = 0; i < model->n_quantities; i++)
    {
        if (strcmp(model->quantities[i].name, name) == 0)
            return i;
    }
    return -1;
}

static int _capability_index(const at_physics_model_t *model, const char *cap)
{
    if (cap == NULL || cap[0] == '\0')
        return -1;
    for (int i = 0; i < model->n_quantities; i++)
    {
        if (strcmp(model->quantities[i].capability, cap) == 0)
            return i;
    }
    return -1;
}

static bool _parse_quantities(json_t *root, at_physics_model_t *out,
                              char *err, size_t errlen)
{
    json_t *quantities = json_object_get(root, "quantities");
    if (quantities == NULL || json_is_null(quantities))
        return true;
    if (!json_is_object(quantities))
    {
        _err(err, errlen, "\"quantities\" must be an object");
        return false;
    }

    const char *name;
    json_t *spec;
    json_object_foreach(quantities, name, spec)
    {
        if (out->n_quantities >= AT_PHYS_MAX_QUANTITIES)
        {
            _err(err, errlen, "more than %d quantities declared",
                 AT_PHYS_MAX_QUANTITIES);
            return false;
        }
        if (!json_is_object(spec))
        {
            _err(err, errlen, "quantity '%s': must be an object", name);
            return false;
        }
        at_phys_quantity_t *q = &out->quantities[out->n_quantities];
        memset(q, 0, sizeof(*q));
        at_strlcpy(q->name, name, sizeof(q->name));

        const char *cap = json_string_value(json_object_get(spec, "capability"));
        if (cap == NULL || cap[0] == '\0')
        {
            _err(err, errlen,
                 "quantity '%s': \"capability\" is required (it is how a task "
                 "result is matched to a quantity)", name);
            return false;
        }
        if (_capability_index(out, cap) >= 0)
        {
            _err(err, errlen,
                 "quantity '%s': capability '%s' is already reported by "
                 "another quantity; a capability may report only one", name, cap);
            return false;
        }
        at_strlcpy(q->capability, cap, sizeof(q->capability));

        const char *unit = json_string_value(json_object_get(spec, "unit"));
        at_strlcpy(q->unit, unit != NULL ? unit : "", sizeof(q->unit));
        char uerr[AT_UNIT_ERR_LEN] = {0};
        if (!at_parse_unit(q->unit, &q->dimension, uerr, sizeof(uerr)))
        {
            _err(err, errlen, "quantity '%s': %s", name, uerr);
            return false;
        }

        q->components = 1;
        json_t *comp = json_object_get(spec, "components");
        if (json_is_integer(comp))
            q->components = (int)json_integer_value(comp);
        if (q->components < 1 || q->components > AT_PHYS_MAX_COMPONENTS)
        {
            _err(err, errlen, "quantity '%s': components must be 1..%d", name,
                 AT_PHYS_MAX_COMPONENTS);
            return false;
        }

        double v;
        if (_num_field(spec, "min", &v))
        {
            q->has_min = true;
            q->si_min = at_dimension_to_si(&q->dimension, v);
        }
        if (_num_field(spec, "max", &v))
        {
            q->has_max = true;
            q->si_max = at_dimension_to_si(&q->dimension, v);
        }
        if (q->has_min && q->has_max && q->si_min > q->si_max)
        {
            _err(err, errlen, "quantity '%s': min exceeds max", name);
            return false;
        }
        /* A RATE is a difference per second, so the offset cancels and only
         * the scale applies. Using at_dimension_to_si here would add 273.15
         * K/s to every Celsius rate bound — the error the affine-unit refusal
         * in units.c exists to make loud elsewhere. */
        if (_num_field(spec, "max_rate", &v))
        {
            if (v < 0)
            {
                _err(err, errlen, "quantity '%s': max_rate must be >= 0", name);
                return false;
            }
            q->has_max_rate = true;
            q->si_max_rate = v * q->dimension.scale;
        }
        if (_num_field(spec, "max_accel", &v))
        {
            if (v < 0)
            {
                _err(err, errlen, "quantity '%s': max_accel must be >= 0", name);
                return false;
            }
            q->has_max_accel = true;
            q->si_max_accel = v * q->dimension.scale;
        }
        if (_num_field(spec, "tolerance", &v))
        {
            if (v < 0)
            {
                _err(err, errlen, "quantity '%s': tolerance must be >= 0", name);
                return false;
            }
            q->si_tolerance = v * q->dimension.scale;  /* half-width: scale only */
        }
        out->n_quantities++;
    }
    return true;
}

/* Sort a relation's terms by quantity NAME. Floating point addition is not
 * associative, so the two runtimes must sum a residual in the same order or
 * they can land on different sides of a tolerance. Python sorts by name; this
 * is that sort, on an array small enough that insertion sort is the honest
 * choice. */
static void _sort_terms(at_phys_relation_t *rel, const at_physics_model_t *model)
{
    for (int i = 1; i < rel->n_terms; i++)
    {
        int    qi = rel->term_quantity[i];
        double ci = rel->term_coeff[i];
        int j = i - 1;
        while (j >= 0 && strcmp(model->quantities[rel->term_quantity[j]].name,
                                model->quantities[qi].name) > 0)
        {
            rel->term_quantity[j + 1] = rel->term_quantity[j];
            rel->term_coeff[j + 1] = rel->term_coeff[j];
            j--;
        }
        rel->term_quantity[j + 1] = qi;
        rel->term_coeff[j + 1] = ci;
    }
}

static bool _parse_relations(json_t *root, at_physics_model_t *out,
                             char *err, size_t errlen)
{
    json_t *relations = json_object_get(root, "relations");
    if (relations == NULL || json_is_null(relations))
        return true;
    if (!json_is_array(relations))
    {
        _err(err, errlen, "\"relations\" must be a list");
        return false;
    }

    size_t idx;
    json_t *spec;
    json_array_foreach(relations, idx, spec)
    {
        if (out->n_relations >= AT_PHYS_MAX_RELATIONS)
        {
            _err(err, errlen, "more than %d relations declared",
                 AT_PHYS_MAX_RELATIONS);
            return false;
        }
        at_phys_relation_t *rel = &out->relations[out->n_relations];
        memset(rel, 0, sizeof(*rel));
        const char *rname = json_is_object(spec)
            ? json_string_value(json_object_get(spec, "name")) : NULL;
        if (rname != NULL)
            at_strlcpy(rel->name, rname, sizeof(rel->name));
        else
            snprintf(rel->name, sizeof(rel->name), "relation[%zu]", idx);

        if (!json_is_object(spec))
        {
            _err(err, errlen, "relation '%s': must be an object", rel->name);
            return false;
        }
        json_t *terms = json_object_get(spec, "terms");
        if (!json_is_object(terms) || json_object_size(terms) == 0)
        {
            _err(err, errlen, "relation '%s': \"terms\" must be a non-empty "
                              "object", rel->name);
            return false;
        }

        const char *qname;
        json_t *coeff;
        int ref = -1;
        json_object_foreach(terms, qname, coeff)
        {
            if (rel->n_terms >= AT_PHYS_MAX_TERMS)
            {
                _err(err, errlen, "relation '%s': more than %d terms",
                     rel->name, AT_PHYS_MAX_TERMS);
                return false;
            }
            int qi = _quantity_index(out, qname);
            if (qi < 0)
            {
                _err(err, errlen,
                     "relation '%s': term names undeclared quantity '%s'",
                     rel->name, qname);
                return false;
            }
            if (out->quantities[qi].components != 1)
            {
                /* A parity relation sums scalars. A vector quantity would need
                 * a relation per component and a rule for which components
                 * pair up, which is more model than this form carries — and
                 * guessing it would produce residuals nobody declared. */
                _err(err, errlen,
                     "relation '%s': term '%s' has %d components; a parity "
                     "relation is over scalar quantities", rel->name, qname,
                     out->quantities[qi].components);
                return false;
            }
            if (ref < 0)
                ref = qi;
            else if (!at_same_dimension(&out->quantities[ref].dimension,
                                        &out->quantities[qi].dimension))
            {
                /* The check that makes the residual mean anything. Summing a
                 * power and a temperature has no physical content, and finding
                 * that out at load is the difference between an operator error
                 * and a peer refuted by arithmetic on nonsense. */
                char da[64], db[64];
                _err(err, errlen,
                     "relation '%s': term '%s' has dimension %s but the "
                     "relation is over %s; every term of a parity relation "
                     "must share one dimension", rel->name, qname,
                     at_dimension_str(&out->quantities[qi].dimension, da, sizeof da),
                     at_dimension_str(&out->quantities[ref].dimension, db, sizeof db));
                return false;
            }
            double c;
            if (json_is_real(coeff))
                c = json_real_value(coeff);
            else if (json_is_integer(coeff))
                c = (double)json_integer_value(coeff);
            else
            {
                _err(err, errlen,
                     "relation '%s': coefficient for '%s' must be a number",
                     rel->name, qname);
                return false;
            }
            rel->term_quantity[rel->n_terms] = qi;
            rel->term_coeff[rel->n_terms] = c;
            rel->n_terms++;
        }
        _sort_terms(rel, out);

        double v;
        if (_num_field(spec, "constant", &v))
            rel->constant = v;
        if (_num_field(spec, "tolerance", &v))
        {
            if (v < 0)
            {
                _err(err, errlen, "relation '%s': tolerance must be >= 0",
                     rel->name);
                return false;
            }
            rel->tolerance = v;
        }
        if (_num_field(spec, "window_sec", &v))
        {
            if (v <= 0)
            {
                _err(err, errlen, "relation '%s': window_sec must be > 0",
                     rel->name);
                return false;
            }
            rel->has_window = true;
            rel->window_sec = v;
        }
        out->n_relations++;
    }
    return true;
}

bool at_physics_model_parse(const char *json_text, at_physics_model_t *out,
                            char *err, size_t errlen)
{
    if (out == NULL)
        return false;
    memset(out, 0, sizeof(*out));
    out->window_sec = 60.0;
    out->max_observations = AT_PHYS_MAX_OBS;
    if (json_text == NULL || json_text[0] == '\0')
        return true;

    json_error_t jerr;
    json_t *root = json_loads(json_text, 0, &jerr);
    if (root == NULL)
    {
        _err(err, errlen, "cannot parse: %s (line %d)", jerr.text, jerr.line);
        return false;
    }
    bool ok = false;
    do
    {
        if (!json_is_object(root))
        {
            _err(err, errlen, "physics declaration must be an object");
            break;
        }
        json_t *ver = json_object_get(root, "version");
        if (ver != NULL && json_is_integer(ver) && json_integer_value(ver) != 1)
        {
            _err(err, errlen, "unsupported physics declaration version %lld",
                 (long long)json_integer_value(ver));
            break;
        }
        double v;
        if (_num_field(root, "window_sec", &v))
        {
            if (v <= 0)
            {
                _err(err, errlen, "window_sec must be positive");
                break;
            }
            out->window_sec = v;
        }
        json_t *maxobs = json_object_get(root, "max_observations");
        if (json_is_integer(maxobs))
        {
            long long m = json_integer_value(maxobs);
            if (m < 2)
            {
                /* Rate needs two samples and acceleration three; refusing a
                 * store too small to hold them is better than silently never
                 * checking a rate. */
                _err(err, errlen, "max_observations must be at least 2");
                break;
            }
            out->max_observations =
                (m > AT_PHYS_MAX_OBS) ? AT_PHYS_MAX_OBS : (int)m;
        }
        if (!_parse_quantities(root, out, err, errlen))
            break;
        if (!_parse_relations(root, out, err, errlen))
            break;
        ok = true;
    } while (0);
    json_decref(root);
    if (!ok)
        memset(out, 0, sizeof(*out));
    return ok;
}

bool at_physics_model_load(const char *path, at_physics_model_t *out,
                           char *err, size_t errlen)
{
    if (out == NULL)
        return false;
    if (path == NULL || path[0] == '\0')
        path = getenv(AT_PHYSICS_ENV);
    if (path == NULL || path[0] == '\0')
    {
        /* Not configured: the EMPTY model, and every check says nothing. */
        return at_physics_model_parse(NULL, out, err, errlen);
    }
    FILE *fp = fopen(path, "rb");
    if (fp == NULL)
    {
        _err(err, errlen, "%s names %s, which cannot be opened",
             AT_PHYSICS_ENV, path);
        memset(out, 0, sizeof(*out));
        return false;
    }
    char *text = NULL;
    size_t len = 0;
    bool ok = false;
    if (fseek(fp, 0, SEEK_END) == 0)
    {
        long size = ftell(fp);
        if (size >= 0 && size < (1 << 20) && fseek(fp, 0, SEEK_SET) == 0)
        {
            text = calloc((size_t)size + 1, 1);
            if (text != NULL)
            {
                len = fread(text, 1, (size_t)size, fp);
                text[len] = '\0';
                ok = true;
            }
        }
    }
    fclose(fp);
    if (!ok)
    {
        _err(err, errlen, "%s: cannot read declaration", path);
        free(text);
        memset(out, 0, sizeof(*out));
        return false;
    }
    ok = at_physics_model_parse(text, out, err, errlen);
    free(text);
    return ok;
}

/****************************
 * Checker lifecycle
 ****************************/

/* Emptying the store is `store_peers[q] = 0`, NOT a memset of the rows.
 *
 * Deliberate, and worth the sentence: the store is over a megabyte, and
 * zeroing it would fault in every page of it on every node — including the
 * overwhelming majority that never enable the layer at all, since it is
 * opt-in. An opt-in feature that costs a megabyte of resident memory when it
 * is off is not opt-in in the way that matters. Nothing reads a row before
 * `store_peers[q]` admits it exists (`_hist` scans only that far, and zeroes a
 * row when it creates one), so the counts are the whole of the state. */
static void _empty_store(at_physics_checker_t *checker)
{
    memset(checker->store_peers, 0, sizeof(checker->store_peers));
}

void at_physics_checker_init(at_physics_checker_t *checker,
                             const at_physics_model_t *model)
{
    if (checker == NULL)
        return;
    if (model != NULL)
        checker->model = *model;
    else
        at_physics_model_parse(NULL, &checker->model, NULL, 0);
    _empty_store(checker);
}

void at_physics_checker_reset(at_physics_checker_t *checker)
{
    if (checker == NULL)
        return;
    _empty_store(checker);
}

bool at_physics_checker_enabled(const at_physics_checker_t *checker)
{
    return checker != NULL && checker->model.n_quantities > 0;
}

/****************************
 * Observation store
 ****************************/

static at_phys_peer_hist_t *_hist(at_physics_checker_t *c, int qi,
                                  const char *peer, bool create)
{
    if (peer == NULL || peer[0] == '\0')
        return NULL;
    for (int i = 0; i < c->store_peers[qi]; i++)
    {
        if (strcmp(c->store[qi][i].peer, peer) == 0)
            return &c->store[qi][i];
    }
    if (!create || c->store_peers[qi] >= AT_PHYS_MAX_PEERS)
        return NULL;
    at_phys_peer_hist_t *h = &c->store[qi][c->store_peers[qi]++];
    memset(h, 0, sizeof(*h));
    at_strlcpy(h->peer, peer, sizeof(h->peer));
    return h;
}

/* Effective ring depth: the declaration's max_observations, clamped to what the
 * fixed-size ring can hold. The declaration is honoured rather than ignored
 * because the Python twin uses it as its deque's maxlen -- nothing reads deeper
 * than two samples today, so the two cannot yet disagree, and that is exactly
 * why the divergence would go unnoticed until something did. */
static int _ring_depth(const at_physics_checker_t *c)
{
    int d = c->model.max_observations;
    if (d < 2)
        d = 2;
    if (d > AT_PHYS_MAX_OBS)
        d = AT_PHYS_MAX_OBS;
    return d;
}

/* Most recent observation, or NULL. `back` 0 is the newest, 1 the one before. */
static const at_phys_obs_t *_recent(const at_phys_peer_hist_t *h, int back,
                                    int depth)
{
    if (h == NULL || h->count <= back || back >= depth)
        return NULL;
    int idx = ((h->head - 1 - back) % depth + depth) % depth;
    return &h->obs[idx];
}

static void _record(at_physics_checker_t *c, int qi, const char *peer,
                    const double *si, int n, double t)
{
    at_phys_peer_hist_t *h = _hist(c, qi, peer, true);
    if (h == NULL)
        return;
    int depth = _ring_depth(c);
    at_phys_obs_t *o = &h->obs[h->head];
    memset(o, 0, sizeof(*o));
    o->t = t;
    for (int i = 0; i < n && i < AT_PHYS_MAX_COMPONENTS; i++)
        o->values[i] = si[i];
    h->head = (h->head + 1) % depth;
    if (h->count < depth)
        h->count++;
}

static double _norm(const double *a, const double *b, int n)
{
    double sum = 0.0;
    for (int i = 0; i < n; i++)
    {
        double d = a[i] - b[i];
        sum += d * d;
    }
    return sqrt(sum);
}

/****************************
 * Diagnosis (Reiter 1987; de Kleer & Williams 1987)
 *
 * A conflict is a set of peers who cannot ALL be reporting honestly; a
 * diagnosis is a minimal hitting set over the conflicts. Bitmasks in both
 * runtimes on purpose: peers are indexed by first appearance across the
 * conflict list and a set is one word, so the Python twin (which uses ints the
 * same way) enumerates the same sets in the same order and the two cannot
 * disagree about a diagnosis.
 *
 * SUBSET-minimal, not cardinality-minimal. The usual GDE refinement prefers
 * the smallest diagnosis, which would refute a lone outlier whenever two other
 * peers corroborate each other — conflicts {A,C} and {B,C} have minimal
 * diagnoses {C} and {A,B}, and taking the smaller convicts C. That is majority
 * rule wearing physics' clothes, and R+D.md §12.8 is explicit that a majority
 * is not an oracle. Keeping every subset-minimal diagnosis leaves C
 * IMPLICATED, which is the true statement.
 ****************************/

typedef struct
{
    const uint64_t *conflicts;
    int n_conflicts;
    uint64_t *out;
    int out_cap;
    int n_out;
    bool overflow;
} hs_state_t;

static void _hs_rec(hs_state_t *st, int idx, uint64_t current)
{
    if (st->overflow)
        return;
    while (idx < st->n_conflicts && (st->conflicts[idx] & current))
        idx++;
    if (idx == st->n_conflicts)
    {
        if (st->n_out >= st->out_cap)
        {
            st->overflow = true;
            return;
        }
        st->out[st->n_out++] = current;
        return;
    }
    uint64_t remaining = st->conflicts[idx];
    int bit = 0;
    while (remaining != 0)
    {
        if (remaining & 1u)
            _hs_rec(st, idx + 1, current | ((uint64_t)1 << bit));
        remaining >>= 1;
        bit++;
    }
}

int at_physics_minimal_hitting_sets(const uint64_t *conflicts, int n_conflicts,
                                    uint64_t *out, int out_cap)
{
    if (out == NULL || out_cap < 1)
        return -1;

    /* A conflict that is a proper superset of another is hit whenever the
     * smaller one is, so it cannot constrain the answer; dropping it only cuts
     * the branching factor. De-duplication keeps first-appearance order, which
     * is what makes the enumeration reproducible across runtimes. */
    uint64_t pruned[AT_PHYS_MAX_CONFLICTS];
    int n_pruned = 0;
    for (int i = 0; i < n_conflicts && i < AT_PHYS_MAX_CONFLICTS; i++)
    {
        uint64_t c = conflicts[i];
        if (c == 0)
            continue;
        bool dup = false;
        for (int j = 0; j < n_pruned; j++)
        {
            if (pruned[j] == c)
            {
                dup = true;
                break;
            }
        }
        if (dup)
            continue;
        bool superset = false;
        for (int j = 0; j < n_conflicts && j < AT_PHYS_MAX_CONFLICTS; j++)
        {
            uint64_t o = conflicts[j];
            if (o != 0 && o != c && (o & c) == o)
            {
                superset = true;
                break;
            }
        }
        if (superset)
            continue;
        pruned[n_pruned++] = c;
    }

    if (n_pruned == 0)
    {
        out[0] = 0;
        return 1;
    }

    uint64_t raw[AT_PHYS_MAX_DIAGNOSES];
    hs_state_t st = {pruned, n_pruned, raw, AT_PHYS_MAX_DIAGNOSES, 0, false};
    _hs_rec(&st, 0, 0);
    if (st.overflow)
        return -1;

    /* Keep only the minimal ones. `raw` is small under the conflict cap, so
     * the quadratic filter is cheap and exact, which matters more here. */
    int n = 0;
    for (int i = 0; i < st.n_out; i++)
    {
        bool dominated = false;
        for (int j = 0; j < st.n_out; j++)
        {
            if (raw[j] != raw[i] && (raw[j] & raw[i]) == raw[j])
            {
                dominated = true;
                break;
            }
        }
        if (dominated)
            continue;
        bool dup = false;
        for (int j = 0; j < n; j++)
        {
            if (out[j] == raw[i])
            {
                dup = true;
                break;
            }
        }
        if (dup)
            continue;
        if (n >= out_cap)
            return -1;
        out[n++] = raw[i];
    }
    return n;
}

/* Conflict accumulator: peers named by string, indexed on first appearance. */
typedef struct
{
    char peers[64][AT_PHYS_NAME_LEN + 1];
    int  n_peers;
    uint64_t masks[AT_PHYS_MAX_CONFLICTS];
    int  sizes[AT_PHYS_MAX_CONFLICTS];   /* for the degraded singleton test */
    uint64_t singleton_mask;             /* union of size-1 conflicts */
    int  n_conflicts;
    bool overflow;
} conflict_set_t;

static int _peer_index(conflict_set_t *cs, const char *peer)
{
    for (int i = 0; i < cs->n_peers; i++)
    {
        if (strcmp(cs->peers[i], peer) == 0)
            return i;
    }
    if (cs->n_peers >= 64)
    {
        cs->overflow = true;
        return -1;
    }
    at_strlcpy(cs->peers[cs->n_peers], peer, sizeof(cs->peers[0]));
    return cs->n_peers++;
}

static void _add_conflict(conflict_set_t *cs, const char *const *peers, int n)
{
    if (cs->n_conflicts >= AT_PHYS_MAX_CONFLICTS)
    {
        cs->overflow = true;
        return;
    }
    uint64_t mask = 0;
    int distinct = 0;
    for (int i = 0; i < n; i++)
    {
        int idx = _peer_index(cs, peers[i]);
        if (idx < 0)
            continue;
        uint64_t bit = (uint64_t)1 << idx;
        if (!(mask & bit))
            distinct++;
        mask |= bit;
    }
    if (mask == 0)
        return;
    if (distinct == 1)
        cs->singleton_mask |= mask;
    cs->sizes[cs->n_conflicts] = distinct;
    cs->masks[cs->n_conflicts++] = mask;
}

static at_physics_verdict_t _diagnose(conflict_set_t *cs, const char *subject)
{
    if (cs->n_conflicts == 0)
        return AT_PHYSICS_NONE;
    int si = -1;
    for (int i = 0; i < cs->n_peers; i++)
    {
        if (strcmp(cs->peers[i], subject) == 0)
        {
            si = i;
            break;
        }
    }
    if (si < 0)
        return AT_PHYSICS_NONE;
    uint64_t subject_bit = (uint64_t)1 << si;

    uint64_t diagnoses[AT_PHYS_MAX_DIAGNOSES];
    int n = cs->overflow ? -1
          : at_physics_minimal_hitting_sets(cs->masks, cs->n_conflicts,
                                            diagnoses, AT_PHYS_MAX_DIAGNOSES);
    if (n < 0)
    {
        /* Degraded: refuted only if the subject forms a conflict by itself,
         * otherwise merely implicated. Strictly the narrower answer. */
        return (cs->singleton_mask & subject_bit) ? AT_PHYSICS_REFUTED
                                                  : AT_PHYSICS_IMPLICATED;
    }
    if (n == 0 || (n == 1 && diagnoses[0] == 0))
        return AT_PHYSICS_NONE;
    bool in_all = true, in_any = false;
    for (int i = 0; i < n; i++)
    {
        if (diagnoses[i] & subject_bit)
            in_any = true;
        else
            in_all = false;
    }
    if (in_all)
        return AT_PHYSICS_REFUTED;
    if (in_any)
        return AT_PHYSICS_IMPLICATED;
    return AT_PHYSICS_NONE;
}

/****************************
 * Claim parsing
 ****************************/

typedef struct
{
    double values[AT_PHYS_MAX_COMPONENTS];
    int    n;
    bool   has_unit;
    char   unit[AT_UNIT_SYMBOL_LEN + 1];
    char   quantity[AT_PHYS_NAME_LEN + 1];
} claim_t;

/* Coerce a JSON value to a vector of finite doubles. A bool is NOT a physical
 * quantity and would otherwise read as 0/1; say so rather than grading it. */
static bool _as_floats(json_t *v, claim_t *out)
{
    out->n = 0;
    if (json_is_boolean(v))
        return false;
    if (json_is_real(v) || json_is_integer(v))
    {
        double d = json_is_real(v) ? json_real_value(v)
                                   : (double)json_integer_value(v);
        if (!isfinite(d))
            return false;
        out->values[0] = d;
        out->n = 1;
        return true;
    }
    if (json_is_array(v))
    {
        size_t n = json_array_size(v);
        if (n == 0 || n > AT_PHYS_MAX_COMPONENTS)
            return false;
        for (size_t i = 0; i < n; i++)
        {
            json_t *item = json_array_get(v, i);
            if (json_is_boolean(item) ||
                !(json_is_real(item) || json_is_integer(item)))
                return false;
            double d = json_is_real(item) ? json_real_value(item)
                                          : (double)json_integer_value(item);
            if (!isfinite(d))
                return false;
            out->values[i] = d;
        }
        out->n = (int)n;
        return true;
    }
    return false;
}

/* Parse the reply text into a claim. `found` says whether anything numeric was
 * recovered; a failure here is evidence about the peer, not a parse error. */
static bool _parse_claim(const char *result_str, claim_t *out)
{
    memset(out, 0, sizeof(*out));
    if (result_str == NULL || result_str[0] == '\0')
        return false;

    json_error_t jerr;
    json_t *root = json_loads(result_str, JSON_DECODE_ANY, &jerr);
    if (root == NULL)
    {
        /* Not JSON. A bare decimal is the other shape a `report results`
         * payload carries; whole-string parse only, so "42abc" is not 42. */
        char *end = NULL;
        double d = strtod(result_str, &end);
        if (end == NULL || *end != '\0' || end == result_str || !isfinite(d))
            return false;
        out->values[0] = d;
        out->n = 1;
        return true;
    }

    bool ok = false;
    if (json_is_object(root))
    {
        const char *named = json_string_value(json_object_get(root, "quantity"));
        if (named != NULL)
            at_strlcpy(out->quantity, named, sizeof(out->quantity));
        json_t *unit = json_object_get(root, "unit");
        if (unit != NULL && !json_is_null(unit))
        {
            if (!json_is_string(unit))
            {
                json_decref(root);
                return false;
            }
            out->has_unit = true;
            at_strlcpy(out->unit, json_string_value(unit), sizeof(out->unit));
        }
        ok = _as_floats(json_object_get(root, "value"), out);
    }
    else
        ok = _as_floats(root, out);
    json_decref(root);
    return ok;
}

/****************************
 * The entry point
 ****************************/

static at_physics_verdict_t _refuted(double *score_out, char *reason_out,
                                     size_t reason_len, const char *reason,
                                     const char *fmt, ...)
    __attribute__((format(printf, 5, 6)));

static at_physics_verdict_t _refuted(double *score_out, char *reason_out,
                                     size_t reason_len, const char *reason,
                                     const char *fmt, ...)
{
    if (score_out != NULL)
        *score_out = AT_PHYSICS_REFUTED_SCORE;
    if (reason_out != NULL && reason_len > 0)
    {
        int n = snprintf(reason_out, reason_len, "%s: ", reason);
        if (n > 0 && (size_t)n < reason_len)
        {
            va_list ap;
            va_start(ap, fmt);
            vsnprintf(reason_out + n, reason_len - (size_t)n, fmt, ap);
            va_end(ap);
        }
    }
    return AT_PHYSICS_REFUTED;
}

at_physics_verdict_t at_physics_check(at_physics_checker_t *checker,
                                      const char *capability,
                                      const char *result_str,
                                      const char *subject,
                                      double now,
                                      double *score_out,
                                      char *reason_out, size_t reason_len)
{
    if (reason_out != NULL && reason_len > 0)
        reason_out[0] = '\0';
    if (!at_physics_checker_enabled(checker) ||
        result_str == NULL || result_str[0] == '\0')
        return AT_PHYSICS_NONE;   /* no declarations, or no answer at all */

    claim_t claim;
    bool parsed = _parse_claim(result_str, &claim);

    /* Resolve the quantity. A result may name its own, which is what lets one
     * capability be reused across scenarios; otherwise the capability's
     * declaration decides. An unknown name falls back to the capability rather
     * than refuting: a peer does not get to pull itself out of a check by
     * mislabelling its answer. */
    int qi = -1;
    if (parsed && claim.quantity[0] != '\0')
        qi = _quantity_index(&checker->model, claim.quantity);
    if (qi < 0)
        qi = _capability_index(&checker->model, capability);
    if (qi < 0)
        return AT_PHYSICS_NONE;
    const at_phys_quantity_t *q = &checker->model.quantities[qi];

    if (!parsed)
        return _refuted(score_out, reason_out, reason_len, "not-a-quantity",
                        "%s expects a finite number or vector, got '%s'",
                        q->name, result_str);
    if (claim.n != q->components)
        return _refuted(score_out, reason_out, reason_len, "arity",
                        "%s is declared with %d component(s), got %d",
                        q->name, q->components, claim.n);

    at_dimension_t dim = q->dimension;
    if (claim.has_unit)
    {
        at_dimension_t claimed;
        char uerr[AT_UNIT_ERR_LEN] = {0};
        if (!at_parse_unit(claim.unit, &claimed, uerr, sizeof(uerr)))
            return _refuted(score_out, reason_out, reason_len, "unit", "%s", uerr);
        if (!at_same_dimension(&claimed, &q->dimension))
        {
            char da[64], db[64];
            return _refuted(score_out, reason_out, reason_len, "dimension",
                            "%s is declared in '%s' (%s) but the claim is in "
                            "'%s' (%s)", q->name, q->unit,
                            at_dimension_str(&q->dimension, da, sizeof da),
                            claim.unit,
                            at_dimension_str(&claimed, db, sizeof db));
        }
        dim = claimed;
    }

    double si[AT_PHYS_MAX_COMPONENTS] = {0};
    for (int i = 0; i < claim.n; i++)
        si[i] = at_dimension_to_si(&dim, claim.values[i]);

    /* Range feasibility, COMPONENTWISE: a declared range is a bounding box, so
     * a position north of the pole is refuted whatever its distance from the
     * origin. The rate checks below use the magnitude instead, because a speed
     * limit is on the vector, not on its axes. */
    for (int i = 0; i < claim.n; i++)
    {
        if (q->has_min && si[i] < q->si_min)
            return _refuted(score_out, reason_out, reason_len, "bounds",
                            "%s[%d] = %g is below the declared minimum %g (SI)",
                            q->name, i, si[i], q->si_min);
        if (q->has_max && si[i] > q->si_max)
            return _refuted(score_out, reason_out, reason_len, "bounds",
                            "%s[%d] = %g exceeds the declared maximum %g (SI)",
                            q->name, i, si[i], q->si_max);
    }

    if (subject == NULL || subject[0] == '\0')
        /* Not attributable to one peer: the checks needing no identity have
         * run, and nothing is stored. */
        return AT_PHYSICS_NONE;

    /* Feasibility of the CHANGE since this peer's OWN last claim — the
     * kinematic half. A peer contradicting itself is a conflict of size one,
     * hence refuted outright rather than merely implicated. */
    if (q->has_max_rate || q->has_max_accel)
    {
        const at_phys_peer_hist_t *h = _hist(checker, qi, subject, false);
        const at_phys_obs_t *prev = _recent(h, 0, _ring_depth(checker));
        if (prev != NULL)
        {
            double dt = now - prev->t;
            /* Out-of-order or same-instant claims say nothing about a rate.
             * Not a refutation: clock skew and queue reordering are ordinary. */
            if (dt > 0)
            {
                double rate = _norm(si, prev->values, claim.n) / dt;
                if (q->has_max_rate && rate > q->si_max_rate)
                    return _refuted(score_out, reason_out, reason_len, "rate",
                                    "%s changed at %g/s since this peer's own "
                                    "last claim, above the declared %g/s (SI)",
                                    q->name, rate, q->si_max_rate);
                const at_phys_obs_t *prev2 = _recent(h, 1, _ring_depth(checker));
                if (q->has_max_accel && prev2 != NULL)
                {
                    double dt_prev = prev->t - prev2->t;
                    if (dt_prev > 0)
                    {
                        /* Vector acceleration: the change in the velocity
                         * VECTOR, not in its magnitude, so a reversal is not
                         * read as no change. */
                        double v_now[AT_PHYS_MAX_COMPONENTS];
                        double v_prev[AT_PHYS_MAX_COMPONENTS];
                        for (int i = 0; i < claim.n; i++)
                        {
                            v_now[i] = (si[i] - prev->values[i]) / dt;
                            v_prev[i] = (prev->values[i] - prev2->values[i]) / dt_prev;
                        }
                        double span = 0.5 * (dt + dt_prev);
                        double accel = _norm(v_now, v_prev, claim.n) / span;
                        if (accel > q->si_max_accel)
                            return _refuted(score_out, reason_out, reason_len,
                                            "accel",
                                            "%s accelerated at %g/s^2, above "
                                            "the declared %g/s^2 (SI)",
                                            q->name, accel, q->si_max_accel);
                    }
                }
            }
        }
    }

    /* Survived every self-check: NOW it may enter the store. A claim already
     * known to be impossible must never be stored, or one liar could
     * manufacture conflicts against honest peers. */
    _record(checker, qi, subject, si, claim.n, now);

    conflict_set_t cs;
    memset(&cs, 0, sizeof(cs));

    /* Set-membership intersection over peers reporting this quantity. Where
     * errors are bounded rather than stochastic, the intersection of the
     * interval constraints is a guaranteed feasible set and a claim outside it
     * is refuted rather than improbable (Milanese; Jaulin). Pairs suffice: on
     * the line a family of intervals has a common point exactly when every
     * pair does (Helly in one dimension).
     *
     * Opt-in via `tolerance`: a zero-width interval makes every distinct float
     * a conflict, which would report disagreement between two honest sensors
     * of the same thing. */
    if (q->si_tolerance > 0.0)
    {
        const at_phys_peer_hist_t *mine = _hist(checker, qi, subject, false);
        const at_phys_obs_t *latest = _recent(mine, 0, _ring_depth(checker));
        if (latest != NULL)
        {
            for (int p = 0; p < checker->store_peers[qi]; p++)
            {
                const at_phys_peer_hist_t *other = &checker->store[qi][p];
                if (strcmp(other->peer, subject) == 0)
                    continue;
                const at_phys_obs_t *o = _recent(other, 0, _ring_depth(checker));
                if (o == NULL)
                    continue;
                /* Stale: peers legitimately disagree about a quantity that has
                 * moved on since, and calling that a conflict refutes honest
                 * peers. */
                if (fabs(now - o->t) > checker->model.window_sec)
                    continue;
                for (int i = 0; i < claim.n; i++)
                {
                    if (fabs(latest->values[i] - o->values[i]) >
                        2.0 * q->si_tolerance)
                    {
                        const char *pair[2] = {subject, other->peer};
                        _add_conflict(&cs, pair, 2);
                        break;
                    }
                }
            }
        }
    }

    /* Parity relations: residuals that vanish under consistency. The freshest
     * value per quantity is used regardless of which peer supplied it, because
     * a conservation law constrains the quantities, not the reporters. A
     * violated relation whose every term came from one peer is a conflict of
     * size one, hence a refutation. */
    for (int r = 0; r < checker->model.n_relations; r++)
    {
        const at_phys_relation_t *rel = &checker->model.relations[r];
        bool participates = false;
        for (int t = 0; t < rel->n_terms; t++)
        {
            if (rel->term_quantity[t] == qi)
            {
                participates = true;
                break;
            }
        }
        if (!participates)
            continue;

        double window = rel->has_window ? rel->window_sec
                                        : checker->model.window_sec;
        double residual = rel->constant;
        const char *contributors[AT_PHYS_MAX_TERMS];
        int n_contrib = 0;
        bool complete = true;
        for (int t = 0; t < rel->n_terms; t++)
        {
            int tq = rel->term_quantity[t];
            const at_phys_obs_t *best = NULL;
            const char *best_peer = NULL;
            for (int p = 0; p < checker->store_peers[tq]; p++)
            {
                const at_phys_obs_t *o = _recent(&checker->store[tq][p], 0,
                                                _ring_depth(checker));
                if (o == NULL || now - o->t > window)
                    continue;
                if (best == NULL || o->t > best->t)
                {
                    best = o;
                    best_peer = checker->store[tq][p].peer;
                }
            }
            if (best == NULL)
            {
                complete = false;
                break;
            }
            residual += rel->term_coeff[t] * best->values[0];
            bool seen = false;
            for (int i = 0; i < n_contrib; i++)
            {
                if (strcmp(contributors[i], best_peer) == 0)
                {
                    seen = true;
                    break;
                }
            }
            if (!seen && n_contrib < AT_PHYS_MAX_TERMS)
                contributors[n_contrib++] = best_peer;
        }
        if (!complete || n_contrib == 0)
            continue;
        if (fabs(residual) > rel->tolerance)
            _add_conflict(&cs, contributors, n_contrib);
    }

    at_physics_verdict_t verdict = _diagnose(&cs, subject);
    if (verdict == AT_PHYSICS_REFUTED)
        return _refuted(score_out, reason_out, reason_len, "conflict",
                        "%s: in every minimal diagnosis of %d conflict(s)",
                        q->name, cs.n_conflicts);
    if (verdict == AT_PHYSICS_IMPLICATED)
    {
        if (score_out != NULL)
            *score_out = AT_PHYSICS_IMPLICATED_SCORE;
        if (reason_out != NULL && reason_len > 0)
            snprintf(reason_out, reason_len,
                     "conflict: %s implicated (not refuted) by %d conflict(s) "
                     "on %s", subject, cs.n_conflicts, q->name);
        return AT_PHYSICS_IMPLICATED;
    }
    return AT_PHYSICS_NONE;
}
