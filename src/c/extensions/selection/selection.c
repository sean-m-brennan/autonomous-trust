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

/* The selection declaration, the draw and the seed chain: the C twin of
 * Python selection/model.py, draw.py and chain.py
 * (RD_12.7_SELECTIVE_ASSIGNMENT_PLAN.md sections 0.1 and 3.2-3.3). Every sum
 * and product runs left to right in canonical order, as Python's explicit
 * loops do. */

#include "selection/selection.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <sodium.h>

#include "utilities/util.h"     /* at_strlcpy */

/* ---- the declaration ---------------------------------------------------- */

static bool _fail(char *err, size_t errlen, const char *fmt, const char *what)
{
    if (err != NULL && errlen > 0)
        snprintf(err, errlen, fmt, what);
    return false;
}

static bool _only_keys(const json_t *obj, const char *const *allowed, size_t n)
{
    const char *key;
    json_t *val;
    json_object_foreach((json_t *)obj, key, val)
    {
        (void)val;
        bool ok = false;
        for (size_t i = 0; i < n; i++)
            if (strcmp(key, allowed[i]) == 0)
                ok = true;
        if (!ok)
            return false;
    }
    return true;
}

static bool _floor(const json_t *v, double *out)
{
    if (!json_is_number(v))
        return false;
    double f = json_number_value(v);
    if (!(f >= 0.0 && f <= 1.0))
        return false;
    *out = f;
    return true;
}

static bool _policy(const json_t *spec, const at_sel_policy_t *base,
                    at_sel_policy_t *out, const char *where, char *err, size_t errlen)
{
    static const char *const keys[] = { "k", "floor", "note" };
    if (!json_is_object(spec))
        return _fail(err, errlen, "%s: not an object", where);
    if (!_only_keys(spec, keys, 3))
        return _fail(err, errlen, "%s: unknown key", where);
    *out = *base;
    json_t *k = json_object_get(spec, "k");
    if (k != NULL)
    {
        if (json_is_null(k))
            out->k = 0;
        else if (json_is_integer(k) && json_integer_value(k) >= 1
                 && json_integer_value(k) <= AT_SEL_MAX_K)
            out->k = (int)json_integer_value(k);
        else
            return _fail(err, errlen, "%s k: not an integer in [1, 1024] or null", where);
    }
    json_t *f = json_object_get(spec, "floor");
    if (f != NULL && !_floor(f, &out->floor))
        return _fail(err, errlen, "%s floor: not a number in [0, 1]", where);
    return true;
}

bool at_selection_parse(const json_t *doc, at_selection_model_t *out,
                        char *err, size_t errlen)
{
    static const char *const keys[] = { "version", "default", "probe",
                                        "capabilities", "log_records", "note" };
    memset(out, 0, sizeof(*out));
    out->def.k = 0;
    out->def.floor = AT_SEL_DEFAULT_FLOOR;
    out->log_records = AT_SEL_DEFAULT_LOG_RECORDS;
    if (doc == NULL)
        return true;
    if (!json_is_object(doc))
        return _fail(err, errlen, "%s", "declaration is not an object");
    json_t *ver = json_object_get(doc, "version");
    if (!json_is_integer(ver) || json_integer_value(ver) != 1)
        return _fail(err, errlen, "%s", "unsupported version; expected 1");
    if (!_only_keys(doc, keys, 6))
        return _fail(err, errlen, "%s", "unknown key");

    at_sel_policy_t base = { .k = 0, .floor = AT_SEL_DEFAULT_FLOOR };
    json_t *def = json_object_get(doc, "default");
    if (def != NULL && !_policy(def, &base, &out->def, "default", err, errlen))
        return false;

    json_t *probe = json_object_get(doc, "probe");
    if (probe != NULL)
    {
        static const char *const pkeys[] = { "floor", "note" };
        if (!json_is_object(probe))
            return _fail(err, errlen, "%s", "probe: not an object");
        if (!_only_keys(probe, pkeys, 2))
            return _fail(err, errlen, "%s", "probe: unknown key");
        out->has_probe = true;
        out->probe_floor = AT_SEL_DEFAULT_FLOOR;
        json_t *f = json_object_get(probe, "floor");
        if (f != NULL && !_floor(f, &out->probe_floor))
            return _fail(err, errlen, "%s", "probe floor: not a number in [0, 1]");
    }

    json_t *caps = json_object_get(doc, "capabilities");
    if (caps != NULL)
    {
        if (!json_is_object(caps))
            return _fail(err, errlen, "%s", "capabilities is not an object");
        if (json_object_size(caps) > AT_SEL_MAX_CAPS)
            return _fail(err, errlen, "%s", "capabilities: too many named");
        const char *name;
        json_t *spec;
        json_object_foreach(caps, name, spec)
        {
            at_sel_cap_t *c = &out->caps[out->num_caps];
            if (strlen(name) > AT_SEL_NAME_LEN)
                return _fail(err, errlen, "capability %.64s...: name too long", name);
            at_strlcpy(c->name, name, sizeof(c->name));
            if (!_policy(spec, &out->def, &c->policy, name, err, errlen))
                return false;
            out->num_caps++;
        }
    }

    json_t *recs = json_object_get(doc, "log_records");
    if (recs != NULL)
    {
        if (!json_is_integer(recs) || json_integer_value(recs) < 1
            || json_integer_value(recs) > AT_SEL_MAX_LOG_RECORDS)
            return _fail(err, errlen, "%s", "log_records: not an integer in [1, 1048576]");
        out->log_records = (int)json_integer_value(recs);
    }
    out->declared = true;
    return true;
}

bool at_selection_parse_text(const char *text, at_selection_model_t *out,
                             char *err, size_t errlen)
{
    json_error_t jerr;
    json_t *doc = json_loads(text, JSON_REJECT_DUPLICATES, &jerr);
    if (doc == NULL)
        return _fail(err, errlen, "not JSON: %s", jerr.text);
    bool ok = at_selection_parse(doc, out, err, errlen);
    json_decref(doc);
    return ok;
}

bool at_selection_load_env(at_selection_model_t *out, char *err, size_t errlen)
{
    const char *path = getenv("AT_SELECTION");
    if (path == NULL || path[0] == '\0')
        return at_selection_parse(NULL, out, err, errlen);
    json_error_t jerr;
    json_t *doc = json_load_file(path, JSON_REJECT_DUPLICATES, &jerr);
    if (doc == NULL)
    {
        at_selection_parse(NULL, out, NULL, 0);
        return _fail(err, errlen, "cannot read: %s", jerr.text);
    }
    bool ok = at_selection_parse(doc, out, err, errlen);
    json_decref(doc);
    return ok;
}

const at_sel_policy_t *at_selection_policy_for(const at_selection_model_t *m,
                                               const char *cap)
{
    for (size_t i = 0; cap != NULL && i < m->num_caps; i++)
        if (strcmp(m->caps[i].name, cap) == 0)
            return &m->caps[i].policy;
    return &m->def;
}

bool at_selection_selects(const at_selection_model_t *m, const char *cap)
{
    return m->declared && at_selection_policy_for(m, cap)->k > 0;
}

/* ---- the draw ------------------------------------------------------------ */

double at_sel_unit(at_splitmix64_t *rng)
{
    return (double)(at_splitmix64_next(rng) >> 11) * (1.0 / 9007199254740992.0);
}

uint64_t at_sel_seed_of(const unsigned char *link)
{
    uint64_t s = 0;
    for (int i = 0; i < 8; i++)
        s = (s << 8) | link[i];
    return s;
}

bool at_sel_propensities(const double *w, size_t n, double floor, double *p)
{
    if (n == 0)
        return false;
    if ((double)n * floor > 1.0)
    {
        for (size_t i = 0; i < n; i++)
            p[i] = 1.0 / (double)n;
        return true;
    }
    double total = 0.0;
    for (size_t i = 0; i < n; i++)
        total += w[i];
    double spread = 1.0 - (double)n * floor;
    for (size_t i = 0; i < n; i++)
        p[i] = total <= 0.0 ? floor + spread / (double)n
                            : floor + spread * (w[i] / total);
    return false;
}

size_t at_sel_pick(const double *p, size_t n, double u)
{
    double cum = 0.0;
    for (size_t i = 0; i < n; i++)
    {
        cum += p[i];
        if (u < cum)
            return i;
    }
    return n - 1;
}

int at_sel_draw(const double *w, size_t n, int k, double floor, uint64_t seed,
                bool *selected, double *inclusion, at_sel_kind_t *kind,
                bool *degraded, bool *fallback)
{
    *degraded = false;
    *fallback = false;
    if (k <= 0 || (k > 1 && (size_t)k >= n))
    {
        *kind = AT_SEL_ALL;
        for (size_t i = 0; i < n; i++)
        {
            selected[i] = true;
            inclusion[i] = 1.0;
        }
        return 0;
    }
    if (n == 0)
    {
        *kind = k == 1 ? AT_SEL_CATEGORICAL : AT_SEL_BERNOULLI;
        return 0;
    }
    at_splitmix64_t rng;
    at_splitmix64_init(&rng, seed);
    double *p = calloc(n, sizeof(*p));
    if (p == NULL)
        return -1;
    *degraded = at_sel_propensities(w, n, floor, p);
    for (size_t i = 0; i < n; i++)
        selected[i] = false;
    if (k == 1)
    {
        *kind = AT_SEL_CATEGORICAL;
        selected[at_sel_pick(p, n, at_sel_unit(&rng))] = true;
        for (size_t i = 0; i < n; i++)
            inclusion[i] = p[i];
        free(p);
        return 0;
    }
    *kind = AT_SEL_BERNOULLI;
    bool any = false;
    double empty = 1.0;
    for (size_t i = 0; i < n; i++)
    {
        double pi = (double)k * p[i];
        if (pi < floor)
            pi = floor;
        if (pi > 1.0)
            pi = 1.0;
        inclusion[i] = pi;
    }
    for (size_t i = 0; i < n; i++)
        if (at_sel_unit(&rng) < inclusion[i])
        {
            selected[i] = true;
            any = true;
        }
    for (size_t i = 0; i < n; i++)
        empty *= (1.0 - inclusion[i]);
    if (!any)
    {
        *fallback = true;
        selected[at_sel_pick(p, n, at_sel_unit(&rng))] = true;
    }
    for (size_t i = 0; i < n; i++)
        inclusion[i] = inclusion[i] + empty * p[i];
    free(p);
    return 0;
}

/* ---- the seed chain ------------------------------------------------------- */

static void _forward(const unsigned char *in, long times, unsigned char *out)
{
    unsigned char cur[AT_SEL_LINK_BYTES];
    memcpy(cur, in, sizeof(cur));
    for (long i = 0; i < times; i++)
        crypto_hash_sha256(cur, cur, sizeof(cur));
    memcpy(out, cur, sizeof(cur));
}

void at_sel_chain_init(at_sel_chain_t *c, const unsigned char *root)
{
    memcpy(c->root, root, AT_SEL_LINK_BYTES);
    memcpy(c->checkpoints[0], root, AT_SEL_LINK_BYTES);
    const size_t points = AT_SEL_CHAIN_LENGTH / AT_SEL_CHAIN_CHECKPOINT;
    for (size_t j = 1; j <= points; j++)
        _forward(c->checkpoints[j - 1], AT_SEL_CHAIN_CHECKPOINT, c->checkpoints[j]);
    memcpy(c->head, c->checkpoints[points], AT_SEL_LINK_BYTES);
}

int at_sel_chain_link(const at_sel_chain_t *c, long index, unsigned char *out)
{
    if (index < 1 || index > AT_SEL_CHAIN_LENGTH)
        return -1;
    long depth = AT_SEL_CHAIN_LENGTH - index;
    _forward(c->checkpoints[depth / AT_SEL_CHAIN_CHECKPOINT],
             depth % AT_SEL_CHAIN_CHECKPOINT, out);
    return 0;
}

bool at_sel_verify_link(const unsigned char *head, long index,
                        const unsigned char *link, long known_index,
                        const unsigned char *known_link)
{
    if (index < 1 || index > AT_SEL_CHAIN_LENGTH)
        return false;
    unsigned char out[AT_SEL_LINK_BYTES];
    if (known_index > 0 && known_index < index)
    {
        _forward(link, index - known_index, out);
        return sodium_memcmp(out, known_link, sizeof(out)) == 0;
    }
    _forward(link, index, out);
    return sodium_memcmp(out, head, sizeof(out)) == 0;
}

bool at_sel_verify_rotation(const unsigned char *old_head,
                            const unsigned char *old_root)
{
    unsigned char out[AT_SEL_LINK_BYTES];
    _forward(old_root, AT_SEL_CHAIN_LENGTH, out);
    return sodium_memcmp(out, old_head, sizeof(out)) == 0;
}

void at_sel_hex(const unsigned char *in, size_t n, char *out)
{
    static const char digits[] = "0123456789abcdef";
    for (size_t i = 0; i < n; i++)
    {
        out[2 * i] = digits[in[i] >> 4];
        out[2 * i + 1] = digits[in[i] & 0xf];
    }
    out[2 * n] = '\0';
}

static int _nibble(char c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

int at_sel_unhex(const char *hex, unsigned char *out, size_t n)
{
    if (hex == NULL || strlen(hex) != 2 * n)
        return -1;
    for (size_t i = 0; i < n; i++)
    {
        int hi = _nibble(hex[2 * i]), lo = _nibble(hex[2 * i + 1]);
        if (hi < 0 || lo < 0)
            return -1;
        out[i] = (unsigned char)(hi << 4 | lo);
    }
    return 0;
}
