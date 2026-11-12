/* ******************
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
 * ****************** */
/* The deployment manifest (RD_13.4 §3.3). See deployment_manifest.h, and the
 * Python twin core/_python/deployment_manifest.py for the full rules. */

#include <pthread.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "config/deployment_manifest.h"
#include "utilities/logger.h"

static void _fail(char *err, size_t err_len, const char *fmt, ...)
{
    if (err == NULL || err_len == 0)
        return;
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(err, err_len, fmt, ap);
    va_end(ap);
}

void deployment_manifest_init(deployment_manifest_t *m)
{
    if (m != NULL)
        memset(m, 0, sizeof(*m));
}

void deployment_manifest_free(deployment_manifest_t *m)
{
    if (m == NULL)
        return;
    for (size_t i = 0; i < m->n_cohorts; i++)
        free(m->cohorts[i].members);
    free(m->cohorts);
    free(m->gateways);
    deployment_manifest_init(m);
}

/* Lowercase, hyphenated, 36 characters: what Python's str(UUID(x)) == x
 * accepts. */
static bool _canonical_uuid(const char *s)
{
    if (s == NULL || strlen(s) != DM_UUID_LEN)
        return false;
    for (int i = 0; i < DM_UUID_LEN; i++) {
        char c = s[i];
        if (i == 8 || i == 13 || i == 18 || i == 23) {
            if (c != '-')
                return false;
        } else if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'))) {
            return false;
        }
    }
    return true;
}

/* [A-Za-z0-9._-]{1,64}, as Python's _NAME_RE. */
static bool _valid_name(const char *s)
{
    if (s == NULL)
        return false;
    size_t n = strlen(s);
    if (n == 0 || n > DM_MAX_NAME_LEN)
        return false;
    for (size_t i = 0; i < n; i++) {
        char c = s[i];
        if (!((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
              (c >= '0' && c <= '9') || c == '.' || c == '_' || c == '-'))
            return false;
    }
    return true;
}

static bool _only_keys(const json_t *obj, const char *const *allowed, size_t n)
{
    const char *key;
    json_t *val;
    json_object_foreach((json_t *)obj, key, val) {
        bool ok = false;
        for (size_t i = 0; i < n; i++)
            if (strcmp(key, allowed[i]) == 0)
                ok = true;
        if (!ok)
            return false;
    }
    return true;
}

static const dm_cohort_t *_find_cohort(const deployment_manifest_t *m,
                                       const char *name)
{
    for (size_t i = 0; i < m->n_cohorts; i++)
        if (strcmp(m->cohorts[i].name, name) == 0)
            return &m->cohorts[i];
    return NULL;
}

static bool _has_member(const dm_cohort_t *c, const char *node)
{
    for (size_t i = 0; i < c->n_members; i++)
        if (strcmp(c->members[i], node) == 0)
            return true;
    return false;
}

static bool _listed(const deployment_manifest_t *m, const char *node,
                    const char *a, const char *b)
{
    for (size_t i = 0; i < m->n_gateways; i++) {
        const dm_gateway_t *g = &m->gateways[i];
        if (strcmp(g->node, node) == 0 && strcmp(g->between[0], a) == 0 &&
            strcmp(g->between[1], b) == 0)
            return true;
    }
    return false;
}

static int _parse_cohorts(const json_t *raw, deployment_manifest_t *out,
                          char *err, size_t err_len)
{
    if (raw == NULL)
        return 0;
    if (!json_is_object(raw)) {
        _fail(err, err_len, "manifest: cohorts is not an object");
        return -1;
    }
    size_t n = json_object_size(raw);
    if (n > DM_MAX_COHORTS) {
        _fail(err, err_len, "manifest: more than %d cohorts", DM_MAX_COHORTS);
        return -1;
    }
    out->cohorts = calloc(n > 0 ? n : 1, sizeof(dm_cohort_t));
    if (out->cohorts == NULL) {
        _fail(err, err_len, "manifest: out of memory");
        return -1;
    }
    static const char *const keys[] = {"members", "n_min"};
    const char *name;
    json_t *body;
    json_object_foreach((json_t *)raw, name, body) {
        if (!_valid_name(name)) {
            _fail(err, err_len, "cohorts: cohort name must be 1 to %d of "
                  "[A-Za-z0-9._-]: '%s'", DM_MAX_NAME_LEN, name);
            return -1;
        }
        if (!json_is_object(body)) {
            _fail(err, err_len, "cohorts.%s: not an object", name);
            return -1;
        }
        if (!_only_keys(body, keys, 2)) {
            _fail(err, err_len, "cohorts.%s: unknown key", name);
            return -1;
        }
        json_t *members = json_object_get(body, "members");
        size_t nm = json_is_array(members) ? json_array_size(members) : 0;
        if (nm == 0) {
            _fail(err, err_len, "cohorts.%s.members: must be a non-empty list",
                  name);
            return -1;
        }
        if (nm > DM_MAX_MEMBERS) {
            _fail(err, err_len, "cohorts.%s.members: more than %d", name,
                  DM_MAX_MEMBERS);
            return -1;
        }
        json_t *n_min = json_object_get(body, "n_min");
        if (n_min != NULL && !json_is_null(n_min) &&
            (!json_is_integer(n_min) || json_integer_value(n_min) < 1)) {
            _fail(err, err_len, "cohorts.%s.n_min: must be an integer of at "
                  "least 1", name);
            return -1;
        }
        dm_cohort_t *c = &out->cohorts[out->n_cohorts++];
        snprintf(c->name, sizeof(c->name), "%s", name);
        if (n_min != NULL && json_is_integer(n_min))
            c->n_min = json_integer_value(n_min) > 1000000000
                           ? 1000000000 : (int)json_integer_value(n_min);
        c->members = calloc(nm, sizeof(*c->members));
        if (c->members == NULL) {
            _fail(err, err_len, "manifest: out of memory");
            return -1;
        }
        size_t i;
        json_t *m;
        json_array_foreach(members, i, m) {
            const char *u = json_string_value(m);
            if (!_canonical_uuid(u)) {
                _fail(err, err_len, "cohorts.%s.members: not a canonical "
                      "(lowercase, hyphenated) uuid", name);
                return -1;
            }
            if (_has_member(c, u)) {
                _fail(err, err_len, "cohorts.%s.members: a member is listed "
                      "twice", name);
                return -1;
            }
            snprintf(c->members[c->n_members++], DM_UUID_LEN + 1, "%s", u);
        }
    }
    return 0;
}

static int _parse_gateways(const json_t *raw, deployment_manifest_t *out,
                           char *err, size_t err_len)
{
    if (raw == NULL)
        return 0;
    if (!json_is_array(raw)) {
        _fail(err, err_len, "manifest: gateways is not a list");
        return -1;
    }
    size_t n = json_array_size(raw);
    if (n > DM_MAX_GATEWAYS) {
        _fail(err, err_len, "manifest: more than %d gateways", DM_MAX_GATEWAYS);
        return -1;
    }
    out->gateways = calloc(n > 0 ? n : 1, sizeof(dm_gateway_t));
    if (out->gateways == NULL) {
        _fail(err, err_len, "manifest: out of memory");
        return -1;
    }
    static const char *const keys[] = {"node", "between"};
    size_t i;
    json_t *e;
    json_array_foreach(raw, i, e) {
        if (!json_is_object(e) || json_object_size(e) != 2 ||
            !_only_keys(e, keys, 2)) {
            _fail(err, err_len, "gateways[%zu]: must be an object with exactly "
                  "\"node\" and \"between\"", i);
            return -1;
        }
        const char *node = json_string_value(json_object_get(e, "node"));
        if (!_canonical_uuid(node)) {
            _fail(err, err_len, "gateways[%zu].node: not a canonical uuid", i);
            return -1;
        }
        json_t *between = json_object_get(e, "between");
        if (!json_is_array(between) || json_array_size(between) != 2) {
            _fail(err, err_len, "gateways[%zu].between: must name two cohorts",
                  i);
            return -1;
        }
        const char *a = json_string_value(json_array_get(between, 0));
        const char *b = json_string_value(json_array_get(between, 1));
        if (!_valid_name(a) || !_valid_name(b)) {
            _fail(err, err_len, "gateways[%zu].between: cohort name must be 1 "
                  "to %d of [A-Za-z0-9._-]", i, DM_MAX_NAME_LEN);
            return -1;
        }
        if (strcmp(a, b) == 0) {
            _fail(err, err_len, "gateways[%zu].between: names one cohort twice",
                  i);
            return -1;
        }
        const char *pair[2] = {a, b};
        for (int k = 0; k < 2; k++) {
            const dm_cohort_t *c = _find_cohort(out, pair[k]);
            if (c == NULL) {
                _fail(err, err_len, "gateways[%zu].between: no cohort named "
                      "'%s'", i, pair[k]);
                return -1;
            }
            if (!_has_member(c, node)) {
                _fail(err, err_len, "gateways[%zu]: %s is not a member of "
                      "cohort '%s'", i, node, pair[k]);
                return -1;
            }
        }
        if (strcmp(a, b) > 0) {
            const char *t = a;
            a = b;
            b = t;
        }
        if (_listed(out, node, a, b)) {
            _fail(err, err_len, "gateways[%zu]: %s is listed twice for (%s, %s)",
                  i, node, a, b);
            return -1;
        }
        dm_gateway_t *g = &out->gateways[out->n_gateways++];
        snprintf(g->node, sizeof(g->node), "%s", node);
        snprintf(g->between[0], sizeof(g->between[0]), "%s", a);
        snprintf(g->between[1], sizeof(g->between[1]), "%s", b);
    }
    return 0;
}

/* Invariant G at design time: a node in two cohorts is a gateway between them,
 * and a node in three or more is a gateway between every pair. */
static int _check_g(const deployment_manifest_t *m, char *err, size_t err_len)
{
    for (size_t i = 0; i < m->n_cohorts; i++) {
        for (size_t j = i + 1; j < m->n_cohorts; j++) {
            const dm_cohort_t *ci = &m->cohorts[i], *cj = &m->cohorts[j];
            const char *a = ci->name, *b = cj->name;
            if (strcmp(a, b) > 0) {
                const char *t = a;
                a = b;
                b = t;
            }
            for (size_t k = 0; k < ci->n_members; k++) {
                const char *node = ci->members[k];
                if (_has_member(cj, node) && !_listed(m, node, a, b)) {
                    _fail(err, err_len, "manifest: %s is in cohorts '%s' and "
                          "'%s' but is not a gateway between them (invariant G)",
                          node, a, b);
                    return -1;
                }
            }
        }
    }
    return 0;
}

int deployment_manifest_parse(const json_t *root, deployment_manifest_t *out,
                              char *err, size_t err_len)
{
    if (out == NULL)
        return -1;
    deployment_manifest_init(out);
    if (!json_is_object(root)) {
        _fail(err, err_len, "manifest: not a JSON object");
        return -1;
    }
    static const char *const keys[] = {"version", "cohorts", "gateways"};
    if (!_only_keys(root, keys, 3)) {
        _fail(err, err_len, "manifest: unknown key");
        return -1;
    }
    json_t *version = json_object_get(root, "version");
    if (!json_is_integer(version) ||
        json_integer_value(version) != DEPLOYMENT_MANIFEST_VERSION) {
        _fail(err, err_len, "manifest: version must be %d",
              DEPLOYMENT_MANIFEST_VERSION);
        return -1;
    }
    if (_parse_cohorts(json_object_get(root, "cohorts"), out, err, err_len) != 0
        || _parse_gateways(json_object_get(root, "gateways"), out, err,
                           err_len) != 0
        || _check_g(out, err, err_len) != 0) {
        deployment_manifest_free(out);
        return -1;
    }
    return 0;
}

int deployment_manifest_load(const char *path, deployment_manifest_t *out,
                             char *err, size_t err_len, logger_t *logger)
{
    if (out == NULL)
        return -1;
    deployment_manifest_init(out);
    bool explicit = path != NULL;
    if (!explicit) {
        path = getenv(DEPLOYMENT_MANIFEST_ENV);
        if (path == NULL || path[0] == '\0')
            return 0;
    }
    if (access(path, F_OK) != 0) {
        if (explicit) {
            _fail(err, err_len, "deployment manifest: %s not found", path);
            return -1;
        }
        log_warn(logger, "deployment manifest: %s=%s not found; no gateway "
                 "role will be accepted\n", DEPLOYMENT_MANIFEST_ENV, path);
        return 0;
    }
    json_error_t jerr;
    json_t *root = json_load_file(path, JSON_REJECT_DUPLICATES, &jerr);
    if (root == NULL) {
        _fail(err, err_len, "deployment manifest: cannot read %s: %s (line %d)",
              path, jerr.text, jerr.line);
        return -1;
    }
    char why[256] = {0};
    int rc = deployment_manifest_parse(root, out, why, sizeof(why));
    json_decref(root);
    if (rc != 0)
        _fail(err, err_len, "%s: %s", path, why);
    return rc;
}

size_t deployment_manifest_gateway_pairs(const deployment_manifest_t *m,
                                         const char *node)
{
    if (m == NULL || node == NULL)
        return 0;
    size_t n = 0;
    for (size_t i = 0; i < m->n_gateways; i++)
        if (strcmp(m->gateways[i].node, node) == 0)
            n++;
    return n;
}

/* The manifest this node holds. Written at network start, before the receiver
 * threads run, and read-only after that; the lock covers a test or adapter
 * that reconfigures it. */
static deployment_manifest_t g_active;
static pthread_mutex_t g_active_lock = PTHREAD_MUTEX_INITIALIZER;

int deployment_manifest_configure(const char *path, logger_t *logger)
{
    deployment_manifest_t loaded;
    char err[384] = {0};
    if (deployment_manifest_load(path, &loaded, err, sizeof(err), logger) != 0) {
        log_error(logger, "%s; not starting\n", err);
        return -1;
    }
    pthread_mutex_lock(&g_active_lock);
    deployment_manifest_free(&g_active);
    g_active = loaded;
    pthread_mutex_unlock(&g_active_lock);
    if (loaded.n_gateways > 0)
        log_info(logger, "deployment manifest: %zu cohort(s), %zu gateway "
                 "entr%s\n", loaded.n_cohorts, loaded.n_gateways,
                 loaded.n_gateways == 1 ? "y" : "ies");
    return 0;
}

const deployment_manifest_t *deployment_manifest_active(void)
{
    return &g_active;
}

void deployment_manifest_reset(void)
{
    pthread_mutex_lock(&g_active_lock);
    deployment_manifest_free(&g_active);
    pthread_mutex_unlock(&g_active_lock);
}
