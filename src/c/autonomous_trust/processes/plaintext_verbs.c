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

#include <errno.h>
#include <pthread.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>

#include <jansson.h>

#include "config/configuration.h"
#include "processes/extension.h"
#include "processes/plaintext_verbs.h"
#include "utilities/util.h"

/* Written at startup (and by the conformance adapter between scenarios), read
 * on each plaintext frame by the network receivers. */
static struct {
    pthread_mutex_t lock;
    char verbs[PLAINTEXT_VERBS_MAX][PLAINTEXT_VERB_LEN + 1];
    size_t n;
} granted = { .lock = PTHREAD_MUTEX_INITIALIZER };

static bool _in(char list[][PLAINTEXT_VERB_LEN + 1], size_t n, const char *v)
{
    for (size_t i = 0; i < n; i++)
        if (strcmp(list[i], v) == 0)
            return true;
    return false;
}

/* Parse @p path into @p out. 1: no file; 0: read; -1: malformed (logged). */
static int _read(const char *path, char out[][PLAINTEXT_VERB_LEN + 1], size_t *n,
                 logger_t *logger)
{
    *n = 0;
    struct stat st;
    if (stat(path, &st) != 0 && errno == ENOENT)
        return 1;
    json_error_t jerr;
    json_t *doc = json_load_file(path, 0, &jerr);
    if (doc == NULL) {
        log_error(logger, "%s: not JSON (%s); refusing to start\n", path, jerr.text);
        return -1;
    }
    json_t *verbs = json_is_object(doc) ? json_object_get(doc, "verbs") : NULL;
    if (verbs == NULL || json_object_size(doc) != 1) {
        log_error(logger, "%s: must be an object holding only \"verbs\"; refusing "
                  "to start\n", path);
        json_decref(doc);
        return -1;
    }
    if (!json_is_array(verbs)) {
        log_error(logger, "%s: \"verbs\" must be a list of verb names; refusing "
                  "to start\n", path);
        json_decref(doc);
        return -1;
    }
    size_t i;
    json_t *item;
    json_array_foreach(verbs, i, item) {
        const char *v = json_string_value(item);
        if (v == NULL || v[0] == '\0') {
            log_error(logger, "%s: \"verbs\" must be a list of verb names; "
                      "refusing to start\n", path);
            json_decref(doc);
            return -1;
        }
        if (*n >= PLAINTEXT_VERBS_MAX || strlen(v) > PLAINTEXT_VERB_LEN) {
            log_error(logger, "%s: more than %d verbs, or a name longer than %d; "
                      "refusing to start\n", path, PLAINTEXT_VERBS_MAX,
                      PLAINTEXT_VERB_LEN);
            json_decref(doc);
            return -1;
        }
        if (_in(out, *n, v)) {
            log_error(logger, "%s: \"verbs\" names a verb twice; refusing to "
                      "start\n", path);
            json_decref(doc);
            return -1;
        }
        at_strlcpy(out[(*n)++], v, PLAINTEXT_VERB_LEN + 1);
    }
    json_decref(doc);
    return 0;
}

static bool _declares(const at_extension_t *ext, const char *verb)
{
    for (const char *const *p = ext->plaintext_verbs; p != NULL && *p != NULL; p++)
        if (strcmp(*p, verb) == 0)
            return true;
    return false;
}

int plaintext_verbs_configure(const char *cfg_dir, logger_t *logger)
{
    char dir[CFG_PATH_LEN + 1] = {0};
    if (cfg_dir == NULL) {
        if (get_cfg_dir(dir, sizeof(dir)) <= 0)
            dir[0] = '\0';
        cfg_dir = dir;
    }
    char path[CFG_PATH_LEN + sizeof(PLAINTEXT_VERBS_FILENAME) + 2];
    snprintf(path, sizeof(path), "%s/%s", cfg_dir, PLAINTEXT_VERBS_FILENAME);

    char named[PLAINTEXT_VERBS_MAX][PLAINTEXT_VERB_LEN + 1];
    size_t n = 0;
    /* No configuration directory at all reads as no file. */
    int rc = cfg_dir[0] != '\0' ? _read(path, named, &n, logger) : 1;
    if (rc < 0)
        return -1;
    bool absent = rc == 1;

    const at_extension_t *exts[AT_EXTENSION_MAX];
    size_t n_exts = at_extensions_enabled(exts, AT_EXTENSION_MAX);

    /* Every named verb must be one an enabled extension declares. */
    char bad[PLAINTEXT_VERBS_MAX * (PLAINTEXT_VERB_LEN + 2) + 1] = "";
    for (size_t i = 0; i < n; i++) {
        bool eligible = false;
        for (size_t e = 0; e < n_exts && !eligible; e++)
            eligible = _declares(exts[e], named[i]);
        if (eligible)
            continue;
        if (bad[0] != '\0')
            strncat(bad, ", ", sizeof(bad) - strlen(bad) - 1);
        strncat(bad, named[i], sizeof(bad) - strlen(bad) - 1);
    }
    if (bad[0] != '\0') {
        log_error(logger, "%s names %s, which no loaded extension may receive in "
                  "plaintext; refusing to start\n", path, bad);
        return -1;
    }
    /* And every enabled extension's declared verbs must be named. */
    for (size_t e = 0; e < n_exts; e++) {
        char missing[PLAINTEXT_VERBS_MAX * (PLAINTEXT_VERB_LEN + 2) + 1] = "";
        for (const char *const *p = exts[e]->plaintext_verbs; p != NULL && *p != NULL; p++) {
            if (_in(named, n, *p))
                continue;
            if (missing[0] != '\0')
                strncat(missing, ", ", sizeof(missing) - strlen(missing) - 1);
            strncat(missing, *p, sizeof(missing) - strlen(missing) - 1);
        }
        if (missing[0] != '\0') {
            log_error(logger, "the %s extension needs %s in %s%s; refusing to "
                      "start\n", exts[e]->name, missing, path,
                      absent ? " (no such file)" : "");
            return -1;
        }
    }

    pthread_mutex_lock(&granted.lock);
    memcpy(granted.verbs, named, sizeof(named));
    granted.n = n;
    pthread_mutex_unlock(&granted.lock);
    return 0;
}

bool plaintext_verb_granted(const char *verb)
{
    if (verb == NULL || verb[0] == '\0')
        return false;
    pthread_mutex_lock(&granted.lock);
    bool found = _in(granted.verbs, granted.n, verb);
    pthread_mutex_unlock(&granted.lock);
    return found;
}

size_t plaintext_verbs_granted_count(void)
{
    pthread_mutex_lock(&granted.lock);
    size_t n = granted.n;
    pthread_mutex_unlock(&granted.lock);
    return n;
}

void plaintext_verbs_reset(void)
{
    pthread_mutex_lock(&granted.lock);
    granted.n = 0;
    pthread_mutex_unlock(&granted.lock);
}
