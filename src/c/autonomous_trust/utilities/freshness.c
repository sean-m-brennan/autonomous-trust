/*******************
 * Copyright 2026 TekFive, Inc., Sean M. Brennan, and contributors
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *******************/
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <jansson.h>

#include "config/configuration.h"
#include "config/discover.h"   /* CFG_FILE_EXT */
#include "structures/data.h"
#include "utilities/exception.h"
#include "utilities/freshness.h"

/* Key form for the marks map. Flat "sender|verb" because jansson has no
 * composite object key and the pair is already two short strings. */
#define FRESHNESS_KEY_LEN 192

static int64_t _fresh_now_us(void)
{
    struct timespec ts;
    if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0)
        return 0;
    return (int64_t)ts.tv_sec * 1000000LL + (int64_t)ts.tv_nsec / 1000LL;
}

static int _fresh_path(const freshness_t *fr, char *out, size_t cap)
{
    char cfg_dir[CFG_PATH_LEN + 1] = {0};
    if (get_cfg_dir(cfg_dir, sizeof(cfg_dir)) < 0)
        return -1;
    int n = snprintf(out, cap, "%s/%s-%s%s", cfg_dir, FRESHNESS_FILE,
                     fr->proc_name, CFG_FILE_EXT);
    if (n < 0 || (size_t)n >= cap)
        return -1;
    return 0;
}

static void _fresh_key(char *out, size_t cap, const char *sender,
                       const char *verb)
{
    snprintf(out, cap, "%s|%s", sender == NULL ? "" : sender,
             verb == NULL ? "" : verb);
}

static void _fresh_write(freshness_t *fr, bool force, logger_t *logger)
{
    if (!force && !fr->dirty)
        return;
    int64_t now_us = _fresh_now_us();
    if (!force && (now_us - fr->last_flush_us) < FRESHNESS_FLUSH_US)
        return;

    char path[CFG_PATH_LEN + 96] = {0};
    if (_fresh_path(fr, path, sizeof(path)) != 0)
    {
        log_warn(logger, "Freshness: cannot build path; not persisting\n");
        return;
    }
    json_t *doc = json_object();
    json_t *marks = json_object();
    if (doc == NULL || marks == NULL)
    {
        if (doc != NULL) json_decref(doc);
        if (marks != NULL) json_decref(marks);
        return;
    }
    json_object_set_new(doc, "seq", json_integer((json_int_t)fr->seq));
    map_key_t key = NULL;
    data_t *val = NULL;
    map_entries_for_each(&fr->marks, key, val)
    {
        int n = 0;
        if (data_integer(val, &n) == 0)
            json_object_set_new(marks, (const char *)key,
                                json_integer((json_int_t)n));
    }
    map_end_for_each
    json_object_set_new(doc, "marks", marks);

    /* Swallowed like the other snapshot writers: the alternative is taking a
     * process down over a full disk. Logged at warning rather than debug
     * because the cost is a reopened replay window. */
    if (json_dump_file(doc, path, JSON_INDENT(2)) != 0)
        log_warn(logger, "Freshness: could not persist to %s\n", path);
    else
    {
        fr->dirty = false;
        fr->last_flush_us = now_us;
    }
    json_decref(doc);
}

static void _fresh_load(freshness_t *fr, logger_t *logger)
{
    char path[CFG_PATH_LEN + 96] = {0};
    if (_fresh_path(fr, path, sizeof(path)) != 0)
        return;
    json_error_t err;
    json_t *doc = json_load_file(path, 0, &err);
    if (doc == NULL)
        return;  /* cold start: no counter, no marks, first message accepted */
    if (!json_is_object(doc))
    {
        log_error(logger,
                  "Freshness: state malformed (%s); replay protection for %s "
                  "starts from empty this boot\n", path, fr->proc_name);
        json_decref(doc);
        return;
    }
    json_t *j_seq = json_object_get(doc, "seq");
    if (json_is_integer(j_seq))
        fr->seq = (int64_t)json_integer_value(j_seq);
    json_t *j_marks = json_object_get(doc, "marks");
    size_t restored = 0;
    if (json_is_object(j_marks))
    {
        const char *k = NULL;
        json_t *v = NULL;
        json_object_foreach(j_marks, k, v)
        {
            if (!json_is_integer(v))
                continue;
            map_set(&fr->marks, (map_key_t)k,
                    integer_data((int)json_integer_value(v)));
            restored++;
        }
    }
    json_decref(doc);
    log_debug(logger, "Freshness restored for %s: seq=%lld, %zu mark(s)\n",
              fr->proc_name, (long long)fr->seq, restored);
}

int freshness_init(freshness_t *fr, const char *proc_name, logger_t *logger)
{
    if (fr == NULL || proc_name == NULL)
        return EXCEPTION(EINVAL);
    memset(fr, 0, sizeof(*fr));
    snprintf(fr->proc_name, sizeof(fr->proc_name), "%s", proc_name);
    map_init(&fr->marks);
    map_init(&fr->refusals);
    fr->initialized = true;
    _fresh_load(fr, logger);
    return 0;
}

void freshness_free(freshness_t *fr, logger_t *logger)
{
    if (fr == NULL || !fr->initialized)
        return;
    _fresh_write(fr, true, logger);
    map_free(&fr->marks);
    map_free(&fr->refusals);
    fr->initialized = false;
}

int64_t freshness_stamp(freshness_t *fr, logger_t *logger)
{
    if (fr == NULL || !fr->initialized)
        return 0;
    fr->seq++;
    /* Forced: the caller is about to put this number on the wire. */
    _fresh_write(fr, true, logger);
    return fr->seq;
}

/* Tally one refusal against @p verb. See freshness_refusals() for why the key
 * is the verb alone and why both refusal shapes share the count. */
static void _fresh_refused(freshness_t *fr, const char *verb)
{
    data_t *cur = NULL;
    int count = 0;
    if (map_get(&fr->refusals, (map_key_t)verb, &cur) == 0 && cur != NULL)
        data_integer(cur, &count);
    map_set(&fr->refusals, (map_key_t)verb, integer_data(count + 1));
    fr->refusals_total++;
}

bool freshness_accept(freshness_t *fr, const char *sender, const char *verb,
                      int64_t seq, logger_t *logger)
{
    if (fr == NULL || !fr->initialized || sender == NULL || verb == NULL)
        return false;  /* no state to tally into */
    if (seq <= 0) {
        _fresh_refused(fr, verb);
        return false;  /* unstamped or stripped; both refused */
    }
    char key[FRESHNESS_KEY_LEN];
    _fresh_key(key, sizeof(key), sender, verb);
    data_t *mark = NULL;
    int applied = 0;
    if (map_get(&fr->marks, (map_key_t)key, &mark) == 0 && mark != NULL)
        data_integer(mark, &applied);
    if (seq <= (int64_t)applied) {
        _fresh_refused(fr, verb);
        return false;
    }
    map_set(&fr->marks, (map_key_t)key, integer_data((int)seq));
    fr->dirty = true;
    _fresh_write(fr, false, logger);
    return true;
}

int64_t freshness_mark(freshness_t *fr, const char *sender, const char *verb)
{
    if (fr == NULL || !fr->initialized || sender == NULL || verb == NULL)
        return 0;
    char key[FRESHNESS_KEY_LEN];
    _fresh_key(key, sizeof(key), sender, verb);
    data_t *mark = NULL;
    int applied = 0;
    if (map_get(&fr->marks, (map_key_t)key, &mark) == 0 && mark != NULL)
        data_integer(mark, &applied);
    return (int64_t)applied;
}

int64_t freshness_refusals(freshness_t *fr, const char *verb)
{
    if (fr == NULL || !fr->initialized)
        return 0;
    if (verb == NULL)
        return fr->refusals_total;
    data_t *cur = NULL;
    int count = 0;
    if (map_get(&fr->refusals, (map_key_t)verb, &cur) == 0 && cur != NULL)
        data_integer(cur, &count);
    return (int64_t)count;
}

void freshness_flush(freshness_t *fr, logger_t *logger)
{
    if (fr == NULL || !fr->initialized)
        return;
    _fresh_write(fr, true, logger);
}

void freshness_reset(freshness_t *fr)
{
    if (fr == NULL || !fr->initialized)
        return;
    /* Deliberately no _fresh_write and no _fresh_load: the point is to end up
     * with the cold-start state, and re-reading the file would restore exactly
     * the marks the caller is trying to be rid of. */
    map_free(&fr->marks);
    map_init(&fr->marks);
    map_free(&fr->refusals);
    map_init(&fr->refusals);
    fr->refusals_total = 0;
    fr->seq = 0;
    fr->dirty = false;
    fr->last_flush_us = 0;
}
