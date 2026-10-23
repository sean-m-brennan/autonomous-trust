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
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <jansson.h>

#include "join_policy.h"
#include "id_ext.h"

static const struct {
    const char *name;
    uint32_t bit;
    /* The extensions that can answer it (id_ext.h), NULL-terminated. */
    const char *providers[3];
} _classes[] = {
    {"verified_contact",   AT_ANCHOR_VERIFIED_CONTACT,   {"first_contact", NULL, NULL}},
    {"unverified_contact", AT_ANCHOR_UNVERIFIED_CONTACT, {"first_contact", NULL, NULL}},
    {"zta",                AT_ANCHOR_ZTA,                {"zta", NULL, NULL}},
    {"operator",           AT_ANCHOR_OPERATOR,           {"zta", "first_contact", NULL}},
};
#define N_CLASSES (sizeof(_classes) / sizeof(_classes[0]))

static void _fail(char *err, size_t err_len, const char *fmt, ...)
{
    if (err == NULL || err_len == 0)
        return;
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(err, err_len, fmt, ap);
    va_end(ap);
}

uint32_t at_join_policy_class(const char *name)
{
    if (name == NULL)
        return 0;
    for (size_t i = 0; i < N_CLASSES; i++)
        if (strcmp(_classes[i].name, name) == 0)
            return _classes[i].bit;
    return 0;
}

const char *at_join_policy_class_name(uint32_t bit)
{
    for (size_t i = 0; i < N_CLASSES; i++)
        if (_classes[i].bit == bit)
            return _classes[i].name;
    return NULL;
}

bool at_join_policy_parse(const char *text, at_join_policy_t *out,
                          char *err, size_t err_len)
{
    if (out == NULL)
        return false;
    memset(out, 0, sizeof(*out));
    if (text == NULL)
        return true;
    json_error_t jerr;
    json_t *root = json_loads(text, 0, &jerr);
    if (root == NULL) {
        _fail(err, err_len, "not JSON: %s", jerr.text);
        return false;
    }
    bool ok = false;
    if (!json_is_object(root)) {
        _fail(err, err_len, "declaration is not an object");
        goto done;
    }
    const char *key;
    json_t *val;
    json_object_foreach(root, key, val) {
        if (strcmp(key, "version") != 0 && strcmp(key, "enabled") != 0
            && strcmp(key, "anchors") != 0 && strcmp(key, "note") != 0) {
            _fail(err, err_len, "unknown key(s) %s", key);
            goto done;
        }
    }
    json_t *version = json_object_get(root, "version");
    if (!json_is_integer(version) || json_integer_value(version) != 1) {
        _fail(err, err_len, "unsupported version; expected 1");
        goto done;
    }
    json_t *enabled = json_object_get(root, "enabled");
    if (enabled != NULL && !json_is_boolean(enabled)) {
        _fail(err, err_len, "enabled: not a boolean");
        goto done;
    }
    json_t *anchors = json_object_get(root, "anchors");
    if (anchors != NULL && !json_is_array(anchors)) {
        _fail(err, err_len, "anchors is not a list");
        goto done;
    }
    uint32_t bits = 0;
    size_t i;
    json_t *item;
    json_array_foreach(anchors, i, item) {
        uint32_t bit = at_join_policy_class(json_string_value(item));
        if (bit == 0) {
            _fail(err, err_len, "anchors: unknown class '%.40s'; expected one of "
                  "verified_contact, unverified_contact, zta, operator",
                  json_is_string(item) ? json_string_value(item) : "(not a string)");
            goto done;
        }
        if (bits & bit) {
            _fail(err, err_len, "anchors: '%s' listed twice", json_string_value(item));
            goto done;
        }
        bits |= bit;
    }
    out->enabled = json_is_true(enabled);
    out->anchors = bits;
    ok = true;
done:
    json_decref(root);
    if (!ok)
        memset(out, 0, sizeof(*out));
    return ok;
}

bool at_join_policy_load(const char *path, at_join_policy_t *out,
                         char *err, size_t err_len)
{
    if (path == NULL || out == NULL)
        return false;
    memset(out, 0, sizeof(*out));
    FILE *fp = fopen(path, "rb");
    if (fp == NULL) {
        _fail(err, err_len, "cannot open %s", path);
        return false;
    }
    if (fseek(fp, 0, SEEK_END) != 0) {
        fclose(fp);
        _fail(err, err_len, "cannot size %s", path);
        return false;
    }
    long len = ftell(fp);
    if (len < 0 || fseek(fp, 0, SEEK_SET) != 0) {
        fclose(fp);
        _fail(err, err_len, "cannot size %s", path);
        return false;
    }
    char *buf = malloc((size_t)len + 1);
    if (buf == NULL) {
        fclose(fp);
        _fail(err, err_len, "out of memory");
        return false;
    }
    size_t got = fread(buf, 1, (size_t)len, fp);
    buf[got] = '\0';
    fclose(fp);
    bool ok = at_join_policy_parse(buf, out, err, err_len);
    free(buf);
    return ok;
}

bool at_join_policy_load_env(at_join_policy_t *out, char *err, size_t err_len)
{
    const char *path = getenv(AT_JOIN_POLICY_ENV);
    if (path == NULL || path[0] == '\0')
        return at_join_policy_parse(NULL, out, err, err_len);
    return at_join_policy_load(path, out, err, err_len);
}

uint32_t at_join_policy_missing_providers(const at_join_policy_t *policy)
{
    if (policy == NULL || !policy->enabled)
        return 0;
    uint32_t missing = 0;
    for (size_t i = 0; i < N_CLASSES; i++) {
        if (!(policy->anchors & _classes[i].bit))
            continue;
        bool answered = false;
        for (size_t p = 0; _classes[i].providers[p] != NULL; p++)
            answered = answered || identity_ext_present(_classes[i].providers[p]);
        if (!answered)
            missing |= _classes[i].bit;
    }
    return missing;
}
