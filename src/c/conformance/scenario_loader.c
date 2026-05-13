/********************
 *  Copyright 2026 Sean M. Brennan and contributors
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

#include "scenario_loader.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static char *xstrdup(const char *s) {
    if (s == NULL) return NULL;
    size_t n = strlen(s) + 1;
    char *r = malloc(n);
    if (r == NULL) return NULL;
    memcpy(r, s, n);
    return r;
}

/* Process-global corpus root.  Lifetime is bounded by the next
 * at_load_corpus() call; ownership stays here. */
static char *g_corpus_root = NULL;

const char *at_corpus_root(void) {
    return g_corpus_root;
}

int at_load_testdata_bytes(const char *rel_path, char **out, size_t *out_len) {
    if (rel_path == NULL || out == NULL || out_len == NULL) return -1;
    if (g_corpus_root == NULL) return -1;
    /* Reject traversal: `..` anywhere in the relative path. */
    if (strstr(rel_path, "..") != NULL) return -1;
    if (rel_path[0] == '/') return -1;  /* must be relative */

    char path[2048];
    int wr = snprintf(path, sizeof(path), "%s/%s", g_corpus_root, rel_path);
    if (wr < 0 || (size_t)wr >= sizeof(path)) return -1;

    FILE *f = fopen(path, "rb");
    if (f == NULL) return -1;
    if (fseek(f, 0, SEEK_END) != 0) { fclose(f); return -1; }
    long sz = ftell(f);
    if (sz < 0) { fclose(f); return -1; }
    rewind(f);

    char *buf = malloc((size_t)sz + 1);
    if (buf == NULL) { fclose(f); return -1; }
    size_t got = fread(buf, 1, (size_t)sz, f);
    fclose(f);
    if (got != (size_t)sz) { free(buf); return -1; }
    buf[sz] = '\0';

    *out = buf;
    *out_len = (size_t)sz;
    return 0;
}

static int load_one_case(const char *json_root, const char *rel_path, at_case_t *out) {
    char path[2048];
    snprintf(path, sizeof(path), "%s/%s", json_root, rel_path);

    json_error_t err;
    json_t *root = json_load_file(path, 0, &err);
    if (root == NULL) {
        fprintf(stderr, "loader: %s: %s (line %d)\n", path, err.text, err.line);
        return -1;
    }

    json_t *case_id = json_object_get(root, "case_id");
    json_t *kind = json_object_get(root, "kind");
    json_t *protocol = json_object_get(root, "protocol");
    json_t *name = json_object_get(root, "name");
    json_t *source = json_object_get(root, "source_path");
    json_t *data = json_object_get(root, "data");

    if (!json_is_string(case_id) || !json_is_string(kind) ||
        !json_is_string(protocol) || !json_is_string(name) ||
        !json_is_object(data)) {
        fprintf(stderr, "loader: %s: missing or wrong-typed required field\n", path);
        json_decref(root);
        return -1;
    }

    out->case_id = xstrdup(json_string_value(case_id));
    out->kind = xstrdup(json_string_value(kind));
    out->protocol = xstrdup(json_string_value(protocol));
    out->name = xstrdup(json_string_value(name));
    out->source_path = json_is_string(source)
        ? xstrdup(json_string_value(source))
        : xstrdup("");
    /* data is borrowed; root is owned. */
    out->data = data;
    out->_root = root;
    return 0;
}

int at_load_corpus(const char *json_root, at_case_t **cases, size_t *n) {
    *cases = NULL;
    *n = 0;

    /* Remember the root for later testdata lookups. */
    free(g_corpus_root);
    g_corpus_root = xstrdup(json_root);

    char index_path[2048];
    snprintf(index_path, sizeof(index_path), "%s/index.json", json_root);

    json_error_t err;
    json_t *index = json_load_file(index_path, 0, &err);
    if (index == NULL) {
        fprintf(stderr, "loader: %s: %s\n", index_path, err.text);
        return -1;
    }
    if (!json_is_array(index)) {
        fprintf(stderr, "loader: %s: expected a JSON array\n", index_path);
        json_decref(index);
        return -1;
    }

    size_t count = json_array_size(index);
    at_case_t *arr = calloc(count, sizeof(at_case_t));
    if (arr == NULL) {
        json_decref(index);
        return -1;
    }

    size_t produced = 0;
    for (size_t i = 0; i < count; i++) {
        json_t *entry = json_array_get(index, i);
        if (!json_is_string(entry)) continue;
        if (load_one_case(json_root, json_string_value(entry), &arr[produced]) == 0) {
            produced++;
        }
    }
    json_decref(index);

    *cases = arr;
    *n = produced;
    return 0;
}

void at_case_free(at_case_t *c) {
    if (c == NULL) return;
    free(c->case_id);
    free(c->kind);
    free(c->protocol);
    free(c->name);
    free(c->source_path);
    if (c->_root != NULL) json_decref(c->_root);
    /* zero out so double-free is safe. */
    memset(c, 0, sizeof(*c));
}
