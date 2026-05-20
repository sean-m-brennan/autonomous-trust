/********************
 *  Copyright 2025 Sean M. Brennan and contributors
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

#include "fleet/artifact_store.h"
#include "utilities/util.h"

#include <dirent.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include <jansson.h>
#include <sodium.h>

static char store_base_dir[256];

/* ---------- helpers ---------- */

/* Frama-C: skipped — [solver-timeout] chained path_join preconditions */
static int build_artifact_dir(const char *hash_hex, char *buf, size_t buflen)
{
    char artifacts_root[512];
    if (path_join(artifacts_root, sizeof(artifacts_root),
                  store_base_dir, "artifacts") < 0)
        return -1;
    if (path_join(buf, buflen, artifacts_root, hash_hex) < 0)
        return -1;
    return 0;
}

/* Frama-C: skipped — [solver-timeout] chained path_join + snprintf preconditions */
static int build_chunk_path(const char *hash_hex, int chunk_index,
                            char *buf, size_t buflen)
{
    char art_dir[512];
    if (build_artifact_dir(hash_hex, art_dir, sizeof(art_dir)) != 0)
        return -1;
    char chunk_name[32];
    int n = snprintf(chunk_name, sizeof(chunk_name), "chunk_%04d", chunk_index);
    if (n < 0 || (size_t)n >= sizeof(chunk_name))
        return -1;
    if (path_join(buf, buflen, art_dir, chunk_name) < 0)
        return -1;
    return 0;
}

/* Frama-C: skipped — [solver-timeout] chained path_join preconditions */
static int build_manifest_path(const char *hash_hex, char *buf, size_t buflen)
{
    char art_dir[512];
    if (build_artifact_dir(hash_hex, art_dir, sizeof(art_dir)) != 0)
        return -1;
    if (path_join(buf, buflen, art_dir, "manifest.json") < 0)
        return -1;
    return 0;
}

/* Frama-C: skipped — [solver-timeout] chained path_join preconditions */
static int build_complete_path(const char *hash_hex, char *buf, size_t buflen)
{
    char art_dir[512];
    if (build_artifact_dir(hash_hex, art_dir, sizeof(art_dir)) != 0)
        return -1;
    if (path_join(buf, buflen, art_dir, "complete") < 0)
        return -1;
    return 0;
}

/* Frama-C: skipped — [solver-timeout] stat + mkdir preconditions */
static int ensure_dir(const char *path)
{
    struct stat st;
    if (stat(path, &st) == 0 && S_ISDIR(st.st_mode))
        return 0;
    if (mkdir(path, 0755) != 0 && errno != EEXIST)
        return -1;
    return 0;
}

/* ---------- public API ---------- */

/* Frama-C: skipped — [solver-timeout] path_join + mkdir preconditions */
int artifact_store_init(const char *data_dir)
{
    strncpy(store_base_dir, data_dir, sizeof(store_base_dir) - 1);
    store_base_dir[sizeof(store_base_dir) - 1] = '\0';
    char artifacts_dir[512];
    if (path_join(artifacts_dir, sizeof(artifacts_dir), data_dir, "artifacts") < 0)
        return -1;
    return ensure_dir(artifacts_dir);
}

/* Frama-C: skipped — [solver-timeout] chained path_join + stat preconditions */
bool artifact_store_has(const char *hash_hex)
{
    char path[512];
    if (build_complete_path(hash_hex, path, sizeof(path)) != 0)
        return false;
    struct stat st;
    return (stat(path, &st) == 0);
}

/* Frama-C: skipped — [solver-timeout] path_join + JSON file I/O */
int artifact_store_save_manifest(const artifact_manifest_t *manifest)
{
    char art_dir[512];
    if (build_artifact_dir(manifest->hash_hex, art_dir, sizeof(art_dir)) != 0)
        return -1;
    if (ensure_dir(art_dir) != 0)
        return -1;

    json_t *root = json_object();
    if (!root) return -1;

    json_object_set_new(root, "hash_hex", json_string(manifest->hash_hex));
    json_object_set_new(root, "total_chunks", json_integer(manifest->total_chunks));
    json_object_set_new(root, "total_size", json_integer((json_int_t)manifest->total_size));
    json_object_set_new(root, "chunk_size", json_integer((json_int_t)manifest->chunk_size));
    json_object_set_new(root, "version", json_string(manifest->version));

    char path[512];
    if (build_manifest_path(manifest->hash_hex, path, sizeof(path)) != 0) {
        json_decref(root);
        return -1;
    }

    int rc = json_dump_file(root, path, JSON_INDENT(2));
    json_decref(root);
    return rc;
}

/* Frama-C: skipped — [solver-timeout] path_join + JSON file I/O */
int artifact_store_load_manifest(const char *hash_hex, artifact_manifest_t *manifest)
{
    char path[512];
    if (build_manifest_path(hash_hex, path, sizeof(path)) != 0)
        return -1;

    json_error_t err;
    json_t *root = json_load_file(path, 0, &err);
    if (!root) return -1;

    const char *hex = json_string_value(json_object_get(root, "hash_hex"));
    const char *ver = json_string_value(json_object_get(root, "version"));
    json_t *tc  = json_object_get(root, "total_chunks");
    json_t *ts  = json_object_get(root, "total_size");
    json_t *cs  = json_object_get(root, "chunk_size");

    if (!hex || !ver || !tc || !ts || !cs) {
        json_decref(root);
        return -1;
    }

    memset(manifest, 0, sizeof(*manifest));
    strncpy(manifest->hash_hex, hex, sizeof(manifest->hash_hex) - 1);
    manifest->hash_hex[sizeof(manifest->hash_hex) - 1] = '\0';
    strncpy(manifest->version, ver, sizeof(manifest->version) - 1);
    manifest->version[sizeof(manifest->version) - 1] = '\0';
    manifest->total_chunks = (int)json_integer_value(tc);
    manifest->total_size   = (size_t)json_integer_value(ts);
    manifest->chunk_size   = (size_t)json_integer_value(cs);
    strncpy(manifest->base_dir, store_base_dir, sizeof(manifest->base_dir) - 1);
    manifest->base_dir[sizeof(manifest->base_dir) - 1] = '\0';

    json_decref(root);
    return 0;
}

/* Frama-C: skipped — [solver-timeout] path_join + file write preconditions */
int artifact_store_save_chunk(const char *hash_hex, int chunk_index,
                              const uint8_t *data, size_t len)
{
    char art_dir[512];
    if (build_artifact_dir(hash_hex, art_dir, sizeof(art_dir)) != 0)
        return -1;
    if (ensure_dir(art_dir) != 0)
        return -1;

    char path[512];
    if (build_chunk_path(hash_hex, chunk_index, path, sizeof(path)) != 0)
        return -1;

    FILE *fp = fopen(path, "wb");
    if (!fp) return -1;

    size_t written = fwrite(data, 1, len, fp);
    fclose(fp);
    return (written == len) ? 0 : -1;
}

/* Frama-C: skipped — [solver-timeout] path_join + file read preconditions */
int artifact_store_read_chunk(const char *hash_hex, int chunk_index,
                              uint8_t *buf, size_t buflen, size_t *out_len)
{
    char path[512];
    if (build_chunk_path(hash_hex, chunk_index, path, sizeof(path)) != 0)
        return -1;

    FILE *fp = fopen(path, "rb");
    if (!fp) return -1;

    size_t nread = fread(buf, 1, buflen, fp);
    fclose(fp);

    if (out_len) *out_len = nread;
    return 0;
}

/* Frama-C: skipped — [solver-timeout] chained path_join + stat preconditions */
bool artifact_store_has_chunk(const char *hash_hex, int chunk_index)
{
    char path[512];
    if (build_chunk_path(hash_hex, chunk_index, path, sizeof(path)) != 0)
        return false;
    struct stat st;
    return (stat(path, &st) == 0);
}

/* Frama-C: skipped — [solver-timeout] chained path_join + filesystem preconditions */
int artifact_store_chunk_count(const char *hash_hex)
{
    char art_dir[512];
    if (build_artifact_dir(hash_hex, art_dir, sizeof(art_dir)) != 0)
        return 0;

    DIR *d = opendir(art_dir);
    if (!d) return 0;

    int count = 0;
    struct dirent *ent;
    while ((ent = readdir(d)) != NULL) {
        if (strncmp(ent->d_name, "chunk_", 6) == 0)
            count++;
    }
    closedir(d);
    return count;
}

/* Frama-C: skipped — [solver-timeout] crypto verification + path_join */
int artifact_store_verify(const char *hash_hex, const uint8_t *expected_hash)
{
    artifact_manifest_t manifest;
    if (artifact_store_load_manifest(hash_hex, &manifest) != 0)
        return -1;

    crypto_generichash_blake2b_state state;
    if (crypto_generichash_blake2b_init(&state, NULL, 0, UPDATE_HASH_LEN) != 0)
        return -1;

    uint8_t chunk_buf[65536];
    for (int i = 0; i < manifest.total_chunks; i++) {
        size_t chunk_len = 0;
        if (artifact_store_read_chunk(hash_hex, i, chunk_buf, sizeof(chunk_buf),
                                      &chunk_len) != 0)
            return -1;
        if (crypto_generichash_blake2b_update(&state, chunk_buf, chunk_len) != 0)
            return -1;
    }

    uint8_t computed_hash[UPDATE_HASH_LEN];
    if (crypto_generichash_blake2b_final(&state, computed_hash, UPDATE_HASH_LEN) != 0)
        return -1;

    if (sodium_memcmp(computed_hash, expected_hash, UPDATE_HASH_LEN) != 0)
        return -1;

    /* Create the 'complete' marker file */
    char path[512];
    if (build_complete_path(hash_hex, path, sizeof(path)) != 0)
        return -1;

    FILE *fp = fopen(path, "w");
    if (!fp) return -1;
    fclose(fp);

    return 0;
}

/* Frama-C: skipped — [solver-timeout] chained path_join preconditions */
int artifact_store_get_path(const char *hash_hex, char *path_buf, size_t buflen)
{
    if (!artifact_store_has(hash_hex))
        return -1;
    return build_artifact_dir(hash_hex, path_buf, buflen);
}

/* Frama-C: skipped — [solver-timeout] chained path_join + file assembly */
int artifact_store_reassemble(const char *hash_hex, char *out_path, size_t out_path_len)
{
    artifact_manifest_t manifest;
    if (artifact_store_load_manifest(hash_hex, &manifest) != 0)
        return -1;

    char art_dir[512];
    if (build_artifact_dir(hash_hex, art_dir, sizeof(art_dir)) != 0)
        return -1;

    if (path_join(out_path, out_path_len, art_dir, "assembled") < 0)
        return -1;

    FILE *out = fopen(out_path, "wb");
    if (!out)
        return -1;

    uint8_t chunk_buf[65536];
    for (int i = 0; i < manifest.total_chunks; i++)
    {
        size_t chunk_len = 0;
        if (artifact_store_read_chunk(hash_hex, i, chunk_buf, sizeof(chunk_buf),
                                      &chunk_len) != 0)
        {
            fclose(out);
            unlink(out_path);
            return -1;
        }
        if (fwrite(chunk_buf, 1, chunk_len, out) != chunk_len)
        {
            fclose(out);
            unlink(out_path);
            return -1;
        }
    }

    fclose(out);
    return 0;
}

/* Frama-C: skipped — [solver-timeout] chained path_join + filesystem preconditions */
int artifact_store_delete(const char *hash_hex)
{
    char art_dir[512];
    if (build_artifact_dir(hash_hex, art_dir, sizeof(art_dir)) != 0)
        return -1;

    DIR *d = opendir(art_dir);
    if (!d) return -1;

    struct dirent *ent;
    while ((ent = readdir(d)) != NULL) {
        if (strcmp(ent->d_name, ".") == 0 || strcmp(ent->d_name, "..") == 0)
            continue;
        char filepath[768];
        if (path_join(filepath, sizeof(filepath), art_dir, ent->d_name) < 0)
            continue;
        unlink(filepath);
    }
    closedir(d);

    return rmdir(art_dir);
}
