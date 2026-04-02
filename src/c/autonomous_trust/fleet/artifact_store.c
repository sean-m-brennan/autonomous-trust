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

static int build_artifact_dir(const char *hash_hex, char *buf, size_t buflen)
{
    int n = snprintf(buf, buflen, "%s/artifacts/%s", store_base_dir, hash_hex);
    if (n < 0 || (size_t)n >= buflen)
        return -1;
    return 0;
}

static int build_chunk_path(const char *hash_hex, int chunk_index,
                            char *buf, size_t buflen)
{
    int n = snprintf(buf, buflen, "%s/artifacts/%s/chunk_%04d",
                     store_base_dir, hash_hex, chunk_index);
    if (n < 0 || (size_t)n >= buflen)
        return -1;
    return 0;
}

static int build_manifest_path(const char *hash_hex, char *buf, size_t buflen)
{
    int n = snprintf(buf, buflen, "%s/artifacts/%s/manifest.json",
                     store_base_dir, hash_hex);
    if (n < 0 || (size_t)n >= buflen)
        return -1;
    return 0;
}

static int build_complete_path(const char *hash_hex, char *buf, size_t buflen)
{
    int n = snprintf(buf, buflen, "%s/artifacts/%s/complete",
                     store_base_dir, hash_hex);
    if (n < 0 || (size_t)n >= buflen)
        return -1;
    return 0;
}

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

int artifact_store_init(const char *data_dir)
{
    snprintf(store_base_dir, sizeof(store_base_dir), "%s", data_dir);
    char artifacts_dir[512];
    snprintf(artifacts_dir, sizeof(artifacts_dir), "%s/artifacts", data_dir);
    return ensure_dir(artifacts_dir);
}

bool artifact_store_has(const char *hash_hex)
{
    char path[512];
    if (build_complete_path(hash_hex, path, sizeof(path)) != 0)
        return false;
    struct stat st;
    return (stat(path, &st) == 0);
}

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
    strncpy(manifest->version, ver, sizeof(manifest->version) - 1);
    manifest->total_chunks = (int)json_integer_value(tc);
    manifest->total_size   = (size_t)json_integer_value(ts);
    manifest->chunk_size   = (size_t)json_integer_value(cs);
    strncpy(manifest->base_dir, store_base_dir, sizeof(manifest->base_dir) - 1);

    json_decref(root);
    return 0;
}

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

bool artifact_store_has_chunk(const char *hash_hex, int chunk_index)
{
    char path[512];
    if (build_chunk_path(hash_hex, chunk_index, path, sizeof(path)) != 0)
        return false;
    struct stat st;
    return (stat(path, &st) == 0);
}

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

int artifact_store_get_path(const char *hash_hex, char *path_buf, size_t buflen)
{
    if (!artifact_store_has(hash_hex))
        return -1;
    return build_artifact_dir(hash_hex, path_buf, buflen);
}

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
        snprintf(filepath, sizeof(filepath), "%s/%s", art_dir, ent->d_name);
        unlink(filepath);
    }
    closedir(d);

    return rmdir(art_dir);
}
