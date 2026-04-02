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

#ifndef ARTIFACT_STORE_H
#define ARTIFACT_STORE_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "fleet/update_proposal.h"  /* UPDATE_HASH_LEN, UPDATE_VERSION_LEN */

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    char hash_hex[UPDATE_HASH_LEN * 2 + 1];   /* blake2b-256 hex string */
    char base_dir[256];                         /* artifacts root directory */
    int total_chunks;
    size_t total_size;
    size_t chunk_size;
    char version[UPDATE_VERSION_LEN + 1];
} artifact_manifest_t;

/* Initialize the store: create artifacts directory under data_dir if needed.
   data_dir is typically "$AUTONOMOUS_TRUST_ROOT/var/at". */
int artifact_store_init(const char *data_dir);

/* Check if a complete, verified artifact exists for this hash. */
bool artifact_store_has(const char *hash_hex);

/* Save manifest JSON for an artifact being downloaded. */
int artifact_store_save_manifest(const artifact_manifest_t *manifest);

/* Load manifest from disk for a previously-seen artifact. */
int artifact_store_load_manifest(const char *hash_hex, artifact_manifest_t *manifest);

/* Save a single chunk to disk. */
int artifact_store_save_chunk(const char *hash_hex, int chunk_index,
                              const uint8_t *data, size_t len);

/* Read a single chunk from disk (for serving to requesting peers). */
int artifact_store_read_chunk(const char *hash_hex, int chunk_index,
                              uint8_t *buf, size_t buflen, size_t *out_len);

/* Check if a specific chunk file exists on disk. */
bool artifact_store_has_chunk(const char *hash_hex, int chunk_index);

/* Count how many chunk files exist for a given hash. */
int artifact_store_chunk_count(const char *hash_hex);

/* Reassemble all chunks, compute blake2b-256 of the whole artifact,
   compare against expected_hash. Creates 'complete' marker on success.
   Returns 0 on success, -1 on hash mismatch or I/O error. */
int artifact_store_verify(const char *hash_hex, const uint8_t *expected_hash);

/* Get path to the artifact directory (valid after verify succeeds).
   Returns 0 on success, -1 if artifact is not complete. */
int artifact_store_get_path(const char *hash_hex, char *path_buf, size_t buflen);

/* Delete an artifact: all chunk files, manifest, and complete marker. */
int artifact_store_delete(const char *hash_hex);

#ifdef __cplusplus
}
#endif

#endif /* ARTIFACT_STORE_H */
