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

/** @addtogroup internal_fleet
 *  @{
 */

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
/*@
  requires data_dir != \null && \valid_read(data_dir);
  assigns \nothing;
  ensures \result == 0 || \result == -1;
*/
int artifact_store_init(const char *data_dir);

/*@
  requires hash_hex != \null && \valid_read(hash_hex);
  assigns \nothing;
  ensures \result == \true || \result == \false;
*/
bool artifact_store_has(const char *hash_hex);

/*@
  requires \valid(manifest);
  assigns \nothing;
  ensures \result == 0 || \result == -1;
*/
int artifact_store_save_manifest(const artifact_manifest_t *manifest);

/*@
  requires hash_hex != \null && \valid_read(hash_hex);
  requires \valid(manifest);
  assigns *manifest;
  ensures \result == 0 || \result == -1;
*/
int artifact_store_load_manifest(const char *hash_hex, artifact_manifest_t *manifest);

/*@
  requires hash_hex != \null && \valid_read(hash_hex);
  requires chunk_index >= 0;
  requires \valid_read(data + (0 .. len - 1));
  assigns \nothing;
  ensures \result == 0 || \result == -1;
*/
int artifact_store_save_chunk(const char *hash_hex, int chunk_index,
                              const uint8_t *data, size_t len);

/*@
  requires hash_hex != \null && \valid_read(hash_hex);
  requires chunk_index >= 0;
  requires \valid(buf + (0 .. buflen - 1));
  requires \valid(out_len);
  assigns buf[0 .. buflen - 1], *out_len;
  ensures \result == 0 || \result == -1;
*/
int artifact_store_read_chunk(const char *hash_hex, int chunk_index,
                              uint8_t *buf, size_t buflen, size_t *out_len);

/*@
  requires hash_hex != \null && \valid_read(hash_hex);
  requires chunk_index >= 0;
  assigns \nothing;
  ensures \result == \true || \result == \false;
*/
bool artifact_store_has_chunk(const char *hash_hex, int chunk_index);

/*@
  requires hash_hex != \null && \valid_read(hash_hex);
  assigns \nothing;
  ensures \result >= 0;
*/
int artifact_store_chunk_count(const char *hash_hex);

/*@
  requires hash_hex != \null && \valid_read(hash_hex);
  requires \valid_read(expected_hash + (0 .. UPDATE_HASH_LEN - 1));
  assigns \nothing;
  ensures \result == 0 || \result == -1;
*/
int artifact_store_verify(const char *hash_hex, const uint8_t *expected_hash);

/*@
  requires hash_hex != \null && \valid_read(hash_hex);
  requires \valid(path_buf + (0 .. buflen - 1));
  assigns path_buf[0 .. buflen - 1];
  ensures \result == 0 || \result == -1;
*/
int artifact_store_get_path(const char *hash_hex, char *path_buf, size_t buflen);

/*@
  requires hash_hex != \null && \valid_read(hash_hex);
  requires \valid(out_path + (0 .. out_path_len - 1));
  assigns out_path[0 .. out_path_len - 1];
  ensures \result == 0 || \result == -1;
*/
int artifact_store_reassemble(const char *hash_hex, char *out_path, size_t out_path_len);

/*@
  requires hash_hex != \null && \valid_read(hash_hex);
  assigns \nothing;
  ensures \result == 0 || \result == -1;
*/
int artifact_store_delete(const char *hash_hex);

#ifdef __cplusplus
}
#endif


/** @} */ /* end of internal_fleet */

#endif /* ARTIFACT_STORE_H */
