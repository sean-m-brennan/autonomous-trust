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

#ifndef ARTIFACT_PROC_H
#define ARTIFACT_PROC_H

/** @addtogroup internal_fleet
 *  @{
 */

#include <stdbool.h>
#include <stdint.h>

#include "autonomous_trust/processes/processes.h"
#include "fleet/update_proposal.h"  /* UPDATE_HASH_LEN, UPDATE_VERSION_LEN */

#ifdef __cplusplus
extern "C" {
#endif

/* Protocol message function names */
#define ARTIFACT_PROTO_REQUEST   "artifact request"
#define ARTIFACT_PROTO_MANIFEST  "artifact manifest"
#define ARTIFACT_PROTO_CHUNK_REQ "artifact chunk request"
#define ARTIFACT_PROTO_CHUNK     "artifact chunk"
#define ARTIFACT_PROTO_COMPLETE  "artifact complete"
#define ARTIFACT_PROTO_READY     "artifact ready"

/* Chunk payload size: MAX_MSG_SIZE(1024) - 64 bytes for JSON header overhead */
#define ARTIFACT_CHUNK_SIZE 960

/* State for an in-progress download */
typedef struct {
    char hash_hex[UPDATE_HASH_LEN * 2 + 1];
    int total_chunks;
    int received_chunks;
    uint8_t expected_hash[UPDATE_HASH_LEN];
    char version[UPDATE_VERSION_LEN + 1];
    char notify_process[65];   /* process to receive ARTIFACT_READY (default: "update") */
} download_state_t;

/* --- Testable helper functions (no process/messaging deps) --- */

/* Compute total number of chunks for a given artifact size */
/*@
  requires chunk_size > 0;
  assigns \nothing;
  ensures \result >= 0;
  ensures \result == (int)((total_size + chunk_size - 1) / chunk_size);
*/
int artifact_calc_total_chunks(size_t total_size, size_t chunk_size);

/*@
  requires \valid(state);
  requires hash_hex != \null && \valid_read(hash_hex);
  requires total_chunks > 0;
  requires \valid_read(expected_hash + (0 .. UPDATE_HASH_LEN - 1));
  assigns *state;
  ensures \result == 0;
  ensures state->total_chunks == total_chunks;
  ensures state->received_chunks == 0;
*/
int artifact_download_state_init(download_state_t *state,
                                 const char *hash_hex,
                                 int total_chunks,
                                 const uint8_t *expected_hash,
                                 const char *version);

/*@
  requires \valid(state);
  assigns state->received_chunks;
  ensures state->received_chunks == \old(state->received_chunks) + 1;
  ensures \result == (state->received_chunks >= state->total_chunks);
*/
bool artifact_download_state_record(download_state_t *state);

/*@
  requires \valid_read(data + (0 .. len - 1));
  requires \valid_read(chunk_hash + (0 .. UPDATE_HASH_LEN - 1));
  assigns \nothing;
  ensures \result == 0 || \result == -1;
*/
int artifact_verify_chunk_hash(const uint8_t *data, size_t len,
                               const uint8_t *chunk_hash);

/*@
  requires \valid(proc);
  requires \valid_read(signal);
  requires logger == \null || \valid(logger);
  assigns *proc;
*/
int artifact_run(process_t *proc, directory_t *queues, queue_id_t signal, logger_t *logger);

#ifdef __cplusplus
}
#endif


/** @} */ /* end of internal_fleet */

#endif /* ARTIFACT_PROC_H */
