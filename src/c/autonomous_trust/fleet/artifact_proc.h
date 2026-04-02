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
int artifact_calc_total_chunks(size_t total_size, size_t chunk_size);

/* Initialize a download_state_t from manifest fields */
int artifact_download_state_init(download_state_t *state,
                                 const char *hash_hex,
                                 int total_chunks,
                                 const uint8_t *expected_hash,
                                 const char *version);

/* Record a received chunk; returns true when all chunks received */
bool artifact_download_state_record(download_state_t *state);

/* Verify a single chunk's blake2b hash.
   Returns 0 if chunk_hash matches blake2b(data, len). */
int artifact_verify_chunk_hash(const uint8_t *data, size_t len,
                               const uint8_t *chunk_hash);

int artifact_run(process_t *proc, directory_t *queues, queue_id_t signal, logger_t *logger);

#ifdef __cplusplus
}
#endif

#endif /* ARTIFACT_PROC_H */
