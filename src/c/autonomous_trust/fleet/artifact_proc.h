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

/* Protocol message function names — writable char arrays (definitions
 * in `artifact_proc.c`). */
extern char ARTIFACT_PROTO_REQUEST[];
extern char ARTIFACT_PROTO_MANIFEST[];
extern char ARTIFACT_PROTO_CHUNK_REQ[];
extern char ARTIFACT_PROTO_CHUNK[];
extern char ARTIFACT_PROTO_COMPLETE[];
extern char ARTIFACT_PROTO_READY[];

/* Raw payload bytes per artifact chunk (§7).
 *
 * NB: this is the *raw* payload size, not the on-wire size. A chunk reply
 * hex-encodes the payload (2x expansion) inside a small JSON envelope
 * (artifact hash + per-chunk hash + index + length), so the resulting
 * datagram is roughly (ARTIFACT_CHUNK_SIZE * 2) + ~200 bytes. The historical
 * `MAX_MSG_SIZE(1024) - 64` comment was wrong on two counts: it ignored the
 * hex doubling, and MAX_MSG_SIZE (1024) is not the transport limit — the UDP
 * receive path buffers a full datagram (UDP_PACKET_SIZE = 65507, see
 * net_transport_priv.h) and nothing enforces MAX_MSG_SIZE on the artifact
 * path. The chunk count was therefore self-imposed, not a UDP constraint.
 *
 * 4096 keeps each datagram ~8 KB (~6 IP fragments at a 1500-byte MTU): a large
 * reduction in message count vs. the historical 960 (a 3.5 MB artifact drops
 * from ~3,646 chunks to ~855) while bounding the per-datagram fragment count
 * that governs loss probability — one dropped fragment loses the whole chunk.
 * Raise toward the transport ceiling on reliable links; lower it for lossy
 * ones. Both peers agree on the size via the manifest (chunk_size), so it can
 * change without a wire-format break. */
#define ARTIFACT_CHUNK_SIZE 4096

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

/* Base64-encode a chunk payload (§7). Standard variant, so the output is safe
 * inside a JSON string. `b64_max` must be at least
 * `sodium_base64_ENCODED_LEN(len, sodium_base64_VARIANT_ORIGINAL)`. Returns 0
 * on success, -1 if `b64_out` is NULL or `b64_max` is too small (the buffer is
 * checked up front so libsodium never aborts on an undersized buffer). */
/*@
  requires \valid_read(data + (0 .. len - 1));
  requires \valid(b64_out + (0 .. b64_max - 1));
  assigns b64_out[0 .. b64_max - 1];
  ensures \result == 0 || \result == -1;
*/
int artifact_encode_chunk(const uint8_t *data, size_t len,
                          char *b64_out, size_t b64_max);

/* Decode a base64 chunk payload into `out` (capacity `out_max`) and verify it
 * matches the advertised `expected_len`. The decode is bounded by `out_max`,
 * so an oversized payload fails rather than overflowing. On success returns 0
 * and sets `*out_len` to the decoded length (which equals `expected_len`).
 * Returns -1 on NULL input, invalid base64, over-capacity, or a length
 * mismatch — so a bogus `expected_len` can never drive an over-read of `out`
 * by a downstream consumer. */
/*@
  requires \valid_read(b64);
  requires \valid(out + (0 .. out_max - 1));
  requires out_len == \null || \valid(out_len);
  assigns out[0 .. out_max - 1], *out_len;
  ensures \result == 0 || \result == -1;
*/
int artifact_decode_chunk(const char *b64, size_t expected_len,
                          uint8_t *out, size_t out_max, size_t *out_len);

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
