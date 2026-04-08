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

#ifndef ZTA_AUDIT_H
#define ZTA_AUDIT_H

#include <stdbool.h>
#include <stdio.h>
#include <pthread.h>
#include <uuid/uuid.h>

#include "zta_verifier.h"

#ifdef __cplusplus
extern "C" {
#endif

#define ZTA_ACTION_LEN 64
#define ZTA_AUDIT_MAX_DEFERRED 256

/**
 * @brief A single audit log entry for ZTA verification events
 */
typedef struct {
    struct timeval timestamp;
    uuid_t peer_uuid;
    char action[ZTA_ACTION_LEN];    /* "admission_check", "periodic_reverify", etc. */
    zta_result_t result;
    bool deferred;
    struct timeval resolved_at;
    zta_result_t resolution_result;
    bool resolved;
} zta_audit_entry_t;

/**
 * @brief Thread-safe, append-only audit log for ZTA verification events
 *
 * Writes JSONL (one JSON object per line) to the log file.
 * Maintains an in-memory list of unresolved deferred entries.
 */
typedef struct {
    FILE *log_file;
    pthread_mutex_t lock;
    zta_audit_entry_t deferred[ZTA_AUDIT_MAX_DEFERRED];
    int deferred_count;
    bool initialized;
} zta_audit_log_t;

/**
 * @brief Initialize the audit log
 *
 * @param log  Audit log instance (caller-allocated)
 * @param path File path for the JSONL log
 * @return 0 on success, -1 on failure
 */
/*@
  requires \valid(log);
  requires path != \null && \valid_read(path);
  assigns *log;
  ensures \result == 0 || \result == -1;
  ensures \result == 0 ==> log->initialized == \true;
*/
int zta_audit_init(zta_audit_log_t *log, const char *path);

/**
 * @brief Record an audit entry
 *
 * Thread-safe. Appends to log file and tracks deferred entries in memory.
 *
 * @param log   Audit log instance
 * @param entry Entry to record
 * @return 0 on success, -1 on failure
 */
/*@
  requires \valid(log);
  requires log->initialized == \true;
  requires \valid(entry);
  assigns log->deferred[0 .. ZTA_AUDIT_MAX_DEFERRED - 1],
          log->deferred_count;
  ensures \result == 0 || \result == -1;
*/
int zta_audit_record(zta_audit_log_t *log, const zta_audit_entry_t *entry);

/**
 * @brief Get count of unresolved deferred entries
 */
/*@
  requires \valid(log);
  assigns \nothing;
  ensures \result >= 0 && \result <= ZTA_AUDIT_MAX_DEFERRED;
*/
int zta_audit_deferred_count(const zta_audit_log_t *log);

/**
 * @brief Get a deferred entry by index (for iteration during re-verification)
 *
 * @param log   Audit log instance
 * @param index Index into deferred list (0-based)
 * @param out   Output: copy of the deferred entry
 * @return 0 on success, -1 if index out of range
 */
/*@
  requires \valid(log);
  requires \valid(out);
  assigns *out;
  behavior valid_index:
    assumes index >= 0 && index < log->deferred_count;
    ensures \result == 0;
  behavior invalid_index:
    assumes index < 0 || index >= log->deferred_count;
    ensures \result == -1;
  disjoint behaviors;
  complete behaviors;
*/
int zta_audit_get_deferred(const zta_audit_log_t *log, int index,
                           zta_audit_entry_t *out);

/**
 * @brief Resolve a deferred verification for a specific peer
 *
 * Thread-safe. Updates the in-memory deferred entry and writes resolution
 * to the log file.
 *
 * @param log        Audit log instance
 * @param peer_uuid  UUID of the peer whose deferral to resolve
 * @param resolution The verification result that resolves the deferral
 * @return 0 on success, -1 if peer not found in deferred list
 */
/*@
  requires \valid(log);
  requires log->initialized == \true;
  requires \valid(resolution);
  assigns log->deferred[0 .. ZTA_AUDIT_MAX_DEFERRED - 1];
  ensures \result == 0 || \result == -1;
*/
int zta_audit_resolve(zta_audit_log_t *log, const uuid_t peer_uuid,
                      const zta_result_t *resolution);

/**
 * @brief Close the audit log and release resources
 */
/*@
  requires log == \null || \valid(log);
  assigns log->log_file, log->initialized;
  ensures log != \null ==> log->initialized == \false;
*/
void zta_audit_close(zta_audit_log_t *log);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* ZTA_AUDIT_H */
