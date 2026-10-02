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
#ifndef DATA_SOURCE_PROC_PRIV_H
#define DATA_SOURCE_PROC_PRIV_H

/* Internal helpers exposed for unit testing (data_source_test.c). Not part of
 * the data-source process's public API. */

#include <stdbool.h>
#include <stddef.h>
#include <jansson.h>

/* The process-table generator (src/c/preprocess.py) rewrites the data-source
 * DECLARE_PROCESS include to this _priv.h once it exists, and the generated
 * table references data_source_run — so this header must make that symbol
 * visible, exactly as rep_proc_priv.h / net_proc_priv.h declare their *_run.
 * Pull it in from the public header rather than redeclaring. */
#include "data_source/data_source_proc.h"

/* Deterministic per-batch decimation for producer-side TransactionScore
 * submission. MUST stay byte-identical to the Python _ts_keep
 * (examples/dod_mission/participant.py & coordinator.py):
 *   int(task_id.replace('-','')[:8], 16) % denom == 0
 * so the C producer and the Python coordinator agree on which batches form a
 * bilateral Transaction. denom <= 1 always keeps; a task_id shorter than 8 hex
 * chars is rejected (false). */
bool _ts_keep(const char *task_id_str, int denom);

/* Extract the shared batch task_id from a parsed Reading-array (metadata.task_id
 * of the first reading; all readings in a batch share it). Returns true and
 * fills out (NUL-terminated within out_len) when a non-empty task_id is present;
 * false for synthetic/unstamped batches or malformed input. */
bool _batch_task_id(json_t *arr, char *out, size_t out_len);

#endif  // DATA_SOURCE_PROC_PRIV_H
