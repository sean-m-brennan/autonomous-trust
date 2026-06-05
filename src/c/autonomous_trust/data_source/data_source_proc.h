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
#ifndef DATA_SOURCE_PROC_H
#define DATA_SOURCE_PROC_H

#include "processes/processes.h"
#include "utilities/message.h"

/* Protocol selectors — wire-compatible with the Python DataProtocol
 * (services/data/server.py:26-28). The C node advertises the `data`
 * capability and answers a subscriber's `request` by streaming `data`
 * messages (each a JSON array of Reading dicts) back to it. */
extern char DATA_PROTO_REQUEST[];   /* "request" */
extern char DATA_PROTO_DATA[];      /* "data"    */

/* Process name as addressed on the wire by the coordinator's DataRcvr
 * (Python DataProcess.name). Must match the subsystem key registered in
 * generate_subsystems_config so net_proc's route_to_process delivers
 * inbound subscribe requests to this process's queue. */
#define DATA_SOURCE_PROC_NAME "data-source"

/**
 * @brief data-source process entry point.
 *
 * Registers the `request` handler, advertises the `data` capability (via the
 * DECLARE_CAPABILITY(data, ...) call site in the .c), and runs a custom loop
 * that drains inbound messages and periodically emits buffered Readings to all
 * subscribers as per-peer-encrypted `data` messages.
 */
int data_source_run(process_t *proc, directory_t *queues, queue_id_t signal,
                    logger_t *logger);

/**
 * @brief Hand the data-source process the latest batch of Readings to emit.
 *
 * @p readings_json must be a NUL-terminated JSON array string of Reading dicts
 * (the shape Reading.to_dict() emits: {t,peer,type,value,unit,quality,metadata}).
 * Ownership is copied; the caller retains its buffer. Thread-safe. The
 * `--ingest-readings` feeder (Phase 2) calls this; until then the process emits
 * a small synthetic reading so the C->coordinator path is independently testable.
 */
void data_source_set_readings(const char *readings_json, size_t len);

#endif  // DATA_SOURCE_PROC_H
