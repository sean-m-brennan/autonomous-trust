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

#ifndef ZTA_PROCESS_H
#define ZTA_PROCESS_H

#include "processes/processes.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief ZTA periodic re-verification process
 *
 * When ZTA is enabled (compile-time + runtime), this process:
 * 1. Periodically re-verifies peer credentials against ZTA infrastructure
 * 2. Applies reputation penalties for revoked/expired credentials
 * 3. Resolves deferred verifications when infrastructure becomes available
 * 4. Broadcasts revocation alerts to the group
 * 5. Enforces reputation caps on peers admitted without ZTA verification
 *
 * When ZTA is disabled at runtime, this process exits immediately.
 */
/*@
  requires \valid(proc);
  assigns \nothing;
  ensures \result == 0 || \result != 0;
*/
int zta_process_run(process_t *proc, directory_t *queues,
                    queue_id_t signal, logger_t *logger);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* ZTA_PROCESS_H */
