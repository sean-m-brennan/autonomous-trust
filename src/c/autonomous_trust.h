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

/**
 * @file autonomous_trust.h
 * @ingroup public_api
 * @brief Top-level public header for embedding AutonomousTrust.
 *
 * Include this single header to pull in everything an application needs to
 * run an AutonomousTrust daemon: message queues, logging, configuration,
 * signal handling, and the node-lifecycle API. See @ref public_api.
 */

#ifndef AUTONOMOUS_TRUST_H
#define AUTONOMOUS_TRUST_H

#ifdef __cplusplus
extern "C" {
#endif

#include "autonomous_trust/version.h"
#include "autonomous_trust/utilities/message.h"
#include "autonomous_trust/utilities/logger.h"
#include "autonomous_trust/config/configuration.h"
#include "autonomous_trust/utilities/sighandler.h"
#include "autonomous_trust/node.h"

/** @addtogroup public_api
 *  @{
 */

/**
 * @brief Run an AutonomousTrust daemon in the current process.
 *
 * Blocks until the daemon exits (on signal or fatal error). Most embedders
 * should prefer the higher-level @ref at_node_init / @ref at_node_start
 * lifecycle in `node.h`, which forks this routine into a child process and
 * wires up the IPC queues for the caller.
 *
 * @param q_in          IPC queue name used for messages **into** the daemon
 *                      (application → AT). NUL-terminated.
 * @param q_out         IPC queue name used for messages **out of** the daemon
 *                      (AT → application). NUL-terminated.
 * @param capabilities  Optional serialized capabilities buffer that overrides
 *                      the on-disk configuration. Pass `NULL` to use the
 *                      config file alone.
 * @param cap_len       Length of @p capabilities in bytes. Ignored when
 *                      @p capabilities is `NULL`.
 * @param log_level     Minimum severity to emit (see @ref log_level_t).
 * @param log_file      Path to the log file; empty string routes to stderr.
 * @return 0 on clean shutdown, non-zero on startup or runtime failure.
 */
int run_autonomous_trust(char *q_in, char *q_out,
                         void *capabilities, size_t cap_len,
                         log_level_t log_level, char log_file[]);

/** @} */ /* end of public_api */

#ifdef __cplusplus
} // extern "C"
#endif

#endif  // AUTONOMOUS_TRUST_H
