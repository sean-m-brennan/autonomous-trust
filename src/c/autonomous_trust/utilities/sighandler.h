/********************
 *  Copyright 2024 TekFive, Inc., Sean M. Brennan, and contributors
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

#ifndef SIGHANDLER_H
#define SIGHANDLER_H

/** @addtogroup public_api
 *  @{
 */

#include "utilities/logger.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Application-supplied callback invoked on @c SIGHUP.
 *
 * The library installs a @c SIGHUP handler that calls this function from the
 * main loop (not from async-signal context). Applications must define it
 * even if empty.
 */
void reread_configs();

/** @brief Application-supplied callback invoked on @c SIGUSR1. Must be defined even if empty. */
void user1_handler();

/** @brief Application-supplied callback invoked on @c SIGUSR2. Must be defined even if empty. */
void user2_handler();

/**
 * @brief Flag set to @c true by the installed handler on SIGINT/SIGTERM.
 *
 * Poll this from the main loop to trigger graceful shutdown.
 */
extern bool stop_process;

/**
 * @brief When @c true, @c stop_process is re-raised to any child processes.
 *
 * Applications typically leave this at its default.
 */
extern bool propagate;

/**
 * @brief Activate signal handling. Must predefine reread_configs(), user1_handler(), user2_handler(), even if they are empty.
 * 
 * @param logger Optional logger
 * @return int 
 */
int init_sig_handling(logger_t *logger);

#ifdef __cplusplus
} // extern "C"
#endif


/** @} */ /* end of public_api */

#endif // SIGHANDLER_H
