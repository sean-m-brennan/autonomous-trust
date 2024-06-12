/********************
 *  Copyright 2024 TekFive, Inc. and contributors
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

#include "utilities/logger.h"

#ifdef __cplusplus
extern "C" {
#endif

void reread_configs();

void user1_handler();

void user2_handler();

extern bool stop_process;

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

#endif // SIGHANDLER_H
