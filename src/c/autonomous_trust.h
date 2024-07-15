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

/**
 * @brief 
 * 
 * @param q_in 
 * @param q_out 
 * @param capabilities 
 * @param cap_len 
 * @param log_level 
 * @param log_file 
 * @return int 
 */
int run_autonomous_trust(char *q_in, char *q_out, 
                         void *capabilities, size_t cap_len, // FIXME from config file?
                         log_level_t log_level, char log_file[]);

#ifdef __cplusplus
} // extern "C"
#endif

#endif  // AUTONOMOUS_TRUST_H
