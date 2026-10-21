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

#ifndef RDV_ROSTER_H
#define RDV_ROSTER_H

/**
 * @file rdv_roster.h
 * @brief The roster app verbs' identity handlers (rdv_roster.c), for tests.
 */

#include <stdbool.h>

#include "processes/processes.h"
#include "utilities/message.h"

/** The app's app_relay_roster_install {ref, roster}: pin the issuer and file
 *  the roster; answers ROSTER_INSTALLED or ROSTER_REFUSED. */
bool handle_roster_app_install(const process_t *proc, directory_t *queues,
                               generic_msg_t *msg);
/** The app's app_relay_roster_remove {ref, issuer}: answers ROSTER_REMOVED or
 *  ROSTER_REFUSED. */
bool handle_roster_app_remove(const process_t *proc, directory_t *queues,
                              generic_msg_t *msg);

#endif /* RDV_ROSTER_H */
