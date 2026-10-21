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

#ifndef NET_TRANSPORT_DTN_H
#define NET_TRANSPORT_DTN_H

/**
 * @file net_transport_dtn.h
 * @brief The DTN transport's process-runner entry point, which
 *        net_transport_dtn.c registers with DEFINE_PROCESS.
 */

#include "processes/processes.h"

int network_dtn_bp_run(process_t *proc, directory_t *queues,
                       queue_id_t signal, logger_t *logger);

#endif /* NET_TRANSPORT_DTN_H */
