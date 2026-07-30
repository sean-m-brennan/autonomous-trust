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

#ifndef AT_NODE_PRIV_H
#define AT_NODE_PRIV_H

/**
 * The half of @ref at_node_start that does not fork, lifted out so a test can
 * reach it: the rest of start launches a daemon, which no unit test can.
 */

#include "node.h"

/**
 * @brief Bind the node's inbound queue and make it this process's assigned one.
 *
 * The name is `config.q_in`, falling back to `config.app_name` for a caller that
 * only ever sends. On failure the socket (if one was opened) is closed and
 * `app_queue.fd` set to -1, so nothing is left half-open and no path is
 * unlinked — on this path the name may belong to whoever won the race.
 *
 * @param[in,out] node  Node, already through @ref at_node_init (this logs).
 * @return 0 on success, -1 if the queue did not bind — which @ref at_node_start
 *         treats as fatal, because an app that cannot receive is not started.
 */
int at_node_bind_inbound(at_node_t *node);

#endif /* AT_NODE_PRIV_H */
