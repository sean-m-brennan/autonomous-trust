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

#ifndef AT_APP_NODE_PRIV_H
#define AT_APP_NODE_PRIV_H

/**
 * The argument checking and config assembly behind @ref at_app_node_start,
 * lifted out of it so a test can reach them without forking a daemon —
 * everything the wrapper decides happens here, and the rest of
 * `at_app_node_start` is `at_node_init` + `at_node_start`.
 *
 * (Same reason `at_route_priv.h` exists.)
 */

#include <stdbool.h>

#include "node.h"
#include "utilities/message.h"
#include "utilities/util.h"
#include "utilities/exception.h"
#include "config/configuration.h"

/**
 * The strings a handle owns.
 *
 * `at_node_config_t` stores the caller's pointers and `at_node_shutdown` reads
 * `app_name` — so with the caller's own pointers, a foreign host that freed a
 * temporary (a Rust `CString`, say) would leave the node reading freed memory.
 * The handle keeps its own copies and the config points at these.
 *
 * Each buffer's size is the length the consumer of that string preserves, so
 * "it fits here" and "it survives" are the same question:
 * `messaging_init` copies `MSG_KEY_LEN - 1` bytes of a queue name, and
 * `logger_init` copies `MAX_FILENAME - 1` of a log path.
 */
typedef struct {
    char app_name[PROC_NAME_LEN];
    char q_in[MSG_KEY_LEN];
    char q_out[MSG_KEY_LEN];
    char log_file[MAX_FILENAME];
    bool has_log_file;
} at_app_node_strings_t;

/**
 * @brief Check the arguments, copy the strings, and fill in a node config.
 *
 * Rejects (rather than repairs) a missing or empty name, one name used for both
 * directions, a name too long for the queue key or the log path, and a log level
 * outside `log_level_t`. Truncation in particular has to be refused: a silently
 * shortened queue name is a name the daemon's peer does not share, which is the
 * break the app-facing carrier already had once.
 *
 * @param[out] cfg    Config to fill; its string fields point into @p owned.
 * @param[out] owned  Storage for the copies. Must outlive @p cfg.
 * @param[in]  app_name        Logging identity. Required.
 * @param[in]  q_in            AT -> app queue. Required, != @p q_out.
 * @param[in]  q_out           app -> AT queue. Required.
 * @param[in]  log_level       `log_level_t` as an int (DEBUG..CRITICAL).
 * @param[in]  generate_config Generate config before launching.
 * @param[in]  log_file        Log path, or NULL for stderr.
 * @return 0 on success, -1 if any argument was rejected (nothing is written on
 *         rejection beyond @p owned's buffers).
 */
int at_app_node_build_config(at_node_config_t *cfg,
                            at_app_node_strings_t *owned,
                            const char *app_name,
                            const char *q_in,
                            const char *q_out,
                            int log_level,
                            bool generate_config,
                            const char *log_file);

#endif /* AT_APP_NODE_PRIV_H */
