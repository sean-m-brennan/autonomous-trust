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

/**
 * Minimal example of an application hosting an Autonomous Trust node.
 *
 * The tick callback receives messages from the AT daemon and can react
 * to them — replace the body with your application logic.
 */

#include <stdio.h>

#include "autonomous_trust.h"

#define EXAMPLE_ITERATIONS 200

static int example_tick(at_node_t *node, void *user_data)
{
    (void)user_data;

    /* Check for messages from AT sub-processes */
    generic_msg_t buf = {0};
    int err = messaging_recv(&buf);
    if (err == -1)
        log_exception(at_node_logger(node));
    if (err != 0)
        return 0;  /* no message this tick */

    /* React to messages here — e.g. transaction scores, task results */
    (void)buf;

    return 0;
}

int main(int argc, char *argv[])
{
    (void)argc;
    (void)argv;

    at_node_config_t cfg = {
        .log_level = DEBUG,
        .app_name = "at_example",
        .q_out = "extern_to_at",
        .q_in = "at_to_extern",
        .max_iterations = EXAMPLE_ITERATIONS,
    };

    at_node_t node = {0};
    if (at_node_init(&node, &cfg) != 0)
        return 1;
    if (at_node_start(&node) != 0)
        return 1;

    int ret = at_node_run(&node, example_tick, NULL);
    at_node_shutdown(&node);
    return ret;
}
