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

/**
 * node.c — AT node lifecycle implementation.
 */

#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <signal.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>

#include "node.h"
#include "config/generate.h"
#include "utilities/sighandler.h"
#include "utilities/util.h"
#include "processes/processes.h"   /* cadence */

/* forward declaration — defined in autonomous_trust.c */
extern int run_autonomous_trust(char *q_in, char *q_out,
                                void *capabilities, size_t cap_len,
                                log_level_t log_level, char log_file[]);


int at_node_init(at_node_t *node, const at_node_config_t *cfg)
{
    memset(node, 0, sizeof(*node));
    node->config = *cfg;

    /* Defaults */
    if (!node->config.app_name)
        node->config.app_name = "at_node";
    if (!node->config.q_out)
        node->config.q_out = "extern_to_at";
    if (!node->config.q_in)
        node->config.q_in = "at_to_extern";

    /* Logger */
    logger_init(&node->log, cfg->log_level, (char *)cfg->log_file);

    /* Ensure required directories exist */
    char cfg_dir[CFG_PATH_LEN + 1];
    char data_dir[CFG_PATH_LEN + 1];
    get_cfg_dir(cfg_dir);
    get_data_dir(data_dir);

    if (makedirs(cfg_dir, 0755) != 0)
    {
        log_error(&node->log, "Failed to create config dir %s: %s\n",
                  cfg_dir, strerror(errno));
        return -1;
    }
    if (makedirs(data_dir, 0755) != 0)
    {
        log_error(&node->log, "Failed to create data dir %s: %s\n",
                  data_dir, strerror(errno));
        return -1;
    }

    /* Optional config generation */
    if (cfg->generate_config)
    {
        log_info(&node->log, "Generating configs in %s\n", cfg_dir);
        /* seed_str=NULL → random_config falls back to AT_PEER_SEED env. */
        int err = random_config(cfg_dir, NULL);
        if (err != 0)
        {
            log_error(&node->log, "Config generation failed: %s\n",
                      strerror(errno));
            log_exception(&node->log);
            return -1;
        }
        log_info(&node->log, "Configs generated successfully\n");
    }

    return 0;
}

int at_node_start(at_node_t *node)
{
    /* Launch the AT daemon */
    node->daemon_pid = run_autonomous_trust(
        (char *)node->config.q_out, (char *)node->config.q_in,
        node->config.capabilities, node->config.cap_len,
        node->config.log_level, (char *)node->config.log_file);

    if (node->daemon_pid <= 0)
    {
        log_error(&node->log,
                  "Autonomous Trust (%d) failed to start: %s\n",
                  node->daemon_pid, strerror(errno));
        return -1;
    }
    node->daemon_alive = true;

    init_sig_handling(NULL);

    /* Set up IPC so the host app can send messages to AT sub-processes */
    if (messaging_init(node->config.app_name, &node->app_queue) != 0)
        log_exception(&node->log);
    messaging_assign(&node->app_queue);

    log_info(&node->log, "%s running (AT daemon at PID %d)\n",
             node->config.app_name, node->daemon_pid);
    return 0;
}

int at_node_run(at_node_t *node, at_node_tick_fn tick, void *user_data)
{
    node->iteration = 0;

    while (!stop_process &&
           (node->config.max_iterations == 0 ||
            node->iteration < node->config.max_iterations))
    {
        node->iteration++;

        /* Per-iteration callback */
        if (tick)
        {
            int rc = tick(node, user_data);
            if (rc != 0)
                break;
        }

        /* Check daemon liveness */
        if (node->daemon_alive)
        {
            int err = kill(node->daemon_pid, 0);
            if (err == -1)
            {
                if (errno == ESRCH)
                {
                    log_info(&node->log, "AT daemon exited\n");
                    stop_process = true;
                    node->daemon_alive = false;
                }
                else
                {
                    SYS_EXCEPTION();
                    log_exception(&node->log);
                }
            }
        }

        usleep(cadence);
    }

    return 0;
}

void at_node_shutdown(at_node_t *node)
{
    if (node->daemon_alive)
    {
        log_info(&node->log, "Sending SIGINT to AT daemon (PID %d)\n",
                 node->daemon_pid);
        kill(node->daemon_pid, SIGINT);
        int status;
        waitpid(node->daemon_pid, &status, 0);
        node->daemon_alive = false;
    }
    log_info(&node->log, "%s exiting\n", node->config.app_name);
}

/* ------------------------------------------------------------------ */
/* Accessors                                                           */
/* ------------------------------------------------------------------ */

int at_node_daemon_pid(const at_node_t *node)
{
    return node->daemon_pid;
}

logger_t *at_node_logger(at_node_t *node)
{
    return &node->log;
}

size_t at_node_iteration(const at_node_t *node)
{
    return node->iteration;
}
