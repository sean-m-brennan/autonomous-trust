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
#include "node_priv.h"
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
    /* Copy BEFORE the memset, and read only the copy afterwards: `cfg` may
     * legitimately alias `&node->config` — the flat wrapper in app_node.c
     * hands over the config it just filled in — and the memset would
     * otherwise zero the very struct being read. That failed silently: every
     * field fell back to a default or zero and init still returned 0. */
    const at_node_config_t requested = *cfg;
    memset(node, 0, sizeof(*node));
    node->config = requested;

    /* Defaults */
    if (!node->config.app_name)
        node->config.app_name = "at_node";
    if (!node->config.q_out)
        node->config.q_out = "extern_to_at";
    if (!node->config.q_in)
        node->config.q_in = "at_to_extern";

    /* Logger */
    logger_init(&node->log, node->config.log_level,
                (char *)node->config.log_file);

    /* Ensure required directories exist */
    char cfg_dir[CFG_PATH_LEN + 1];
    char data_dir[CFG_PATH_LEN + 1];
    get_cfg_dir(cfg_dir, sizeof(cfg_dir));
    get_data_dir(data_dir, sizeof(data_dir));

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
    if (node->config.generate_config)
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

int at_node_bind_inbound(at_node_t *node)
{
    /* Set up IPC. The queue we BIND has to be the one the daemon sends to,
     * which is `q_in` (AT -> app) — binding `app_name` instead left the
     * daemon's outbound datagrams addressed to a socket path nobody had
     * bound, so nothing an app was meant to receive ever arrived. Falls back
     * to app_name for a caller that sets no q_in and only ever sends. */
    const char *inbound = (node->config.q_in != NULL
                           && node->config.q_in[0] != '\0')
                              ? node->config.q_in : node->config.app_name;
    if (messaging_init(inbound, &node->app_queue) != 0)
    {
        log_exception(&node->log);
        log_error(&node->log,
                  "Could not bind inbound queue '%s'; this app could never "
                  "receive from the daemon\n", inbound);
        /* messaging_init may have opened the socket before failing to bind it.
         * Closed here, not by messaging_qclose, which also unlinks the path —
         * on this path the name may well belong to whoever we lost the race to. */
        if (node->app_queue.fd >= 0)
            close(node->app_queue.fd);
        node->app_queue.fd = -1;
        return -1;
    }
    messaging_assign(&node->app_queue);
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

    /* A bind failure is fatal, not a warning. An app whose inbound queue did not
     * bind can never receive anything the daemon sends — the same silent failure
     * as binding the wrong name (doc/architecture/app-peer-carrier.md, break #4),
     * and indistinguishable from a quiet network. Reap the daemon we just forked
     * rather than orphan it. */
    if (at_node_bind_inbound(node) != 0)
    {
        log_error(&node->log, "Refusing to start %s\n", node->config.app_name);
        at_node_shutdown(node);
        return -1;
    }

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

        /* `waitpid` here CANNOT reap this daemon and never could: `daemonize`
         * double-forks (`FORK` defaults to 2, daemonize.c), so `daemon_pid` names
         * a grandchild that init has already adopted. waitpid returns -1/ECHILD
         * immediately, which is why it went unnoticed — the call looked like it
         * was doing the waiting and was doing nothing at all. Kept because a
         * single-fork build (`-DFORK=1`) DOES make the daemon our child, and then
         * this both reaps it and is the whole wait.
         *
         * Measured 2026-08-04: the daemon needs about 5.3 s to shut down, because
         * it gives its own subsystem processes a grace period before SIGKILL. So
         * without a wait, `at_node_shutdown` returned while the daemon was still
         * running and still holding its sockets — and a host that stopped a node
         * and immediately started another raced the corpse for the socket path.
         * "Reap rather than orphan" was the intent at the call site in
         * `at_node_start`; this makes it true. */
        int status = 0;
        (void)waitpid(node->daemon_pid, &status, 0);

        /* Poll for actual exit, since ECHILD leaves us no event to block on. */
        const int step_ms = 50;
        int waited_ms = 0;
        while (waited_ms < AT_DAEMON_EXIT_TIMEOUT_MS)
        {
            if (kill(node->daemon_pid, 0) == -1 && errno == ESRCH)
                break;
            usleep(step_ms * 1000);
            waited_ms += step_ms;
        }
        if (kill(node->daemon_pid, 0) == 0)
        {
            /* Named, not papered over. Escalating to SIGKILL is deliberately NOT
             * done here: the daemon may be mid-write to the identity or peer
             * stores, and a corrupted store is worse than a lingering process.
             * A caller that must have the pid back has it from
             * `at_node_daemon_pid` and can make that choice itself. */
            log_error(&node->log,
                      "AT daemon (PID %d) has not exited %d ms after SIGINT; "
                      "leaving it rather than risking SIGKILL mid-write\n",
                      node->daemon_pid, AT_DAEMON_EXIT_TIMEOUT_MS);
        }
        else
        {
            log_info(&node->log, "AT daemon (PID %d) exited after %d ms\n",
                     node->daemon_pid, waited_ms);
        }
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
