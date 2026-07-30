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
 * @file
 * @brief The flat lifecycle: an opaque handle around `at_node_t`, so a foreign
 *        consumer never mirrors it. See the header for why.
 */

#include <signal.h>
#include <stdlib.h>
#include <string.h>

#include "app_node.h"
#include "app_node_priv.h"
#include "node.h"
#include "utilities/logger.h"
#include "utilities/message.h"

/* The whole point of the opacity: at_node_t embeds logger_t and queue_t by
 * value, and stays on this side of the boundary. The strings live here too, so
 * the caller may free its own the moment start returns. */
struct at_app_node_s {
    at_node_t             node;
    at_app_node_strings_t owned;
};

/* Copy `src` into `dst` (capacity `cap` including the terminator), refusing to
 * truncate. */
static int copy_exact(char *dst, size_t cap, const char *src)
{
    size_t len = strlen(src);
    if (len == 0 || len >= cap)
        return -1;
    memcpy(dst, src, len + 1);
    return 0;
}

int at_app_node_build_config(at_node_config_t *cfg,
                            at_app_node_strings_t *owned,
                            const char *app_name,
                            const char *q_in,
                            const char *q_out,
                            int log_level,
                            bool generate_config,
                            const char *log_file)
{
    if (cfg == NULL || owned == NULL
        || app_name == NULL || q_in == NULL || q_out == NULL)
        return -1;
    /* The two directions are separate sockets; one name for both would have the
     * daemon receiving its own output. */
    if (strcmp(q_in, q_out) == 0)
        return -1;
    /* Rejected rather than clamped: a caller passing 0 or 99 has misunderstood
     * the scale, and silently picking a level for them hides that. */
    if (log_level < DEBUG || log_level > CRITICAL)
        return -1;

    memset(owned, 0, sizeof(*owned));
    if (copy_exact(owned->app_name, sizeof(owned->app_name), app_name) != 0
        || copy_exact(owned->q_in, sizeof(owned->q_in), q_in) != 0
        || copy_exact(owned->q_out, sizeof(owned->q_out), q_out) != 0)
        return -1;
    if (log_file != NULL)
    {
        if (copy_exact(owned->log_file, sizeof(owned->log_file), log_file) != 0)
            return -1;
        owned->has_log_file = true;
    }

    memset(cfg, 0, sizeof(*cfg));
    cfg->log_level = (log_level_t)log_level;
    cfg->log_file = owned->has_log_file ? owned->log_file : NULL;
    cfg->generate_config = generate_config;
    cfg->app_name = owned->app_name;
    cfg->q_out = owned->q_out;
    cfg->q_in = owned->q_in;
    /* capabilities/cap_len omitted: run_autonomous_trust discards them. See the
     * header. max_iterations is irrelevant — a foreign host owns its own loop and
     * never calls at_node_run. */
    return 0;
}

at_app_node_t *at_app_node_start(const char *app_name,
                                 const char *q_in,
                                 const char *q_out,
                                 int log_level,
                                 bool generate_config,
                                 const char *log_file)
{
    at_app_node_t *h = calloc(1, sizeof(*h));
    if (h == NULL)
        return NULL;

    at_node_config_t cfg;
    if (at_app_node_build_config(&cfg, &h->owned, app_name, q_in, q_out,
                                 log_level, generate_config, log_file) != 0)
    {
        free(h);
        return NULL;
    }

    if (at_node_init(&h->node, &cfg) != 0)
    {
        free(h);
        return NULL;
    }
    if (at_node_start(&h->node) != 0)
    {
        /* No messaging_qclose here: a start that fails closes its own socket,
         * and the queue in an unstarted node has fd 0 — closing that would take
         * stdin with it. */
        free(h);
        return NULL;
    }
    return h;
}

bool at_app_node_alive(at_app_node_t *node)
{
    if (node == NULL || !node->node.daemon_alive)
        return false;
    /* Probe rather than trust the flag: a daemon that exited looks exactly like
     * one with nothing to say from the queue's side. Mirrors the liveness check
     * in at_node_run's loop. */
    if (kill(node->node.daemon_pid, 0) == -1)
    {
        node->node.daemon_alive = false;
        return false;
    }
    return true;
}

int at_app_node_pid(const at_app_node_t *node)
{
    return node == NULL ? 0 : node->node.daemon_pid;
}

void at_app_node_stop(at_app_node_t *node)
{
    if (node == NULL)
        return;
    at_node_shutdown(&node->node);
    /* at_node_shutdown leaves the queue bound — harmless for a C embedder on its
     * way out, a leaked socket for a host that outlives the node. */
    messaging_qclose(&node->node.app_queue);
    free(node);
}
