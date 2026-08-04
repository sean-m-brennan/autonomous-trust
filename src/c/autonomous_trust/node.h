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
 * node.h — AT node lifecycle API.
 *
 * Provides a reusable lifecycle for any application that hosts an
 * Autonomous Trust daemon: directory setup, optional config generation,
 * daemon launch, IPC init, monitor loop with per-iteration callback,
 * and graceful shutdown.
 *
 * Usage:
 *   at_node_config_t cfg = { .app_name = "my_app", .log_level = INFO };
 *   at_node_t node = {0};
 *   at_node_init(&node, &cfg);
 *   at_node_start(&node);
 *   at_node_run(&node, my_tick, my_ctx);
 *   at_node_shutdown(&node);
 */

#ifndef AT_NODE_H
#define AT_NODE_H

/** @addtogroup public_api
 *  @{
 */

#include <stdbool.h>
#include <stddef.h>

#include "utilities/logger.h"
#include "utilities/message.h"
#include "config/configuration.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ------------------------------------------------------------------ */
/* Configuration                                                       */
/* ------------------------------------------------------------------ */

typedef struct {
    log_level_t   log_level;
    const char   *log_file;        /* NULL = stderr */
    bool          generate_config; /* run random_config() before launch */
    const char   *app_name;        /* logging identity, e.g. "at_demo"  */
    const char   *q_out;           /* queue: app -> AT daemon           */
    /* queue: AT daemon -> app. at_node_start BINDS this, so it is the name
     * the app receives on (at_node_tick's messaging_recv). Must differ from
     * q_out — the two directions are separate sockets. */
    const char   *q_in;
    void         *capabilities;    /* passed to run_autonomous_trust    */
    size_t        cap_len;
    size_t        max_iterations;  /* 0 = unlimited (run until signal)  */
} at_node_config_t;

/* ------------------------------------------------------------------ */
/* Node handle                                                         */
/* ------------------------------------------------------------------ */

typedef struct {
    at_node_config_t config;
    logger_t         log;
    queue_t          app_queue;
    int              daemon_pid;
    bool             daemon_alive;
    size_t           iteration;
} at_node_t;

/* ------------------------------------------------------------------ */
/* Per-iteration callback                                              */
/* ------------------------------------------------------------------ */

/**
 * Called once per monitor-loop iteration.
 * Return 0 to continue, non-zero to request shutdown.
 */
typedef int (*at_node_tick_fn)(at_node_t *node, void *user_data);

/* ------------------------------------------------------------------ */
/* Lifecycle                                                           */
/* ------------------------------------------------------------------ */

/**
 * Initialise the node: create logger, ensure cfg/data directories exist,
 * optionally run config generation.
 * Returns 0 on success.
 *
 * @p cfg may alias `&node->config`; it is copied before the node is cleared.
 * The config stores the caller's string pointers rather than copying them, so
 * they must outlive the node (`at_node_shutdown` logs `app_name`). A caller
 * that cannot promise that should own copies — see app_node.h, which does.
 */
/*@
  requires \valid(node);
  requires \valid(cfg);
  assigns *node;
  behavior success:
    ensures \result == 0;
  behavior failure:
    ensures \result != 0;
  disjoint behaviors;
*/
int at_node_init(at_node_t *node, const at_node_config_t *cfg);

/**
 * Launch the AT daemon, install signal handlers, set up IPC.
 * Returns 0 on success (daemon PID stored internally).
 *
 * Binding the inbound queue (`q_in`, falling back to `app_name`) is part of
 * success: if it fails, the daemon is stopped again and this returns non-zero,
 * because an app that cannot receive is not started, however live the daemon.
 */
/*@
  requires \valid(node);
  assigns node->daemon_pid, node->daemon_alive, node->app_queue;
  behavior success:
    ensures \result == 0;
    ensures node->daemon_pid > 0;
    ensures node->daemon_alive == \true;
  behavior failure:
    ensures \result != 0;
  disjoint behaviors;
*/
int at_node_start(at_node_t *node);

/**
 * Monitor loop: check daemon liveness, invoke tick callback, sleep.
 * Returns 0 on clean exit.
 * @param tick  per-iteration callback (may be NULL)
 * @param user_data  opaque pointer forwarded to tick
 */
/*@
  requires \valid(node);
  assigns node->iteration, node->daemon_alive;
  ensures \result == 0 || \result != 0;
*/
int at_node_run(at_node_t *node, at_node_tick_fn tick, void *user_data);

/** How long @ref at_node_shutdown waits for the daemon to actually exit.
 *
 *  Generous on purpose: the daemon gives its own subsystem processes a grace
 *  period before SIGKILL, and a full shutdown was measured at about 5.3 s. A
 *  bound tighter than that would turn an ordinary stop into a reported failure.
 */
#define AT_DAEMON_EXIT_TIMEOUT_MS 15000

/**
 * Graceful shutdown: SIGINT the daemon, wait for it to exit, log it.
 *
 * Returns once the daemon is gone, or after @ref AT_DAEMON_EXIT_TIMEOUT_MS with
 * an error logged naming the pid. It does **not** escalate to SIGKILL: the
 * daemon may be mid-write to a store.
 *
 * The wait is a poll, not a `waitpid`, and that is forced rather than chosen —
 * `daemonize` double-forks, so the daemon is init's child and not ours. Before
 * 2026-08-04 this called `waitpid` alone, which returned ECHILD at once, so
 * "wait for it" was not happening and a stop returned with the daemon still
 * live and still holding its sockets.
 */
/*@
  requires \valid(node);
  assigns node->daemon_alive;
  ensures node->daemon_alive == \false;
*/
void at_node_shutdown(at_node_t *node);

/* ------------------------------------------------------------------ */
/* Accessors (for use inside tick callbacks)                           */
/* ------------------------------------------------------------------ */

/**
 * @brief Return the PID of the AT daemon spawned by at_node_start().
 *
 * @param[in] node  Node handle.
 * @return Daemon PID, or whatever was stored during start (typically -1 if
 *         the daemon has not been launched).
 */
/*@
  requires \valid(node);
  assigns \nothing;
  ensures \result == node->daemon_pid;
*/
int         at_node_daemon_pid(const at_node_t *node);

/**
 * @brief Return a pointer to the node's embedded logger.
 *
 * Intended for use from inside a tick callback so the application can log
 * through the same sink as the daemon lifecycle code.
 *
 * @param[in] node  Node handle.
 * @return Non-owning pointer to the node's logger.
 */
/*@
  requires \valid(node);
  assigns \nothing;
  ensures \result == &node->log;
*/
logger_t   *at_node_logger(at_node_t *node);

/**
 * @brief Return the current monitor-loop iteration count.
 *
 * Incremented once per tick by at_node_run(). Useful for throttling work
 * inside tick callbacks.
 *
 * @param[in] node  Node handle.
 * @return Zero-based iteration counter.
 */
/*@
  requires \valid(node);
  assigns \nothing;
  ensures \result == node->iteration;
*/
size_t      at_node_iteration(const at_node_t *node);

#ifdef __cplusplus
}
#endif


/** @} */ /* end of public_api */

#endif /* AT_NODE_H */
