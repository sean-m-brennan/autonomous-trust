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
 * @brief Own an AT daemon's lifecycle from another language — the flat
 *        counterpart to @ref app_events.h.
 *
 * # Why this exists
 *
 * `node.h` is the lifecycle for a **C** embedder. It cannot be bound from
 * another language: `at_node_init` and `at_node_start` take an `at_node_t *`
 * the caller allocates, and `at_node_t` embeds `logger_t` and `queue_t` **by
 * value**, so a foreign mirror of it would have to reproduce two opaque C
 * layouts. That is the same silent-corruption hazard @ref app_events.h exists to
 * prevent for the message stream.
 *
 * `run_autonomous_trust` looks flat enough to call directly and is not a safe
 * shortcut: its declared contract ("blocks until the daemon exits", returns
 * 0/non-zero) disagrees with `node.c`, which assigns the return value to
 * `daemon_pid` and carries on; and the header declares `capabilities` as
 * `void *` where the definition takes `capability_t *`.
 *
 * So a foreign consumer could receive AT's events but never start AT. This
 * closes that: an **opaque heap handle**, so nothing is mirrored, and the same
 * lifecycle `node.h` gives a C embedder.
 *
 * # Ordering, and the one sharp edge
 *
 * @ref at_app_node_start **binds** `q_in` and makes it the process's assigned
 * queue, exactly as `at_node_start` does. A consumer therefore reads events with
 * @ref at_app_events_open_existing, **not** @ref at_app_events_open — two binders
 * of one name fight over the same socket path, and the second unlinks the first's.
 *
 *     at_app_node_t *node = at_app_node_start("my_app", "at_to_app", "app_to_at",
 *                                            2 / * INFO * /, false, NULL);
 *     at_app_events_t *ev = at_app_events_open_existing();
 *     ... poll / request_roster ...
 *     at_app_events_close(ev);   // close the reader FIRST
 *     at_app_node_stop(node);    // then the node, which closes the queue
 *
 * # No `capabilities` parameter, deliberately
 *
 * `at_node_config_t` carries `capabilities`/`cap_len` and passes them to
 * `run_autonomous_trust`, which opens with `(void)capabilities; (void)cap_len;` —
 * they are discarded. Propagating a knob that does nothing would be worse than
 * omitting it; when the parameter becomes live, add it here.
 *
 * @see doc/architecture/app-peer-carrier.md
 */

#ifndef AT_APP_NODE_H
#define AT_APP_NODE_H

/** @addtogroup public_api
 *  @{
 */

#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/** Opaque handle; owns the node and the queue it bound. */
typedef struct at_app_node_s at_app_node_t;

/**
 * @brief Launch an AT daemon and bind this process's app-facing queue.
 *
 * Equivalent to `at_node_init` + `at_node_start`. Returns as soon as the daemon
 * is forked — it does **not** wait for the daemon to be ready, so the first
 * requests a consumer sends may find no recipient. Retry them; see the warnings
 * on @ref at_app_events_request_roster.
 *
 * Every string is **copied**: a caller may free its own the moment this returns.
 * (`node.h` keeps the caller's pointers, which no foreign host can promise to
 * hold — `at_node_shutdown` still reads `app_name`.)
 *
 * @param[in] app_name        Logging identity, e.g. `"ethne"`. Required, at most
 *                            63 bytes.
 * @param[in] q_in            Queue the daemon sends **to** (AT → app). Bound and
 *                            assigned here. Required, at most 63 bytes, and must
 *                            differ from @p q_out.
 * @param[in] q_out           Queue the daemon receives **on** (app → AT).
 *                            Required, at most 63 bytes — the length the
 *                            messaging layer keeps. A longer name is rejected,
 *                            not truncated: a shortened name is a name the
 *                            daemon does not share, which is break #4 again.
 * @param[in] log_level       `log_level_t` as an int: 1 DEBUG, 2 INFO,
 *                            3 WARNING, 4 ERROR, 5 CRITICAL. Out-of-range values
 *                            are rejected rather than clamped.
 * @param[in] generate_config Run config generation before launching, for a root
 *                            that has none (`at_demo --generate-config`).
 * @param[in] log_file        Log path, or NULL for stderr.
 * @return Handle, or NULL on failure (bad argument, directories not creatable,
 *         config generation failed, the daemon did not launch, or @p q_in did
 *         not bind — a handle therefore means the event stream is reachable, not
 *         merely that a daemon is running).
 */
at_app_node_t *at_app_node_start(const char *app_name,
                                 const char *q_in,
                                 const char *q_out,
                                 int log_level,
                                 bool generate_config,
                                 const char *log_file);

/**
 * @brief Whether the daemon is still running.
 *
 * Probes the process (signal 0) rather than trusting a cached flag, because a
 * daemon that died is otherwise indistinguishable from one with nothing to say —
 * a consumer polling an empty queue forever would never learn. Once this returns
 * false it stays false.
 *
 * @param[in] node Handle, or NULL (returns false).
 */
bool at_app_node_alive(at_app_node_t *node);

/**
 * @brief The daemon's pid, for logs and diagnostics. 0 if @p node is NULL.
 */
int at_app_node_pid(const at_app_node_t *node);

/**
 * @brief Stop the daemon (SIGINT, then reap it), close the queue, free the
 *        handle.
 *
 * Also closes the bound queue, which `at_node_shutdown` does not — for a C
 * embedder the process is exiting anyway, but a foreign host may outlive the node
 * and would otherwise leak the socket. So close any @ref at_app_events_t **first**:
 * one opened with @ref at_app_events_open_existing borrows this queue.
 *
 * Safe on NULL.
 */
void at_app_node_stop(at_app_node_t *node);

#ifdef __cplusplus
} // extern "C"
#endif

/** @} */ /* end of public_api */

#endif /* AT_APP_NODE_H */
