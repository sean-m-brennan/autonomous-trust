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

#ifndef AT_SEND_RETRY_H
#define AT_SEND_RETRY_H

/**
 * @file send_retry.h
 * @brief One-shot frames a full queue refused, kept and retried on the
 *        process tick instead of dropped (ISSUES §2.40, §2.14).
 *
 * An AF_UNIX datagram queue holds about ten frames, and a non-blocking send
 * into a full one returns EAGAIN: the frame was NOT queued, so sending it
 * again later cannot duplicate it. @ref at_send tries (for 200 ms, or once
 * with @ref AT_SEND_NOW) and then files the frame here; every process's tick
 * (sleep_until, processes.c; the main daemon's loop) drains the list one
 * attempt per frame, oldest first, until it lands or ages out.
 *
 * Unlike the sibling hand-off retry (§2.27), which rebuilds STATE from the
 * current view, this keeps a copy of the FRAME, because these are one-shot
 * actions (a DM, a joiner's history, a task result) with no state to rebuild
 * them from. What can be copied (@ref at_send_retry_supported):
 * - NET_MESSAGE: a deep copy of @c obj and @c function, with the heap pointers
 *   inside its identities cleared (the IPC serializer reads only their inline
 *   fields);
 * - TASK_RESULT: a deep copy of @c result_data;
 * - the plain-data core types (TASK_STATUS, TRANSACTION_SCORE, PEER_STANDING,
 *   PEER_RTT_UPDATE, PEER_RTT_OBSERVED, PEER_OBSERVED, PEER_REPUTATION,
 *   PEER_REMOVED, PEER_PRESENCE), copied whole;
 * - any registered feature type serialized as a fixed raw copy (its vtable
 *   has no @c to_proto, msg_registry.h), which is plain data by construction.
 * Anything else (TASK, GROUP, PEER, ...) is refused, and its caller reports
 * the loss as before.
 *
 * Every process is a fork, so the list's statics are per process. One mutex
 * guards it, so receiver threads may defer while the main loop drains.
 */

#include <stdbool.h>
#include <stddef.h>

#include "processes/processes.h"
#include "utilities/msg_types.h"

/** Most frames kept at once; a defer beyond it is refused. Entries are
 *  allocated one by one, so only this many pointers are reserved. */
#define AT_SEND_RETRY_MAX 256
/** Seconds a frame is retried before it is given up on (env
 *  AT_SEND_RETRY_SEC overrides; AT_ID_SEND_RETRY_SEC, its old name, too). */
#define AT_SEND_RETRY_AGE_DEFAULT 30.0

/** Bytes of caller context an on-sent callback can carry (copied in). */
#define AT_SEND_RETRY_CTX_MAX 192

/** @ref at_send flag: one try, then keep. For a sender that must not sleep
 *  200 ms per frame: a receiver thread, the main daemon's hop, an app-bound
 *  emit inside a roster replay. */
#define AT_SEND_NOW 0x1u

/** The outcome of a frame @ref at_send owned: @p sent true once it is on its
 *  queue (at once if the inline send took it, or from the tick that drained
 *  it), false if it was given up on (age bound, or a hard send fault while
 *  kept). Run exactly once for every 0 that call returned, and never after a
 *  non-zero one, so a caller that must only act on real delivery (social's
 *  bilateral scores) acts here and not on the 0. @p proc is the process that
 *  sent or drained it (NULL in tests); @p ctx is the caller's bytes. Runs with
 *  no retry-list lock held, so it may send again. An at_send_retry_reset
 *  drops kept frames without running it. */
typedef void (*at_send_sent_fn)(const process_t *proc, const void *ctx,
                                bool sent);

/** Hand @p out to @p queue, keeping it if the queue is full.
 *
 *  A send to a queue that already holds kept frames waits behind them, so
 *  order holds. Otherwise it tries 10 times, 20 ms apart (once with
 *  @ref AT_SEND_NOW), and if the queue is still full the frame is kept for
 *  the tick. @p what / @p whom name it in the log lines; @p proc's logger
 *  takes them (NULL for the root logger). @p on_sent (may be NULL) is told
 *  the frame's fate, with a copy of the @p ctx_len bytes at @p ctx.
 *  @return 0 when sent or kept -- the process owns the delivery -- or the
 *  messaging_send error (a hard fault, or a full queue with no room to keep
 *  it, or a type that cannot be kept). */
int at_send(const process_t *proc, const char *queue, generic_msg_t *out,
            const char *what, const char *whom, unsigned flags,
            at_send_sent_fn on_sent, const void *ctx, size_t ctx_len);

/** Whether a frame of @p type can be kept (its payload can be copied). */
bool at_send_retry_supported(long type);

/** Keep a copy of @p msg for @p queue, first deferred at @p now (seconds).
 *  @p what / @p whom name it in later log lines. The caller keeps ownership of
 *  @p msg and may free its payload at once.
 *  @return 0 kept; -1 unsupported type, list full, or out of memory. */
int at_send_retry_defer(const char *queue, const generic_msg_t *msg,
                        const char *what, const char *whom, double now);

/** @ref at_send_retry_defer, and run @p on_sent with a copy of the
 *  @p ctx_len bytes at @p ctx (at most AT_SEND_RETRY_CTX_MAX) once the frame
 *  lands or is given up on. @p on_sent may be NULL.
 *  @return as at_send_retry_defer; -1 too if @p ctx_len is too large. */
int at_send_retry_defer_then(const char *queue, const generic_msg_t *msg,
                             const char *what, const char *whom, double now,
                             at_send_sent_fn on_sent, const void *ctx,
                             size_t ctx_len);

/** One pass: try each kept frame (all queues if @p queue is NULL) once, oldest
 *  first. A frame that lands is released; one older than the age bound at
 *  @p now is given up on with a WARNING; after an EAGAIN the rest of that
 *  queue's frames wait for the next pass, so their order holds. The on-sent
 *  callbacks of the frames that landed or were given up on run after the
 *  pass, unlocked, with @p proc (whose logger takes the lines; NULL for the
 *  root logger).
 *  @return the number delivered. */
size_t at_send_retry_drain(const process_t *proc, const char *queue, double now);

/** Frames kept for @p queue (all queues if NULL). */
size_t at_send_retry_pending(const char *queue);

/** Drop every kept frame (tests, conformance resets). */
void at_send_retry_reset(void);

#endif /* AT_SEND_RETRY_H */
