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

#ifndef AT_ID_SEND_RETRY_H
#define AT_ID_SEND_RETRY_H

/**
 * @file id_send_retry.h
 * @brief Frames the identity process could not hand a sibling queue, kept and
 *        retried on the identity tick instead of dropped (ISSUES §2.40).
 *
 * An AF_UNIX datagram queue holds about ten frames, and a non-blocking send
 * into a full one returns EAGAIN: the frame was NOT queued, so sending it
 * again later cannot duplicate it. identity_send_to (id_proc.c) tries for
 * 200 ms and then files the frame here; the identity tick drains the list one
 * attempt per frame, oldest first, until it lands or ages out.
 *
 * Unlike the sibling hand-off retry (§2.27), which rebuilds STATE from the
 * current view, this keeps a copy of the FRAME, because these are one-shot
 * actions (a DM, a joiner's history, an attestation ad) with no state to
 * rebuild them from. The copy owns a deep copy of a NET_MESSAGE's @c obj and
 * @c function, and the heap pointers inside its identities are cleared (the
 * IPC serializer reads only their inline fields). Plain-data types
 * (TRANSACTION_SCORE, PEER_STANDING) are copied whole; anything else is
 * refused, and its caller reports the loss as before.
 *
 * Per process, one mutex, and only the identity process drains it.
 */

#include <stdbool.h>
#include <stddef.h>

#include "processes/processes.h"
#include "utilities/msg_types.h"

/** Most frames kept at once; a defer beyond it is refused. */
#define ID_SEND_RETRY_MAX 64
/** Seconds a frame is retried before it is given up on (env
 *  AT_ID_SEND_RETRY_SEC overrides). */
#define ID_SEND_RETRY_AGE_DEFAULT 30.0

/** Bytes of caller context an on-sent callback can carry (copied in). */
#define ID_SEND_RETRY_CTX_MAX 192

/** The outcome of a frame identity_send_to_then owned: @p sent true once it is
 *  on its queue (at once if the inline send took it, or from the identity tick
 *  that drained it), false if it was given up on (age bound, or a hard send
 *  fault while kept). Run exactly once for every 0 that call returned, and
 *  never after a non-zero one, so a caller that must only act on real delivery
 *  (social's bilateral scores) acts here and not on the 0. @p proc is the
 *  process that sent or drained it (NULL in tests); @p ctx is the caller's
 *  bytes. Runs with no retry-list lock held, so it may send again. A
 *  id_send_retry_reset drops kept frames without running it. */
typedef void (*id_send_sent_fn)(const process_t *proc, const void *ctx,
                                bool sent);

/** Whether a frame of @p type can be kept (its payload can be copied). */
bool id_send_retry_supported(long type);

/** Keep a copy of @p msg for @p queue, first deferred at @p now (seconds).
 *  @p what / @p whom name it in later log lines. The caller keeps ownership of
 *  @p msg and may free its payload at once.
 *  @return 0 kept; -1 unsupported type, list full, or out of memory. */
int id_send_retry_defer(const char *queue, const generic_msg_t *msg,
                        const char *what, const char *whom, double now);

/** @ref id_send_retry_defer, and run @p on_sent with a copy of the
 *  @p ctx_len bytes at @p ctx (at most ID_SEND_RETRY_CTX_MAX) once the frame
 *  lands or is given up on. @p on_sent may be NULL.
 *  @return as id_send_retry_defer; -1 too if @p ctx_len is too large. */
int id_send_retry_defer_then(const char *queue, const generic_msg_t *msg,
                             const char *what, const char *whom, double now,
                             id_send_sent_fn on_sent, const void *ctx,
                             size_t ctx_len);

/** One pass: try each kept frame (all queues if @p queue is NULL) once, oldest
 *  first. A frame that lands is released; one older than the age bound at
 *  @p now is given up on with a WARNING; after an EAGAIN the rest of that
 *  queue's frames wait for the next pass, so their order holds. The on-sent
 *  callbacks of the frames that landed or were given up on run after the
 *  pass, unlocked, with @p proc (whose logger takes the lines; NULL for the
 *  root logger).
 *  @return the number delivered. */
size_t id_send_retry_drain(const process_t *proc, const char *queue, double now);

/** Frames kept for @p queue (all queues if NULL). */
size_t id_send_retry_pending(const char *queue);

/** Drop every kept frame (tests, conformance resets). */
void id_send_retry_reset(void);

#endif /* AT_ID_SEND_RETRY_H */
