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

#ifndef AT_ROUTE_PRIV_H
#define AT_ROUTE_PRIV_H

/**
 * The daemon main loop's message routing, lifted out of the loop body so it
 * is reachable from a test. Two collaborators, both driven by the loop in
 * @ref run_autonomous_trust:
 *
 *  - @ref at_route_extern_msg routes one app -> daemon message inward.
 *  - @ref at_route_internal_msgs drains the accumulated process -> daemon
 *    messages, forwarding each either to a sibling process or outward to the
 *    app queue.
 *
 * Neither owns any state; the loop supplies the array and the queue names.
 */

#include "structures/array.h"
#include "utilities/logger.h"
#include "utilities/msg_types.h"

/**
 * @brief Queue one message received from a sibling process for draining.
 *
 * Takes a reference to the WHOLE @ref generic_msg_t, not to its `info` union:
 * @ref at_route_internal_msgs reads the queued entry back as a
 * `generic_msg_t *` and switches on its `type`, so a reference to `info`
 * (offset 16) makes the switch read the first eight payload bytes as if they
 * were the tag. @p msg must outlive the matching drain call.
 *
 * @param[in,out] unhandled  Accumulating queue.
 * @param[in]     msg        Message to queue by reference.
 * @return 0 on success, -1 on allocation or append failure.
 */
int at_route_queue_msg(array_t *unhandled, generic_msg_t *msg);

/**
 * @brief Route one message received from the app (the daemon's `q_in`).
 *
 * @param[in]  msg     The inbound message.
 * @param[in]  logger  Log sink (may be NULL).
 * @return 0 if the message was routed, -1 if its type is not one the daemon
 *         accepts from an app.
 */
int at_route_extern_msg(generic_msg_t *msg, logger_t *logger);

/**
 * @brief Drain @p unhandled in FIFO order, routing every message by type.
 *
 * Sibling-process traffic is forwarded to the owning process; app-bound
 * traffic is sent to @p q_out. Every entry is removed from @p unhandled
 * whether or not its type is routable, so the array is empty on return.
 *
 * @param[in,out] unhandled  Accumulated messages, emptied in place.
 * @param[in]     q_out      Queue name for app-bound messages (may be NULL,
 *                           in which case app-bound messages are dropped).
 * @param[in]     logger     Log sink (may be NULL).
 * @return The number of messages sent outward to @p q_out.
 */
int at_route_internal_msgs(array_t *unhandled, const char *q_out,
                           logger_t *logger);

/** How many one-time app events are held while no app is attached; past it
 *  the oldest is dropped. */
#define AT_APP_HELD_MAX 64

/** True iff the roster pull re-emits events of @p type (state), so one sent
 *  while no app is attached is dropped rather than held. */
bool at_app_event_replayed(long type);

/** If an app is now bound to @p q_out, send it the held events in order and
 *  end the gap with one log line. at_route_internal_msgs calls it every pass
 *  while no app is attached. Returns how many were sent. */
size_t at_app_flush_held(const char *q_out, logger_t *logger);

/** Test seams: how many events are held; forget them and the gap. */
size_t at_app_held_count(void);
void at_app_hold_reset(void);

#endif /* AT_ROUTE_PRIV_H */
