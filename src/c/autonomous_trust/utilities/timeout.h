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

#ifndef AT_TIMEOUT_H
#define AT_TIMEOUT_H

/**
 * @file timeout.h
 * @brief Transport-aware timeout scaling (at-over-dtn.md §5).
 *
 * AT's protocol layer was designed with sub-second LAN round-trips in
 * mind: Paxos rounds, identity challenges, voting windows. When any
 * member of a quorum is reachable only via a slow transport (DTN/BP,
 * deep-space relay), those deadlines fire before bundles arrive and
 * the protocol is effectively bricked.
 *
 * This header exports a single scaling helper that the protocol code
 * uses to convert a compile-time base deadline into an effective
 * deadline accounting for the slowest peer in the quorum:
 *
 *   @code
 *     int effective_ms = at_timeout_scale_ms(PAXOS_PROTOCOL_TIMEOUT_SEC * 1000, proc);
 *     pthread_cond_timedwait(&cv, &mx, abs_time_plus_ms(effective_ms));
 *   @endcode
 *
 * Policy:
 *   scaled_rtt = (per-peer-max-rtt OR forced-rtt OR default-rtt) × multiplier
 *   effective  = max(base_ms, scaled_rtt)
 *
 * The helper never returns a value smaller than the base so a call over
 * a pure-LAN deployment is a no-op.
 *
 * Configuration is loaded from a `timeouts` JSON section (see
 * utilities/timeout.c for the struct + serde). Absence of the config
 * means: multiplier = @ref AT_TIMEOUT_DEFAULT_MULTIPLIER, per-peer
 * RTTs come from the network-transport link-class estimate, no forced
 * override.
 */

#include "processes/processes.h"

#define AT_TIMEOUT_DEFAULT_MULTIPLIER    3
#define AT_TIMEOUT_DEFAULT_RTT_MS       50   /**< Fast-LAN fallback. */

/** JSON-loaded section; registered as the "timeouts" config in timeout.c. */
typedef struct timeouts_config_s {
    /** Multiplier applied to the slowest peer's RTT. 0 or negative
     *  means "use AT_TIMEOUT_DEFAULT_MULTIPLIER". */
    int multiplier;

    /** When > 0, overrides the dynamically-estimated per-peer RTT with
     *  this value for ALL scaling. Useful on processes that don't yet
     *  receive per-peer RTT propagation, or when the operator knows a
     *  cluster-wide SLA they want to enforce. Value is in milliseconds. */
    int forced_rtt_ms;
} timeouts_config_t;

/**
 * @brief Scale @p base_ms upward to account for the slowest peer.
 *
 * @param base_ms  The pre-DTN base deadline in milliseconds.
 * @param proc     Owning process; walks @c proc->protocol.peer_rtt_ms
 *                 and reads the timeouts config from @c proc->configs
 *                 if present. May be NULL — treated as "LAN-only",
 *                 which returns @p base_ms unchanged.
 * @return An effective deadline in milliseconds, never less than @p base_ms.
 */
int at_timeout_scale_ms(int base_ms, const process_t *proc);

/**
 * @brief Pure-function scaler (exposed for unit tests).
 *
 * Given a max observed RTT and a multiplier, return the scaled deadline.
 * Clamps to @p base_ms from below.
 */
int at_timeout_apply_scale(int base_ms, int max_rtt_ms, int multiplier);

/* JSON serde — registered as the "timeouts" config via the macro in timeout.c. */
#include <jansson.h>
int timeouts_to_json(const void *data_struct, json_t **obj_ptr);
int timeouts_from_json(const json_t *obj, void *data_struct);

#endif /* AT_TIMEOUT_H */
