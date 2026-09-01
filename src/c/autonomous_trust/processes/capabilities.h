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

#ifndef CAPABILITIES_H
#define CAPABILITIES_H

/** @addtogroup internal_processes
 *  @{
 */

#include <stdbool.h>
#include <stdio.h>
#include <stdarg.h>

#include "structures/map.h"
#include "structures/array.h"
#include "utilities/util.h"

#define MAX_CAPABILITIES 128 // # processes beyond required core

#define CAP_NAMELEN PROC_NAME_LEN

#define MAX_ARGS 10

typedef struct {
    smrt_ptr_t;
    size_t argc;
    array_t argv;
} thread_args_t;

typedef void (*capability_function_t)(thread_args_t);

/** Bound on a capability's returned result, as text. Sized for the bootstrap
 *  corpus's answers (an incremented nonce, a Unix timestamp, an echoed token)
 *  with room to spare; a capability whose result does not fit needs a payload
 *  channel, not a bigger scratch buffer. */
#define CAP_RESULT_LEN 255

/** Result-producing capability. @p kwargs_json is the invocation's keyword
 *  arguments as a compact JSON object ("" for none, the C carriage of Python
 *  @c TaskParameters.kwargs); the answer is written as text into @p result_out.
 *  Returns 0 if a result was produced, non-zero otherwise.
 *
 *  Why a second function pointer rather than a return value on
 *  ::capability_function_t: that signature returns void, so until now a C
 *  capability could be *invoked* but its answer could not be collected, and a
 *  worker had nothing to report. Changing it would break every existing
 *  fire-and-forget capability; a capability may supply either shape, or both.
 *  Python needs no equivalent because a Python capability is an ordinary
 *  callable and its return value is the result. */
typedef int (*capability_result_function_t)(const char *kwargs_json,
                                            char *result_out,
                                            size_t result_len);

typedef struct
{
    smrt_ptr_t;
    char name[CAP_NAMELEN+1];
    map_t arguments; // map of name to data_type_t
    bool local;
    capability_function_t function;
    /** Result-producing entry point, or NULL for a capability that produces
     *  none (every capability declared before this field existed). Not
     *  exported over the wire -- @c capability_sync_out carries a peer's
     *  ability, never a pointer into our address space. */
    capability_result_function_t result_function;
    /* Trust-tier metadata — mirrors Python Capability.required_tier /
     * transaction_weight (capabilities.py). required_tier = minimum
     * peer.tier needed to invoke this capability (0 = any admitted).
     * transaction_weight = multiplier applied in _pure_reputation;
     * proto3 can't distinguish "not set" from 0, so consumers treat
     * 0 as 1 (sentinel for back-compat with peers lacking the field).
     * See doc/architecture/trust-tiers.md §4. */
    int required_tier;
    int transaction_weight;
} capability_t;

typedef map_t peer_capabilities_matrix_t;   // map of UUID string to array of capabilities

/*@
  requires name != \null && \valid_read(name);
  assigns \nothing;
  ensures \result == \null || \valid(\result);
*/
capability_t *find_capability(const char *name);

/*@
  requires my_uuid != \null && \valid_read(my_uuid);
  requires \valid(caps_out);
  allocates *caps_out;
  behavior success:
    ensures \result == 0;
    ensures *caps_out != \null;
  behavior failure:
    ensures \result != 0;
  disjoint behaviors;
*/
int build_local_capabilities(const char *my_uuid, array_t **caps_out);

/**
 * @brief Invoke @p cap with @p args. Mirrors Python `Capability.execute()`
 *        (capabilities.py:35-40).
 *
 * Returns 0 on dispatch (caller doesn't get the function's return value;
 * the @c capability_function_t typedef returns void). Returns -1 if @p cap
 * has a NULL @c function pointer (remote-only capabilities synced in via
 * `proto_to_capability` always have function==NULL — they describe a
 * peer's ability, not a callable here).
 */
int capability_execute(const capability_t *cap, thread_args_t args);

/**
 * @brief Invoke @p cap's result-producing entry point and collect its answer.
 *
 * Returns 0 with @p result_out written (NUL-terminated) on success, -1 if
 * @p cap has no @c result_function, or the function's own non-zero status.
 * This is what lets a worker report anything back: see the negotiation
 * process's job drain.
 */
int capability_execute_result(const capability_t *cap, const char *kwargs_json,
                             char *result_out, size_t result_len);

/* Reflection placeholder consumed by scripts/preprocess.py to emit a
 * `capability_table[]` static initializer from `DECLARE_CAPABILITY(...)`
 * call sites. Currently no call sites exist — the table is populated
 * dynamically via register_ability-style helpers — so the macro is a
 * no-op declaration. See `capability_table_priv.h.in` for the LIST__
 * expansion shape if/when call sites get added. */
#define DECLARE_CAPABILITY(cap_name, cap_func, cap_res_func)

#define QUOTE(x) #x


/** @} */ /* end of internal_processes */

#endif  // CAPABILITIES_H
