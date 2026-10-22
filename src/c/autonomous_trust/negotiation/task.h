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

#ifndef TASK_H
#define TASK_H

/** @addtogroup internal_negotiation
 *  @{
 */

#include <uuid/uuid.h>
#include "processes/capabilities.h"
#include "structures/datetime.h"

/** Bound on the serialized keyword arguments a task carries (see
 *  @c task_t::kwargs_json). 255 bytes is far more than any bootstrap probe
 *  needs (a nonce or a 14-byte echo token) and keeps @c task_t copyable by
 *  value, which @c job_t and @c proposed_tasks both rely on. */
#define TASK_KWARGS_LEN 255

/** Bound on a selection draw's JSON (see @c task_t::draw_json): three
 *  64-hex fields, an index and the keys, with room to spare. */
#define TASK_DRAW_LEN 383

typedef struct {
    capability_t capability;
    datetime_t when;
    timedelta_t duration;
    long timeout;
    thread_args_t;
    uuid_t uuid;
    uuid_t requestor_uuid;
    bool flexible;
    /** How many participants the requestor expects to hear back from. C twin
     *  of Python @c TaskInfo.size, carried on the wire and back on the reply.
     *  No completion rule reads it: both runtimes forward the first result,
     *  score every one, and count the peers they invited. 0 (the
     *  memset default) and 1 both mean single-participant; every
     *  C-originated task is one. */
    int size;
    /** Freshness sequence of the INVITATION that carried this task; 0 means
     *  unstamped, which handle_invite refuses. The requestor's monotonic
     *  per-process counter (utilities/freshness.h), checked against the
     *  receiver's per-(sender, verb) high-water mark. Field 12 of
     *  negotiation/task.proto and the "seq" key of the JSON form; C twin of
     *  Python TaskInfo.seq. Only NEG_PROTO_ANNOUNCE stamps or reads it -- the
     *  other verbs that reuse this struct carry whatever arrived. */
    int64_t seq;
    /** The invocation's keyword arguments, as a compact JSON object ("" or
     *  "{}" for none). C twin of Python @c TaskParameters.kwargs, which
     *  crosses the wire inside the serialized task and is forwarded verbatim
     *  to @c Capability.execute.
     *
     *  A string rather than a parsed map because @c task_t is copied by value
     *  (into @c job_t, into @c proposed_tasks) and a map_t would need an owner
     *  at each hop. The executor parses it; nothing else interprets it.
     *
     *  Load-bearing for the known-answer probes: without the challenge the
     *  responder cannot compute the answer, and the requestor -- which keeps
     *  its own copy on the tracker -- has nothing to check the answer
     *  against. See @ref verify_bootstrap_result and R+D.md §12.7. */
    char kwargs_json[TASK_KWARGS_LEN + 1];
    /** The requestor's auditable coin for this invitation (RD_12.7 plan
     *  section 0.1): a compact JSON object {head, index, link[, prev_root]}
     *  from its committed seed chain, "" when nothing selected the invitee.
     *  The "draw" key of the JSON form, omitted when empty, so a task nothing
     *  selected serializes as it always has; the proto form does not carry
     *  it. C twin of Python @c TaskInfo.draw. */
    char draw_json[TASK_DRAW_LEN + 1];
} task_t;

/*@
  requires \valid(task);
  assigns \nothing;
  behavior success:
    ensures \result == 0;
  behavior no_capability:
    ensures \result == -1;
  disjoint behaviors;
*/
int task_run(task_t *task);


/** @} */ /* end of internal_negotiation */

#endif  // TASK_H
