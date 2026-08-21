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

typedef struct {
    capability_t capability;
    datetime_t when;
    timedelta_t duration;
    long timeout;
    thread_args_t;
    uuid_t uuid;
    uuid_t requestor_uuid;
    bool flexible;
    /** Freshness sequence of the INVITATION that carried this task; 0 means
     *  unstamped, which handle_invite refuses. The requestor's monotonic
     *  per-process counter (utilities/freshness.h), checked against the
     *  receiver's per-(sender, verb) high-water mark. Field 12 of
     *  negotiation/task.proto and the "seq" key of the JSON form; C twin of
     *  Python TaskInfo.seq. Only NEG_PROTO_ANNOUNCE stamps or reads it -- the
     *  other verbs that reuse this struct carry whatever arrived. */
    int64_t seq;
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
