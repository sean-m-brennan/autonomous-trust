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

#ifndef NEGOTIATION_H
#define NEGOTIATION_H

/** @addtogroup internal_negotiation
 *  @{
 */

#include <stdbool.h>
#include <stdint.h>
#include <time.h>
#include <uuid/uuid.h>

#include "structures/map.h"
#include "structures/data.h"
#include "identity/identity.h"
#include "negotiation/task.h"
#include "utilities/exception.h"

/****************************
 * Protocol constants (must match Python NegotiationProtocol).
 * Writable char arrays — definitions in `neg_proc.c`. Lets call
 * sites assign to `net_msg.function` (typed `char *`) without a
 * `(char *)` cast under `-Wwrite-strings`.
 ****************************/

extern char NEG_PROTO_START[];
extern char NEG_PROTO_ANNOUNCE[];
extern char NEG_PROTO_RESPONSE[];
extern char NEG_PROTO_ACCEPT[];
extern char NEG_PROTO_REFUSE[];
extern char NEG_PROTO_STAT_REQ[];
extern char NEG_PROTO_STAT_RSP[];
extern char NEG_PROTO_RESULT[];
extern char NEG_PROTO_CANCEL[];

/****************************
 * Negotiation status
 ****************************/

typedef enum {
    NEG_RUNNING = 1,
    NEG_SLEEPING,
    NEG_ZOMBIE,
    NEG_STOPPED,
    NEG_DEAD,
    NEG_PENDING,
    NEG_UNKNOWN,
    NEG_NO_PEERS,
    NEG_REJECTED
} neg_status_t;

/****************************
 * Task status tracking
 ****************************/

typedef struct {
    task_t task;
    neg_status_t status;
} task_status_t;

typedef struct {
    uuid_t task_uuid;
    uint8_t *result_data;
    size_t result_len;
} task_result_t;

/****************************
 * Task counter (flood detection)
 ****************************/

typedef struct {
    uuid_t task_uuid;
    int flood_count;
} task_counter_t;

/****************************
 * Task tracker (result collection)
 ****************************/

typedef struct {
    uuid_t task_uuid;
    map_t results;     /* uuid_str -> data_t* (result blob) */
    int expected;
    /** What WE asked for, kept so the returned result can be judged against
     *  it. Python's TaskTracker subclasses Task and so keeps the whole
     *  `parameters` for free; this is the same fact, narrowed to the two
     *  pieces the requestor-side scorer needs.
     *
     *  It must be our own record and never anything read back off the
     *  responder's reply: a known-answer check that trusts the reply's account
     *  of the challenge verifies nothing, because a peer that computed the
     *  wrong answer reports the challenge its answer would have satisfied
     *  (result 99 with a claimed nonce of 98 is a perfect increment). Mirrors
     *  Python TaskResult.attach_requested_parameters. See R+D.md §12.7. */
    char capability_name[CAP_NAMELEN + 1];
    char kwargs_json[TASK_KWARGS_LEN + 1];
} task_tracker_t;

/*@
  requires \valid(tracker);
  requires expected >= 0;
  allocates *tracker;
  behavior success:
    ensures \result == 0;
    ensures *tracker != \null;
  behavior failure:
    ensures \result != 0;
  disjoint behaviors;
*/
int  task_tracker_create(task_tracker_t **tracker, const uuid_t task_uuid, int expected);

/*@
  requires \valid(tracker);
  requires expected >= 0;
  requires \separated(tracker + (0 .. 0), task_uuid + (0 .. 15));
  assigns *tracker;
  ensures \result == 0 || \result != 0;
*/
int  task_tracker_init(task_tracker_t *tracker, const uuid_t task_uuid, int expected);

/*@
  requires tracker == \null || \valid(tracker);
  frees tracker;
*/
void task_tracker_destroy(task_tracker_t *tracker);

/*@
  requires \valid(tracker);
  requires data != \null && \valid_read(data + (0 .. len - 1));
  requires len > 0;
  assigns tracker->results;
  ensures \result == 0 || \result != 0;
*/
int  task_tracker_set_result(task_tracker_t *tracker, const uuid_t peer_uuid, const uint8_t *data, size_t len);

/*@
  requires \valid(tracker);
  assigns \nothing;
  ensures \result >= 0;
*/
int  task_tracker_result_count(const task_tracker_t *tracker);

/** Record what the requestor asked for on this tracker: the capability name
 *  and the compact-JSON keyword arguments (either may be NULL, which clears
 *  that field). Separate from @ref task_tracker_init so the existing
 *  two-and-three-argument creators keep their signatures; call it from the
 *  announce path, where the task is still in hand. */
/*@
  requires \valid(tracker);
  assigns tracker->capability_name[0 .. CAP_NAMELEN],
          tracker->kwargs_json[0 .. TASK_KWARGS_LEN];
  ensures \result == 0;
*/
int  task_tracker_set_request(task_tracker_t *tracker,
                              const char *capability_name,
                              const char *kwargs_json);

/*@
  requires \valid(tracker);
  requires tracker->results.length <= tracker->results.capacity;
  assigns tracker->results;
*/
void task_tracker_free(task_tracker_t *tracker);

/****************************
 * Job queue (sorted by start time)
 ****************************/

#define MAX_JOBS 256

typedef struct {
    task_t task;
    time_t start_time;
    time_t end_time;
} job_t;

typedef struct {
    job_t jobs[MAX_JOBS];
    int count;
} job_queue_t;

/*@
  requires \valid(q);
  allocates *q;
  behavior success:
    ensures \result == 0;
    ensures *q != \null;
  behavior failure:
    ensures \result != 0;
  disjoint behaviors;
*/
int  job_queue_create(job_queue_t **q);

/*@
  requires \valid(q);
  assigns *q;
  ensures \result == 0;
  ensures q->count == 0;
*/
int  job_queue_init(job_queue_t *q);

/*@
  requires q == \null || \valid(q);
  frees q;
*/
void job_queue_destroy(job_queue_t *q);

/*@
  requires \valid(q);
  requires \valid(job);
  requires q->count >= 0;
  assigns q->jobs[0 .. MAX_JOBS - 1], q->count;
  behavior full:
    assumes q->count >= MAX_JOBS;
    ensures \result != 0;
  behavior success:
    assumes q->count < MAX_JOBS;
    ensures \result == 0;
    ensures q->count == \old(q->count) + 1;
  disjoint behaviors;
  complete behaviors;
*/
int  job_queue_push(job_queue_t *q, const job_t *job);

/*@
  requires \valid(q);
  requires \valid(job);
  assigns q->jobs[0 .. MAX_JOBS - 1], q->count, *job;
  behavior empty:
    assumes q->count == 0;
    ensures \result != 0;
  behavior success:
    assumes q->count > 0;
    ensures \result == 0;
    ensures q->count == \old(q->count) - 1;
  disjoint behaviors;
  complete behaviors;
*/
int job_queue_pop(job_queue_t *q, job_t *job);

/*@
  requires \valid(q);
  requires \valid(job);
  assigns *job;
  behavior empty:
    assumes q->count == 0;
    ensures \result != 0;
  behavior success:
    assumes q->count > 0;
    ensures \result == 0;
  disjoint behaviors;
  complete behaviors;
*/
int job_queue_min(const job_queue_t *q, job_t *job);

/*@
  requires \valid(q);
  assigns \nothing;
  ensures \result == \true || \result == \false;
*/
bool job_queue_contains(const job_queue_t *q, const uuid_t task_uuid);

/*@
  requires \valid(q);
  assigns \nothing;
  ensures \result == q->count;
  ensures \result >= 0;
*/
int job_queue_count(const job_queue_t *q);

/*@
  requires \valid(q);
  requires duration > 0;
  requires max_concurrency > 0;
  requires \valid(slot_time);
  assigns *slot_time;
  ensures \result == 0;
  ensures *slot_time >= 0;
*/
int job_queue_find_nearest_slot(const job_queue_t *q, time_t duration, int max_concurrency, time_t *slot_time);

/*@
  requires \valid(q);
  assigns *q;
  ensures q->count == 0;
*/
void job_queue_clear(job_queue_t *q);

/****************************
 * Error codes
 ****************************/

#define ENEG_NOCAP 240
DECLARE_ERROR(ENEG_NOCAP, "Required capability not available");

#define ENEG_FULL 241
DECLARE_ERROR(ENEG_FULL, "Job queue is full");

#define ENEG_NOTASK 242
DECLARE_ERROR(ENEG_NOTASK, "Task not found");


/** @} */ /* end of internal_negotiation */

#endif  /* NEGOTIATION_H */
