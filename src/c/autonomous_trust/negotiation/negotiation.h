/********************
 *  Copyright 2025 Sean M. Brennan and contributors
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

#include <stdbool.h>
#include <stdint.h>
#include <time.h>
#include <uuid/uuid.h>

#include "structures/map_priv.h"
#include "structures/data_priv.h"
#include "identity/identity.h"
#include "negotiation/task.h"
#include "utilities/exception.h"

/****************************
 * Protocol constants (must match Python NegotiationProtocol)
 ****************************/

#define NEG_PROTO_START    "spawn task"
#define NEG_PROTO_ANNOUNCE "invitation"
#define NEG_PROTO_RESPONSE "haggle"
#define NEG_PROTO_ACCEPT   "ack"
#define NEG_PROTO_REFUSE   "nack"
#define NEG_PROTO_STAT_REQ "status request"
#define NEG_PROTO_STAT_RSP "status response"
#define NEG_PROTO_RESULT   "report results"
#define NEG_PROTO_CANCEL   "cancel"

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
    NEG_UNKNOWN
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
} task_tracker_t;

int task_tracker_init(task_tracker_t *tracker, const uuid_t task_uuid, int expected);
int task_tracker_set_result(task_tracker_t *tracker, const uuid_t peer_uuid, const uint8_t *data, size_t len);
int task_tracker_result_count(const task_tracker_t *tracker);
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

int job_queue_init(job_queue_t *q);
int job_queue_push(job_queue_t *q, const job_t *job);
int job_queue_pop(job_queue_t *q, job_t *job);
int job_queue_min(const job_queue_t *q, job_t *job);
bool job_queue_contains(const job_queue_t *q, const uuid_t task_uuid);
int job_queue_count(const job_queue_t *q);
int job_queue_find_nearest_slot(const job_queue_t *q, time_t duration, int max_concurrency, time_t *slot_time);
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

#endif  /* NEGOTIATION_H */
