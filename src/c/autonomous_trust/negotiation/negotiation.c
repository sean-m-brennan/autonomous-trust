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

#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <uuid/uuid.h>

#include "negotiation/negotiation.h"
#include "structures/map_priv.h"
#include "structures/data_priv.h"
#include "utilities/allocation.h"
#include "utilities/exception.h"

DEFINE_ERROR(ENEG_NOCAP, "Required capability not available");
DEFINE_ERROR(ENEG_FULL,  "Job queue is full");
DEFINE_ERROR(ENEG_NOTASK, "Task not found");

/****************************
 * Job queue
 ****************************/

int job_queue_init(job_queue_t *q)
{
    memset(q, 0, sizeof(job_queue_t));
    return 0;
}

/**
 * Sorted insert by start_time (ascending).
 * Uses a linear search to find insertion point then shifts.
 */
int job_queue_push(job_queue_t *q, const job_t *job)
{
    if (q->count >= MAX_JOBS)
        return EXCEPTION(ENEG_FULL);

    /* Find insertion point (sorted ascending by start_time) */
    int ins = q->count;
    for (int i = 0; i < q->count; i++)
    {
        if (job->start_time < q->jobs[i].start_time)
        {
            ins = i;
            break;
        }
    }

    /* Shift elements right to make room */
    for (int i = q->count; i > ins; i--)
        q->jobs[i] = q->jobs[i - 1];

    q->jobs[ins] = *job;
    q->count++;
    return 0;
}

/**
 * Pop the first (earliest start_time) job.
 */
int job_queue_pop(job_queue_t *q, job_t *job)
{
    if (q->count == 0)
        return EXCEPTION(ENEG_NOTASK);

    *job = q->jobs[0];

    /* Shift elements left */
    for (int i = 0; i < q->count - 1; i++)
        q->jobs[i] = q->jobs[i + 1];

    q->count--;
    return 0;
}

/**
 * Peek at the first (minimum start_time) job without removing it.
 */
int job_queue_min(const job_queue_t *q, job_t *job)
{
    if (q->count == 0)
        return EXCEPTION(ENEG_NOTASK);

    *job = q->jobs[0];
    return 0;
}

int job_queue_count(const job_queue_t *q)
{
    return q->count;
}

bool job_queue_contains(const job_queue_t *q, const uuid_t task_uuid)
{
    for (int i = 0; i < q->count; i++)
    {
        if (uuid_compare(q->jobs[i].task.capability.uuid, task_uuid) == 0)
            return true;
    }
    return false;
}

void job_queue_clear(job_queue_t *q)
{
    memset(q, 0, sizeof(job_queue_t));
}

/**
 * Find the nearest available time slot of the given duration,
 * respecting the max_concurrency constraint.
 *
 * Algorithm: scan from now forward; at each existing job boundary,
 * count how many jobs are active. Find the first gap where fewer than
 * max_concurrency jobs run over a window of 'duration' seconds.
 *
 * Returns 0 with *slot_time set, or -1 if no slot found.
 */
int job_queue_find_nearest_slot(const job_queue_t *q, time_t duration,
                                int max_concurrency, time_t *slot_time)
{
    time_t now = time(NULL);
    *slot_time = now;

    if (q->count == 0)
        return 0;

    /* Collect all boundary times */
    time_t boundaries[MAX_JOBS * 2 + 1];
    int nb = 0;
    boundaries[nb++] = now;
    for (int i = 0; i < q->count; i++)
    {
        if (q->jobs[i].start_time > now)
            boundaries[nb++] = q->jobs[i].start_time;
        if (q->jobs[i].end_time > now)
            boundaries[nb++] = q->jobs[i].end_time;
    }

    /* Simple sort (insertion) */
    for (int i = 1; i < nb; i++)
    {
        time_t key = boundaries[i];
        int j = i - 1;
        while (j >= 0 && boundaries[j] > key)
        {
            boundaries[j + 1] = boundaries[j];
            j--;
        }
        boundaries[j + 1] = key;
    }

    /* Try each boundary as a candidate slot start */
    for (int b = 0; b < nb; b++)
    {
        time_t candidate = boundaries[b];
        if (candidate < now) candidate = now;
        time_t candidate_end = candidate + duration;

        /* Count overlapping jobs */
        int overlap = 0;
        for (int i = 0; i < q->count; i++)
        {
            /* Overlap if job starts before candidate ends AND ends after candidate starts */
            if (q->jobs[i].start_time < candidate_end &&
                q->jobs[i].end_time   > candidate)
                overlap++;
        }

        if (overlap < max_concurrency)
        {
            *slot_time = candidate;
            return 0;
        }
    }

    /* No slot found within existing boundaries: schedule after last job */
    time_t latest = now;
    for (int i = 0; i < q->count; i++)
    {
        if (q->jobs[i].end_time > latest)
            latest = q->jobs[i].end_time;
    }
    *slot_time = latest;
    return 0;
}

/****************************
 * Task tracker
 ****************************/

int task_tracker_init(task_tracker_t *tracker, const uuid_t task_uuid, int expected)
{
    memset(tracker, 0, sizeof(task_tracker_t));
    uuid_copy(tracker->task_uuid, task_uuid);
    tracker->expected = expected;
    return map_init(&tracker->results);
}

int task_tracker_set_result(task_tracker_t *tracker, const uuid_t peer_uuid,
                            const uint8_t *data, size_t len)
{
    char uuid_str[UUID_STRING_LEN + 1];
    uuid_unparse_lower(peer_uuid, uuid_str);

    data_t *blob = bytes_data((bytes_t)data, len);
    if (blob == NULL)
        return EXCEPTION(ENOMEM);

    return map_set(&tracker->results, uuid_str, blob);
}

int task_tracker_result_count(const task_tracker_t *tracker)
{
    return (int)map_size((map_t *)&tracker->results);
}

void task_tracker_free(task_tracker_t *tracker)
{
    map_free(&tracker->results);
}
