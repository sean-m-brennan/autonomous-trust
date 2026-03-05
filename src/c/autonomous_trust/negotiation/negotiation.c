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

#include "negotiation/negotiation.h"
#include "structures/map_priv.h"
#include "structures/data_priv.h"

DEFINE_ERROR(ENEG_NOCAP, "Required capability not available");
DEFINE_ERROR(ENEG_FULL, "Job queue is full");
DEFINE_ERROR(ENEG_NOTASK, "Task not found");

/****************************
 * Task tracker
 ****************************/

int task_tracker_init(task_tracker_t *tracker, const uuid_t task_uuid, int expected)
{
    uuid_copy(tracker->task_uuid, task_uuid);
    tracker->expected = expected;
    return map_init(&tracker->results);
}

int task_tracker_set_result(task_tracker_t *tracker, const uuid_t peer_uuid, const uint8_t *data, size_t len)
{
    char uuid_str[UUID_STRING_LEN + 1];
    uuid_unparse_lower(peer_uuid, uuid_str);

    uint8_t *copy = smrt_create(len);
    if (copy == NULL)
        return EXCEPTION(ENOMEM);
    memcpy(copy, data, len);

    data_t *dat = object_ptr_data(copy, len);
    return map_set(&tracker->results, uuid_str, dat);
}

int task_tracker_result_count(const task_tracker_t *tracker)
{
    return (int)map_size((map_t *)&tracker->results);
}

void task_tracker_free(task_tracker_t *tracker)
{
    map_free(&tracker->results);
}

/****************************
 * Job queue (sorted by start_time ascending)
 ****************************/

int job_queue_init(job_queue_t *q)
{
    memset(q, 0, sizeof(job_queue_t));
    return 0;
}

int job_queue_push(job_queue_t *q, const job_t *job)
{
    if (q->count >= MAX_JOBS)
        return EXCEPTION(ENEG_FULL);

    /* Find insertion point via binary search */
    int lo = 0, hi = q->count;
    while (lo < hi)
    {
        int mid = (lo + hi) / 2;
        if (q->jobs[mid].start_time <= job->start_time)
            lo = mid + 1;
        else
            hi = mid;
    }

    /* Shift elements right */
    if (lo < q->count)
        memmove(&q->jobs[lo + 1], &q->jobs[lo], (q->count - lo) * sizeof(job_t));

    q->jobs[lo] = *job;
    q->count++;
    return 0;
}

int job_queue_pop(job_queue_t *q, job_t *job)
{
    if (q->count <= 0)
        return -1;

    *job = q->jobs[0];
    q->count--;
    if (q->count > 0)
        memmove(&q->jobs[0], &q->jobs[1], q->count * sizeof(job_t));
    return 0;
}

int job_queue_min(const job_queue_t *q, job_t *job)
{
    if (q->count <= 0)
        return -1;
    *job = q->jobs[0];
    return 0;
}

bool job_queue_contains(const job_queue_t *q, const uuid_t task_uuid)
{
    for (int i = 0; i < q->count; i++)
    {
        if (uuid_compare(q->jobs[i].task.uuid, task_uuid) == 0)
            return true;
    }
    return false;
}

int job_queue_count(const job_queue_t *q)
{
    return q->count;
}

void job_queue_clear(job_queue_t *q)
{
    q->count = 0;
}

/**
 * Find the nearest time slot where a job of given duration can fit
 * without exceeding max_concurrency overlapping jobs.
 *
 * Algorithm: collect all interval endpoints, then probe each to find
 * a time where the overlap count < max_concurrency.
 */
int job_queue_find_nearest_slot(const job_queue_t *q, time_t duration, int max_concurrency, time_t *slot_time)
{
    if (q->count == 0 || q->count < max_concurrency)
    {
        *slot_time = time(NULL);
        return 0;
    }

    /* Collect unique time endpoints (start and end of each job) */
    time_t endpoints[MAX_JOBS * 2];
    int num_endpoints = 0;

    for (int i = 0; i < q->count; i++)
    {
        endpoints[num_endpoints++] = q->jobs[i].start_time;
        endpoints[num_endpoints++] = q->jobs[i].end_time;
    }

    /* Sort endpoints */
    for (int i = 0; i < num_endpoints - 1; i++)
    {
        for (int j = i + 1; j < num_endpoints; j++)
        {
            if (endpoints[j] < endpoints[i])
            {
                time_t tmp = endpoints[i];
                endpoints[i] = endpoints[j];
                endpoints[j] = tmp;
            }
        }
    }

    /* Probe each endpoint to find a slot with room */
    for (int i = 0; i < num_endpoints; i++)
    {
        time_t probe = endpoints[i];
        time_t probe_end = probe + duration;

        /* Count overlapping jobs at this probe time */
        int overlap = 0;
        for (int j = 0; j < q->count; j++)
        {
            if (q->jobs[j].start_time < probe_end && q->jobs[j].end_time > probe)
                overlap++;
        }

        if (overlap < max_concurrency)
        {
            *slot_time = probe;
            return 0;
        }
    }

    /* No slot found within existing range; schedule after last job ends */
    time_t latest_end = 0;
    for (int i = 0; i < q->count; i++)
    {
        if (q->jobs[i].end_time > latest_end)
            latest_end = q->jobs[i].end_time;
    }
    *slot_time = latest_end;
    return 0;
}
