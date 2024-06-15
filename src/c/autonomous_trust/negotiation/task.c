/********************
 *  Copyright 2024 TekFive, Inc. and contributors
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

#include <stdint.h>
#include <stdlib.h>
#include <stdarg.h>
#include <pthread.h>
#include <errno.h>

#include "task_priv.h"

int task_init(task_t *task)
{
    AutonomousTrust__Core__Negotiation__Task tmp = AUTONOMOUS_TRUST__CORE__NEGOTIATION__TASK__INIT;
    memcpy(&task->proto, &tmp, sizeof(task->proto));

    task->proto.capability = &task->capability.proto;
    capability_init(&task->capability);
    task->proto.when = &task->when.proto;
    datetime_init(&task->when);
    task->proto.duration = &task->duration.proto;
    timedelta_init(&task->duration);
    task->argc = 0;
    memset(&task->argv, 0, sizeof(task->argv));
    return 0;
}

int task_sync_out(task_t *task)
{
    capability_sync_out(&task->capability);
    datetime_sync_out(&task->when);
    timedelta_sync_out(&task->duration);
    task->proto.timeout = task->timeout;
    proto_repeated_sync_out(&task->argv, task->proto.args, &task->proto.n_args);
    return 0;
}

int task_sync_in(task_t *task)
{
    capability_sync_in(&task->capability);
    datetime_sync_in(&task->when);
    timedelta_sync_in(&task->duration);
    task->timeout = task->proto.timeout;
    proto_repeated_sync_in(task->proto.args, task->proto.n_args, &task->argv);
    return 0;
}

typedef void * (*pthread_function_t)(void *);

int task_run(task_t *task)
{
    capability_t *capability = find_capability(task->capability.name);
    if (capability == NULL)
        return -1; // FIXME specific error

    thread_args_t *args = malloc(sizeof(thread_args_t));
    if (args == NULL)
        return EXCEPTION(ENOMEM);
    args->argc = task->argc;
    memcpy(&args->argv, &task->argv, sizeof(args->argv));
    args->alloc = true;

    pthread_t thread;
    int err = pthread_create(&thread, NULL, (pthread_function_t)capability->function, args);
    if (err != 0)
        return EXCEPTION(err);

    // FIXME track thread for results
    // place result on queue for routing
    // FIXME args must be freed somewhere
    return 0;
}

int task_to_proto(const task_t *msg, size_t size, void **data_ptr, size_t *data_len_ptr)
{
    datetime_sync_out((datetime_t*)&msg->when);
    timedelta_sync_out((timedelta_t*)&msg->duration);
    *data_len_ptr = autonomous_trust__core__negotiation__task__get_packed_size(&msg->proto);
    *data_ptr = malloc(*data_len_ptr);
    if (*data_ptr == NULL)
        return EXCEPTION(ENOMEM);
    autonomous_trust__core__negotiation__task__pack(&msg->proto, *data_ptr);
    return 0;
}

int proto_to_task(uint8_t *data, size_t len, task_t *task)
{
    AutonomousTrust__Core__Negotiation__Task *msg =
        autonomous_trust__core__negotiation__task__unpack(NULL, len, data);
    memcpy(&task->proto, msg, sizeof(task->proto));
    datetime_sync_in(&task->when);
    timedelta_sync_in(&task->duration);
    free(msg);
    return 0;
}