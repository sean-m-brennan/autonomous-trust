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

#include <stdint.h>
#include <stdlib.h>
#include <stdarg.h>
#include <pthread.h>
#include <errno.h>

#include "task_priv.h"

typedef void * (*pthread_function_t)(void *);

int task_run(task_t *task)
{
    capability_t *capability = find_capability(task->capability.name);
    if (capability == NULL)
        return -1; // FIXME specific error

    thread_args_t *args = smrt_create(sizeof(thread_args_t));
    if (args == NULL)
        return EXCEPTION(ENOMEM);
    args->argc = task->argc;
    memcpy(&args->argv, &task->argv, sizeof(args->argv));

    pthread_t thread;
    int err = pthread_create(&thread, NULL, (pthread_function_t)capability->function, args);
    if (err != 0)
        return EXCEPTION(err);

    // FIXME track thread for results
    // place result on queue for routing
    // FIXME args must be freed somewhere
    return 0;
}

/* FIXME task.proto is empty — no protobuf types generated.
   Stub out proto functions until task.proto is populated. */

int task_to_proto(task_t *msg, size_t size, void **data_ptr, size_t *data_len_ptr)
{
    (void)msg; (void)size; (void)data_ptr; (void)data_len_ptr;
    return -1;  /* no proto support */
}

int proto_to_task(uint8_t *data, size_t len, task_t *task)
{
    (void)data; (void)len; (void)task;
    return -1;  /* no proto support */
}