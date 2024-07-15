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

int task_sync_out(task_t *task, AutonomousTrust__Core__Protobuf__Negotiation__Task *proto)
{
    AutonomousTrust__Core__Protobuf__Processes__Capability *cap_proto = malloc(sizeof(AutonomousTrust__Core__Protobuf__Processes__Capability));
    proto->capability = cap_proto;
    capability_sync_out(&task->capability, proto->capability);

    AutonomousTrust__Core__Protobuf__Structures__DateTime *dt_proto = malloc(sizeof(AutonomousTrust__Core__Protobuf__Structures__DateTime));
    proto->when = dt_proto;
    datetime_sync_out(&task->when, proto->when);

    AutonomousTrust__Core__Protobuf__Structures__TimeDelta *td_proto = malloc(sizeof(AutonomousTrust__Core__Protobuf__Structures__TimeDelta));
    proto->duration = td_proto;
    timedelta_sync_out(&task->duration, proto->duration);

    proto->timeout = task->timeout;
    array_sync_out(&task->argv, proto->args, &proto->n_args);
    return 0;
}

void task_proto_free(AutonomousTrust__Core__Protobuf__Negotiation__Task *proto)
{
    capability_proto_free(proto->capability);
    smrt_deref(proto->capability);
    smrt_deref(proto->when);
    smrt_deref(proto->duration);
    array_proto_free(proto->args);
}

int task_sync_in(AutonomousTrust__Core__Protobuf__Negotiation__Task *proto, task_t *task)
{
    capability_sync_in(proto->capability, &task->capability);
    datetime_sync_in(proto->when, &task->when);
    timedelta_sync_in(proto->duration, &task->duration);
    task->timeout = proto->timeout;
    array_sync_in(proto->args, proto->n_args, &task->argv);
    return 0;
}

int task_to_proto(task_t *msg, size_t size, void **data_ptr, size_t *data_len_ptr)
{
    AutonomousTrust__Core__Protobuf__Negotiation__Task proto;
    task_sync_out(msg, &proto);
    *data_len_ptr = autonomous_trust__core__protobuf__negotiation__task__get_packed_size(&proto);
    *data_ptr = smrt_create(*data_len_ptr);
    if (*data_ptr == NULL)
        return EXCEPTION(ENOMEM);
    autonomous_trust__core__protobuf__negotiation__task__pack(&proto, *data_ptr);
    task_proto_free(&proto);
    return 0;
}

int proto_to_task(uint8_t *data, size_t len, task_t *task)
{
    AutonomousTrust__Core__Protobuf__Negotiation__Task *msg =
        autonomous_trust__core__protobuf__negotiation__task__unpack(NULL, len, data);
    task_sync_in(msg, task);
    smrt_deref(msg);
    return 0;
}