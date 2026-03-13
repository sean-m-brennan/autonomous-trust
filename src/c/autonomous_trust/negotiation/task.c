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
#include "negotiation/task.pb-c.h"

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

    pthread_detach(thread);
    return 0;
}

int task_to_proto(task_t *msg, size_t size, void **data_ptr, size_t *data_len_ptr)
{
    (void)size;
    AutonomousTrust__Core__Protobuf__Negotiation__Task proto =
        AUTONOMOUS_TRUST__CORE__PROTOBUF__NEGOTIATION__TASK__INIT;

    proto.uuid.data = msg->uuid;
    proto.uuid.len = sizeof(uuid_t);
    proto.requestor_uuid.data = msg->requestor_uuid;
    proto.requestor_uuid.len = sizeof(uuid_t);
    proto.capability_name = msg->capability.name;
    proto.when_seconds = (int64_t)msg->when.tm_sec;
    proto.when_nanos = (int32_t)msg->when.tm_nsec;
    proto.duration_days = msg->duration.days;
    proto.duration_seconds = msg->duration.seconds;
    proto.duration_nsecs = msg->duration.nsecs;
    proto.timeout = msg->timeout;
    proto.flexible = msg->flexible;
    proto.argc = (int32_t)msg->argc;

    *data_len_ptr = autonomous_trust__core__protobuf__negotiation__task__get_packed_size(&proto);
    *data_ptr = smrt_create(*data_len_ptr);
    if (*data_ptr == NULL)
        return EXCEPTION(ENOMEM);
    autonomous_trust__core__protobuf__negotiation__task__pack(&proto, *data_ptr);
    return 0;
}

int proto_to_task(uint8_t *data, size_t len, task_t *task)
{
    AutonomousTrust__Core__Protobuf__Negotiation__Task *proto =
        autonomous_trust__core__protobuf__negotiation__task__unpack(NULL, len, data);
    if (proto == NULL)
        return -1;

    if (proto->uuid.len == sizeof(uuid_t))
        uuid_copy(task->uuid, proto->uuid.data);
    if (proto->requestor_uuid.len == sizeof(uuid_t))
        uuid_copy(task->requestor_uuid, proto->requestor_uuid.data);
    if (proto->capability_name)
        strncpy(task->capability.name, proto->capability_name, CAP_NAMELEN);
    task->when.tm_sec = (int)proto->when_seconds;
    task->when.tm_nsec = (unsigned long)proto->when_nanos;
    task->duration.days = proto->duration_days;
    task->duration.seconds = proto->duration_seconds;
    task->duration.nsecs = proto->duration_nsecs;
    task->timeout = proto->timeout;
    task->flexible = proto->flexible;
    task->argc = (size_t)proto->argc;

    autonomous_trust__core__protobuf__negotiation__task__free_unpacked(proto, NULL);
    return 0;
}