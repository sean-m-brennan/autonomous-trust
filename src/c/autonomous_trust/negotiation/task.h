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

#ifndef TASK_H
#define TASK_H

#include "processes/capabilities.h"
#include "structures/datetime.h"

typedef struct {
    capability_t capability;
    datetime_t when;
    timedelta_t duration;
    long timeout;
    thread_args_t;
} task_t;

int task_run(task_t *task);

#endif  // TASK_H
