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
 ********************/
#ifndef TASK_PRIV_H
#define TASK_PRIV_H

#include <string.h>

/* Full definitions needed before task.h (capabilities.h uses array_t/map_t as fields) */
#include "structures/map.h"
#include "structures/data.h"
#include "structures/array.h"

#include "negotiation/task.h"
#include "processes/capabilities_priv.h"
#include "structures/datetime_priv.h"

/* Task proto not yet defined — stub declarations */
int task_to_proto(task_t *msg, size_t size, void **data_ptr, size_t *data_len_ptr);
int proto_to_task(uint8_t *data, size_t len, task_t *task);

#endif  /* TASK_PRIV_H */
