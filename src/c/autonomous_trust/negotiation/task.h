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

typedef struct task_s task_t;

int task_init(task_t *task);

int task_run(task_t *task);

int task_to_proto(const task_t *msg, size_t size, void **data_ptr, size_t *data_len_ptr);

int proto_to_task(uint8_t *data, size_t len, task_t *task);


#endif  // TASK_H
