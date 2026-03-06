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

#ifndef QUEUE_POOL_H
#define QUEUE_POOL_H

#include <stdbool.h>

#include "message.h"

#ifdef __cplusplus
extern "C" {
#endif

#define QUEUE_POOL_SIZE 128

typedef struct {
    bool in_use;
    queue_t queue;
} pooled_queue_t;

typedef struct {
    pooled_queue_t pool[QUEUE_POOL_SIZE];
    int initialized;
} queue_pool_t;

int queue_pool_init(queue_pool_t *pool);

queue_t *queue_pool_next(queue_pool_t *pool);

int queue_pool_recycle(queue_pool_t *pool, queue_t *queue);

#ifdef __cplusplus
} // extern "C"
#endif

#endif  // QUEUE_POOL_H
