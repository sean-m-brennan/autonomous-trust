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
#include <errno.h>

#include "queue_pool.h"

int queue_pool_init(queue_pool_t *pool)
{
    if (pool == NULL)
        return EINVAL;
    memset(pool, 0, sizeof(queue_pool_t));
    for (int i = 0; i < QUEUE_POOL_SIZE; i++)
    {
        pool->pool[i].in_use = false;
        memset(&pool->pool[i].queue, 0, sizeof(queue_t));
    }
    pool->initialized = 1;
    return 0;
}

queue_t *queue_pool_next(queue_pool_t *pool)
{
    if (pool == NULL || !pool->initialized)
        return NULL;
    for (int i = 0; i < QUEUE_POOL_SIZE; i++)
    {
        if (!pool->pool[i].in_use)
        {
            pool->pool[i].in_use = true;
            return &pool->pool[i].queue;
        }
    }
    return NULL;
}

int queue_pool_recycle(queue_pool_t *pool, queue_t *queue)
{
    if (pool == NULL || queue == NULL)
        return EINVAL;
    for (int i = 0; i < QUEUE_POOL_SIZE; i++)
    {
        if (&pool->pool[i].queue == queue)
        {
            pool->pool[i].in_use = false;
            return 0;
        }
    }
    return -1;
}
