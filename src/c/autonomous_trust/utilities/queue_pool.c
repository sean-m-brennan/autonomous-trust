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

/*@
  requires pool == \null || \valid(pool);
  assigns pool->pool[0 .. QUEUE_POOL_SIZE - 1], pool->initialized;
  behavior null_pool:
    assumes pool == \null;
    ensures \result == EINVAL;
  behavior valid_pool:
    assumes pool != \null;
    ensures \result == 0;
    ensures pool->initialized == 1;
    ensures \forall integer i; 0 <= i < QUEUE_POOL_SIZE ==>
              pool->pool[i].in_use == \false;
  disjoint behaviors;
  complete behaviors;
*/
int queue_pool_init(queue_pool_t *pool)
{
    if (pool == NULL)
        return EINVAL;
    memset(pool, 0, sizeof(queue_pool_t));
    /*@
      loop invariant 0 <= i <= QUEUE_POOL_SIZE;
      loop invariant \forall integer j; 0 <= j < i ==>
                       pool->pool[j].in_use == \false;
      loop assigns i, pool->pool[0 .. QUEUE_POOL_SIZE - 1];
      loop variant QUEUE_POOL_SIZE - i;
    */
    for (int i = 0; i < QUEUE_POOL_SIZE; i++)
    {
        pool->pool[i].in_use = false;
        memset(&pool->pool[i].queue, 0, sizeof(queue_t));
    }
    pool->initialized = 1;
    return 0;
}

/*@
  requires pool == \null || \valid(pool);
  assigns pool->pool[0 .. QUEUE_POOL_SIZE - 1].in_use;
  behavior null_or_uninit:
    assumes pool == \null || pool->initialized != 1;
    ensures \result == \null;
  behavior found:
    assumes pool != \null && pool->initialized == 1;
    assumes \exists integer i; 0 <= i < QUEUE_POOL_SIZE &&
              pool->pool[i].in_use == \false;
    ensures \result != \null;
  behavior exhausted:
    assumes pool != \null && pool->initialized == 1;
    assumes \forall integer i; 0 <= i < QUEUE_POOL_SIZE ==>
              pool->pool[i].in_use == \true;
    ensures \result == \null;
  disjoint behaviors;
*/
queue_t *queue_pool_next(queue_pool_t *pool)
{
    if (pool == NULL || !pool->initialized)
        return NULL;
    /*@
      loop invariant 0 <= i <= QUEUE_POOL_SIZE;
      loop invariant \forall integer j; 0 <= j < i ==>
                       pool->pool[j].in_use == \true;
      loop assigns i, pool->pool[0 .. QUEUE_POOL_SIZE - 1].in_use;
      loop variant QUEUE_POOL_SIZE - i;
    */
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

/*@
  requires pool == \null || \valid(pool);
  requires queue == \null || \valid(queue);
  assigns pool->pool[0 .. QUEUE_POOL_SIZE - 1].in_use;
  behavior null_args:
    assumes pool == \null || queue == \null;
    ensures \result == EINVAL;
  behavior found:
    assumes pool != \null && queue != \null;
    assumes \exists integer i; 0 <= i < QUEUE_POOL_SIZE &&
              &pool->pool[i].queue == queue;
    ensures \result == 0;
  behavior not_found:
    assumes pool != \null && queue != \null;
    assumes \forall integer i; 0 <= i < QUEUE_POOL_SIZE ==>
              &pool->pool[i].queue != queue;
    ensures \result == -1;
  disjoint behaviors;
*/
int queue_pool_recycle(queue_pool_t *pool, queue_t *queue)
{
    if (pool == NULL || queue == NULL)
        return EINVAL;
    /*@
      loop invariant 0 <= i <= QUEUE_POOL_SIZE;
      loop assigns i, pool->pool[0 .. QUEUE_POOL_SIZE - 1].in_use;
      loop variant QUEUE_POOL_SIZE - i;
    */
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
