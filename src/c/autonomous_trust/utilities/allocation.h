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

#ifndef ALLOCATION_H
#define ALLOCATION_H

#include <stdlib.h>
#include <stdbool.h>

typedef struct {
    bool alloc;
    size_t refs;
} smrt_ptr_t;

void *smrt_create(size_t size);

void *smrt_recreate(void *orig, size_t size);

void smrt_ref(void *ptr);

void smrt_deref(void *ptr);

#endif  // ALLOCATION_H
