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

#ifndef DAG_H
#define DAG_H

#include <stdbool.h>
#include <stddef.h>

#include "datetime.h"
#include "map.h"
#include "array.h"
#include "utilities/exception.h"

#ifdef __cplusplus
extern "C" {
#endif

#define DAG_UUID_LEN 37
#define DAG_MAIN_BRANCH "main"

typedef struct linked_step_s linked_step_t;

struct linked_step_s {
    char uuid[DAG_UUID_LEN];
    datetime_t timestamp;
    void *payload;
    linked_step_t *parent;
    int length;
};

extern const linked_step_t dag_genesis;

int linked_step_create(const char *uuid, void *payload, linked_step_t **step);

void linked_step_free(linked_step_t *step);

typedef struct {
    map_t *heads;          /* branch_name -> linked_step_t* (as object_ptr_data) */
    map_t *branch_lists;   /* branch_name -> array_t* of linked_step_t* */
} step_dag_t;

int dag_init(step_dag_t *dag);

int dag_create(step_dag_t **dag);

int dag_add_step(step_dag_t *dag, linked_step_t *step, const char *branch);

int dag_branch(step_dag_t *dag, const char *name, linked_step_t *step, const char *source);

int dag_ingest_branch(step_dag_t *dag, linked_step_t **steps, size_t count, const char *name, char *name_out, size_t name_out_len);

int dag_diff(step_dag_t *dag, const char *branch, const char *target, int *idx_out, linked_step_t **common_root);

int dag_merge(step_dag_t *dag, const char *branch, const char *target, bool keep);

int dag_fork(step_dag_t *dag, const char *branch, linked_step_t **head_out);

int dag_recite(step_dag_t *dag, const char *branch, linked_step_t *root, array_t **steps_out);

void dag_free(step_dag_t *dag);

#define EDAG_INVALID_BRANCH 220
DECLARE_ERROR(EDAG_INVALID_BRANCH, "Invalid branch name in DAG");

#define EDAG_BRANCH_EXISTS 221
DECLARE_ERROR(EDAG_BRANCH_EXISTS, "Branch already exists in DAG");

#ifdef __cplusplus
} // extern "C"
#endif

#endif  // DAG_H
