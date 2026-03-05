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
#include <time.h>

#include <uuid/uuid.h>

#include "utilities/exception.h"
#include "utilities/allocation.h"
#include "structures/datetime.h"

/**
 * @brief Step: base type for DAG nodes.
 */
typedef struct step_s step_t;

struct step_s {
    uuid_t uuid;
};

/**
 * @brief Genesis: the unique root of every chain.
 */
step_t *dag_genesis(void);

/**
 * @brief Check if a step is the genesis step.
 */
bool dag_is_genesis(const step_t *step);

/**
 * @brief LinkedStep: an immutable link in a chain, pointing backward to genesis.
 */
typedef struct linked_step_s linked_step_t;

struct linked_step_s {
    smrt_ptr_t;
    uuid_t uuid;
    datetime_t timestamp;
    void *payload;         /**< Arbitrary user data */
    step_t *parent;        /**< Previous step (step_t* or linked_step_t*) */
    size_t length;         /**< Chain length from this node to genesis */
};

/**
 * @brief Create a linked step with auto-generated UUID and current timestamp.
 */
int linked_step_create(void *payload, step_t *parent, linked_step_t **step_out);

/**
 * @brief Create a linked step with explicit UUID and timestamp.
 */
int linked_step_create_full(const uuid_t uuid, const datetime_t *ts,
                            void *payload, step_t *parent,
                            linked_step_t **step_out);

/**
 * @brief Free a linked step (does not free payload).
 */
void linked_step_free(linked_step_t *step);

/****************************
 * StepDAG: branching DAG
 ****************************/

#define DAG_MAIN_BRANCH "main"
#define DAG_BRANCH_NAME_LEN 64

/**
 * @brief A named branch: head step + ordered history list.
 */
typedef struct {
    char name[DAG_BRANCH_NAME_LEN + 1];
    linked_step_t *head;
    linked_step_t **steps;
    size_t step_count;
    size_t step_capacity;
} dag_branch_t;

/**
 * @brief StepDAG: directed acyclic graph of LinkedSteps.
 */
typedef struct {
    smrt_ptr_t;
    dag_branch_t *branches;
    size_t branch_count;
    size_t branch_capacity;
} step_dag_t;

/**
 * @brief Create a new empty DAG with a main branch.
 */
int step_dag_create(step_dag_t **dag_out);

/**
 * @brief Number of branches in the DAG.
 */
size_t step_dag_size(const step_dag_t *dag);

/**
 * @brief Get the main branch head.
 */
linked_step_t *step_dag_main(const step_dag_t *dag);

/**
 * @brief Find branch by name (NULL if not found).
 */
dag_branch_t *step_dag_find_branch(const step_dag_t *dag, const char *name);

/**
 * @brief Add a step to a branch (default: main).
 */
int step_dag_add_step(step_dag_t *dag, linked_step_t *step, const char *branch);

/**
 * @brief Create a new branch from a source branch head.
 */
int step_dag_branch(step_dag_t *dag, const char *name, linked_step_t *step,
                    const char *source);

/**
 * @brief Import an external list of steps (head-to-root order) as a new branch.
 * @param steps Array of linked_step_t pointers (head first, root last)
 * @param count Number of steps
 * @param name Branch name (NULL for auto-generated)
 * @param branch_out Output branch name
 * @return 0 on success
 */
int step_dag_ingest_branch(step_dag_t *dag, linked_step_t **steps, size_t count,
                           const char *name, char *branch_out);

/**
 * @brief Prepare step list for transmission: steps from branch head down to root.
 * @param dag The DAG
 * @param branch Branch name (NULL for main)
 * @param steps_out Output array (caller must free)
 * @param count_out Number of steps
 * @return 0 on success
 */
int step_dag_recite(const step_dag_t *dag, const char *branch,
                    linked_step_t ***steps_out, size_t *count_out);

/**
 * @brief Free the DAG (does not free step payloads).
 */
void step_dag_free(step_dag_t *dag);


#define EDAG_BRANCH_EXISTS 224
DECLARE_ERROR(EDAG_BRANCH_EXISTS, "Branch already exists in DAG");

#define EDAG_BRANCH_INVALID 225
DECLARE_ERROR(EDAG_BRANCH_INVALID, "Invalid branch name in DAG");

#endif // DAG_H
