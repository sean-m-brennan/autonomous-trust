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

#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#include "dag.h"

DEFINE_ERROR(EDAG_BRANCH_EXISTS, "Branch already exists in DAG");
DEFINE_ERROR(EDAG_BRANCH_INVALID, "Invalid branch name in DAG");

/****************************
 * Genesis singleton
 ****************************/

static step_t genesis_instance = {{0}};
static bool genesis_initialized = false;

step_t *dag_genesis(void)
{
    if (!genesis_initialized)
    {
        uuid_clear(genesis_instance.uuid);
        genesis_initialized = true;
    }
    return &genesis_instance;
}

bool dag_is_genesis(const step_t *step)
{
    if (step == NULL)
        return false;
    return uuid_is_null(step->uuid);
}

/****************************
 * LinkedStep
 ****************************/

int linked_step_create(void *payload, step_t *parent, linked_step_t **step_out)
{
    if (step_out == NULL)
        return EXCEPTION(EINVAL);

    linked_step_t *ls = smrt_create(sizeof(linked_step_t));
    if (ls == NULL)
        return SYS_EXCEPTION();

    uuid_generate(ls->uuid);
    datetime_now(false, &ls->timestamp);
    ls->payload = payload;
    ls->parent = (parent != NULL) ? parent : (step_t *)dag_genesis();

    if (dag_is_genesis(ls->parent))
        ls->length = 1;
    else
    {
        linked_step_t *p = (linked_step_t *)ls->parent;
        ls->length = p->length + 1;
    }

    *step_out = ls;
    return 0;
}

int linked_step_create_full(const uuid_t uuid, const datetime_t *ts,
                            void *payload, step_t *parent,
                            linked_step_t **step_out)
{
    if (step_out == NULL)
        return EXCEPTION(EINVAL);

    linked_step_t *ls = smrt_create(sizeof(linked_step_t));
    if (ls == NULL)
        return SYS_EXCEPTION();

    uuid_copy(ls->uuid, uuid);
    if (ts != NULL)
        memcpy(&ls->timestamp, ts, sizeof(datetime_t));
    else
        datetime_now(false, &ls->timestamp);

    ls->payload = payload;
    ls->parent = (parent != NULL) ? parent : (step_t *)dag_genesis();

    if (dag_is_genesis(ls->parent))
        ls->length = 1;
    else
    {
        linked_step_t *p = (linked_step_t *)ls->parent;
        ls->length = p->length + 1;
    }

    *step_out = ls;
    return 0;
}

void linked_step_free(linked_step_t *step)
{
    if (step == NULL)
        return;
    smrt_deref(step);
}

/****************************
 * Branch management
 ****************************/

static int branch_init(dag_branch_t *branch, const char *name)
{
    memset(branch, 0, sizeof(dag_branch_t));
    strncpy(branch->name, name, DAG_BRANCH_NAME_LEN);
    branch->head = NULL;
    branch->steps = NULL;
    branch->step_count = 0;
    branch->step_capacity = 0;
    return 0;
}

static int branch_add_step(dag_branch_t *branch, linked_step_t *step)
{
    if (branch->step_count >= branch->step_capacity)
    {
        size_t new_cap = (branch->step_capacity == 0) ? 8 : branch->step_capacity * 2;
        linked_step_t **new_steps = realloc(branch->steps, new_cap * sizeof(linked_step_t *));
        if (new_steps == NULL)
            return SYS_EXCEPTION();
        branch->steps = new_steps;
        branch->step_capacity = new_cap;
    }
    branch->steps[branch->step_count++] = step;
    branch->head = step;
    return 0;
}

static void branch_free(dag_branch_t *branch)
{
    free(branch->steps);
    branch->steps = NULL;
    branch->step_count = 0;
}

/****************************
 * StepDAG
 ****************************/

int step_dag_create(step_dag_t **dag_out)
{
    if (dag_out == NULL)
        return EXCEPTION(EINVAL);

    step_dag_t *dag = smrt_create(sizeof(step_dag_t));
    if (dag == NULL)
        return SYS_EXCEPTION();

    dag->branch_capacity = 4;
    dag->branches = calloc(dag->branch_capacity, sizeof(dag_branch_t));
    if (dag->branches == NULL)
    {
        smrt_deref(dag);
        return SYS_EXCEPTION();
    }

    /* Initialize main branch */
    branch_init(&dag->branches[0], DAG_MAIN_BRANCH);
    dag->branch_count = 1;

    *dag_out = dag;
    return 0;
}

size_t step_dag_size(const step_dag_t *dag)
{
    if (dag == NULL)
        return 0;
    return dag->branch_count;
}

linked_step_t *step_dag_main(const step_dag_t *dag)
{
    if (dag == NULL || dag->branch_count == 0)
        return NULL;
    return dag->branches[0].head;
}

dag_branch_t *step_dag_find_branch(const step_dag_t *dag, const char *name)
{
    if (dag == NULL || name == NULL)
        return NULL;
    for (size_t i = 0; i < dag->branch_count; i++)
    {
        if (strncmp(dag->branches[i].name, name, DAG_BRANCH_NAME_LEN) == 0)
            return &dag->branches[i];
    }
    return NULL;
}

int step_dag_add_step(step_dag_t *dag, linked_step_t *step, const char *branch_name)
{
    if (dag == NULL || step == NULL)
        return EXCEPTION(EINVAL);

    const char *bname = (branch_name != NULL) ? branch_name : DAG_MAIN_BRANCH;
    dag_branch_t *branch = step_dag_find_branch(dag, bname);
    if (branch == NULL)
        return EXCEPTION(EDAG_BRANCH_INVALID);

    /* Set parent to current head */
    if (branch->head != NULL)
        step->parent = (step_t *)branch->head;
    else
        step->parent = (step_t *)dag_genesis();

    return branch_add_step(branch, step);
}

int step_dag_branch(step_dag_t *dag, const char *name, linked_step_t *step,
                    const char *source)
{
    if (dag == NULL || name == NULL || step == NULL)
        return EXCEPTION(EINVAL);

    if (step_dag_find_branch(dag, name) != NULL)
        return EXCEPTION(EDAG_BRANCH_EXISTS);

    const char *src = (source != NULL) ? source : DAG_MAIN_BRANCH;
    dag_branch_t *src_branch = step_dag_find_branch(dag, src);
    if (src_branch == NULL)
        return EXCEPTION(EDAG_BRANCH_INVALID);

    /* Grow branch array if needed */
    if (dag->branch_count >= dag->branch_capacity)
    {
        size_t new_cap = dag->branch_capacity * 2;
        dag_branch_t *new_branches = realloc(dag->branches, new_cap * sizeof(dag_branch_t));
        if (new_branches == NULL)
            return SYS_EXCEPTION();
        dag->branches = new_branches;
        dag->branch_capacity = new_cap;
    }

    dag_branch_t *new_branch = &dag->branches[dag->branch_count];
    branch_init(new_branch, name);
    dag->branch_count++;

    /* Set step's parent to source branch head */
    if (src_branch->head != NULL)
        step->parent = (step_t *)src_branch->head;
    else
        step->parent = (step_t *)dag_genesis();

    return branch_add_step(new_branch, step);
}

int step_dag_ingest_branch(step_dag_t *dag, linked_step_t **steps, size_t count,
                           const char *name, char *branch_out)
{
    if (dag == NULL || steps == NULL || count == 0)
        return EXCEPTION(EINVAL);

    char bname[DAG_BRANCH_NAME_LEN + 1] = {0};
    if (name != NULL)
        strncpy(bname, name, DAG_BRANCH_NAME_LEN);
    else
        snprintf(bname, DAG_BRANCH_NAME_LEN, "tmp_%08x", (unsigned int)rand());

    if (branch_out != NULL)
        strncpy(branch_out, bname, DAG_BRANCH_NAME_LEN);

    /* Create new branch from last step (root end) */
    linked_step_t *root_step = steps[count - 1];
    int ret = step_dag_branch(dag, bname, root_step, NULL);
    if (ret != 0)
        return ret;

    /* Add remaining steps in reverse (root+1 to head) */
    dag_branch_t *branch = step_dag_find_branch(dag, bname);
    for (int i = (int)count - 2; i >= 0; i--)
    {
        ret = branch_add_step(branch, steps[i]);
        if (ret != 0)
            return ret;
    }

    return 0;
}

int step_dag_recite(const step_dag_t *dag, const char *branch_name,
                    linked_step_t ***steps_out, size_t *count_out)
{
    if (dag == NULL || steps_out == NULL || count_out == NULL)
        return EXCEPTION(EINVAL);

    const char *bname = (branch_name != NULL) ? branch_name : DAG_MAIN_BRANCH;
    dag_branch_t *branch = step_dag_find_branch(dag, bname);
    if (branch == NULL)
        return EXCEPTION(EDAG_BRANCH_INVALID);

    /* Walk from head to genesis, collecting steps */
    size_t count = branch->step_count;
    if (count == 0)
    {
        *steps_out = NULL;
        *count_out = 0;
        return 0;
    }

    linked_step_t **out = calloc(count, sizeof(linked_step_t *));
    if (out == NULL)
        return SYS_EXCEPTION();

    /* Output in head-to-root order */
    for (size_t i = 0; i < count; i++)
        out[i] = branch->steps[count - 1 - i];

    *steps_out = out;
    *count_out = count;
    return 0;
}

void step_dag_free(step_dag_t *dag)
{
    if (dag == NULL)
        return;
    for (size_t i = 0; i < dag->branch_count; i++)
        branch_free(&dag->branches[i]);
    free(dag->branches);
    smrt_deref(dag);
}
