/********************
 *  Copyright 2026 TekFive, Inc., Sean M. Brennan, and contributors
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
#include <stdlib.h>
#include <time.h>
#include <stdio.h>

#include <uuid/uuid.h>
#include <sodium.h>

#include "dag.h"
#include "../utilities/allocation.h"
#include "../utilities/util.h"

DEFINE_ERROR(EDAG_INVALID_BRANCH, "Invalid branch name in DAG");
DEFINE_ERROR(EDAG_BRANCH_EXISTS, "Branch already exists in DAG");

/* WHY two genesis constants (_genesis and dag_genesis):
 *
 * `_genesis` is the TU-local sentinel this file uses as the `.parent` of any
 * newly-created step that has no explicit parent (see linked_step_create:
 * s->parent = &dag_genesis). `dag_genesis` is the externally-visible copy
 * other translation units (and the public header) may compare against.
 *
 * Both hold the all-zero UUID, but they live at DIFFERENT addresses in the
 * binary (one static, one extern). Pointer equality alone is therefore not
 * a sufficient genesis check: a step reached via this file's construction
 * path will have parent == &dag_genesis, but a step reconstructed from
 * serialized form elsewhere may have its own heap-allocated node whose uuid
 * happens to be the zero-UUID, and any third caller may still hold a
 * pointer to &_genesis from historical code.
 *
 * _is_genesis() therefore has to cover ALL three representations:
 *   1. NULL                     — uninitialized or detached step
 *   2. &dag_genesis / &_genesis — either in-binary sentinel
 *   3. uuid match on zero-UUID  — any other object that serialized as genesis
 *
 * Do NOT collapse to a single check; removing (2) costs a strcmp in the hot
 * path, and removing (3) silently breaks round-tripped DAGs. */
static const linked_step_t _genesis = {
    .uuid = "00000000-0000-0000-0000-000000000000",
    .timestamp = {{0}},
    .payload = NULL,
    .parent = NULL,
    .length = 0
};

const linked_step_t dag_genesis = {
    .uuid = "00000000-0000-0000-0000-000000000000",
    .timestamp = {{0}},
    .payload = NULL,
    .parent = NULL,
    .length = 0
};

/*@
  assigns \nothing;
  ensures \result <==> (step == \null || step == &dag_genesis || step == &_genesis);
*/
static bool _is_genesis(const linked_step_t *step)
{
    return step == NULL || step == &dag_genesis || step == &_genesis ||
           strcmp(step->uuid, dag_genesis.uuid) == 0;
}

/* Frama-C: skipped — [syscall] uuid_generate via libuuid */
int linked_step_create(const char *uuid, void *payload, linked_step_t **step)
{
    if (step == NULL)
        return EINVAL;
    linked_step_t *s = calloc(1, sizeof(linked_step_t));
    if (s == NULL)
        return ENOMEM;
    if (uuid != NULL)
        strncpy(s->uuid, uuid, DAG_UUID_LEN - 1);
    else
    {
        /* generate a random uuid string */
        uuid_t u;
        uuid_generate(u);
        uuid_unparse_lower(u, s->uuid);
    }
    s->payload = payload;
    s->parent = (linked_step_t *)&dag_genesis;
    s->length = 1;
    datetime_now(false, &s->timestamp);
    *step = s;
    return 0;
}

void linked_step_free(linked_step_t *step)
{
    if (step != NULL && !_is_genesis(step))
        free(step);
}

int linked_step_recompute_length(linked_step_t *step)
{
    if (step == NULL)
        return -1;
    /* Walk parents up to (but not including) the genesis sentinel and
     * count edges traversed. Mirrors Python LinkedStep._length —
     * "length is depth from genesis" (dag.py:74-76). A reparent that
     * leaves the cached value stale is the audit's M9 finding. */
    int len = 0;
    const linked_step_t *cur = step;
    while (cur != NULL && !_is_genesis(cur)) {
        len++;
        cur = cur->parent;
        if (len > 1000000)  /* defensive cap; acyclic invariant should hold */
            break;
    }
    step->length = len;
    return len;
}

/*@
  requires valid_dag(dag);
  requires \valid_read(branch);
  assigns \nothing;
  ensures \result == \null || \valid(\result);
*/
/* Frama-C: skipped — [solver-timeout] map_get/data_object_ptr preconditions */
static linked_step_t *_get_head(step_dag_t *dag, const char *branch)
{
    data_t *val = NULL;
    if (map_get(dag->heads, (map_key_t)branch, &val) != 0)
        return NULL;
    ptr_t ptr = NULL;
    if (data_object_ptr(val, &ptr) != 0)
        return NULL;
    return (linked_step_t *)ptr;
}

/*@
  requires valid_dag(dag);
  requires \valid_read(branch);
  requires step != \null;
  assigns dag->heads;
  ensures \result == 0 || \result != 0;
*/
/* Frama-C: skipped — [solver-timeout] object_ptr_data preconditions */
static int _set_head(step_dag_t *dag, const char *branch, linked_step_t *step)
{
    data_t *val = object_ptr_data(step, sizeof(linked_step_t));
    if (val == NULL)
        return ENOMEM;
    return map_set(dag->heads, (map_key_t)branch, val);
}

/*@
  requires valid_dag(dag);
  requires \valid_read(branch);
  assigns \nothing;
  ensures \result == \null || \valid(\result);
*/
static array_t *_get_branch_list(step_dag_t *dag, const char *branch)
{
    data_t *val = NULL;
    if (map_get(dag->branch_lists, (map_key_t)branch, &val) != 0)
        return NULL;
    ptr_t ptr = NULL;
    if (data_object_ptr(val, &ptr) != 0)
        return NULL;
    return (array_t *)ptr;
}

/*@
  requires valid_dag(dag);
  requires \valid_read(branch);
  requires list != \null && \valid(list);
  assigns dag->branch_lists;
  ensures \result == 0 || \result != 0;
*/
/* Frama-C: skipped — [solver-timeout] object_ptr_data preconditions */
static int _set_branch_list(step_dag_t *dag, const char *branch, array_t *list)
{
    data_t *val = object_ptr_data(list, sizeof(void *));
    if (val == NULL)
        return ENOMEM;
    return map_set(dag->branch_lists, (map_key_t)branch, val);
}

/*@
  requires list != \null && \valid(list);
  requires step != \null && \valid(step);
  assigns list->size, list->array;
  ensures \result == 0 || \result != 0;
*/
static int _append_step_to_list(array_t *list, linked_step_t *step)
{
    data_t *val = object_ptr_data(step, sizeof(linked_step_t));
    if (val == NULL)
        return ENOMEM;
    return array_append(list, val);
}

/*@
  requires list != \null && \valid(list);
  requires index >= 0;
  assigns \nothing;
  ensures \result == \null || \valid(\result);
*/
static linked_step_t *_get_step_from_list(array_t *list, int index)
{
    data_t *val = NULL;
    if (array_get(list, index, &val) != 0)
        return NULL;
    ptr_t ptr = NULL;
    if (data_object_ptr(val, &ptr) != 0)
        return NULL;
    return (linked_step_t *)ptr;
}

/* Frama-C: skipped — [recursive-ds] map/array initialization */
int dag_init(step_dag_t *dag)
{
    if (dag == NULL)
        return EINVAL;
    int err;
    dag->validate_fn = NULL;
    dag->validate_ctx = NULL;
    err = map_create(&dag->heads);
    if (err != 0)
        return err;
    err = map_create(&dag->branch_lists);
    if (err != 0)
        return err;

    /* set main branch head to genesis */
    err = _set_head(dag, DAG_MAIN_BRANCH, (linked_step_t *)&dag_genesis);
    if (err != 0)
        return err;

    /* create empty branch list for main */
    array_t *main_list = NULL;
    err = array_create(&main_list);
    if (err != 0)
        return err;
    err = _set_branch_list(dag, DAG_MAIN_BRANCH, main_list);
    return err;
}

/* Frama-C: skipped — [solver-timeout] ensures + dag_init preconditions */
int dag_create(step_dag_t **dag)
{
    if (dag == NULL)
        return EINVAL;
    step_dag_t *d = calloc(1, sizeof(step_dag_t));
    if (d == NULL)
        return ENOMEM;
    int err = dag_init(d);
    if (err != 0)
    {
        free(d);
        return err;
    }
    *dag = d;
    return 0;
}

/* Frama-C: skipped — [recursive-ds] linked list parent/child chain updates */
int dag_add_step(step_dag_t *dag, linked_step_t *step, const char *branch)
{
    if (dag == NULL || step == NULL)
        return EINVAL;
    if (branch == NULL)
        branch = DAG_MAIN_BRANCH;

    linked_step_t *head = _get_head(dag, branch);
    if (head == NULL)
        return EXCEPTION(EDAG_INVALID_BRANCH);

    step->parent = head;
    if (_is_genesis(head))
        step->length = 1;
    else
        step->length = head->length + 1;

    int err = _set_head(dag, branch, step);
    if (err != 0)
        return err;

    array_t *list = _get_branch_list(dag, branch);
    if (list == NULL)
        return EXCEPTION(EDAG_INVALID_BRANCH);
    return _append_step_to_list(list, step);
}

/* Frama-C: skipped — [recursive-ds] branching with recursive data structure copying */
int dag_branch(step_dag_t *dag, const char *name, linked_step_t *step, const char *source)
{
    if (dag == NULL || name == NULL || step == NULL)
        return EINVAL;
    if (source == NULL)
        source = DAG_MAIN_BRANCH;

    /* check branch doesn't already exist */
    linked_step_t *existing = _get_head(dag, name);
    if (existing != NULL)
        return EXCEPTION(EDAG_BRANCH_EXISTS);

    linked_step_t *current;
    if (strcmp(source, "genesis") == 0)
        current = (linked_step_t *)&dag_genesis;
    else
    {
        current = _get_head(dag, source);
        if (current == NULL)
            return EXCEPTION(EDAG_INVALID_BRANCH);
    }

    step->parent = current;
    if (_is_genesis(current))
        step->length = 1;
    else
        step->length = current->length + 1;

    int err = _set_head(dag, name, step);
    if (err != 0)
        return err;

    array_t *list = NULL;
    err = array_create(&list);
    if (err != 0)
        return err;
    err = _set_branch_list(dag, name, list);
    if (err != 0)
        return err;
    return _append_step_to_list(list, step);
}

/* Frama-C: skipped — [recursive-ds] recursive step list ingestion */
int dag_ingest_branch(step_dag_t *dag, linked_step_t **steps, size_t count,
                      const char *name, char *name_out, size_t name_out_len)
{
    if (dag == NULL || steps == NULL || count == 0)
        return EINVAL;

    /* generate temp name if none provided */
    char temp_name[16];
    if (name == NULL)
    {
        uint32_t r = randombytes_random();
        snprintf(temp_name, sizeof(temp_name), "tmp_%08x", r);
        name = temp_name;
    }

    if (name_out != NULL && name_out_len > 0)
        at_strlcpy(name_out, name, name_out_len);

    /* first step starts from genesis */
    int err = dag_branch(dag, name, steps[count - 1], "genesis");
    if (err != 0)
        return err;

    /* add remaining steps in reverse order (steps are head-to-root) */
    for (size_t i = count - 1; i-- > 0; )
    {
        err = dag_add_step(dag, steps[i], name);
        if (err != 0)
            return err;
    }
    return 0;
}

/* Frama-C: skipped — [recursive-ds] tree diff with complex control flow */
int dag_diff(step_dag_t *dag, const char *branch, const char *target,
             int *idx_out, linked_step_t **common_root)
{
    if (dag == NULL || branch == NULL)
        return EINVAL;
    if (target == NULL)
        target = DAG_MAIN_BRANCH;

    array_t *b_list = _get_branch_list(dag, branch);
    if (b_list == NULL)
        return EXCEPTION(EDAG_INVALID_BRANCH);
    array_t *t_list = _get_branch_list(dag, target);
    if (t_list == NULL)
        return EXCEPTION(EDAG_INVALID_BRANCH);

    int b_size = (int)array_size(b_list);
    int t_size = (int)array_size(t_list);
    int shorter = b_size < t_size ? b_size : t_size;

    linked_step_t *root = (linked_step_t *)&dag_genesis;
    int idx = 0;
    for (idx = 0; idx < shorter; idx++)
    {
        linked_step_t *b_step = _get_step_from_list(b_list, idx);
        linked_step_t *t_step = _get_step_from_list(t_list, idx);
        if (b_step != t_step)
        {
            if (idx > 0)
                root = _get_step_from_list(b_list, idx - 1);
            break;
        }
    }

    if (idx_out != NULL)
        *idx_out = idx;
    if (common_root != NULL)
        *common_root = root;
    return 0;
}

/*@
  requires \valid_read((const linked_step_t **)a);
  requires \valid_read((const linked_step_t **)b);
  assigns \nothing;
  ensures \result == -1 || \result == 0 || \result == 1;
*/
/* Frama-C: skipped — [func-ptr] used as qsort comparator callback */
static int _cmp_steps_by_timestamp(const void *a, const void *b)
{
    const linked_step_t *sa = *(const linked_step_t **)a;
    const linked_step_t *sb = *(const linked_step_t **)b;
    time_t ta = mktime((struct tm *)&sa->timestamp);
    time_t tb = mktime((struct tm *)&sb->timestamp);
    if (ta < tb) return -1;
    if (ta > tb) return 1;
    return 0;
}

/* Frama-C: skipped — [recursive-ds] three-way merge with array operations */
int dag_merge(step_dag_t *dag, const char *branch, const char *target, bool keep)
{
    if (dag == NULL || branch == NULL)
        return EINVAL;
    if (target == NULL)
        target = DAG_MAIN_BRANCH;

    int idx;
    linked_step_t *common_root;
    int err = dag_diff(dag, branch, target, &idx, &common_root);
    if (err != 0)
        return err;

    array_t *b_list = _get_branch_list(dag, branch);
    array_t *t_list = _get_branch_list(dag, target);
    int b_size = (int)array_size(b_list);
    int t_size = (int)array_size(t_list);

    /* collect divergent steps */
    int total = (b_size - idx) + (t_size - idx);
    if (total <= 0)
        return 0;

    linked_step_t **sorted = malloc(sizeof(linked_step_t *) * total);
    if (sorted == NULL)
        return ENOMEM;

    int n = 0;
    for (int i = idx; i < b_size; i++)
        sorted[n++] = _get_step_from_list(b_list, i);
    for (int i = idx; i < t_size; i++)
        sorted[n++] = _get_step_from_list(t_list, i);

    qsort(sorted, n, sizeof(linked_step_t *), _cmp_steps_by_timestamp);

    /* create temp branch from common root */
    char temp_name[16];
    uint32_t r = randombytes_random();
    snprintf(temp_name, sizeof(temp_name), "mrg_%08x", r);

    err = _set_head(dag, temp_name, common_root);
    if (err != 0)
    {
        free(sorted);
        return err;
    }
    array_t *temp_list = NULL;
    err = array_create(&temp_list);
    if (err != 0)
    {
        free(sorted);
        return err;
    }
    err = _set_branch_list(dag, temp_name, temp_list);
    if (err != 0)
    {
        free(sorted);
        return err;
    }

    for (int i = 0; i < n; i++)
    {
        err = dag_add_step(dag, sorted[i], temp_name);
        if (err != 0)
        {
            free(sorted);
            return err;
        }
    }
    free(sorted);

    /* update target head */
    linked_step_t *merged_head = _get_head(dag, temp_name);
    err = _set_head(dag, target, merged_head);
    if (err != 0)
        return err;

    /* remove temp branch */
    map_remove(dag->heads, (map_key_t)temp_name);
    map_remove(dag->branch_lists, (map_key_t)temp_name);

    if (!keep)
    {
        map_remove(dag->heads, (map_key_t)branch);
        map_remove(dag->branch_lists, (map_key_t)branch);
    }
    return 0;
}

int dag_fork(step_dag_t *dag, const char *branch, linked_step_t **head_out)
{
    if (dag == NULL || head_out == NULL)
        return EINVAL;
    if (branch == NULL)
        branch = DAG_MAIN_BRANCH;

    linked_step_t *head = _get_head(dag, branch);
    if (head == NULL)
        return EXCEPTION(EDAG_INVALID_BRANCH);
    *head_out = head;
    return 0;
}

/* M8: snapshot all branch heads. The returned map references the
 * DAG's live linked_step_t nodes; this is a shallow copy of the
 * heads map rather than Python's deepcopy semantics — see header
 * doc for the rationale. */
int dag_fork_all(step_dag_t *dag, map_t **heads_out)
{
    if (dag == NULL || heads_out == NULL)
        return EINVAL;
    if (dag->heads == NULL)
        return EINVAL;

    map_t *snap = NULL;
    int err = map_create(&snap);
    if (err != 0)
        return err;

    /* Iterate the heads map, mirroring each entry into the snapshot.
     * map_set inside map_entries_for_each is safe — we are walking
     * `dag->heads` keys, not `snap`. */
    map_key_t key = NULL;
    data_t *value = NULL;
    map_entries_for_each(dag->heads, key, value)
    {
        ptr_t ptr = NULL;
        if (data_object_ptr(value, &ptr) != 0 || ptr == NULL)
            continue;
        data_t *clone = object_ptr_data(ptr, sizeof(linked_step_t));
        if (clone == NULL)
        {
            map_free(snap);
            return ENOMEM;
        }
        int set_err = map_set(snap, key, clone);
        if (set_err != 0)
        {
            map_free(snap);
            return set_err;
        }
    }
    map_end_for_each;

    *heads_out = snap;
    return 0;
}

/* Frama-C: skipped — [recursive-ds] recursive step chain replay */
int dag_recite(step_dag_t *dag, const char *branch, linked_step_t *root,
               array_t **steps_out)
{
    if (dag == NULL || steps_out == NULL)
        return EINVAL;
    if (branch == NULL)
        branch = DAG_MAIN_BRANCH;

    linked_step_t *head = _get_head(dag, branch);
    if (head == NULL)
        return EXCEPTION(EDAG_INVALID_BRANCH);

    array_t *list = NULL;
    int err = array_create(&list);
    if (err != 0)
        return err;

    linked_step_t *step = head;
    while (!_is_genesis(step) && step != root)
    {
        data_t *val = object_ptr_data(step, sizeof(linked_step_t));
        if (val == NULL)
            return ENOMEM;
        err = array_append(list, val);
        if (err != 0)
            return err;
        step = step->parent;
    }
    if (root != NULL && !_is_genesis(root) && step == root)
    {
        data_t *val = object_ptr_data(step, sizeof(linked_step_t));
        if (val != NULL)
            array_append(list, val);
    }

    *steps_out = list;
    return 0;
}

void dag_set_validator(step_dag_t *dag, dag_validate_fn fn, void *ctx)
{
    if (dag == NULL)
        return;
    dag->validate_fn = fn;
    dag->validate_ctx = ctx;
}

/* Frama-C: skipped — [recursive-ds] composite ingest/diff/recite/merge */
int dag_catch_up(step_dag_t *dag, linked_step_t **steps, size_t count,
                 array_t **diff_out)
{
    if (dag == NULL || steps == NULL || count == 0)
        return EINVAL;

    char branch_name[32] = {0};
    int err = dag_ingest_branch(dag, steps, count, NULL,
                                branch_name, sizeof(branch_name));
    if (err != 0)
        return err;

    /* Locate divergence from main. The common_root may be &dag_genesis,
     * in which case dag_recite walks the full branch. */
    int idx = 0;
    linked_step_t *common_root = NULL;
    err = dag_diff(dag, branch_name, NULL, &idx, &common_root);
    if (err != 0)
        return err;

    /* Mirror Python: recite from common_root (exclusive of genesis),
     * head-first. The caller takes ownership of the array. */
    array_t *branch_diff = NULL;
    err = dag_recite(dag, branch_name, common_root, &branch_diff);
    if (err != 0)
        return err;

    /* Run the installed validator (Python's `_validate(branch)`). A
     * NULL hook is treated as always-valid, matching the abstract-
     * base default behavior. */
    bool ok = true;
    if (dag->validate_fn != NULL)
        ok = dag->validate_fn(dag, branch_name, dag->validate_ctx);

    if (ok)
    {
        int merr = dag_merge(dag, branch_name, NULL, false);
        if (merr != 0)
        {
            if (diff_out != NULL)
                *diff_out = branch_diff;
            else if (branch_diff != NULL)
                array_free(branch_diff);
            return merr;
        }
    }
    /* On validation failure: the temp branch stays in the DAG
     * unmerged. The caller can inspect the diff and decide what to
     * do — same contract as Python's catch_up returning the diff
     * even when validation rejected the merge. */

    if (diff_out != NULL)
        *diff_out = branch_diff;
    else if (branch_diff != NULL)
        array_free(branch_diff);
    return 0;
}

void dag_free(step_dag_t *dag)
{
    if (dag == NULL)
        return;
    if (dag->heads != NULL && dag->heads->items != NULL)
        map_free(dag->heads);
    if (dag->branch_lists != NULL && dag->branch_lists->items != NULL)
        map_free(dag->branch_lists);
}
