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

/** @addtogroup internal_structures
 *  @{
 */

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

/*@ axiomatic DagAcyclicity {
      // A step is reachable from another by following parent pointers.
      predicate reachable{L}(linked_step_t *from, linked_step_t *to) =
        from == to ||
        (from != \null && from->parent != \null &&
         reachable(from->parent, to));

      // The DAG acyclicity invariant: no step can reach itself via its parent chain
      // (except trivially).  Equivalently, following parent pointers from any step
      // eventually terminates at genesis (parent == NULL or is genesis).
      axiom acyclic_parent_chain:
        \forall linked_step_t *s;
          \valid(s) && s->parent != \null && s->parent != s ==>
            !reachable(s->parent, s);
    }
*/

/*@ predicate valid_step{L}(linked_step_t *s) =
      s != \null && \valid(s) &&
      s->length >= 0 &&
      s->uuid[DAG_UUID_LEN - 1] == '\0';
*/

typedef struct step_dag_s step_dag_t;

/**
 * @brief Per-DAG branch validation hook (parity with Python
 *        `StepDAG._validate`, dag.py:283-285).
 *
 * Invoked by `dag_catch_up` after a foreign branch is ingested and
 * before it is merged into the target. Implementations decide what
 * "valid" means for the payload domain (e.g. timestamp monotonicity
 * for `IdentityHistory`, dag.py history.py:155-168). A NULL hook is
 * treated as "always valid", matching the Python abstract-base
 * default of subclasses opting in.
 *
 * @return true to allow the merge, false to leave the branch unmerged.
 */
typedef bool (*dag_validate_fn)(step_dag_t *dag, const char *branch, void *ctx);

struct step_dag_s {
    map_t *heads;          /* branch_name -> linked_step_t* (as object_ptr_data) */
    map_t *branch_lists;   /* branch_name -> array_t* of linked_step_t* */
    dag_validate_fn validate_fn;  /* NULL => always-valid (Python ABC default) */
    void *validate_ctx;           /* opaque, passed to validate_fn */
};

/*@ predicate valid_dag{L}(step_dag_t *d) =
      d != \null && \valid(d) &&
      d->heads != \null && \valid(d->heads) &&
      d->branch_lists != \null && \valid(d->branch_lists);
*/

/**
 * @brief Allocate and initialise a new linked step.
 */
/*@
  requires \valid(step);
  requires uuid == \null || \valid_read(uuid + (0 .. DAG_UUID_LEN - 1));
  allocates *step;
  assigns *step;
  behavior success:
    ensures \result == 0;
    ensures *step != \null;
    ensures \fresh(*step, sizeof(linked_step_t));
    ensures (*step)->parent == &dag_genesis;
    ensures (*step)->length == 1;
    ensures (*step)->uuid[DAG_UUID_LEN - 1] == '\0';
  behavior failure:
    ensures \result != 0;
  disjoint behaviors;
*/
int linked_step_create(const char *uuid, void *payload, linked_step_t **step);

/**
 * @brief Recompute @p step->length by walking the parent chain.
 *
 * The C representation caches `length` at insert time. Python's
 * `LinkedStep._length` recomputes on demand from the parent chain
 * (dag.py:74-76). If a step has been reparented (e.g. a branch merge
 * moved it under a different ancestor), the cached length is stale.
 * Call this helper after any parent-mutation to bring it back into
 * line. Stops at NULL or the genesis sentinel.
 *
 * @return new length, or -1 if @p step is NULL.
 */
int linked_step_recompute_length(linked_step_t *step);

/**
 * @brief Free a linked step (does not free genesis).
 */
/*@
  behavior null_or_genesis:
    assumes step == \null ||
            step == &dag_genesis;
    assigns \nothing;
  behavior normal:
    assumes step != \null &&
            step != &dag_genesis;
    frees step;
  disjoint behaviors;
*/
void linked_step_free(linked_step_t *step);

/**
 * @brief Initialise an existing DAG structure with a main branch at genesis.
 */
/*@
  requires \valid(dag);
  assigns dag->heads, dag->branch_lists;
  behavior success:
    ensures \result == 0;
    ensures dag->heads != \null;
    ensures dag->branch_lists != \null;
  behavior failure:
    ensures \result != 0;
  disjoint behaviors;
*/
int dag_init(step_dag_t *dag);

/**
 * @brief Allocate and initialise a new DAG.
 */
/*@
  requires \valid(dag);
  allocates *dag;
  assigns *dag;
  behavior null_ptr:
    assumes dag == \null;
    ensures \result != 0;
  behavior success:
    assumes dag != \null;
    ensures \result == 0;
    ensures *dag != \null;
    ensures \fresh(*dag, sizeof(step_dag_t));
    ensures (*dag)->heads != \null;
    ensures (*dag)->branch_lists != \null;
  behavior failure:
    assumes dag != \null;
    ensures \result != 0;
  disjoint behaviors;
*/
int dag_create(step_dag_t **dag);

/**
 * @brief Add a step to an existing branch in the DAG.
 */
/*@
  requires valid_dag(dag);
  requires valid_step(step);
  requires branch == \null || \valid_read(branch);
  assigns step->parent, step->length;
  behavior success:
    ensures \result == 0;
    ensures step->length >= 1;
  behavior invalid_branch:
    ensures \result == 220;
  behavior error:
    ensures \result != 0 && \result != 220;
  disjoint behaviors;
*/
int dag_add_step(step_dag_t *dag, linked_step_t *step, const char *branch);

/**
 * @brief Create a new named branch from an existing source branch.
 */
/*@
  requires valid_dag(dag);
  requires name != \null && \valid_read(name);
  requires valid_step(step);
  requires source == \null || \valid_read(source);
  assigns step->parent, step->length;
  behavior success:
    ensures \result == 0;
    ensures step->length >= 1;
  behavior already_exists:
    ensures \result == 221;
  behavior invalid_source:
    ensures \result == 220;
  behavior error:
    ensures \result != 0;
  disjoint behaviors;
*/
int dag_branch(step_dag_t *dag, const char *name, linked_step_t *step, const char *source);

/**
 * @brief Ingest an array of steps as a new branch in the DAG.
 */
/*@
  requires valid_dag(dag);
  requires count > 0;
  requires \valid_read(steps + (0 .. count - 1));
  requires \forall integer i; 0 <= i < count ==> \valid(steps[i]);
  requires name_out == \null ||
           (name_out_len > 0 && \valid(name_out + (0 .. name_out_len - 1)));
  assigns name_out[0 .. name_out_len - 1];
  behavior success:
    ensures \result == 0;
    ensures name_out != \null ==> name_out[name_out_len - 1] == '\0' ||
            (\exists integer i; 0 <= i < name_out_len && name_out[i] == '\0');
  behavior error:
    ensures \result != 0;
  disjoint behaviors;
*/
int dag_ingest_branch(step_dag_t *dag, linked_step_t **steps, size_t count, const char *name, char *name_out, size_t name_out_len);

/**
 * @brief Find the divergence point between two branches.
 */
/*@
  requires valid_dag(dag);
  requires branch != \null && \valid_read(branch);
  requires target == \null || \valid_read(target);
  requires idx_out == \null || \valid(idx_out);
  requires common_root == \null || \valid(common_root);
  assigns *idx_out, *common_root;
  behavior success:
    ensures \result == 0;
    ensures idx_out != \null ==> *idx_out >= 0;
  behavior invalid_branch:
    ensures \result == 220;
  disjoint behaviors;
*/
int dag_diff(step_dag_t *dag, const char *branch, const char *target, int *idx_out, linked_step_t **common_root);

/**
 * @brief Merge a branch into a target branch, interleaving by timestamp.
 */
/*@
  requires valid_dag(dag);
  requires branch != \null && \valid_read(branch);
  requires target == \null || \valid_read(target);
  behavior success:
    ensures \result == 0;
  behavior error:
    ensures \result != 0;
  disjoint behaviors;
*/
int dag_merge(step_dag_t *dag, const char *branch, const char *target, bool keep);

/**
 * @brief Retrieve the head step of a branch.
 */
/*@
  requires valid_dag(dag);
  requires \valid(head_out);
  requires branch == \null || \valid_read(branch);
  assigns *head_out;
  behavior success:
    ensures \result == 0;
    ensures *head_out != \null;
  behavior invalid_branch:
    ensures \result == 220;
  disjoint behaviors;
*/
int dag_fork(step_dag_t *dag, const char *branch, linked_step_t **head_out);

/**
 * @brief Collect all steps from branch head back to root into an array.
 */
/*@
  requires valid_dag(dag);
  requires \valid(steps_out);
  requires branch == \null || \valid_read(branch);
  allocates *steps_out;
  assigns *steps_out;
  behavior success:
    ensures \result == 0;
    ensures *steps_out != \null;
  behavior invalid_branch:
    ensures \result == 220;
  behavior error:
    ensures \result != 0;
  disjoint behaviors;
*/
int dag_recite(step_dag_t *dag, const char *branch, linked_step_t *root, array_t **steps_out);

/**
 * @brief Install a per-DAG validation hook (C13).
 *
 * The hook is consulted by `dag_catch_up` before merging an ingested
 * foreign branch. Pass NULL @p fn to clear an installed hook. The
 * @p ctx pointer is opaque to the DAG and is passed verbatim to the
 * validator on each invocation.
 */
void dag_set_validator(step_dag_t *dag, dag_validate_fn fn, void *ctx);

/**
 * @brief Incorporate an external branch (C12, parity with Python
 *        `StepDAG.catch_up`, dag.py:287-297).
 *
 * Sequence: `dag_ingest_branch` the inbound steps into a freshly
 * named branch, then `dag_diff` against main to locate the common
 * root, then `dag_recite` from that root to populate @p diff_out
 * with the divergent steps, then run the installed validator (if
 * any), and finally `dag_merge` on success.
 *
 * On validation failure the temporary branch is left in the DAG
 * but not merged (mirrors Python). @p diff_out is populated either
 * way so callers can inspect the divergence even if the merge was
 * vetoed; pass NULL if not needed.
 *
 * @param dag         destination DAG.
 * @param steps       head-to-root step list (same layout as
 *                    `dag_ingest_branch`).
 * @param count       number of entries in @p steps; must be > 0.
 * @param diff_out    optional out parameter; receives an
 *                    allocated `array_t*` of `linked_step_t*` in
 *                    head-first order, owned by the caller.
 * @return 0 on success (whether or not the validator allowed the
 *         merge), non-zero on ingest/diff/recite failure.
 */
int dag_catch_up(step_dag_t *dag, linked_step_t **steps, size_t count,
                 array_t **diff_out);

/**
 * @brief Free all DAG resources (maps for heads and branch_lists).
 */
/*@
  behavior null:
    assumes dag == \null;
    assigns \nothing;
  behavior valid:
    assumes dag != \null;
    requires \valid(dag);
    requires dag->heads == \null || \valid(dag->heads);
    requires dag->branch_lists == \null || \valid(dag->branch_lists);
  disjoint behaviors;
*/
void dag_free(step_dag_t *dag);

#define EDAG_INVALID_BRANCH 220
DECLARE_ERROR(EDAG_INVALID_BRANCH, "Invalid branch name in DAG");

#define EDAG_BRANCH_EXISTS 221
DECLARE_ERROR(EDAG_BRANCH_EXISTS, "Branch already exists in DAG");

#ifdef __cplusplus
} // extern "C"
#endif


/** @} */ /* end of internal_structures */

#endif  // DAG_H
