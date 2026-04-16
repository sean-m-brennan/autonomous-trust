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
#include <stdlib.h>

#include "merkle.h"
#include "../utilities/allocation.h"

DEFINE_ERROR(EMRKL_NOTFOUND, "Blob not found in Merkle tree");

#define INITIAL_NODE_CAPACITY 32

int merkle_hash(const uint8_t *data, size_t data_len, uint8_t *hash_out)
{
    return crypto_generichash_blake2b(hash_out, MERKLE_DIGEST_LEN,
                                      data, data_len,
                                      NULL, 0);
}

/*@
  requires valid_merkle_tree(tree);
  requires blob != \null;
  assigns \nothing;
  ensures \result >= -1;
  ensures \result < (int)tree->blobs->size;
*/
/* Frama-C: skipped — [alloc-pattern] dynamic node search */
static int _find_blob_index(merkle_tree_t *tree, merkle_blob_t *blob)
{
    int sz = (int)array_size(tree->blobs);
    for (int i = 0; i < sz; i++)
    {
        data_t *val = NULL;
        if (array_get(tree->blobs, i, &val) != 0)
            continue;
        ptr_t ptr = NULL;
        if (data_object_ptr(val, &ptr) != 0)
            continue;
        if ((merkle_blob_t *)ptr == blob)
            return i;
    }
    return -1;
}

/*@
  requires tree != \null && \valid(tree);
  requires needed >= 0;
  assigns tree->nodes, tree->node_capacity;
  behavior already_sufficient:
    assumes needed <= tree->node_capacity;
    ensures \result == 0;
    ensures tree->node_capacity == \old(tree->node_capacity);
  behavior grow:
    assumes needed > tree->node_capacity;
    ensures \result == 0 || \result == ENOMEM;
    ensures \result == 0 ==> tree->node_capacity >= needed;
    ensures \result == 0 ==> tree->nodes != \null;
  disjoint behaviors;
  complete behaviors;
*/
/* Frama-C: skipped — [alloc-pattern] node array realloc */
static int _ensure_node_capacity(merkle_tree_t *tree, int needed)
{
    if (needed <= tree->node_capacity)
        return 0;
    int new_cap = tree->node_capacity * 2;
    if (new_cap < needed)
        new_cap = needed;
    merkle_node_t *new_nodes = realloc(tree->nodes, sizeof(merkle_node_t) * new_cap);
    if (new_nodes == NULL)
        return ENOMEM;
    tree->nodes = new_nodes;
    tree->node_capacity = new_cap;
    return 0;
}

/*@
  requires tree != \null && \valid(tree);
  requires tree->node_count >= 0;
  assigns tree->nodes, tree->node_count, tree->node_capacity;
  ensures \result >= -1;
  behavior success:
    ensures \result >= 0;
    ensures \result == \old(tree->node_count);
    ensures tree->node_count == \old(tree->node_count) + 1;
    ensures tree->nodes[\result].left == -1;
    ensures tree->nodes[\result].right == -1;
    ensures tree->nodes[\result].parent == -1;
    ensures tree->nodes[\result].blob == \null;
  behavior failure:
    ensures \result == -1;
  disjoint behaviors;
*/
/* Frama-C: skipped — [alloc-pattern] dynamic node insertion */
static int _add_node(merkle_tree_t *tree)
{
    int err = _ensure_node_capacity(tree, tree->node_count + 1);
    if (err != 0)
        return -1;
    int idx = tree->node_count++;
    memset(&tree->nodes[idx], 0, sizeof(merkle_node_t));
    tree->nodes[idx].left = -1;
    tree->nodes[idx].right = -1;
    tree->nodes[idx].parent = -1;
    tree->nodes[idx].blob = NULL;
    return idx;
}

/*@
  requires valid_merkle_tree(tree);
  assigns tree->nodes, tree->node_count, tree->node_capacity,
          tree->root, tree->root_digest[0 .. MERKLE_DIGEST_LEN - 1],
          tree->has_root_digest;
  ensures tree->blobs->size == 0 ==>
            (tree->root == -1 && tree->has_root_digest == false);
  ensures tree->blobs->size > 0 ==>
            (tree->has_root_digest == true &&
             tree->root >= 0 && tree->root < tree->node_count);
*/
/* Frama-C: skipped — [recursive-ds] iterative tree rebuild with realloc */
static void _rehash(merkle_tree_t *tree)
{
    int blob_count = (int)array_size(tree->blobs);
    if (blob_count == 0)
    {
        tree->node_count = 0;
        tree->root = -1;
        tree->has_root_digest = false;
        memset(tree->root_digest, 0, MERKLE_DIGEST_LEN);
        return;
    }

    /* build a complete binary tree bottom-up */
    tree->node_count = 0;

    /* create leaf nodes */
    int *leaf_indices = malloc(sizeof(int) * blob_count);
    if (leaf_indices == NULL)
        return;

    for (int i = 0; i < blob_count; i++)
    {
        int idx = _add_node(tree);
        if (idx < 0)
        {
            free(leaf_indices);
            return;
        }
        leaf_indices[i] = idx;

        data_t *val = NULL;
        array_get(tree->blobs, i, &val);
        ptr_t ptr = NULL;
        data_object_ptr(val, &ptr);
        merkle_blob_t *blob = (merkle_blob_t *)ptr;
        tree->nodes[idx].blob = blob;

        if (blob->get_hash != NULL)
            blob->get_hash(blob, NULL, 0, tree->nodes[idx].digest);
        else
            memset(tree->nodes[idx].digest, 0, MERKLE_DIGEST_LEN);
    }

    /* build internal nodes level by level */
    int *current_level = leaf_indices;
    int current_count = blob_count;

    while (current_count > 1)
    {
        int parent_count = (current_count + 1) / 2;
        int *parent_indices = malloc(sizeof(int) * parent_count);
        if (parent_indices == NULL)
        {
            if (current_level != leaf_indices)
                free(current_level);
            return;
        }

        for (int i = 0; i < current_count; i += 2)
        {
            int parent_idx = _add_node(tree);
            if (parent_idx < 0)
            {
                free(parent_indices);
                if (current_level != leaf_indices)
                    free(current_level);
                return;
            }
            parent_indices[i / 2] = parent_idx;

            int left = current_level[i];
            tree->nodes[parent_idx].left = left;
            tree->nodes[left].parent = parent_idx;

            if (i + 1 < current_count)
            {
                int right = current_level[i + 1];
                tree->nodes[parent_idx].right = right;
                tree->nodes[right].parent = parent_idx;

                /* hash(left || right) */
                uint8_t combined[MERKLE_DIGEST_LEN * 2];
                memcpy(combined, tree->nodes[left].digest, MERKLE_DIGEST_LEN);
                memcpy(combined + MERKLE_DIGEST_LEN, tree->nodes[right].digest, MERKLE_DIGEST_LEN);
                merkle_hash(combined, MERKLE_DIGEST_LEN * 2, tree->nodes[parent_idx].digest);
            }
            else
            {
                /* single child - copy digest (CVE-2012-2459 protection) */
                memcpy(tree->nodes[parent_idx].digest,
                       tree->nodes[left].digest, MERKLE_DIGEST_LEN);
            }
        }

        if (current_level != leaf_indices)
            free(current_level);
        current_level = parent_indices;
        current_count = parent_count;
    }

    tree->root = current_level[0];
    memcpy(tree->root_digest, tree->nodes[tree->root].digest, MERKLE_DIGEST_LEN);
    tree->has_root_digest = true;

    if (current_level != leaf_indices)
        free(current_level);
}

/* Frama-C: skipped — [alloc-pattern] initialization with dynamic node arrays */
int merkle_tree_create(merkle_tree_t **tree)
{
    if (tree == NULL)
        return EINVAL;
    merkle_tree_t *t = calloc(1, sizeof(merkle_tree_t));
    if (t == NULL)
        return ENOMEM;

    t->nodes = malloc(sizeof(merkle_node_t) * INITIAL_NODE_CAPACITY);
    if (t->nodes == NULL)
    {
        free(t);
        return ENOMEM;
    }
    t->node_capacity = INITIAL_NODE_CAPACITY;
    t->node_count = 0;
    t->root = -1;
    t->has_root_digest = false;

    int err = array_create(&t->blobs);
    if (err != 0)
    {
        free(t->nodes);
        free(t);
        return err;
    }

    *tree = t;
    return 0;
}

/* Frama-C: skipped — [recursive-ds] binary tree insertion with rebalancing */
int merkle_insert(merkle_tree_t *tree, merkle_blob_t *blob)
{
    if (tree == NULL || blob == NULL)
        return EINVAL;
    if (_find_blob_index(tree, blob) >= 0)
        return 0; /* already present */

    data_t *val = object_ptr_data(blob, sizeof(merkle_blob_t));
    if (val == NULL)
        return ENOMEM;
    int err = array_append(tree->blobs, val);
    if (err != 0)
        return err;

    _rehash(tree);
    return 0;
}

/* Frama-C: skipped — [recursive-ds] binary tree deletion with rebalancing */
int merkle_delete(merkle_tree_t *tree, merkle_blob_t *blob)
{
    if (tree == NULL || blob == NULL)
        return EINVAL;
    int idx = _find_blob_index(tree, blob);
    if (idx < 0)
        return EXCEPTION(EMRKL_NOTFOUND);

    data_t *val = NULL;
    array_get(tree->blobs, idx, &val);
    array_remove(tree->blobs, val);

    _rehash(tree);
    return 0;
}

/* Frama-C: skipped — [recursive-ds] tree merge operation */
int merkle_merge(merkle_tree_t *tree, merkle_tree_t *other)
{
    if (tree == NULL || other == NULL)
        return EINVAL;
    int other_count = (int)array_size(other->blobs);
    int added = 0;
    for (int i = 0; i < other_count; i++)
    {
        data_t *val = NULL;
        if (array_get(other->blobs, i, &val) != 0)
            continue;
        ptr_t ptr = NULL;
        if (data_object_ptr(val, &ptr) != 0)
            continue;
        merkle_blob_t *blob = (merkle_blob_t *)ptr;
        if (_find_blob_index(tree, blob) < 0)
        {
            data_t *new_val = object_ptr_data(blob, sizeof(merkle_blob_t));
            if (new_val != NULL)
            {
                array_append(tree->blobs, new_val);
                added++;
            }
        }
    }
    if (added > 0)
        _rehash(tree);
    return 0;
}

/* Frama-C: skipped — [solver-timeout] memcpy separation precondition */
int merkle_root_digest(merkle_tree_t *tree, uint8_t *digest_out)
{
    if (tree == NULL || digest_out == NULL)
        return EINVAL;
    if (!tree->has_root_digest)
        return EXCEPTION(EMRKL_NOTFOUND);
    memcpy(digest_out, tree->root_digest, MERKLE_DIGEST_LEN);
    return 0;
}

/* Frama-C: skipped — [recursive-ds] unbounded tree traversal */
int merkle_inclusion_proof(merkle_tree_t *tree, merkle_blob_t *blob,
                           merkle_proof_step_t **proof_out, int *proof_len)
{
    if (tree == NULL || blob == NULL || proof_out == NULL || proof_len == NULL)
        return EINVAL;

    /* find the leaf node for this blob */
    int leaf_idx = -1;
    for (int i = 0; i < tree->node_count; i++)
    {
        if (tree->nodes[i].blob == blob)
        {
            leaf_idx = i;
            break;
        }
    }
    if (leaf_idx < 0)
        return EXCEPTION(EMRKL_NOTFOUND);

    /* walk from leaf to root, collecting sibling digests */
    int depth = 0;
    int tmp = leaf_idx;
    while (tmp != tree->root && tree->nodes[tmp].parent >= 0)
    {
        depth++;
        tmp = tree->nodes[tmp].parent;
    }

    merkle_proof_step_t *proof = malloc(sizeof(merkle_proof_step_t) * depth);
    if (proof == NULL)
        return ENOMEM;

    int step = 0;
    int current = leaf_idx;
    while (current != tree->root && tree->nodes[current].parent >= 0)
    {
        int parent = tree->nodes[current].parent;
        proof[step].has_left = false;
        proof[step].has_right = false;
        memset(proof[step].left, 0, MERKLE_DIGEST_LEN);
        memset(proof[step].right, 0, MERKLE_DIGEST_LEN);

        int left = tree->nodes[parent].left;
        int right = tree->nodes[parent].right;

        if (left >= 0 && right >= 0)
        {
            if (current == left)
            {
                proof[step].has_right = true;
                memcpy(proof[step].right, tree->nodes[right].digest, MERKLE_DIGEST_LEN);
            }
            else
            {
                proof[step].has_left = true;
                memcpy(proof[step].left, tree->nodes[left].digest, MERKLE_DIGEST_LEN);
            }
        }
        /* else: single child, both false (rehash step) */

        step++;
        current = parent;
    }

    *proof_out = proof;
    *proof_len = step;
    return 0;
}

/* Frama-C: skipped — [recursive-ds] unbounded tree traversal */
bool merkle_audit(merkle_tree_t *tree, merkle_blob_t *blob,
                  merkle_proof_step_t *proof, int proof_len)
{
    if (tree == NULL || blob == NULL || proof == NULL || proof_len <= 0)
        return false;
    if (!tree->has_root_digest)
        return false;

    uint8_t digest[MERKLE_DIGEST_LEN];
    if (blob->get_hash != NULL)
        blob->get_hash(blob, NULL, 0, digest);
    else
        return false;

    for (int i = 0; i < proof_len; i++)
    {
        if (!proof[i].has_left && !proof[i].has_right)
        {
            /* single-child: just rehash */
            merkle_hash(digest, MERKLE_DIGEST_LEN, digest);
        }
        else if (!proof[i].has_left)
        {
            /* we are the left child */
            uint8_t combined[MERKLE_DIGEST_LEN * 2];
            memcpy(combined, digest, MERKLE_DIGEST_LEN);
            memcpy(combined + MERKLE_DIGEST_LEN, proof[i].right, MERKLE_DIGEST_LEN);
            merkle_hash(combined, MERKLE_DIGEST_LEN * 2, digest);
        }
        else
        {
            /* we are the right child */
            uint8_t combined[MERKLE_DIGEST_LEN * 2];
            memcpy(combined, proof[i].left, MERKLE_DIGEST_LEN);
            memcpy(combined + MERKLE_DIGEST_LEN, digest, MERKLE_DIGEST_LEN);
            merkle_hash(combined, MERKLE_DIGEST_LEN * 2, digest);
        }
    }

    return memcmp(digest, tree->root_digest, MERKLE_DIGEST_LEN) == 0;
}

/* Frama-C: skipped — [solver-timeout] memcmp danglingness preconditions */
bool merkle_consistent(merkle_tree_t *tree, int other_size,
                       const uint8_t *other_root_digest)
{
    if (tree == NULL || other_root_digest == NULL)
        return false;
    if ((int)array_size(tree->blobs) != other_size)
        return false;
    if (!tree->has_root_digest)
        return false;
    return memcmp(tree->root_digest, other_root_digest, MERKLE_DIGEST_LEN) == 0;
}

/* Frama-C: skipped — [solver-timeout] array_free preconditions */
void merkle_tree_free(merkle_tree_t *tree)
{
    if (tree == NULL)
        return;
    if (tree->nodes != NULL)
        free(tree->nodes);
    if (tree->blobs != NULL)
        array_free(tree->blobs);
    free(tree);
}
