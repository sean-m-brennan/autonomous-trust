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

/* TODO (divergence.md L4 follow-up): this is a status snapshot, NOT a
 * round-trip serializer — there is no `merkle_from_json` counterpart.
 * Python's `Merkle.to_dict()` round-trips because the blob payloads are
 * self-typed Python objects (`json.dumps` falls back to their `__repr__`
 * / dict). On the C side, blob content is opaque to the tree (the
 * application supplies `blob_designation_fn` to hash payload bytes), so
 * reconstructing a tree from a JSON dump would need a caller-typed blob
 * deserializer. The supported checkpoint pattern is "save the blob list,
 * reinsert on restore"; add `merkle_from_json` only if a generic
 * blob-payload encoding becomes available. */
/* Frama-C: skipped — [alloc-pattern] jansson allocations */
json_t *merkle_to_json(const merkle_tree_t *tree)
{
    if (tree == NULL) return NULL;
    json_t *out = json_object();
    if (out == NULL) return NULL;

    if (tree->has_root_digest) {
        char hex[MERKLE_DIGEST_LEN * 2 + 1];
        for (int i = 0; i < MERKLE_DIGEST_LEN; i++)
            snprintf(&hex[i * 2], 3, "%02x", tree->root_digest[i]);
        hex[MERKLE_DIGEST_LEN * 2] = '\0';
        json_object_set_new(out, "root_digest", json_string(hex));
    } else {
        json_object_set_new(out, "root_digest", json_null());
    }
    size_t blob_count = (tree->blobs != NULL) ? array_size(tree->blobs) : 0;
    json_object_set_new(out, "blob_count", json_integer((json_int_t)blob_count));
    json_object_set_new(out, "node_count", json_integer((json_int_t)tree->node_count));
    return out;
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

    if (depth <= 0)
    {
        /* leaf IS root; empty proof */
        *proof_out = NULL;
        *proof_len = 0;
        return 0;
    }
    size_t bytes;
    if (__builtin_mul_overflow((size_t)depth, sizeof(merkle_proof_step_t), &bytes))
        return ENOMEM;
    merkle_proof_step_t *proof = malloc(bytes);
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

/* Forward declaration; definition lives after merkle_audit since it
 * is also used by merkle_audit_chain. */
static void _merkle_walk_proof(uint8_t *digest,
                               const merkle_proof_step_t *proof, int n);

/* Frama-C: skipped — [recursive-ds] unbounded tree traversal */
bool merkle_audit(merkle_tree_t *tree, merkle_blob_t *blob,
                  merkle_proof_step_t *proof, int proof_len)
{
    if (tree == NULL || blob == NULL || proof == NULL || proof_len <= 0)
        return false;
    if (!tree->has_root_digest)
        return false;
    if (blob->get_hash == NULL)
        return false;

    uint8_t digest[MERKLE_DIGEST_LEN];
    blob->get_hash(blob, NULL, 0, digest);
    _merkle_walk_proof(digest, proof, proof_len);

    return memcmp(digest, tree->root_digest, MERKLE_DIGEST_LEN) == 0;
}

/* Membership check by uuid match. Walks the blob list — small in
 * practice. Mirrors Python's MerkleTree.__contains__ (merkle.py:249).
 * Hash-correctness is *not* verified here; for that, build an inclusion
 * proof and audit it. */
bool merkle_contains(const merkle_tree_t *tree, const merkle_blob_t *blob)
{
    if (tree == NULL || blob == NULL || tree->blobs == NULL)
        return false;
    size_t n = array_size(tree->blobs);
    for (size_t i = 0; i < n; i++) {
        data_t *dat = NULL;
        if (array_get(tree->blobs, (int)i, &dat) != 0 || dat == NULL)
            continue;
        ptr_t ptr = NULL;
        if (data_object_ptr(dat, &ptr) != 0 || ptr == NULL)
            continue;
        const merkle_blob_t *b = (const merkle_blob_t *)ptr;
        if (strncmp(b->uuid, blob->uuid, MERKLE_UUID_LEN) == 0)
            return true;
    }
    return false;
}

/* Internal helper shared by merkle_audit and merkle_audit_chain. Walks
 * a single proof segment, accumulating @p digest in place. */
static void _merkle_walk_proof(uint8_t *digest,
                               const merkle_proof_step_t *proof, int n)
{
    for (int i = 0; i < n; i++)
    {
        if (!proof[i].has_left && !proof[i].has_right)
        {
            /* single-child: just rehash (matches merkle_audit) */
            merkle_hash(digest, MERKLE_DIGEST_LEN, digest);
        }
        else if (!proof[i].has_left)
        {
            /* we are the left child */
            uint8_t combined[MERKLE_DIGEST_LEN * 2];
            memcpy(combined, digest, MERKLE_DIGEST_LEN);
            memcpy(combined + MERKLE_DIGEST_LEN, proof[i].right,
                   MERKLE_DIGEST_LEN);
            merkle_hash(combined, MERKLE_DIGEST_LEN * 2, digest);
        }
        else
        {
            /* we are the right child */
            uint8_t combined[MERKLE_DIGEST_LEN * 2];
            memcpy(combined, proof[i].left, MERKLE_DIGEST_LEN);
            memcpy(combined + MERKLE_DIGEST_LEN, digest,
                   MERKLE_DIGEST_LEN);
            merkle_hash(combined, MERKLE_DIGEST_LEN * 2, digest);
        }
    }
}

/* H12: chain-extended audit. */
bool merkle_audit_chain(merkle_tree_t *tree, merkle_blob_t *blob,
                        merkle_proof_step_t *proof, int proof_n,
                        merkle_proof_step_t *extra_chain, int extra_n,
                        const uint8_t *super_hash)
{
    if (tree == NULL || blob == NULL || super_hash == NULL)
        return false;
    if (proof == NULL && proof_n != 0)
        return false;
    if (extra_chain == NULL && extra_n != 0)
        return false;
    if (blob->get_hash == NULL)
        return false;

    uint8_t digest[MERKLE_DIGEST_LEN];
    blob->get_hash(blob, NULL, 0, digest);

    if (proof_n > 0)
        _merkle_walk_proof(digest, proof, proof_n);
    if (extra_n > 0)
        _merkle_walk_proof(digest, extra_chain, extra_n);

    return memcmp(digest, super_hash, MERKLE_DIGEST_LEN) == 0;
}

/* Helper: a "CVE-protection lift" is when a single-child parent inherits
 * its lone child's digest verbatim (merkle.c:223-226). The parent-child
 * pair will share a digest but does not represent a duplicate subtree
 * in the data-collision sense. Distinguishing this from a genuine
 * duplicate keeps merkle_subtree_duplications useful — without the
 * filter, every tree built from an odd-leaf-count level emits spurious
 * dup-pairs. */
static bool _is_lone_child_lift(const merkle_tree_t *tree, int a, int b)
{
    /* Treat "a" as candidate parent of "b" first. */
    if (tree->nodes[b].parent == a)
    {
        const merkle_node_t *p = &tree->nodes[a];
        if ((p->left == b && p->right == -1) ||
            (p->right == b && p->left == -1))
            return true;
    }
    if (tree->nodes[a].parent == b)
    {
        const merkle_node_t *p = &tree->nodes[b];
        if ((p->left == a && p->right == -1) ||
            (p->right == a && p->left == -1))
            return true;
    }
    return false;
}

/* H11: find subtrees with genuine duplicate digests. O(n²) pairwise
 * scan, excluding parent-child digest lifts inherent to CVE-2012-2459
 * protection. */
int merkle_subtree_duplications(merkle_tree_t *tree,
                                int **idx_out, size_t *count_out)
{
    if (tree == NULL || idx_out == NULL || count_out == NULL)
        return EINVAL;

    *idx_out = NULL;
    *count_out = 0;

    if (tree->node_count <= 1)
        return 0;

    int *out = malloc(sizeof(int) * (size_t)tree->node_count);
    if (out == NULL)
        return ENOMEM;
    size_t out_n = 0;

    for (int i = 0; i < tree->node_count; i++)
    {
        bool dup = false;
        for (int j = 0; j < tree->node_count; j++)
        {
            if (i == j)
                continue;
            if (memcmp(tree->nodes[i].digest, tree->nodes[j].digest,
                       MERKLE_DIGEST_LEN) != 0)
                continue;
            if (_is_lone_child_lift(tree, i, j))
                continue;
            dup = true;
            break;
        }
        if (dup)
            out[out_n++] = i;
    }

    if (out_n == 0)
    {
        free(out);
        return 0;
    }
    *idx_out = out;
    *count_out = out_n;
    return 0;
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
