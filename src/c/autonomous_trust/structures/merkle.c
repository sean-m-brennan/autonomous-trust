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

#include "merkle.h"
#include "array.h"

DEFINE_ERROR(EMRK_DUP, "Duplicate blob insertion in Merkle tree");
DEFINE_ERROR(EMRK_NOTFOUND, "Blob not found in Merkle tree");

/***************************
 * Internal node structure
 ***************************/

struct merkleNode
{
    uint8_t digest[MERKLE_HASH_LEN];
    merkle_blob_t *blob;    /**< Non-NULL only for leaf nodes */
    uuid_t uuid;
    struct merkleNode *left;
    struct merkleNode *right;
    struct merkleNode *parent;
};

struct merkleTree
{
    smrt_ptr_t;
    merkle_node_t *root;
    merkle_blob_t **blobs;
    size_t blob_count;
    size_t blob_capacity;
    uint8_t super_hash[MERKLE_HASH_LEN];
    bool has_super_hash;
};

/***************************
 * Hashing
 ***************************/

int merkle_hash(const uint8_t *input, size_t input_len,
                uint8_t output[MERKLE_HASH_LEN])
{
    if (crypto_generichash_blake2b(output, MERKLE_HASH_LEN,
                                   input, input_len, NULL, 0) != 0)
        return -1;
    return 0;
}

int merkle_blob_hash(const merkle_blob_t *blob, const uint8_t *nonce, size_t nonce_len,
                     uint8_t output[MERKLE_HASH_LEN])
{
    if (blob == NULL || blob->designation == NULL)
        return EXCEPTION(EINVAL);

    size_t desig_len = 0;
    const uint8_t *desig = blob->designation(blob->user_data, &desig_len);
    if (desig == NULL || desig_len == 0)
        return EXCEPTION(EINVAL);

    size_t total = desig_len + nonce_len;
    uint8_t *combined = malloc(total);
    if (combined == NULL)
        return SYS_EXCEPTION();

    memcpy(combined, desig, desig_len);
    if (nonce_len > 0 && nonce != NULL)
        memcpy(combined + desig_len, nonce, nonce_len);

    int ret = merkle_hash(combined, total, output);
    free(combined);
    return ret;
}

/***************************
 * Node management
 ***************************/

static merkle_node_t *node_create(void)
{
    merkle_node_t *n = calloc(1, sizeof(merkle_node_t));
    return n;
}

static void node_free_tree(merkle_node_t *node)
{
    if (node == NULL)
        return;
    node_free_tree(node->left);
    node_free_tree(node->right);
    free(node);
}

/***************************
 * Tree build from blob list
 ***************************/

/**
 * Build a balanced binary tree from leaf nodes.
 * Leaves are positioned at the bottom; inner nodes hash children.
 * CVE-2012-2459 mitigation: if one child is missing, copy sibling digest.
 */
static merkle_node_t *build_tree_level(merkle_node_t **nodes, size_t count)
{
    if (count == 0)
        return NULL;
    if (count == 1)
        return nodes[0];

    size_t parent_count = (count + 1) / 2;
    merkle_node_t **parents = calloc(parent_count, sizeof(merkle_node_t *));
    if (parents == NULL)
        return NULL;

    for (size_t i = 0; i < parent_count; i++)
    {
        merkle_node_t *p = node_create();
        if (p == NULL)
        {
            free(parents);
            return NULL;
        }

        size_t li = i * 2;
        size_t ri = li + 1;

        p->left = nodes[li];
        nodes[li]->parent = p;

        if (ri < count)
        {
            p->right = nodes[ri];
            nodes[ri]->parent = p;
            /* Hash: left.digest + right.digest */
            uint8_t combined[MERKLE_HASH_LEN * 2];
            memcpy(combined, p->left->digest, MERKLE_HASH_LEN);
            memcpy(combined + MERKLE_HASH_LEN, p->right->digest, MERKLE_HASH_LEN);
            merkle_hash(combined, sizeof(combined), p->digest);
        }
        else
        {
            /* Odd child: hash left with itself (consistent with proof verification) */
            p->right = NULL;
            uint8_t combined[MERKLE_HASH_LEN * 2];
            memcpy(combined, p->left->digest, MERKLE_HASH_LEN);
            memcpy(combined + MERKLE_HASH_LEN, p->left->digest, MERKLE_HASH_LEN);
            merkle_hash(combined, sizeof(combined), p->digest);
        }

        parents[i] = p;
    }

    merkle_node_t *result = build_tree_level(parents, parent_count);
    free(parents);
    return result;
}

static int rehash(merkle_tree_t *tree)
{
    /* Free old tree structure (not blobs) */
    node_free_tree(tree->root);
    tree->root = NULL;

    if (tree->blob_count == 0)
        return 0;

    /* Create leaf nodes */
    merkle_node_t **leaves = calloc(tree->blob_count, sizeof(merkle_node_t *));
    if (leaves == NULL)
        return SYS_EXCEPTION();

    for (size_t i = 0; i < tree->blob_count; i++)
    {
        leaves[i] = node_create();
        if (leaves[i] == NULL)
        {
            for (size_t j = 0; j < i; j++)
                free(leaves[j]);
            free(leaves);
            return SYS_EXCEPTION();
        }
        leaves[i]->blob = tree->blobs[i];
        memcpy(leaves[i]->uuid, tree->blobs[i]->uuid, sizeof(uuid_t));
        merkle_blob_hash(tree->blobs[i], NULL, 0, leaves[i]->digest);
    }

    tree->root = build_tree_level(leaves, tree->blob_count);
    free(leaves);

    if (tree->root == NULL && tree->blob_count > 0)
        return -1;

    return 0;
}

/***************************
 * Public API
 ***************************/

int merkle_tree_create(merkle_tree_t **tree_ptr)
{
    if (tree_ptr == NULL)
        return EXCEPTION(EINVAL);

    merkle_tree_t *tree = smrt_create(sizeof(merkle_tree_t));
    if (tree == NULL)
        return SYS_EXCEPTION();

    tree->root = NULL;
    tree->blobs = NULL;
    tree->blob_count = 0;
    tree->blob_capacity = 0;
    tree->has_super_hash = false;

    *tree_ptr = tree;
    return 0;
}

static int find_blob_index(const merkle_tree_t *tree, const merkle_blob_t *blob)
{
    for (size_t i = 0; i < tree->blob_count; i++)
    {
        if (uuid_compare(tree->blobs[i]->uuid, blob->uuid) == 0)
            return (int)i;
    }
    return -1;
}

int merkle_tree_insert(merkle_tree_t *tree, merkle_blob_t *blob)
{
    if (tree == NULL || blob == NULL)
        return EXCEPTION(EINVAL);

    /* Check for duplicate */
    if (find_blob_index(tree, blob) >= 0)
        return EXCEPTION(EMRK_DUP);

    /* Grow capacity if needed */
    if (tree->blob_count >= tree->blob_capacity)
    {
        size_t new_cap = (tree->blob_capacity == 0) ? 8 : tree->blob_capacity * 2;
        merkle_blob_t **new_blobs = realloc(tree->blobs, new_cap * sizeof(merkle_blob_t *));
        if (new_blobs == NULL)
            return SYS_EXCEPTION();
        tree->blobs = new_blobs;
        tree->blob_capacity = new_cap;
    }

    tree->blobs[tree->blob_count++] = blob;
    return rehash(tree);
}

int merkle_tree_delete(merkle_tree_t *tree, const merkle_blob_t *blob)
{
    if (tree == NULL || blob == NULL)
        return EXCEPTION(EINVAL);

    int idx = find_blob_index(tree, blob);
    if (idx < 0)
        return EXCEPTION(EMRK_NOTFOUND);

    /* Shift remaining blobs */
    for (size_t i = (size_t)idx; i < tree->blob_count - 1; i++)
        tree->blobs[i] = tree->blobs[i + 1];
    tree->blob_count--;

    return rehash(tree);
}

int merkle_tree_merge(merkle_tree_t *tree, merkle_tree_t *other)
{
    if (tree == NULL || other == NULL)
        return EXCEPTION(EINVAL);

    bool changed = false;
    for (size_t i = 0; i < other->blob_count; i++)
    {
        if (find_blob_index(tree, other->blobs[i]) < 0)
        {
            if (tree->blob_count >= tree->blob_capacity)
            {
                size_t new_cap = (tree->blob_capacity == 0) ? 8 : tree->blob_capacity * 2;
                merkle_blob_t **new_blobs = realloc(tree->blobs, new_cap * sizeof(merkle_blob_t *));
                if (new_blobs == NULL)
                    return SYS_EXCEPTION();
                tree->blobs = new_blobs;
                tree->blob_capacity = new_cap;
            }
            tree->blobs[tree->blob_count++] = other->blobs[i];
            changed = true;
        }
    }

    if (changed)
        return rehash(tree);
    return 0;
}

const uint8_t *merkle_tree_root_digest(const merkle_tree_t *tree)
{
    if (tree == NULL || tree->root == NULL)
        return NULL;
    return tree->root->digest;
}

size_t merkle_tree_size(const merkle_tree_t *tree)
{
    if (tree == NULL)
        return 0;
    return tree->blob_count;
}

/***************************
 * Proofs
 ***************************/

static merkle_node_t *find_leaf(merkle_node_t *node, const uuid_t uuid)
{
    if (node == NULL)
        return NULL;
    if (node->blob != NULL && uuid_compare(node->uuid, uuid) == 0)
        return node;
    merkle_node_t *found = find_leaf(node->left, uuid);
    if (found != NULL)
        return found;
    return find_leaf(node->right, uuid);
}

int merkle_inclusion_proof(const merkle_tree_t *tree, const merkle_blob_t *blob,
                           merkle_proof_t *proof)
{
    if (tree == NULL || blob == NULL || proof == NULL)
        return EXCEPTION(EINVAL);

    proof->steps = NULL;
    proof->count = 0;

    merkle_node_t *leaf = find_leaf(tree->root, blob->uuid);
    if (leaf == NULL)
        return EXCEPTION(EMRK_NOTFOUND);

    /* Count depth */
    size_t depth = 0;
    merkle_node_t *n = leaf;
    while (n->parent != NULL)
    {
        depth++;
        n = n->parent;
    }

    if (depth == 0)
    {
        proof->steps = NULL;
        proof->count = 0;
        return 0;
    }

    proof->steps = calloc(depth, sizeof(merkle_proof_step_t));
    if (proof->steps == NULL)
        return SYS_EXCEPTION();
    proof->count = depth;

    n = leaf;
    for (size_t i = 0; i < depth; i++)
    {
        merkle_node_t *p = n->parent;
        if (p->left == n)
        {
            proof->steps[i].is_left = false;
            if (p->right != NULL)
                memcpy(proof->steps[i].sibling_digest, p->right->digest, MERKLE_HASH_LEN);
            else
                memcpy(proof->steps[i].sibling_digest, n->digest, MERKLE_HASH_LEN);
        }
        else
        {
            proof->steps[i].is_left = true;
            memcpy(proof->steps[i].sibling_digest, p->left->digest, MERKLE_HASH_LEN);
        }
        n = p;
    }

    return 0;
}

bool merkle_audit(const uint8_t root_digest[MERKLE_HASH_LEN],
                  const merkle_blob_t *blob, const merkle_proof_t *proof)
{
    if (root_digest == NULL || blob == NULL || proof == NULL)
        return false;

    uint8_t current[MERKLE_HASH_LEN];
    merkle_blob_hash(blob, NULL, 0, current);

    for (size_t i = 0; i < proof->count; i++)
    {
        uint8_t combined[MERKLE_HASH_LEN * 2];
        if (proof->steps[i].is_left)
        {
            memcpy(combined, proof->steps[i].sibling_digest, MERKLE_HASH_LEN);
            memcpy(combined + MERKLE_HASH_LEN, current, MERKLE_HASH_LEN);
        }
        else
        {
            memcpy(combined, current, MERKLE_HASH_LEN);
            memcpy(combined + MERKLE_HASH_LEN, proof->steps[i].sibling_digest, MERKLE_HASH_LEN);
        }
        merkle_hash(combined, sizeof(combined), current);
    }

    return memcmp(current, root_digest, MERKLE_HASH_LEN) == 0;
}

bool merkle_tree_contains(const merkle_tree_t *tree, const merkle_blob_t *blob)
{
    if (tree == NULL || blob == NULL)
        return false;

    merkle_proof_t proof = {0};
    if (merkle_inclusion_proof(tree, blob, &proof) != 0)
        return false;

    const uint8_t *root = merkle_tree_root_digest(tree);
    if (root == NULL)
    {
        merkle_proof_free(&proof);
        return false;
    }

    bool result = merkle_audit(root, blob, &proof);
    merkle_proof_free(&proof);
    return result;
}

void merkle_proof_free(merkle_proof_t *proof)
{
    if (proof == NULL)
        return;
    free(proof->steps);
    proof->steps = NULL;
    proof->count = 0;
}

void merkle_tree_free(merkle_tree_t *tree)
{
    if (tree == NULL)
        return;
    node_free_tree(tree->root);
    free(tree->blobs);
    smrt_deref(tree);
}
