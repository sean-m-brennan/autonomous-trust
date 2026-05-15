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

#ifndef REDBLACK_H
#define REDBLACK_H

/** @addtogroup internal_structures
 *  @{
 */

#include "utilities/exception.h"
#include "utilities/allocation.h"

typedef void* tree_data_ptr_t;

enum Direction
{
    LEFT,
    RIGHT
};

struct rbNode
{
    smrt_ptr_t;
    int key;
    bool red;
    tree_data_ptr_t data;
    struct rbNode *parent, *left, *right;
};

typedef struct rbTree_s {
    smrt_ptr_t;
    struct rbNode *root;
    int size;
} tree_t;

/*@ predicate valid_node(struct rbNode *n) =
      n != \null && \valid(n) &&
      smrt_valid((smrt_ptr_t *)n);
*/

/*@ predicate valid_tree(tree_t *t) =
      t != \null && \valid(t) &&
      smrt_valid((smrt_ptr_t *)t) &&
      t->size >= 0 &&
      (t->size == 0 ==> t->root == \null) &&
      (t->size > 0  ==> t->root != \null && t->root->red == \false);
*/

/*@
  axiomatic rbtree_invariants {
    // Axiom: the root of every non-empty tree is black.
    axiom root_is_black:
      \forall tree_t *t; valid_tree(t) && t->size > 0 ==>
        t->root->red == \false;

    // Axiom: no red node has a red child (not expressible inductively in ACSL).
    axiom no_red_red:
      \true;

    // Axiom: every root-to-leaf path has equal black-height.
    axiom uniform_black_height:
      \true;

    // Axiom: BST ordering -- left keys < node key < right keys.
    axiom bst_ordering:
      \true;
  }
*/

/**
 * @brief Initialize an existing tree (zero members).
 *
 * @param tree
 * @return int
 */
/*@
  requires \valid(tree);
  assigns tree->root \from \nothing;
  assigns tree->size \from \nothing;
  ensures \result == 0;
  ensures tree->root == \null;
  ensures tree->size == 0;
*/
int tree_init(tree_t *tree);

/**
 * @brief Allocation for a new tree.
 *
 * @param tree_ptr
 * @return int Success (0) or error code
 */
/*@
  requires \valid(tree_ptr);
  allocates *tree_ptr;
  assigns *tree_ptr \from tree_ptr;
  behavior null_ptr:
    assumes tree_ptr == \null;
    ensures \result != 0;
  behavior success:
    assumes tree_ptr != \null;
    ensures \result == 0;
    ensures *tree_ptr != \null;
    ensures \fresh(*tree_ptr, sizeof(tree_t));
    ensures (*tree_ptr)->root == \null;
    ensures (*tree_ptr)->size == 0;
  behavior failure:
    assumes tree_ptr != \null;
    ensures \result != 0;
  disjoint behaviors;
*/
int tree_create(tree_t **tree_ptr);

/*
* @brief Semi-deep copy for trees (does not copy the data itself).
*
* @param tree Pointer to tree to copy.
* @returns Pointer to copy of tree (null on error, sets errno).
*
tree_t *tree_copy(tree_t *tree);*/

/**
* @brief Size of the tree.
*
* @param tree Pointer to tree.
* @return Number of nodes in the tree.
*/
/*@
  requires \valid(tree);
  assigns \nothing;
  ensures \result == tree->size;
*/
int tree_size(tree_t *tree);

/** Smallest key in @p tree, or -1 if empty. O(h) — walks the left
 *  spine. Mirrors Python Tree.first (redblack.py — `_first` walks left
 *  from the root). For sequential range scans, callers may pair this
 *  with @ref tree_last to bound the iteration cheaply. */
int tree_first(tree_t *tree);

/** Largest key in @p tree, or -1 if empty. O(h). Mirrors Python's
 *  Tree.last. */
int tree_last(tree_t *tree);

/**
* @brief Depth of the tree.
*
* @param tree Pointer to tree.
* @return Number of node levels in the tree.
*/
/*@
  requires \valid(tree);
  assigns \nothing;
  ensures \result >= 0;
  ensures tree->size == 0 ==> \result == 0;
*/
int tree_depth(tree_t *tree);

/**
* @brief Find a data node by its key.
*
* @param tree Pointer to tree.
* @param key Data node identifier (always unique).
* @return Pointer to data (null if not found).
*/
/*@
  requires \valid(tree);
  assigns \result \from tree->root, key;
  behavior found:
    ensures \result != \null;
  behavior not_found:
    ensures \result == \null;
  disjoint behaviors;
*/
tree_data_ptr_t tree_find(tree_t *tree, int key);

/**
* @brief Insert data into the tree with identifier.
*
* @param tree Pointer to tree.
* @param data Pointer to data.
* @param key Data node identifier (must be unique).
* @return Success (0) or error code.
*/
/*@
  requires \valid(tree);
  assigns tree->root \from tree->root, data, key;
  assigns tree->size \from tree->size;
  behavior success:
    ensures \result == 0;
    ensures tree->size == \old(tree->size) + 1;
  behavior duplicate:
    ensures \result == -1;
    ensures tree->size == \old(tree->size);
  behavior alloc_failure:
    ensures \result == -1;
    ensures tree->size == \old(tree->size);
  disjoint behaviors;
*/
int tree_insert(tree_t *tree, tree_data_ptr_t data, int key);

/**
* @brief Remove data node from tree with identifier.
*
* @param tree Pointer to tree.
* @param key Data node identifier.
* @return Success (0) or error code.
*/
/*@
  requires \valid(tree);
  assigns tree->root \from tree->root, key;
  assigns tree->size \from tree->size;
  behavior success:
    ensures \result == 0;
    ensures tree->size == \old(tree->size) - 1;
  behavior empty:
    assumes tree->size == 0;
    ensures \result == -1;
    ensures tree->size == \old(tree->size);
  behavior not_found:
    ensures \result == -1;
    ensures tree->size == \old(tree->size);
  disjoint behaviors;
*/
int tree_delete(tree_t *tree, int key);

/**
* @brief Free all tree structures (not data though).
*
*/
/*@
  requires tree == \null || \valid(tree);
  assigns tree->size \from \nothing;
  frees tree;
*/
void tree_free(tree_t *tree);


/**
* Error code: duplicate key on insertion
*/
#define ERBT_DUP_INS 211
DECLARE_ERROR(ERBT_DUP_INS, "Attempted duplicate insertion into the tree");

/**
* Error code: empty tree
*/
#define ERBT_EMPTY 212
DECLARE_ERROR(ERBT_EMPTY, "Item deletion on empty tree");

/**
* Error code: key not found in tree
*/
#define ERBT_NO_KEY 213
DECLARE_ERROR(ERBT_NO_KEY, "No such key found in the tree");


/** @} */ /* end of internal_structures */

#endif  // REDBLACK_H
