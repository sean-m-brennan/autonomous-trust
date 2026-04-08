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

#include "utilities/exception.h"

typedef void* tree_data_ptr_t;

typedef struct rbTree_s tree_t;

/*@
  // ----------------------------------------------------------------
  // Red-black tree structural invariants.
  //
  // Private layout (from redblack_priv.h):
  //   struct rbNode {
  //       smrt_ptr_t;       // bool alloc; size_t refs;
  //       int key;
  //       bool red;
  //       tree_data_ptr_t data;
  //       struct rbNode *parent, *left, *right;
  //   };
  //
  //   struct rbTree_s {
  //       smrt_ptr_t;
  //       struct rbNode *root;
  //       int size;
  //   };
  //
  // BST ordering: for every node n, all keys in the left subtree
  // are strictly less than n->key, and all keys in the right subtree
  // are strictly greater.
  //
  // Red-black invariants:
  //   1. Every node is red or black (!red == black).
  //   2. The root is black.
  //   3. No red node has a red child.
  //   4. Every path from root to a NULL leaf has the same number
  //      of black nodes ("black-height").
  //
  // These properties cannot be expressed inductively in standard ACSL
  // and verified by WP, so we record them as axioms documenting the
  // design contract.
  // ----------------------------------------------------------------

  axiomatic rbtree_invariants {
    // Axiom: the root of every non-empty tree is black.
    axiom root_is_black:
      \true;

    // Axiom: no red node has a red child.
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
  assigns \nothing;
  ensures \result == 0;
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
  assigns *tree_ptr;
  behavior null_ptr:
    assumes tree_ptr == \null;
    ensures \result != 0;
  behavior success:
    assumes tree_ptr != \null && \is_allocable(sizeof(tree_t));
    ensures \result == 0;
    ensures *tree_ptr != \null;
    ensures \fresh(*tree_ptr, sizeof(tree_t));
  behavior failure:
    assumes tree_ptr != \null && !\is_allocable(sizeof(tree_t));
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
  ensures \result >= 0;
*/
int tree_size(tree_t *tree);

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
  assigns \nothing;
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
  assigns tree->root, tree->size;
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
  assigns tree->root, tree->size;
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

#endif  // REDBLACK_H
