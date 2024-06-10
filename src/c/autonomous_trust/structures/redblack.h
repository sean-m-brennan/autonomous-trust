#ifndef REDBLACK_H
#define REDBLACK_H

#include "utilities/exception.h"

typedef void* tree_data_ptr_t;

typedef struct rbTree_s tree_t;

/**
 * @brief 
 * 
 * @param tree 
 * @return int 
 */
int tree_init(tree_t *tree);

/**
 * @brief Allocation for a new tree.
 *
 * @param tree 
 * @return int Success (0) or error code
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
int tree_size(tree_t *tree);

/**
* @brief Depth of the tree.
*
* @param tree Pointer to tree.
* @return Number of node levels in the tree.
*/
int tree_depth(tree_t *tree);

/**
* @brief Find a data node by its key.
*
* @param tree Pointer to tree.
* @param key Data node identifier (always unique).
* @return Pointer to data (null if not found).
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
int tree_insert(tree_t *tree, tree_data_ptr_t data, int key);

/**
* @brief Remove data node from tree with identifier.
*
* @param tree Pointer to tree.
* @param key Data node identifier.
* @return Success (0) or error code.
*/
int tree_delete(tree_t *tree, int key);

/**
* @brief Free all tree structures (not data though).
*
*/
void tree_free(tree_t *tree);


/**
* Error code: duplicate key on insertion
*/
#define ERBT_DUP_INS 140

DECLARE_ERROR(ERBT_DUP_INS, "Attempted duplicate insertion into the tree");

/**
* Error code: empty tree
*/
#define ERBT_EMPTY 141

DECLARE_ERROR(ERBT_EMPTY, "Item deletion on empty tree");

/**
* Error code: key not found in tree
*/
#define ERBT_NO_KEY 142

DECLARE_ERROR(ERBT_NO_KEY, "No such key found in the tree");

#endif  // REDBLACK_H
