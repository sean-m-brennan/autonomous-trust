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
#include <stdbool.h>
#include <errno.h>

#include <jansson.h>

#include "redblack_priv.h"
#include "array_priv.h"

/*@
  requires dir == LEFT || dir == RIGHT;
  assigns \nothing;
  ensures dir == LEFT ==> \result == RIGHT;
  ensures dir == RIGHT ==> \result == LEFT;
*/
enum Direction opposite_direction(enum Direction dir)
{
    return (enum Direction)(dir + 1) % 2;
}

/**********************/
// Red/Black node in tree (private)

/*@
  requires \valid(node_ptr);
  allocates *node_ptr;
  assigns *node_ptr \from data, key;
  behavior success:
    ensures \result == 0;
    ensures *node_ptr != \null;
    ensures (*node_ptr)->key == key;
    ensures (*node_ptr)->data == data;
    ensures (*node_ptr)->red == true;
    ensures (*node_ptr)->left == \null;
    ensures (*node_ptr)->right == \null;
    ensures (*node_ptr)->parent == \null;
  behavior failure:
    ensures \result != 0;
  disjoint behaviors;
*/
/* Frama-C: skipped — [solver-timeout] smrt_ptr allocation postconditions */
int createNode(tree_data_ptr_t data, int key, struct rbNode **node_ptr)
{
    *node_ptr = smrt_create(sizeof(struct rbNode));
    struct rbNode *node = *node_ptr;
    if (node == NULL)
        return EXCEPTION(ENOMEM);
    node->data = data;
    node->key = key;
    node->red = true;
    node->parent = node->left = node->right = NULL;
    //@ assert node->key == key && node->red == true;
    return 0;
}

/*@
  requires \valid(child);
  assigns *child \from orig, parent;
*/
/* Frama-C: skipped — [recursive-ds] recursive BST copy */
int copyNodes(struct rbNode *orig, struct rbNode *parent, struct rbNode **child)
{
    if (orig == NULL)
        return EXCEPTION(EINVAL);
    struct rbNode *copy;
    int err = createNode(orig->data, orig->key, &copy);
    if (err != 0)
        return err;

    copy->red = orig->red;
    err = copyNodes(orig->left, copy, &copy->left);
    if (err != 0)
        return err;
    err = copyNodes(orig->right, copy, &copy->right);
    if (err != 0)
        return err;
    copy->parent = parent;
    return 0;
}

/*@
  requires \valid(tree);
  assigns \result \from tree->root, key;
  behavior found:
    ensures \result != \null;
    ensures \result->key == key;
  behavior not_found:
    ensures \result == \null;
  disjoint behaviors;
*/
/* Frama-C: skipped — [recursive-ds] recursive node search */
struct rbNode *findNode(tree_t *tree, int key)
{
    struct rbNode *current = tree->root;
    while (current != NULL)
    {
        if (key < current->key)
            current = current->left;
        else if (key > current->key)
            current = current->right;
        else
            return current;
    }
    return NULL;
}

/*@
  requires \valid(node);
  requires which == LEFT || which == RIGHT;
  assigns \result \from node->left, node->right, which;
  ensures which == LEFT ==> \result == node->left;
  ensures which == RIGHT ==> \result == node->right;
*/
struct rbNode *getNodeChild(struct rbNode *node, enum Direction which)
{
    if (which == LEFT)
        return node->left;
    return node->right;
};

/*@
  requires \valid(node);
  requires which == LEFT || which == RIGHT;
  assigns node->left \from which, child;
  assigns node->right \from which, child;
  ensures which == LEFT ==> node->left == child;
  ensures which == RIGHT ==> node->right == child;
*/
void setNodeChild(struct rbNode *node, enum Direction which, struct rbNode *child)
{
    if (which == LEFT)
        node->left = child;
    else
        node->right = child;
};

/*@
  requires \valid(node);
  requires node->parent == \null || \valid(node->parent);
  assigns \result \from node, node->parent;
  ensures node->parent == \null ==> \result == \null;
*/
struct rbNode *nodeSibling(struct rbNode *node)
{
    if (node->parent == NULL)
        return NULL;
    if (node == node->parent->left)
        return node->parent->right;
    return node->parent->left;
};

/*@
  requires \valid(node);
  assigns \nothing;
  ensures \result >= 0;
*/
int nodeDepth(struct rbNode *node)
{
    struct rbNode *cur = node->parent;
    int level = 0;
    while (cur != NULL)
    {
        level++;
        cur = cur->parent;
    }
    return level;
};

/*@
  requires \valid(node);
  assigns \nothing;
  ensures \result == (node->left == \null && node->right == \null);
*/
bool nodeIsLeaf(struct rbNode *node)
{
    return node->left == NULL && node->right == NULL;
};

/*@
  requires \valid(node);
  assigns \result \from node;
  ensures \result != \null;
*/
/* Frama-C: skipped — [recursive-ds] recursive minimum-leaf traversal */
struct rbNode *nodeMinLeaf(struct rbNode *node)
{
    struct rbNode *current = node;
    while (current->left != NULL)
        current = current->left;
    if (!nodeIsLeaf(current))
        current = nodeMinLeaf(current->right);
    return current;
}

/*@
  requires node == \null || \valid(node);
  assigns \nothing;
*/
/* Frama-C: skipped — [recursive-ds] recursive tree free */
void nodesFree(struct rbNode *node) {
    if (node == NULL)
        return;
    if (node->left != NULL)
        nodesFree(node->left);
    if (node->right != NULL)
        nodesFree(node->right);
    smrt_deref(node);
}


/**********************/
// private tree functions

/*@
  requires \valid(tree);
  requires \valid(node);
  requires dir == LEFT || dir == RIGHT;
  assigns tree->root \from tree->root, node, dir;
*/
/* Frama-C: skipped — [recursive-ds] BST rotation */
void rotateTree(tree_t *tree, enum Direction dir, struct rbNode *node)
{
    enum Direction direction = dir;
    enum Direction counter = opposite_direction(dir);
    struct rbNode *pivot = getNodeChild(node, counter);
    setNodeChild(node, counter, getNodeChild(pivot, direction));
    if (getNodeChild(pivot, direction) != NULL)
        getNodeChild(pivot, direction)->parent = node;

    pivot->parent = node->parent;
    if (node->parent == NULL)
        tree->root = pivot;
    else if (node == getNodeChild(node->parent, direction))
        setNodeChild(node->parent, direction, pivot);
    else
        setNodeChild(node->parent, counter, pivot);
    setNodeChild(pivot, direction, node);
    node->parent = pivot;
}

/*@
  requires \valid(tree);
  requires \valid(node);
  assigns tree->root \from tree->root, node;
*/
/* Frama-C: skipped — [recursive-ds] red-black recoloring after insert */
void recolorInsert(tree_t *tree, struct rbNode *node)
{
    while (node != tree->root && node->parent != NULL && node->parent->red)
    {
        struct rbNode *grandparent = node->parent->parent;
        if (grandparent == NULL)
            break;

        if (node->parent == grandparent->left)
        {
            struct rbNode *uncle = grandparent->right;
            if (uncle != NULL && uncle->red)
            {
                node->parent->red = false;
                uncle->red = false;
                grandparent->red = true;
                node = grandparent;
            }
            else
            {
                if (node == node->parent->right)
                {
                    node = node->parent;
                    rotateTree(tree, LEFT, node);
                }
                node->parent->red = false;
                node->parent->parent->red = true;
                rotateTree(tree, RIGHT, node->parent->parent);
            }
        }
        else
        {
            struct rbNode *uncle = grandparent->left;
            if (uncle != NULL && uncle->red)
            {
                node->parent->red = false;
                uncle->red = false;
                grandparent->red = true;
                node = grandparent;
            }
            else
            {
                if (node == node->parent->left)
                {
                    node = node->parent;
                    rotateTree(tree, RIGHT, node);
                }
                node->parent->red = false;
                node->parent->parent->red = true;
                rotateTree(tree, LEFT, node->parent->parent);
            }
        }
    }
    tree->root->red = false;
}

/*@
  requires \valid(tree);
  requires \valid(u);
  assigns tree->root \from tree->root, u, v;
*/
/* Frama-C: skipped — [recursive-ds] BST subtree transplant */
void transplant(tree_t *tree, struct rbNode *u, struct rbNode *v)
{
    if (u->parent == NULL)
        tree->root = v;
    else if (u == u->parent->left)
        u->parent->left = v;
    else
        u->parent->right = v;
    if (v != NULL)
        v->parent = u->parent;
}

/*@
  requires \valid(tree);
  requires \valid(node);
  requires dir == LEFT || dir == RIGHT;
  assigns \result \from tree, node, dir;
*/
/* Frama-C: skipped — [recursive-ds] partial recoloring during delete */
struct rbNode *recolorDelPartial(tree_t *tree, enum Direction dir, struct rbNode *node)
{
    struct rbNode *sibling, *other;
    if (dir == LEFT)
    {
        sibling = node->parent->right;
        other = node->parent->left;
    }
    else
    {
        sibling = node->parent->left;
        other = node->parent->right;
    }
    /* NULL leaves are conceptually black in a red-black tree; these guards
     * encode that so the algorithm works without an explicit NIL sentinel. */
    if (sibling->red)
    {
        sibling->red = false;
        node->parent->red = true;
        rotateTree(tree, dir, node->parent);
        sibling = other;
    }

    bool left_black = (sibling->left == NULL) || !sibling->left->red;
    bool right_black = (sibling->right == NULL) || !sibling->right->red;
    if (left_black && right_black)
    {
        sibling->red = true;
        node = node->parent;
    }
    else
    {
        if (dir == LEFT)
        {
            if (sibling->right == NULL || !sibling->right->red)
            {
                if (sibling->left != NULL)
                    sibling->left->red = false;
                sibling->red = true;
                rotateTree(tree, opposite_direction(dir), sibling);
                sibling = node->parent->right;
            }
            sibling->red = node->parent->red;
            node->parent->red = false;
            if (sibling->right != NULL)
                sibling->right->red = false;
            rotateTree(tree, dir, node->parent);
            node = tree->root;
        }
        else
        {
            if (sibling->left == NULL || !sibling->left->red)
            {
                if (sibling->right != NULL)
                    sibling->right->red = false;
                sibling->red = true;
                rotateTree(tree, opposite_direction(dir), sibling);
                sibling = node->parent->left;
            }
            sibling->red = node->parent->red;
            node->parent->red = false;
            if (sibling->left != NULL)
                sibling->left->red = false;
            rotateTree(tree, dir, node->parent);
            node = tree->root;
        }
        node->red = false;
    }
    return node;
}

/*@
  requires \valid(tree);
  requires \valid(node);
  assigns tree->root \from tree->root, node;
*/
/* Frama-C: skipped — [recursive-ds] red-black recoloring after delete */
void recolorDelete(tree_t *tree, struct rbNode *node)
{
    while (node != tree->root && !node->red)
    {
        if (node == node->parent->left)
            node = recolorDelPartial(tree, LEFT, node);
        else
            node = recolorDelPartial(tree, RIGHT, node);
    }
    node->red = false;
}

/**********************/
// public tree functions

int tree_init(tree_t *tree)
{
    return 0;
}

/* Frama-C: skipped — [solver-timeout] smrt_ptr allocation postconditions */
int tree_create(tree_t **tree_ptr)
{
    if (tree_ptr == NULL)
        return EXCEPTION(EINVAL);
    *tree_ptr = smrt_create(sizeof(tree_t));
    if (*tree_ptr == NULL)
        return EXCEPTION(ENOMEM);
    return tree_init(*tree_ptr);
}

/*@
  requires \valid(orig);
  requires \valid(copy_ptr);
  allocates *copy_ptr;
  assigns *copy_ptr \from orig;
  behavior success:
    ensures \result == 0;
    ensures *copy_ptr != \null;
  behavior failure:
    ensures \result != 0;
  disjoint behaviors;
*/
/* Frama-C: skipped — [recursive-ds] full tree deep copy */
int tree_copy(tree_t *orig, tree_t **copy_ptr)
{
    int err = tree_create(copy_ptr);
    if (err != 0)
        return err;
    tree_t *copy = *copy_ptr;
    err = copyNodes(orig->root, NULL, &copy->root);
    if (err != 0) {
        tree_free(copy);
        return err;
    }
    copy->size = orig->size;
    return 0;
}

int tree_size(tree_t *tree)
{
    return tree->size;
}

int tree_first(tree_t *tree)
{
    if (tree == NULL || tree->root == NULL || tree->size == 0)
        return -1;
    struct rbNode *n = tree->root;
    while (n->left != NULL)
        n = n->left;
    return n->key;
}

int tree_last(tree_t *tree)
{
    if (tree == NULL || tree->root == NULL || tree->size == 0)
        return -1;
    struct rbNode *n = tree->root;
    while (n->right != NULL)
        n = n->right;
    return n->key;
}

/*@
  requires node == \null || \valid(node);
  assigns \nothing;
  ensures \result >= 0;
  ensures node == \null ==> \result == 0;
*/
/* Frama-C: skipped — [recursive-ds] recursive depth calculation */
static int node_depth(struct rbNode *node)
{
    if (node == NULL)
        return 0;
    int left_depth = node_depth(node->left);
    int right_depth = node_depth(node->right);
    return 1 + (left_depth > right_depth ? left_depth : right_depth);
}

/* Frama-C: skipped — [recursive-ds] recursive depth calculation */
int tree_depth(tree_t *tree)
{
    return node_depth(tree->root);
}

tree_data_ptr_t tree_find(tree_t *tree, int key)
{
    struct rbNode *node = findNode(tree, key);
    if (node == NULL)
        return NULL;
    return node->data;
}

/*@
  requires \valid(tree);
  assigns tree->root, tree->size \from tree->root, tree->size, data;
  behavior success:
    ensures \result == 0;
    ensures tree->size == \old(tree->size) + 1;
  behavior failure:
    ensures \result != 0;
    ensures tree->size == \old(tree->size);
  disjoint behaviors;
*/
int tree_insert_auto_key(tree_t *tree, tree_data_ptr_t data)
{
    int key = tree->size + 1;
    return tree_insert(tree, data, key);
}

/* Frama-C: skipped — [recursive-ds] BST insert with rebalance */
int tree_insert(tree_t *tree, void *data, int key)
{
    struct rbNode *node;
    int err = createNode(data, key, &node);
    if (err != 0)
        return err;
    struct rbNode *current = tree->root;
    struct rbNode *parent = current;
    while (current != NULL)
    {
        parent = current;
        if (node->key < current->key)
            current = current->left;
        else if (node->key > current->key)
            current = current->right;
        else
        {
            smrt_deref(node);
            return EXCEPTION(ERBT_DUP_INS);
        }
    }
    node->parent = parent;
    if (parent == NULL)
        tree->root = node;
    else if (node->key < parent->key)
        parent->left = node;
    else
        parent->right = node;
    tree->size++;
    recolorInsert(tree, node);
    return 0;
}

/* Frama-C: skipped — [recursive-ds] BST delete with rebalance */
int tree_delete(tree_t *tree, int key)
{
    if (!tree->root)
        return EXCEPTION(ERBT_EMPTY);

    struct rbNode *node = findNode(tree, key);
    if (node == NULL)
        return EXCEPTION(ERBT_NO_KEY);

    struct rbNode *temp = node;
    bool color = temp->red;
    struct rbNode *fix_root;
    if (node->left == NULL)
    {
        fix_root = node->right;
        transplant(tree, node, node->right);
    }
    else if (node->right == NULL)
    {
        fix_root = node->left;
        transplant(tree, node, node->left);
    }
    else
    {
        temp = nodeMinLeaf(node->right);
        color = temp->red;
        fix_root = temp->right;
        if (temp->parent == node)
        {
            if (fix_root != NULL)
                fix_root->parent = temp;
        }
        else
        {
            transplant(tree, temp, temp->right);
            temp->right = node->right;
            if (temp->right != NULL)
                temp->right->parent = temp;
        }
        transplant(tree, node, temp);
        temp->left = node->left;
        if (temp->left != NULL)
            temp->left->parent = temp;
        temp->red = node->red;
    }
    if (!color && fix_root != NULL)
        recolorDelete(tree, fix_root);
    tree->size--;
    return 0;
}


/* H14 helpers. */

/* Recursively walk @p node, appending leaf pointers (no rbNode
 * children) into @p out. Matches Python Node.leaves recursion. */
static int _tree_collect_leaves(struct rbNode *node, array_t *out)
{
    if (node == NULL)
        return 0;
    if (nodeIsLeaf(node))
    {
        data_t *d = object_ptr_data(node, sizeof(struct rbNode));
        if (d == NULL)
            return ENOMEM;
        return array_append(out, d);
    }
    int err = _tree_collect_leaves(node->left, out);
    if (err != 0)
        return err;
    return _tree_collect_leaves(node->right, out);
}

int tree_node_leaves(struct rbNode *node, array_t **leaves_out)
{
    if (leaves_out == NULL)
        return EINVAL;
    array_t *list = NULL;
    int err = array_create(&list);
    if (err != 0)
        return err;
    /* A NULL node yields an empty list (matches Python: a None
     * subtree contributes nothing). */
    if (node != NULL)
    {
        err = _tree_collect_leaves(node, list);
        if (err != 0)
        {
            array_free(list);
            return err;
        }
    }
    *leaves_out = list;
    return 0;
}

/* Recursive build of the (key, left_json, right_json) shape. Returns
 * an empty JSON array for NULL nodes, matching Python's `()` for
 * absent children. */
static json_t *_tree_node_to_json(const struct rbNode *node)
{
    if (node == NULL)
        return json_array();
    json_t *arr = json_array();
    if (arr == NULL)
        return NULL;
    if (json_array_append_new(arr, json_integer(node->key)) != 0)
        goto err;
    json_t *left = _tree_node_to_json(node->left);
    if (left == NULL || json_array_append_new(arr, left) != 0)
    {
        if (left != NULL) json_decref(left);
        goto err;
    }
    json_t *right = _tree_node_to_json(node->right);
    if (right == NULL || json_array_append_new(arr, right) != 0)
    {
        if (right != NULL) json_decref(right);
        goto err;
    }
    return arr;
err:
    json_decref(arr);
    return NULL;
}

void *tree_to_json(tree_t *tree)
{
    if (tree == NULL || tree->root == NULL)
        return json_array();
    return _tree_node_to_json(tree->root);
}

/* Recursive insertion driver — walks the [key, left, right] shape and
 * inserts each key into @p tree. The encoding preserves the original
 * topology by construction order: pre-order insertion. */
static int _tree_insert_from_json(tree_t *tree, json_t *j)
{
    if (j == NULL || !json_is_array(j))
        return EINVAL;
    size_t n = json_array_size(j);
    if (n == 0)
        return 0;
    json_t *jkey = json_array_get(j, 0);
    if (!json_is_integer(jkey))
        return EINVAL;
    int err = tree_insert(tree, NULL, (int)json_integer_value(jkey));
    if (err != 0)
        return err;
    if (n > 1)
    {
        err = _tree_insert_from_json(tree, json_array_get(j, 1));
        if (err != 0)
            return err;
    }
    if (n > 2)
    {
        err = _tree_insert_from_json(tree, json_array_get(j, 2));
        if (err != 0)
            return err;
    }
    return 0;
}

int tree_from_json(void *j, tree_t **tree_out)
{
    if (j == NULL || tree_out == NULL)
        return EINVAL;
    if (!json_is_array((json_t *)j))
        return EINVAL;
    tree_t *t = NULL;
    int err = tree_create(&t);
    if (err != 0)
        return err;
    err = _tree_insert_from_json(t, (json_t *)j);
    if (err != 0)
    {
        tree_free(t);
        return err;
    }
    *tree_out = t;
    return 0;
}

/* Frama-C: skipped — [solver-timeout] map_free/smrt_deref preconditions */
void tree_free(tree_t *tree) {
    nodesFree(tree->root);
    tree->size = 0;
    smrt_deref(tree);
}
