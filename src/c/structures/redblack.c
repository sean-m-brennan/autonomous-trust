#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>

#include "redblack.h"
#include "array.h"

enum Direction
{
    LEFT,
    RIGHT
};

enum Direction opposite_direction(enum Direction dir)
{
    return (enum Direction)(dir + 1) % 2;
};

/**********************/
// Red/Black node in tree (private)

struct rbNode
{
    int key;
    bool red;
    tree_data data;
    struct rbNode *parent, *left, *right;
};

struct rbNode *createNode(tree_data data, int key)
{
    struct rbNode *newNode = (struct rbNode *)malloc(sizeof(struct rbNode));
    newNode->data = data;
    newNode->key = key;
    newNode->red = true;
    newNode->parent = newNode->left = newNode->right = NULL;
    return newNode;
}

struct rbNode *copyNodes(struct rbNode *orig, struct rbNode *parent)
{
    if (orig == NULL)
        return NULL;
    struct rbNode *copy = createNode(orig->data, orig->key);
    copy->red = orig->red;
    copy->left = copyNodes(orig->left, copy);
    copy->right = copyNodes(orig->right, copy);
    copy->parent = parent;
    return copy;
}

struct rbNode *findNode(RedBlackTree *tree, int key)
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

struct rbNode *getNodeChild(struct rbNode *node, enum Direction which)
{
    if (which == LEFT)
        return node->left;
    return node->right;
};

void setNodeChild(struct rbNode *node, enum Direction which, struct rbNode *child)
{
    if (which == LEFT)
        node->left = child;
    else
        node->right = child;
};

struct rbNode *nodeSibling(struct rbNode *node)
{
    if (node->parent == NULL)
        return NULL;
    if (node == node->parent->left)
        return node->parent->right;
    return node->parent->left;
};

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

bool nodeIsLeaf(struct rbNode *node)
{
    return node->left == NULL && node->right == NULL;
};

struct rbNode *nodeMinLeaf(struct rbNode *node)
{
    struct rbNode *current = node;
    while (current->left != NULL)
        current = current->left;
    if (!nodeIsLeaf(current))
        current = minLeaf(current->right);
    return current;
}

/**********************/
// private tree functions

void rotateTree(RedBlackTree *tree, enum Direction dir, struct rbNode *node)
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

struct rbNode *recolorInsPartial(RedBlackTree *tree, enum Direction dir, struct rbNode *node)
{
    struct rbNode *cousin;
    struct rbNode *sibling;
    if (dir == LEFT)
    {
        cousin = node->parent->parent->left;
        sibling = node->parent->left;
    }
    else
    {
        cousin = node->parent->parent->right;
        sibling = node->parent->right;
    }
    if (cousin->red)
    {
        cousin->red = false;
        node->parent->red = false;
        node->parent->parent->red = true;
        node = node->parent->parent;
    }
    else
    {
        if (node == sibling)
        {
            node = node->parent;
            rotateTree(tree, opposite_direction(dir), node);
        }
        node->parent->red = false;
        node->parent->parent->red = true;
        rotateTree(tree, dir, node->parent->parent);
    }
    return node;
}

void recolorInsert(RedBlackTree *tree, struct rbNode *node)
{
    while (node != tree->root && node->parent->red)
    {
        if (node->parent == node->parent->parent->right)
            node = recolorInsPartial(tree, LEFT, node);
        else
            node = recolorInsPartial(tree, RIGHT, node);
        tree->root->red = false;
        node = node->parent;
    }
}

void transplant(RedBlackTree *tree, struct rbNode *u, struct rbNode *v)
{
    if (u->parent == NULL)
        tree->root = v;
    else if (u == u->parent->left)
        u->parent->left = v;
    else
        u->parent->right = v;
    v->parent = u->parent;
}

struct rbNode *recolorDelPartial(RedBlackTree *tree, enum Direction dir, struct rbNode *node)
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
    if (sibling->red)
    {
        sibling->red = false;
        node->parent->red = true;
        rotate(tree, dir, node->parent);
        sibling = other;
    }

    if (!sibling->left->red && !sibling->right->red)
    {
        sibling->red = true;
        node = node->parent;
    }
    else
    {
        if (dir == LEFT)
        {
            if (!sibling->right->red)
            {
                sibling->left->red = false;
                sibling->red = true;
                rotate(tree, opposite_direction(dir), sibling);
                sibling = node->parent->right;
            }
            sibling->red = node->parent->red;
            node->parent->red = false;
            sibling->right->red = false;
            rotate(tree, dir, node->parent);
            node = tree->root;
        }
        else
        {
            if (!sibling->left->red)
            {
                sibling->right->red = false;
                sibling->red = true;
                rotate(tree, opposite_direction(dir), sibling);
                sibling = node->parent->left;
            }
            sibling->red = node->parent->red;
            node->parent->red = false;
            sibling->left->red = false;
            rotate(tree, dir, node->parent);
            node = tree->root;
        }
        node->red = false;
    }
}

void recolorDelete(RedBlackTree *tree, struct rbNode *node)
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

RedBlackTree *tree_create()
{
    RedBlackTree *newTree = (RedBlackTree *)malloc(sizeof(RedBlackTree));
    initTree(newTree);
    return newTree;
}

void tree_init(RedBlackTree *tree)
{
    tree->root = NULL;
    tree->size = 0;
}

RedBlackTree *tree_copy(RedBlackTree *tree)
{ // semi-deep copy
    RedBlackTree *newTree = createTree();
    newTree->root = copyNodes(tree->root, NULL);
    newTree->size = tree->size;
    return newTree;
}

tree_data tree_find(RedBlackTree *tree, int key)
{
    return findNode(tree, key)->data;
}

int tree_insert(RedBlackTree *tree, tree_data data)
{
    int key = tree->size + 1;
    return insertion_with_key(tree, data, key);
}

int tree_insert_with_key(RedBlackTree *tree, void *data, int key)
{
    struct rbNode *node = createNode(data, key);
    struct rbNode *parent = NULL;
    struct rbNode *current = tree->root;
    while (current != NULL)
    {
        parent = current;
        if (node->key < current->key)
            current = current->left;
        else if (node->key > current->key)
            current = current->right;
        else
        {
            free(node);
            return ERBT_DUP_INS;
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

int tree_delete(RedBlackTree *tree, int key)
{
    if (!tree->root)
        return ERBT_EMPTY;

    struct rbNode *node = tree_find(tree, key);
    if (node == NULL)
        return ERBT_NO_KEY;

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
            fix_root->parent = temp;
        else
        {
            transplant(tree, temp, temp->right);
            temp->right = node->right;
            temp->right->parent = temp;
        }
    }
    if (!color)
        recolorDelete(tree, fix_root);
    tree->size--;
    return 0;
}
