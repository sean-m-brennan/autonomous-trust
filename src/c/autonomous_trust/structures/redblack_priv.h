#ifndef REDBLACK_PRIV_H
#define REDBLACK_PRIV_H

#include "redblack.h"

enum Direction
{
    LEFT,
    RIGHT
};

enum Direction opposite_direction(enum Direction dir);

struct rbNode
{
    int key;
    bool red;
    tree_data_ptr_t data;
    struct rbNode *parent, *left, *right;
};

struct rbTree_s {
    struct rbNode *root;
    int size;
};

#endif  // REDBLACK_PRIV_H
