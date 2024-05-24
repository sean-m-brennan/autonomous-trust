//
// Created by user on 5/10/24.
//

#include "merkle.h"
#include "array.h"
#include "redblack.h"

struct merkleNode
{
    int digest; // FIXME hash
    void *blob;
    char *uuid;
};

struct merkleTree
{
    tree_t *tree;
    int superHash;
    array_t *blobs;
    array_t *unique;
    array_t *nonUnique;
};

