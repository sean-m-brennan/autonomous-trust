#ifndef MERKLE_H
#define MERKLE_H

#include "array.h"
#include "redblack.h"

typedef struct
{
    int digest; // FIXME hash
    void *blob;
    char *uuid;
} MerkleNode;

typedef struct
{
    RedBlackTree tree;
    int superHash;
    Array blobs;
    Array unique;
    Array nonUnique;
} MerkleTree;

#endif // MERKLE_H
