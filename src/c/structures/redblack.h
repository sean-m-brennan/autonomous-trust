#ifndef C_RED_BLACK_TREE_H
#define C_RED_BLACK_TREE_H

typedef void *tree_data;

struct rbNode;

typedef struct
{
    struct rbNode *root;
    int size;
} RedBlackTree;

RedBlackTree *tree_create();
void tree_init(RedBlackTree *tree);
RedBlackTree *tree_copy(RedBlackTree *tree);
int tree_size(RedBlackTree *tree);
int tree_depth(RedBlackTree *tree);
tree_data tree_find(RedBlackTree *tree, int key);
int tree_insert_with_key(RedBlackTree *tree, tree_data data, int key);
int tree_insert(RedBlackTree *tree, tree_data data);
int tree_delete(RedBlackTree *tree, int key);

#define ERBT_DUP_INS 140
#define ERBT_EMPTY 141
#define ERBT_NO_KEY 142

#endif // C_RED_BLACK_TREE_H