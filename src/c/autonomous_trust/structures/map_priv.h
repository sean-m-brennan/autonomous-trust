#ifndef MAP_PRIV
#define MAP_PRIV

#include <stddef.h>

#include <sodium.h>

#include "map.h"
#include "array_priv.h"

struct map_s
{
    map_item_t *items;
    size_t length;
    size_t capacity;
    array_t keys;
    unsigned char hashkey[crypto_shorthash_KEYBYTES];
    bool alloc;
};

#endif // MAP_PRIV
