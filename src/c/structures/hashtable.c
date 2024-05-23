#include <stdlib.h>
#include <stddef.h>
#include <stdint.h>
#include <errno.h>
#include <string.h>

#include "hashtable.h"
#include "array.h"

typedef struct {
    const char* key;
    hashtable_data_ptr_t value;
} entry_t;

struct hashtable_s {
    entry_t* entries;
    size_t capacity;
    size_t length;
    array_t *keys;
};

typedef uint64_t hash_t;

// Fowler–Noll–Vo (FNV-1a) hash (64-bit)
hash_t hash_key(const char *key) {
    hash_t hash = 0xcbf29ce484222325;
    for (const char* byte = key; *byte; byte++) {
        hash ^= (hash_t)(*byte);
        hash *= 0x100000001b3;
    }
    return hash;
}

const size_t CAP_INCR = 31;

int hashtable_create(hashtable_t **ht) {
    if (ht == NULL)
        return EINVAL;
    *ht = calloc(1, sizeof(hashtable_t));
    if (ht == NULL)
        return ENOMEM;
    hashtable_t *t = *ht;
    t->entries = calloc(t->capacity, sizeof(entry_t));
    if (t->entries == NULL)
        return ENOMEM;
    t->capacity = CAP_INCR;
    t->length = 0;
    return array_create(&t->keys);
}

size_t key2index(hashtable_t *ht, const char *key) {
    hash_t hash = hash_key(key);
    return (size_t)(hash & (hash_t)(ht->capacity - 1));
}

hashtable_data_ptr_t hashtable_get(hashtable_t *ht, const char *key) {
    size_t index = key2index(ht, key);

    if (!array_contains(ht->keys, (void*)key))
        return NULL;

    while (index < ht->capacity) {
        if (strcmp(key, ht->entries[index].key) == 0)
            return ht->entries[index].value;
        index++;
    }
    return NULL;
}

int hashtable_set(hashtable_t *ht, const char *key, hashtable_data_ptr_t value) {
    if (value == NULL)
        return EINVAL;

    if (ht->length >= ht->capacity - 1) {  // always leave room at the end
        ht->capacity += CAP_INCR;  // linear growth
        entry_t *entries = realloc(ht->entries, ht->capacity * sizeof(entry_t));
        if (entries == NULL)
            return ENOMEM;
        ht->entries = entries;
    }

    size_t index = key2index(ht, key);

    while (index < ht->capacity) {
        if (strcmp(key, ht->entries[index].key) == 0) {
            ht->entries[index].value = value;
            return 0;
        }
        index++;
    }

    const char *key_cpy = strdup(key);
    if (key_cpy == NULL)
        return ENOMEM;
    ht->entries[index].key = key_cpy;
    ht->entries[index].value = value;
    int err = array_append(ht->keys, (void*)key_cpy);
    if (err != 0)
        return err;
    ht->length++;

    return 0;
}

void hashtable_free(hashtable_t *ht) {
    for (size_t i = 0; i < ht->capacity; i++)
        free((void*)ht->entries[i].key);
    free(ht->entries);
    free(ht);
}
