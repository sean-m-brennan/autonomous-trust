#ifndef ARRAY_H
#define ARRAY_H

#include <stddef.h>
#include <stdbool.h>

typedef void *array_data;

typedef struct
{
    array_data *array;
    size_t used;
    size_t size;
} Array;

void array_init(Array *a, size_t initialSize);
int array_insert(Array *a, array_data element);
int array_find(Array *a, array_data element);
int array_filter(Array *a, bool (*filter)(array_data));
bool aray_contains(Array *a, array_data element);
int array_get(Array *a, int index, array_data *element);
int array_set(Array *a, int index, array_data element);
int array_remove(Array *a, array_data element);
void array_free(Array *a);

#define EARR_OOB 150
#define EARR_NOELT 151

int max(int a, int b);
int min(int a, int b);

#endif // ARRAY_H
