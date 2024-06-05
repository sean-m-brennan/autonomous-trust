#ifndef ARRAY_PRIV_H
#define ARRAY_PRIV_H

#include <stddef.h>
#include <stdbool.h>

#include "array.h"
#include "data.h"

struct array_s
{
    size_t size;
    bool alloc;
    data_t *array;
};

#endif // ARRAY_PRIV_H