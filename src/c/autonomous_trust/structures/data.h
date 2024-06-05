#ifndef DATA_H
#define DATA_H

#include <stdbool.h>
#include <stddef.h>
#include <string.h>

typedef enum
{
    INT,
    UINT,
    FLOAT,
    BOOL,
    STRING,
    BYTES,
    OBJECT
} type_t;

typedef struct data_s
{
    type_t type;
    int (*cmp)(struct data_s*, struct data_s*);
    size_t size;
    union
    {
        long intgr;
        unsigned long uintr;
        double flt_pt;
        bool bl;
        char *str;
        unsigned char *byt;
        void *obj;
    };
} data_t;


int i_cmp(data_t *a, data_t *b);
int u_cmp(data_t *a, data_t *b);
int f_cmp(data_t *a, data_t *b);
int b_cmp(data_t *a, data_t *b);
int s_cmp(data_t *a, data_t *b);
int d_cmp(data_t *a, data_t *b);
int o_cmp(data_t *a, data_t *b);

#define idat(val)     \
    {                 \
        .type = INT,  \
        .intgr = val, \
        .cmp = i_cmp, \
        .size = 1,    \
    }

#define udat(val)     \
    {                 \
        .type = UINT, \
        .uintr = val, \
        .cmp = u_cmp, \
        .size = 1,    \
    }

#define fdat(val)      \
    {                  \
        .type = FLOAT, \
        .flt_pt = val, \
        .cmp = f_cmp,  \
        .size = 1,     \
    }

#define bdat(val)     \
    {                 \
        .type = BOOL, \
        .bl = val,    \
        .cmp = b_cmp, \
        .size = 1,    \
    }

#define sdat(val)            \
    {                        \
        .type = STRING,      \
        .str = val,          \
        .cmp = s_cmp,        \
        .size = strlen(val), \
    }

#define ddat(val, len) \
    {                  \
        .type = BYTES, \
        .byt = val,    \
        .cmp = d_cmp,  \
        .size = len,   \
    }

#define odat(val)       \
    {                   \
        .type = OBJECT, \
        .obj = val,     \
        .cmp = o_cmp,   \
        .size = 1,      \
    }

bool data_equal(data_t *a, data_t *b);

#endif // DATA_H
