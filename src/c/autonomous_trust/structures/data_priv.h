#ifndef DATA_PRIV_H
#define DATA_PRIV_H

#include "data.h"

typedef enum
{
    NONE,
    INT,
    UINT,
    FLOAT,
    BOOL,
    STRING,
    BYTES,
    OBJECT
} type_t;

struct data_s
{
    type_t type;
    int (*cmp)(struct data_s *, struct data_s *);
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
    int ref;
};

#endif  // DATA_PRIV_H
