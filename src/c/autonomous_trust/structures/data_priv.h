/********************
 *  Copyright 2024 TekFive, Inc. and contributors
 *
 *   Licensed under the Apache License, Version 2.0 (the "License");
 *   you may not use this file except in compliance with the License.
 *   You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 *   Unless required by applicable law or agreed to in writing, software
 *   distributed under the License is distributed on an "AS IS" BASIS,
 *   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *   See the License for the specific language governing permissions and
 *   limitations under the License.
 *******************/

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
