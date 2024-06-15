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
#include "structures/data.pb-c.h"

struct data_s
{
    data_type_t type;
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
    int (*cmp)(struct data_s *, struct data_s *);
};

int i_cmp(data_t *a, data_t *b);
int u_cmp(data_t *a, data_t *b);
int f_cmp(data_t *a, data_t *b);
int b_cmp(data_t *a, data_t *b);
int s_cmp(data_t *a, data_t *b);
int d_cmp(data_t *a, data_t *b);
int o_cmp(data_t *a, data_t *b);

#define INT_DATA(i)   \
    {                 \
        .type = INT,  \
        .intgr = i,   \
        .size = 1,    \
        .cmp = i_cmp, \
    }

#define STRING_DATA(s)    \
    {                     \
        .type = STRING,   \
        .str = (char *)s, \
        .size = 1,        \
        .cmp = s_cmp,     \
    }

int data_sync_out(data_t *data, AutonomousTrust__Core__Structures__Data *pdata);

void data_free_out_sync(AutonomousTrust__Core__Structures__Data *pdata);

int data_sync_in(AutonomousTrust__Core__Structures__Data *pdata, data_t *data);

void data_free_in_sync(data_t *data);


#define EDAT_SER_OBJ 216
DECLARE_ERROR(EDAT_SER_OBJ, "Serializing arbitrary data objects not allowed")

#define EDAT_DSER_OBJ 217
DECLARE_ERROR(EDAT_DSER_OBJ, "De-serializing arbitrary data objects not allowed")

#endif  // DATA_PRIV_H
