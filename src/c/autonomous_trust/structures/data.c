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

#include <stdlib.h>

#include "utilities/exception.h"
#include "data_priv.h"


#define pod_cmp(a, b) ((a) < (b)) ? -1 : (((a) > (b)) ? 1 : 0)

int i_cmp(data_t *a, data_t *b) { return pod_cmp(a->intgr, b->intgr); }
int u_cmp(data_t *a, data_t *b) { return pod_cmp(a->uintr, b->uintr); }
int f_cmp(data_t *a, data_t *b) { return pod_cmp(a->flt_pt, b->flt_pt); }
int b_cmp(data_t *a, data_t *b) { return pod_cmp(a->bl, b->bl); }
int s_cmp(data_t *a, data_t *b) { return strcmp(a->str, b->str); }
int d_cmp(data_t *a, data_t *b) { return memcmp(a->str, b->str, a->size); }
int o_cmp(data_t *a, data_t *b) { return a->obj == b->obj; }

bool data_equal(data_t *a, data_t *b)
{
    return a->type == b->type && a->cmp(a, b) == 0;
}

data_t *l_integer_data(long val)
{
    data_t *dat = calloc(1, sizeof(data_t));
    if (dat == NULL)
        return dat;
    dat->type = INT;
    dat->intgr = val;
    dat->cmp = i_cmp;
    dat->size = 1;
    dat->ref = 1;
    return dat;
}

data_t *integer_data(int val)
{
    return l_integer_data((long)val);
}

data_t *ul_integer_data(unsigned long val)
{
    data_t *dat = calloc(1, sizeof(data_t));
    if (dat == NULL)
        return dat;
    dat->type = UINT;
    dat->uintr = val;
    dat->cmp = u_cmp;
    dat->size = 1;
    dat->ref = 1;
    return dat;
}

data_t *u_integer_data(unsigned int val)
{
    return ul_integer_data((unsigned long)val);
}

data_t *floating_pt_dbl_data(double val)
{
    data_t *dat = calloc(1, sizeof(data_t));
    if (dat == NULL)
        return dat;
    dat->type = FLOAT;
    dat->flt_pt = val;
    dat->cmp = f_cmp;
    dat->size = 1;
    dat->ref = 1;
    return dat;
}

data_t *floating_pt_data(float val)
{
    return floating_pt_dbl_data((double)val);
}

data_t *boolean_data(bool val)
{
    data_t *dat = calloc(1, sizeof(data_t));
    if (dat == NULL)
        return dat;
    dat->type = BOOL;
    dat->bl = val;
    dat->cmp = b_cmp;
    dat->size = 1;
    dat->ref = 1;
    return dat;
}

data_t *string_data(char *val, size_t len)
{
    data_t *dat = calloc(1, sizeof(data_t));
    if (dat == NULL)
        return dat;
    dat->type = STRING;
    dat->str = val; // FIXME
    dat->cmp = s_cmp;
    dat->size = strlen(val);
    dat->ref = 1;
    return dat;
}

data_t *bytes_data(unsigned char *val, size_t len)
{
    data_t *dat = calloc(1, sizeof(data_t));
    if (dat == NULL)
        return dat;
    dat->type = BYTES;
    dat->byt = val; // FIXME
    dat->cmp = d_cmp;
    dat->size = len;
    dat->ref = 1;
    return dat;
}

data_t *object_ptr_data(void *val, size_t len)
{
    data_t *dat = calloc(1, sizeof(data_t));
    if (dat == NULL)
        return dat;
    dat->type = OBJECT;
    dat->obj = val;
    dat->cmp = o_cmp;
    dat->size = 1;
    dat->ref = 1;
    return dat;
}

void data_incr(data_t *d){
    d->ref++;
}

void data_decr(data_t *d){
    d->ref--;
    if (d->ref <= 0)
        free(d);
}

int data_l_integer(data_t *d, long *i)
{
    if (d->type != INT)
        return EXCEPTION(EDAT_INVL);
    *i = d->intgr;
    return 0;
}

int data_integer(data_t *d, int *i)
{
      if (d->type != INT)
        return EXCEPTION(EDAT_INVL);
    *i = (int)d->intgr;
    return 0;
}


int data_ul_integer(data_t *d, unsigned long *u)
{
    if (d->type != UINT)
        return EXCEPTION(EDAT_INVL);
    *u = d->uintr;
    return 0;
}

int data_u_integer(data_t *d, unsigned int *u)
{
    if (d->type != UINT)
        return EXCEPTION(EDAT_INVL);
    *u = (unsigned int)d->uintr;
    return 0;
}

int data_floating_pt_dbl(data_t *d, double *f)
{
    if (d->type != FLOAT)
        return EXCEPTION(EDAT_INVL);
    *f = d->flt_pt;
    return 0;
}

int data_floating_pt(data_t *d, float *f)
{
    if (d->type != FLOAT)
        return EXCEPTION(EDAT_INVL);
    *f = (float)d->flt_pt;
    return 0;
}

int data_boolean(data_t *d, bool *b)
{
    if (d->type != BOOL)
        return EXCEPTION(EDAT_INVL);
    *b = d->bl;
    return 0;
}

int data_string(data_t *d, char *s, size_t max_len)
{
    if (d->type != STRING)
        return EXCEPTION(EDAT_INVL);
    strncpy(s, d->str, max_len);
    return 0;
}

int data_string_ptr(data_t *d, char **s)
{
    if (d->type != STRING)
        return EXCEPTION(EDAT_INVL);
    *s = d->str;
    return 0;
}

int data_bytes(data_t *d, unsigned char *b, size_t max_len)
{
    if (d->type != BYTES)
        return EXCEPTION(EDAT_INVL);
    memcpy(b, d->byt, max_len);
    return 0;
}

int data_bytes_ptr(data_t *d, unsigned char **b)
{
    if (d->type != BYTES)
        return EXCEPTION(EDAT_INVL);
    *b = d->byt;
    return 0;
}

int data_object(data_t *d, void *o, size_t max_len)
{
    if (d->type != OBJECT)
        return EXCEPTION(EDAT_INVL);
    memcpy(o, d->obj, max_len);
    return 0;
}

int data_object_ptr(data_t *d, void **o)
{
    if (d->type != OBJECT)
        return EXCEPTION(EDAT_INVL);
    *o = d->obj;
    return 0;
}
