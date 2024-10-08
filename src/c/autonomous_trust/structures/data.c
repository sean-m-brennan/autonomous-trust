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
#include <string.h>

#include "utilities/exception.h"
#include "utilities/util.h"
#include "data_priv.h"
#include "utilities/b64.h"

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
    data_t *dat = smrt_create(sizeof(data_t));
    if (dat == NULL)
        return dat;
    dat->type = INT;
    dat->intgr = val;
    dat->cmp = i_cmp;
    dat->size = 1;
    return dat;
}

data_t *integer_data(int val)
{
    return l_integer_data((long)val);
}

data_t *ul_integer_data(unsigned long val)
{
    data_t *dat = smrt_create(sizeof(data_t));
    if (dat == NULL)
        return dat;
    dat->type = UINT;
    dat->uintr = val;
    dat->cmp = u_cmp;
    dat->size = 1;
    return dat;
}

data_t *u_integer_data(unsigned int val)
{
    return ul_integer_data((unsigned long)val);
}

data_t *floating_pt_dbl_data(double val)
{
    data_t *dat = smrt_create(sizeof(data_t));
    if (dat == NULL)
        return dat;
    dat->type = FLOAT;
    dat->flt_pt = val;
    dat->cmp = f_cmp;
    dat->size = 1;
    return dat;
}

data_t *floating_pt_data(float val)
{
    return floating_pt_dbl_data((double)val);
}

data_t *boolean_data(bool val)
{
    data_t *dat = smrt_create(sizeof(data_t));
    if (dat == NULL)
        return dat;
    dat->type = BOOL;
    dat->bl = val;
    dat->cmp = b_cmp;
    dat->size = 1;
    return dat;
}

data_t *string_data(char *val, size_t len)
{
    data_t *dat = smrt_create(sizeof(data_t));
    if (dat == NULL)
        return dat;
    dat->type = STRING;
    dat->size = len;
    dat->str = calloc(1, len+1);
    strncpy(dat->str, val, len);
    dat->cmp = s_cmp;
    return dat;
}

data_t *bytes_data(unsigned char *val, size_t len)
{
    data_t *dat = smrt_create(sizeof(data_t));
    if (dat == NULL)
        return dat;
    dat->type = BYTES;
    dat->byt = calloc(1, len);
    memcpy(dat->byt, val, len);
    dat->cmp = d_cmp;
    dat->size = len;
    return dat;
}

data_t *object_ptr_data(void *val, size_t len)
{
    data_t *dat = smrt_create(sizeof(data_t));
    if (dat == NULL)
        return dat;
    dat->type = OBJECT;
    dat->obj = val;
    dat->cmp = o_cmp;
    dat->size = 1;
    return dat;
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

int data_sync_out(data_t *data, AutonomousTrust__Core__Protobuf__Structures__Data *pdata)
{
    AutonomousTrust__Core__Protobuf__Structures__Data tmp = AUTONOMOUS_TRUST__CORE__PROTOBUF__STRUCTURES__DATA__INIT;
    memcpy(pdata, &tmp, sizeof(tmp));
    pdata->size = data->size;
    switch (data->type)
    {
    case INT:
        pdata->type = AUTONOMOUS_TRUST__CORE__PROTOBUF__STRUCTURES__DATA_TYPE__INT;
        pdata->dat_case = AUTONOMOUS_TRUST__CORE__PROTOBUF__STRUCTURES__DATA__DAT_INTGR;
        pdata->intgr = data->intgr;
        break;
    case UINT:
        pdata->type = AUTONOMOUS_TRUST__CORE__PROTOBUF__STRUCTURES__DATA_TYPE__UINT;
        pdata->dat_case = AUTONOMOUS_TRUST__CORE__PROTOBUF__STRUCTURES__DATA__DAT_UINTR;
        pdata->uintr = data->uintr;
        break;
    case FLOAT:
        pdata->type = AUTONOMOUS_TRUST__CORE__PROTOBUF__STRUCTURES__DATA_TYPE__FLOAT;
        pdata->dat_case = AUTONOMOUS_TRUST__CORE__PROTOBUF__STRUCTURES__DATA__DAT_FLT_PT;
        pdata->flt_pt = data->flt_pt;
        break;
    case BOOL:
        pdata->type = AUTONOMOUS_TRUST__CORE__PROTOBUF__STRUCTURES__DATA_TYPE__BOOL;
        pdata->dat_case = AUTONOMOUS_TRUST__CORE__PROTOBUF__STRUCTURES__DATA__DAT_BL;
        pdata->bl = data->bl;
        break;
    case STRING:
        pdata->type = AUTONOMOUS_TRUST__CORE__PROTOBUF__STRUCTURES__DATA_TYPE__STRING;
        pdata->dat_case = AUTONOMOUS_TRUST__CORE__PROTOBUF__STRUCTURES__DATA__DAT_STR;
        pdata->str = malloc(data->size);
        if (pdata->str == NULL)
            return EXCEPTION(ENOMEM);
        strncpy(pdata->str, data->str, min(strlen(data->str), data->size));
        break;
    case BYTES:
        pdata->type = AUTONOMOUS_TRUST__CORE__PROTOBUF__STRUCTURES__DATA_TYPE__BYTES;
        pdata->dat_case = AUTONOMOUS_TRUST__CORE__PROTOBUF__STRUCTURES__DATA__DAT_BYT;
        pdata->byt.len = data->size;
        pdata->byt.data = malloc(data->size);
        if (pdata->str == NULL)
            return EXCEPTION(ENOMEM);
        memcpy(pdata->byt.data, data->byt, data->size);
        break;
    case OBJECT:
        return EXCEPTION(EDAT_SER_OBJ);
        break;
    case NONE:
    default:
        break;
    }
    return 0;
}

void data_proto_free(AutonomousTrust__Core__Protobuf__Structures__Data *pdata)
{
    switch (pdata->type)
    {
    case AUTONOMOUS_TRUST__CORE__PROTOBUF__STRUCTURES__DATA_TYPE__STRING:
        free(pdata->str);
        break;
    case AUTONOMOUS_TRUST__CORE__PROTOBUF__STRUCTURES__DATA_TYPE__BYTES:
        free(pdata->byt.data);
    case AUTONOMOUS_TRUST__CORE__PROTOBUF__STRUCTURES__DATA_TYPE__NONE:
    case AUTONOMOUS_TRUST__CORE__PROTOBUF__STRUCTURES__DATA_TYPE__INT:
    case AUTONOMOUS_TRUST__CORE__PROTOBUF__STRUCTURES__DATA_TYPE__UINT:
    case AUTONOMOUS_TRUST__CORE__PROTOBUF__STRUCTURES__DATA_TYPE__FLOAT:
    case AUTONOMOUS_TRUST__CORE__PROTOBUF__STRUCTURES__DATA_TYPE__BOOL:
    case AUTONOMOUS_TRUST__CORE__PROTOBUF__STRUCTURES__DATA_TYPE__OBJECT:
    case _AUTONOMOUS_TRUST__CORE__PROTOBUF__STRUCTURES__DATA_TYPE_IS_INT_SIZE:
    default:
        break;
    }
}

int data_sync_in(AutonomousTrust__Core__Protobuf__Structures__Data *pdata, data_t *data)
{
    data->type = pdata->type;
    data->size = pdata->size;
    switch (pdata->type)
    {
    case AUTONOMOUS_TRUST__CORE__PROTOBUF__STRUCTURES__DATA_TYPE__INT:
        data->intgr = pdata->intgr;
        break;
    case AUTONOMOUS_TRUST__CORE__PROTOBUF__STRUCTURES__DATA_TYPE__UINT:
        data->uintr = pdata->uintr;
        break;
    case AUTONOMOUS_TRUST__CORE__PROTOBUF__STRUCTURES__DATA_TYPE__FLOAT:
        data->flt_pt = pdata->flt_pt;
        break;
    case AUTONOMOUS_TRUST__CORE__PROTOBUF__STRUCTURES__DATA_TYPE__BOOL:
        data->bl = pdata->bl;
        break;
    case AUTONOMOUS_TRUST__CORE__PROTOBUF__STRUCTURES__DATA_TYPE__STRING:
        data->str = malloc(pdata->size);
        strncpy(data->str, pdata->str, min(strlen(pdata->str), pdata->size));
        break;
    case AUTONOMOUS_TRUST__CORE__PROTOBUF__STRUCTURES__DATA_TYPE__BYTES:
        data->byt = malloc(pdata->size);
        memcpy(data->byt, pdata->byt.data, pdata->size);
        break;
    case AUTONOMOUS_TRUST__CORE__PROTOBUF__STRUCTURES__DATA_TYPE__OBJECT:
        return EXCEPTION(EDAT_SER_OBJ);
        break;
    case AUTONOMOUS_TRUST__CORE__PROTOBUF__STRUCTURES__DATA_TYPE__NONE:
    case _AUTONOMOUS_TRUST__CORE__PROTOBUF__STRUCTURES__DATA_TYPE_IS_INT_SIZE:
    default:
        break;
    }
    return 0;
}

int data_to_json(const void *data_struct, json_t **obj_ptr)
{
    const data_t *data = data_struct;
    *obj_ptr = json_object();
    json_t *obj = *obj_ptr;
    if (obj == NULL)
        return EXCEPTION(ENOMEM);

    json_object_set(obj, "type", json_integer(data->type));
    json_object_set(obj, "size", json_integer(data->size));
    switch (data->type)
    {
    case INT:
        json_object_set_new(obj, "dat", json_integer(data->intgr));
        break;
    case UINT:
        json_object_set_new(obj, "dat", json_integer(data->uintr));
        break;
    case FLOAT:
        json_object_set_new(obj, "dat", json_real(data->flt_pt));
        break;
    case BOOL:
        json_object_set_new(obj, "dat", json_boolean(data->bl));
        break;
    case STRING:
        json_object_set_new(obj, "dat", json_stringn(data->str, data->size));
        break;
    case BYTES:
    {
        size_t enc_size = b64_encoded_len(data->size);
        char *enc_str = malloc(enc_size);
        if (enc_str == NULL)
            return EXCEPTION(ENOMEM);
        base64_encode(data->byt, data->size, enc_str, enc_size);
        json_object_set_new(obj, "dat", json_stringn_nocheck(enc_str, enc_size));
        break;
    }
    case NONE:
    case OBJECT:
        return EXCEPTION(EINVAL); // neither arbitray objects nor None can be encoded
    }
    return 0;
}

int data_from_json(const json_t *obj, void *data_struct)
{
    data_t *data = data_struct;
    data->type = json_integer_value(json_object_get(obj, "type"));
    data->size = json_integer_value(json_object_get(obj, "size"));
    json_t *dat = json_object_get(obj, "dat");
    switch (data->type)
    {
    case INT:
        data->intgr = json_integer_value(dat);
        break;
    case UINT:
        data->uintr = json_integer_value(dat);
        break;
    case FLOAT:
        data->flt_pt = json_real_value(dat);
        break;
    case BOOL:
        data->bl = json_boolean_value(dat);
        break;
    case STRING:
        data->str = malloc(data->size + 1);
        strncpy(data->str, json_string_value(dat), data->size);
        break;
    case BYTES:
    {
        size_t enc_size = json_string_length(dat);
        const char *enc_str = json_string_value(dat);
        data->size = b64_decoded_len(enc_size, enc_str[enc_size-1]);
        data->byt = malloc(data->size);
        base64_decode(enc_str, enc_size, data->byt, data->size);
        break;
    }
    case NONE:
    case OBJECT:
        return EXCEPTION(EINVAL); // neither arbitray objects nor None can be encoded
    }
    return 0;
}
