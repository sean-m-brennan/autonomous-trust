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

#ifndef DATA_H
#define DATA_H

#include <stdbool.h>
#include <stddef.h>
#include <string.h>

#include "utilities/exception.h"

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
} data_type_t;


typedef struct data_s data_t;

typedef char* string_t;

typedef unsigned char* bytes_t;

typedef void* ptr_t;

/********************/
// convert from pod to data_t* (with allocation)

data_t *integer_data(int i);

data_t *l_integer_data(long i);

data_t *u_integer_data(unsigned int u);

data_t *ul_integer_data(unsigned long u);

data_t *floating_pt_data(float f);

data_t *floating_pt_dbl_data(double f);

data_t *boolean_data(bool b);

data_t *string_data(string_t s, size_t len);

data_t *bytes_data(bytes_t b, size_t len);

data_t *object_ptr_data(ptr_t o, size_t len);


/********************/
// convert from data_t* to pod

int data_integer(data_t *d, int *i_ptr);

int data_l_integer(data_t *d, long *i_ptr);

int data_u_integer(data_t *d, unsigned int *u_ptr);

int data_ul_integer(data_t *d, unsigned long *u_ptr);

int data_floating_pt(data_t *d, float *f_ptr);

int data_floating_pt_dbl(data_t *d, double *f_ptr);

int data_boolean(data_t *d, bool *b_ptr);

int data_string(data_t *d, string_t s, size_t max_len);

int data_string_ptr(data_t *d, string_t *s_ptr);

int data_bytes(data_t *d, bytes_t b, size_t max_len);

int data_bytes_ptr(data_t *d, bytes_t *b_ptr);

int data_object(data_t *d, ptr_t o, size_t max_len);

int data_object_ptr(data_t *d, ptr_t *o_ptr);



void data_incr(data_t *d);

void data_decr(data_t *d);


bool data_equal(data_t *a, data_t *b);

#define EDAT_INVL 210
DECLARE_ERROR(EDAT_INVL, "Invalid data type");

#endif  // DATA_H
