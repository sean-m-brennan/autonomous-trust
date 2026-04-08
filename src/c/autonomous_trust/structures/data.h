/********************
 *  Copyright 2025 Sean M. Brennan and contributors
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
#include "utilities/allocation.h"

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

/*@
  allocates \result;
  behavior success:
    assumes \is_allocable(sizeof(data_t));
    ensures \result != \null;
    ensures \fresh(\result, sizeof(data_t));
    assigns \nothing;
  behavior failure:
    assumes !\is_allocable(sizeof(data_t));
    ensures \result == \null;
    assigns \nothing;
  complete behaviors;
  disjoint behaviors;
*/
data_t *integer_data(int i);

/*@
  allocates \result;
  behavior success:
    assumes \is_allocable(sizeof(data_t));
    ensures \result != \null;
    ensures \fresh(\result, sizeof(data_t));
    assigns \nothing;
  behavior failure:
    assumes !\is_allocable(sizeof(data_t));
    ensures \result == \null;
    assigns \nothing;
  complete behaviors;
  disjoint behaviors;
*/
data_t *l_integer_data(long i);

/*@
  allocates \result;
  behavior success:
    assumes \is_allocable(sizeof(data_t));
    ensures \result != \null;
    ensures \fresh(\result, sizeof(data_t));
    assigns \nothing;
  behavior failure:
    assumes !\is_allocable(sizeof(data_t));
    ensures \result == \null;
    assigns \nothing;
  complete behaviors;
  disjoint behaviors;
*/
data_t *u_integer_data(unsigned int u);

/*@
  allocates \result;
  behavior success:
    assumes \is_allocable(sizeof(data_t));
    ensures \result != \null;
    ensures \fresh(\result, sizeof(data_t));
    assigns \nothing;
  behavior failure:
    assumes !\is_allocable(sizeof(data_t));
    ensures \result == \null;
    assigns \nothing;
  complete behaviors;
  disjoint behaviors;
*/
data_t *ul_integer_data(unsigned long u);

/*@
  allocates \result;
  behavior success:
    assumes \is_allocable(sizeof(data_t));
    ensures \result != \null;
    ensures \fresh(\result, sizeof(data_t));
    assigns \nothing;
  behavior failure:
    assumes !\is_allocable(sizeof(data_t));
    ensures \result == \null;
    assigns \nothing;
  complete behaviors;
  disjoint behaviors;
*/
data_t *floating_pt_data(float f);

/*@
  allocates \result;
  behavior success:
    assumes \is_allocable(sizeof(data_t));
    ensures \result != \null;
    ensures \fresh(\result, sizeof(data_t));
    assigns \nothing;
  behavior failure:
    assumes !\is_allocable(sizeof(data_t));
    ensures \result == \null;
    assigns \nothing;
  complete behaviors;
  disjoint behaviors;
*/
data_t *floating_pt_dbl_data(double f);

/*@
  allocates \result;
  behavior success:
    assumes \is_allocable(sizeof(data_t));
    ensures \result != \null;
    ensures \fresh(\result, sizeof(data_t));
    assigns \nothing;
  behavior failure:
    assumes !\is_allocable(sizeof(data_t));
    ensures \result == \null;
    assigns \nothing;
  complete behaviors;
  disjoint behaviors;
*/
data_t *boolean_data(bool b);

/*@
  requires len > 0;
  requires \valid(s + (0 .. len - 1));
  allocates \result;
  behavior success:
    assumes \is_allocable(sizeof(data_t));
    ensures \result != \null;
    ensures \fresh(\result, sizeof(data_t));
    assigns \nothing;
  behavior failure:
    assumes !\is_allocable(sizeof(data_t));
    ensures \result == \null;
    assigns \nothing;
  complete behaviors;
  disjoint behaviors;
*/
data_t *string_data(string_t s, size_t len);

/*@
  requires len > 0;
  requires \valid(b + (0 .. len - 1));
  allocates \result;
  behavior success:
    assumes \is_allocable(sizeof(data_t));
    ensures \result != \null;
    ensures \fresh(\result, sizeof(data_t));
    assigns \nothing;
  behavior failure:
    assumes !\is_allocable(sizeof(data_t));
    ensures \result == \null;
    assigns \nothing;
  complete behaviors;
  disjoint behaviors;
*/
data_t *bytes_data(bytes_t b, size_t len);

/*@
  requires len > 0;
  requires \valid((char *)o + (0 .. len - 1));
  allocates \result;
  behavior success:
    assumes \is_allocable(sizeof(data_t));
    ensures \result != \null;
    ensures \fresh(\result, sizeof(data_t));
    assigns \nothing;
  behavior failure:
    assumes !\is_allocable(sizeof(data_t));
    ensures \result == \null;
    assigns \nothing;
  complete behaviors;
  disjoint behaviors;
*/
data_t *object_ptr_data(ptr_t o, size_t len);


/********************/
// convert from data_t* to pod

/*@
  requires \valid(d);
  requires \valid(i_ptr);
  assigns *i_ptr;
  behavior success:
    assumes d->type == INT;
    ensures \result == 0;
    ensures \initialized(i_ptr);
  behavior type_error:
    assumes d->type != INT;
    ensures \result != 0;
  complete behaviors;
  disjoint behaviors;
*/
int data_integer(data_t *d, int *i_ptr);

/*@
  requires \valid(d);
  requires \valid(i_ptr);
  assigns *i_ptr;
  behavior success:
    assumes d->type == INT;
    ensures \result == 0;
    ensures \initialized(i_ptr);
  behavior type_error:
    assumes d->type != INT;
    ensures \result != 0;
  complete behaviors;
  disjoint behaviors;
*/
int data_l_integer(data_t *d, long *i_ptr);

/*@
  requires \valid(d);
  requires \valid(u_ptr);
  assigns *u_ptr;
  behavior success:
    assumes d->type == UINT;
    ensures \result == 0;
    ensures \initialized(u_ptr);
  behavior type_error:
    assumes d->type != UINT;
    ensures \result != 0;
  complete behaviors;
  disjoint behaviors;
*/
int data_u_integer(data_t *d, unsigned int *u_ptr);

/*@
  requires \valid(d);
  requires \valid(u_ptr);
  assigns *u_ptr;
  behavior success:
    assumes d->type == UINT;
    ensures \result == 0;
    ensures \initialized(u_ptr);
  behavior type_error:
    assumes d->type != UINT;
    ensures \result != 0;
  complete behaviors;
  disjoint behaviors;
*/
int data_ul_integer(data_t *d, unsigned long *u_ptr);

/*@
  requires \valid(d);
  requires \valid(f_ptr);
  assigns *f_ptr;
  behavior success:
    assumes d->type == FLOAT;
    ensures \result == 0;
    ensures \initialized(f_ptr);
  behavior type_error:
    assumes d->type != FLOAT;
    ensures \result != 0;
  complete behaviors;
  disjoint behaviors;
*/
int data_floating_pt(data_t *d, float *f_ptr);

/*@
  requires \valid(d);
  requires \valid(f_ptr);
  assigns *f_ptr;
  behavior success:
    assumes d->type == FLOAT;
    ensures \result == 0;
    ensures \initialized(f_ptr);
  behavior type_error:
    assumes d->type != FLOAT;
    ensures \result != 0;
  complete behaviors;
  disjoint behaviors;
*/
int data_floating_pt_dbl(data_t *d, double *f_ptr);

/*@
  requires \valid(d);
  requires \valid(b_ptr);
  assigns *b_ptr;
  behavior success:
    assumes d->type == BOOL;
    ensures \result == 0;
    ensures \initialized(b_ptr);
  behavior type_error:
    assumes d->type != BOOL;
    ensures \result != 0;
  complete behaviors;
  disjoint behaviors;
*/
int data_boolean(data_t *d, bool *b_ptr);

/*@
  requires \valid(d);
  requires max_len > 0;
  requires \valid(s + (0 .. max_len - 1));
  assigns s[0 .. max_len - 1];
  behavior success:
    assumes d->type == STRING;
    ensures \result == 0;
  behavior type_error:
    assumes d->type != STRING;
    ensures \result != 0;
  complete behaviors;
  disjoint behaviors;
*/
int data_string(data_t *d, string_t s, size_t max_len);

/*@
  requires \valid(d);
  requires \valid(s_ptr);
  assigns *s_ptr;
  behavior success:
    assumes d->type == STRING;
    ensures \result == 0;
    ensures \initialized(s_ptr);
  behavior type_error:
    assumes d->type != STRING;
    ensures \result != 0;
  complete behaviors;
  disjoint behaviors;
*/
int data_string_ptr(data_t *d, string_t *s_ptr);

/*@
  requires \valid(d);
  requires max_len > 0;
  requires \valid(b + (0 .. max_len - 1));
  assigns b[0 .. max_len - 1];
  behavior success:
    assumes d->type == BYTES;
    ensures \result == 0;
  behavior type_error:
    assumes d->type != BYTES;
    ensures \result != 0;
  complete behaviors;
  disjoint behaviors;
*/
int data_bytes(data_t *d, bytes_t b, size_t max_len);

/*@
  requires \valid(d);
  requires \valid(b_ptr);
  assigns *b_ptr;
  behavior success:
    assumes d->type == BYTES;
    ensures \result == 0;
    ensures \initialized(b_ptr);
  behavior type_error:
    assumes d->type != BYTES;
    ensures \result != 0;
  complete behaviors;
  disjoint behaviors;
*/
int data_bytes_ptr(data_t *d, bytes_t *b_ptr);

/*@
  requires \valid(d);
  requires max_len > 0;
  requires \valid((char *)o + (0 .. max_len - 1));
  assigns ((char *)o)[0 .. max_len - 1];
  behavior success:
    assumes d->type == OBJECT;
    ensures \result == 0;
  behavior type_error:
    assumes d->type != OBJECT;
    ensures \result != 0;
  complete behaviors;
  disjoint behaviors;
*/
int data_object(data_t *d, ptr_t o, size_t max_len);

/*@
  requires \valid(d);
  requires \valid(o_ptr);
  assigns *o_ptr;
  behavior success:
    assumes d->type == OBJECT;
    ensures \result == 0;
    ensures \initialized(o_ptr);
  behavior type_error:
    assumes d->type != OBJECT;
    ensures \result != 0;
  complete behaviors;
  disjoint behaviors;
*/
int data_object_ptr(data_t *d, ptr_t *o_ptr);


/*@
  requires \valid(a);
  requires \valid(b);
  assigns \nothing;
  ensures a == b ==> \result == true;
*/
bool data_equal(data_t *a, data_t *b);

#define EDAT_INVL 210
DECLARE_ERROR(EDAT_INVL, "Invalid data type");

#endif  // DATA_H
