/**
 * @file jansson_stubs.h
 * @brief ACSL-annotated stub declarations for jansson JSON library functions
 *        used by AutonomousTrust.  Frama-C/WP uses these contracts to reason
 *        about JSON manipulation without analysing jansson itself.
 *
 * JSON values are modelled as opaque pointers.  We track:
 *   - non-NULL returns from constructors (success) vs NULL (OOM)
 *   - ownership: "new" references that the caller must eventually decref
 *   - borrowed references returned by getters (caller must NOT free)
 *   - malloc'd strings from json_dumps (caller must free)
 *
 * Copyright 2025 Sean M. Brennan and contributors
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef JANSSON_STUBS_H
#define JANSSON_STUBS_H

#include <stddef.h>
#include <stdint.h>

/* ================================================================
 * Opaque JSON type — mirrors jansson's json_t.
 * For Frama-C purposes we only need the typedef.
 * ================================================================ */

#ifndef JANSSON_H  /* avoid redefinition if real jansson.h is also visible */

typedef long long json_int_t;

typedef struct json_t {
    unsigned int type;
    size_t refcount;
} json_t;

/* json_type enum values */
#define JSON_OBJECT  0
#define JSON_ARRAY   1
#define JSON_STRING  2
#define JSON_INTEGER 3
#define JSON_REAL    4
#define JSON_TRUE    5
#define JSON_FALSE   6
#define JSON_NULL    7

/* json_dumps flags */
#define JSON_COMPACT 0x20

/* Type check macros — modelled as functions for ACSL */
/*@ ghost
  /@ assigns \nothing;
     ensures \result == 0 || \result == 1; @/
  int json_is_object_g(const json_t *j);

  /@ assigns \nothing;
     ensures \result == 0 || \result == 1; @/
  int json_is_array_g(const json_t *j);

  /@ assigns \nothing;
     ensures \result == 0 || \result == 1; @/
  int json_is_string_g(const json_t *j);

  /@ assigns \nothing;
     ensures \result == 0 || \result == 1; @/
  int json_is_integer_g(const json_t *j);

  /@ assigns \nothing;
     ensures \result == 0 || \result == 1; @/
  int json_is_boolean_g(const json_t *j);
*/

#define json_typeof(json) ((json)->type)
#define json_is_object(json)  (json != NULL && json_typeof(json) == JSON_OBJECT)
#define json_is_array(json)   (json != NULL && json_typeof(json) == JSON_ARRAY)
#define json_is_string(json)  (json != NULL && json_typeof(json) == JSON_STRING)
#define json_is_integer(json) (json != NULL && json_typeof(json) == JSON_INTEGER)
#define json_is_real(json)    (json != NULL && json_typeof(json) == JSON_REAL)
#define json_is_true(json)    (json != NULL && json_typeof(json) == JSON_TRUE)
#define json_is_false(json)   (json != NULL && json_typeof(json) == JSON_FALSE)
#define json_is_null(json)    (json != NULL && json_typeof(json) == JSON_NULL)
#define json_is_boolean(json) (json_is_true(json) || json_is_false(json))

/* json_object_foreach helper macros (opaque iteration) */
#define json_object_foreach(object, key, value)                         \
    for (key = json_object_iter_key(json_object_iter(object));          \
         key && (value = json_object_iter_value(                        \
                     json_object_key_to_iter(key)));                    \
         key = json_object_iter_key(json_object_iter_next(              \
                   object, json_object_key_to_iter(key))))

#endif /* JANSSON_H */

/* ================================================================
 * Constructors — return a NEW reference (refcount == 1).
 * Return NULL only on allocation failure.
 * ================================================================ */

/*@
  allocates \result;
  assigns \nothing;
  ensures \result == \null || \valid(\result);
*/
json_t *json_object(void);

/*@
  allocates \result;
  assigns \nothing;
  ensures \result == \null || \valid(\result);
*/
json_t *json_array(void);

/*@
  requires \valid_read(value);
  allocates \result;
  assigns \nothing;
  ensures \result == \null || \valid(\result);
*/
json_t *json_string(const char *value);

/*@
  allocates \result;
  assigns \nothing;
  ensures \result == \null || \valid(\result);
*/
json_t *json_integer(json_int_t value);

/*@
  allocates \result;
  assigns \nothing;
  ensures \result == \null || \valid(\result);
*/
json_t *json_real(double value);

/*@
  assigns \nothing;
  ensures \result != \null && \valid(\result);
*/
json_t *json_true(void);

/*@
  assigns \nothing;
  ensures \result != \null && \valid(\result);
*/
json_t *json_false(void);

/*@
  assigns \nothing;
  ensures \result != \null && \valid(\result);
*/
json_t *json_null(void);

/*@
  allocates \result;
  assigns \nothing;
  ensures \result == \null || \valid(\result);
*/
json_t *json_boolean(int value);

/* ================================================================
 * json_pack — variadic constructor.
 * Models as returning a new reference or NULL.
 * ================================================================ */

/*@
  requires \valid_read(fmt);
  allocates \result;
  assigns \nothing;
  ensures \result == \null || \valid(\result);
*/
json_t *json_pack(const char *fmt, ...);

/* ================================================================
 * Object mutators — "set_new" steals the reference to value.
 * Return 0 on success, -1 on error.
 * ================================================================ */

/*@
  requires \valid(object);
  requires \valid_read(key);
  requires \valid(value);
  assigns *object;
  ensures \result == 0 || \result == -1;
*/
int json_object_set_new(json_t *object, const char *key, json_t *value);

/*@
  requires \valid(object);
  requires \valid_read(key);
  requires \valid(value);
  assigns *object;
  ensures \result == 0 || \result == -1;
*/
int json_object_set(json_t *object, const char *key, json_t *value);

/* ================================================================
 * Array mutators — "append_new" steals the reference to value.
 * Return 0 on success, -1 on error.
 * ================================================================ */

/*@
  requires \valid(array);
  requires \valid(value);
  assigns *array;
  ensures \result == 0 || \result == -1;
*/
int json_array_append_new(json_t *array, json_t *value);

/*@
  requires \valid(array);
  requires \valid(value);
  assigns *array;
  ensures \result == 0 || \result == -1;
*/
int json_array_append(json_t *array, json_t *value);

/* ================================================================
 * Object getters — return BORROWED references (do not decref).
 * Return NULL if key is not present.
 * ================================================================ */

/*@
  requires \valid_read(object);
  requires \valid_read(key);
  assigns \nothing;
  ensures \result == \null || \valid(\result);
*/
json_t *json_object_get(const json_t *object, const char *key);

/*@
  requires \valid_read(object);
  assigns \nothing;
  ensures \result >= 0;
*/
size_t json_object_size(const json_t *object);

/* ================================================================
 * Object iteration helpers.
 * ================================================================ */

/*@
  requires \valid(object);
  assigns \nothing;
*/
void *json_object_iter(json_t *object);

/*@
  requires \valid(object);
  assigns \nothing;
*/
void *json_object_iter_next(json_t *object, void *iter);

/*@
  assigns \nothing;
  ensures \result == \null || \valid_read(\result);
*/
const char *json_object_iter_key(void *iter);

/*@
  assigns \nothing;
  ensures \result == \null || \valid(\result);
*/
json_t *json_object_iter_value(void *iter);

/*@
  requires \valid_read(key);
  assigns \nothing;
*/
void *json_object_key_to_iter(const char *key);

/* ================================================================
 * Array getters — return BORROWED references.
 * ================================================================ */

/*@
  requires \valid_read(array);
  assigns \nothing;
  ensures \result >= 0;
*/
size_t json_array_size(const json_t *array);

/*@
  requires \valid_read(array);
  requires index < json_array_size(array);
  assigns \nothing;
  ensures \result == \null || \valid(\result);
*/
json_t *json_array_get(const json_t *array, size_t index);

/* ================================================================
 * Value extractors — these return plain-old-data copies.
 * ================================================================ */

/*@
  requires \valid_read(string);
  assigns \nothing;
  ensures \result == \null || \valid_read(\result);
*/
const char *json_string_value(const json_t *string);

/*@
  requires \valid_read(integer);
  assigns \nothing;
*/
json_int_t json_integer_value(const json_t *integer);

/*@
  requires \valid_read(real);
  assigns \nothing;
*/
double json_real_value(const json_t *real);

/*@
  requires \valid_read(json);
  assigns \nothing;
*/
double json_number_value(const json_t *json);

/*@
  requires \valid_read(boolean);
  assigns \nothing;
  ensures \result == 0 || \result == 1;
*/
int json_boolean_value(const json_t *boolean);

/* ================================================================
 * Serialisation / Deserialisation
 * ================================================================ */

/*@
  requires \valid_read(root);
  allocates \result;
  assigns \nothing;
  ensures \result == \null || \valid(\result);
  // Caller must free() the returned string.
*/
char *json_dumps(const json_t *root, size_t flags);

/*@
  requires \valid_read(buffer + (0 .. buflen - 1));
  requires error == \null || \valid(error);
  allocates \result;
  assigns *error \from buffer[0 .. buflen - 1], flags;
  ensures \result == \null || \valid(\result);
*/
json_t *json_loadb(const char *buffer, size_t buflen,
                   size_t flags, void *error);

/*@
  requires \valid_read(input);
  requires error == \null || \valid(error);
  allocates \result;
  assigns *error \from input[..], flags;
  ensures \result == \null || \valid(\result);
*/
json_t *json_loads(const char *input, size_t flags, void *error);

/* ================================================================
 * Reference counting
 * ================================================================ */

/*@
  requires json != \null ==> \valid(json);
  assigns *json;
  ensures \result == json;
*/
json_t *json_incref(json_t *json);

/*@
  requires json == \null || \valid(json);
  frees json;
  assigns *json;
*/
void json_decref(json_t *json);

#endif /* JANSSON_STUBS_H */
