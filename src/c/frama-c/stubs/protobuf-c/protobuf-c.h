/********************
 *  Copyright 2026 TekFive, Inc., Sean M. Brennan, and contributors
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

/* Frama-C stub wrapper: redirect <protobuf-c/protobuf-c.h> to stubs.
   Provides the macros and types that generated .pb-c.h files expect. */
#ifndef PROTOBUF_C__PROTOBUF_C_H
#define PROTOBUF_C__PROTOBUF_C_H

/* Version macros — satisfy the generated version check */
#define PROTOBUF_C_VERSION_NUMBER 1005002
#define PROTOBUF_C_MIN_COMPILER_VERSION 1000000

/* Scope macros */
#ifdef __cplusplus
#define PROTOBUF_C__BEGIN_DECLS extern "C" {
#define PROTOBUF_C__END_DECLS }
#else
#define PROTOBUF_C__BEGIN_DECLS
#define PROTOBUF_C__END_DECLS
#endif

/* Force enum to int size — generated .pb-c.h files use this */
#include <limits.h>
#ifndef PROTOBUF_C__FORCE_ENUM_TO_BE_INT_SIZE
#define PROTOBUF_C__FORCE_ENUM_TO_BE_INT_SIZE(enum_name) \
  , _##enum_name##_IS_INT_SIZE = INT_MAX
#endif

/* Message initialiser macro — used in INIT macros for each message type */
#define PROTOBUF_C_MESSAGE_INIT(descriptor) { (descriptor) }

/* Bool type for protobuf fields */
typedef int protobuf_c_boolean;

/* Pull in the type definitions from the existing stubs */
#include "../protobuf_stubs.h"

#endif /* PROTOBUF_C__PROTOBUF_C_H */
