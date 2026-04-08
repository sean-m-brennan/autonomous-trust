/**
 * @file protobuf_stubs.h
 * @brief ACSL-annotated stub declarations for protobuf-c runtime functions
 *        used by AutonomousTrust.  The project uses protobuf-c generated code
 *        for serialisation of Identity, Group, Task, Capability, and
 *        google.protobuf.Any messages.
 *
 * Generated protobuf-c code follows a uniform pattern per message type T:
 *   - T__get_packed_size(const T *msg)          -> size_t
 *   - T__pack(const T *msg, uint8_t *out)       -> size_t
 *   - T__unpack(alloc, len, data)               -> T *
 *   - T__free_unpacked(T *msg, alloc)           -> void
 *   - T__init(T *msg)                           -> void
 *
 * Rather than stub every generated function individually, we provide
 * generic contracts that match the protobuf-c calling convention.
 * The actual generated headers (*.pb-c.h) supply the real prototypes;
 * these contracts are applied via Frama-C's -wp-model or merge headers.
 *
 * Copyright 2025 Sean M. Brennan and contributors
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef PROTOBUF_STUBS_H
#define PROTOBUF_STUBS_H

#include <stddef.h>
#include <stdint.h>

/* ================================================================
 * protobuf-c allocator — NULL means use default (malloc/free).
 * We model it as an opaque pointer.
 * ================================================================ */

typedef struct ProtobufCAllocator ProtobufCAllocator;

/* ================================================================
 * ProtobufCMessageDescriptor — opaque, used for type introspection.
 * We only need the c_name field for the codebase's type-name lookups.
 * ================================================================ */

typedef struct {
    unsigned int     magic;
    const char      *name;
    const char      *short_name;
    const char      *c_name;
    const char      *package_name;
    /* remaining fields omitted for stub purposes */
} ProtobufCMessageDescriptor;

/* ================================================================
 * ProtobufCMessage — base type for all generated message structs.
 * Every generated struct starts with this as its first member.
 * ================================================================ */

typedef struct {
    const ProtobufCMessageDescriptor *descriptor;
} ProtobufCMessage;

/* ================================================================
 * ProtobufCBinaryData — used for bytes fields.
 * ================================================================ */

typedef struct {
    size_t   len;
    uint8_t *data;
} ProtobufCBinaryData;

/* ================================================================
 * Generic pack/unpack contracts.
 *
 * These model the protobuf-c generated function families.  In the
 * project, the actual calls use fully-qualified names like:
 *   autonomous_trust__core__protobuf__identity__identity__pack(...)
 *
 * Frama-C processes these via the generated *.pb-c.h headers.
 * The contracts below document the expected calling convention.
 * ================================================================ */

/* -- get_packed_size -------------------------------------------- */

/*@
  // T__get_packed_size(const T *message) -> size_t
  //
  // Generic contract for any protobuf-c get_packed_size function.
  //
  // requires \valid_read(message);
  // assigns  \nothing;
  // ensures  \result >= 0;
  //
  // (Applied to the concrete generated functions via separate
  //  annotation files or -wp-model directives.)
*/

/* -- pack ------------------------------------------------------ */

/*@
  // T__pack(const T *message, uint8_t *out) -> size_t
  //
  // Generic contract:
  //
  // requires \valid_read(message);
  // requires \valid(out + (0 .. T__get_packed_size(message) - 1));
  // assigns  out[0 .. \result - 1];
  // ensures  \result == T__get_packed_size(message);
*/

/* -- unpack ---------------------------------------------------- */

/*@
  // T__unpack(ProtobufCAllocator *allocator, size_t len,
  //           const uint8_t *data) -> T *
  //
  // Generic contract:
  //
  // requires allocator == \null || \valid(allocator);
  // requires len > 0;
  // requires \valid_read(data + (0 .. len - 1));
  // allocates \result;
  // ensures  \result == \null || \valid(\result);
  //   // NULL = parse error or OOM
*/

/* -- free_unpacked --------------------------------------------- */

/*@
  // T__free_unpacked(T *message, ProtobufCAllocator *allocator)
  //
  // Generic contract:
  //
  // requires message == \null || \valid(message);
  // requires allocator == \null || \valid(allocator);
  // frees    message;
  // assigns  \nothing;
*/

/* -- init ------------------------------------------------------ */

/*@
  // T__init(T *message)
  //
  // Generic contract:
  //
  // requires \valid(message);
  // assigns  *message;
  //   // Initialises all fields to their default values.
*/

/* ================================================================
 * Concrete stubs for google.protobuf.Any — the project uses this
 * wrapper type directly in msg_types.c.
 * ================================================================ */

/* Forward-declare the generated struct */
typedef struct Google__Protobuf__Any {
    ProtobufCMessage base;
    char            *type_url;
    ProtobufCBinaryData value;
} Google__Protobuf__Any;

extern const ProtobufCMessageDescriptor google__protobuf__any__descriptor;

/*@
  requires \valid(message);
  assigns *message;
*/
void google__protobuf__any__init(Google__Protobuf__Any *message);

/*@
  requires \valid_read(message);
  assigns \nothing;
  ensures \result >= 0;
*/
size_t google__protobuf__any__get_packed_size(
    const Google__Protobuf__Any *message);

/*@
  requires \valid_read(message);
  requires \valid(out + (0 .. google__protobuf__any__get_packed_size(message) - 1));
  assigns out[0 .. \result - 1];
  ensures \result == google__protobuf__any__get_packed_size(message);
*/
size_t google__protobuf__any__pack(
    const Google__Protobuf__Any *message,
    uint8_t *out);

/*@
  requires allocator == \null || \valid(allocator);
  requires len > 0;
  requires \valid_read(data + (0 .. len - 1));
  allocates \result;
  ensures \result == \null || \valid(\result);
*/
Google__Protobuf__Any *google__protobuf__any__unpack(
    ProtobufCAllocator *allocator,
    size_t len,
    const uint8_t *data);

/*@
  requires message == \null || \valid(message);
  requires allocator == \null || \valid(allocator);
  frees message;
  assigns \nothing;
*/
void google__protobuf__any__free_unpacked(
    Google__Protobuf__Any *message,
    ProtobufCAllocator *allocator);

/* ================================================================
 * Shutdown helper — called from autonomous_trust.c via the C++
 * wrapper in protobuf_shutdown.cpp.
 * ================================================================ */

/*@
  assigns \nothing;
  // Frees internal protobuf library state.  Must be called at most once.
*/
void shutdown_protobuf_library(void);

#endif /* PROTOBUF_STUBS_H */
