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

#ifndef MSG_REGISTRY_H
#define MSG_REGISTRY_H

/** @addtogroup internal_utilities
 *  @{
 */

/**
 * @file msg_registry.h
 * @brief Runtime registry for IPC message types a feature adds to the core.
 *
 * The core's own message types (@ref message_type_t, ids below
 * @ref AT_MSG_TYPE_EXT_MIN) are named arms of `generic_msg_t.info` and are
 * serialized by the switches in msg_types.c. A FEATURE's types -- social, ZTA,
 * and whatever follows -- are not known to the core at compile time: each
 * registers an id, a name and a payload size here, and its payload rides the
 * opaque `info.payload` arm, read through @ref AT_MSG_EXT.
 *
 * NUMBERS ARE NOT ON ANY WIRE. The IPC hop carries the type as the
 * `google.protobuf.Any.type_url` NAME, which the receiver maps back to an id.
 * Ids are process-local, so the ranges below exist only so that two features
 * never collide, not for compatibility; the NAME is the stable identifier and
 * must never change once a type has shipped.
 *
 * See doc/architecture/extensions.md.
 */

#include <stdbool.h>
#include <stddef.h>

/** @brief Bytes of the opaque payload arm of `generic_msg_t.info`.
 *
 *  A fixed cap, not a pointer, so that messages stay copy-by-value through the
 *  queue and no allocation is needed on the hot path. The core must size it
 *  for payloads it cannot see; 8 KiB clears the widest today
 *  (peer_cosign_request_msg_t, 6,384 B) with headroom. Every registered
 *  payload is pinned against it with @ref AT_MSG_ASSERT_FITS. Changing it is
 *  an IPC-ABI change for every linked feature library. */
#define AT_MSG_PAYLOAD_MAX 8192

/** @name Reserved id ranges
 *  Core ids are the @ref message_type_t enum and never registered. @{ */
#define AT_MSG_TYPE_CORE_MIN     1
#define AT_MSG_TYPE_CORE_MAX     999
#define AT_MSG_TYPE_EXT_MIN      1000
#define AT_MSG_TYPE_SOCIAL_MIN   1000
#define AT_MSG_TYPE_SOCIAL_MAX   1999
#define AT_MSG_TYPE_ZTA_MIN      2000
#define AT_MSG_TYPE_ZTA_MAX      2099
#define AT_MSG_TYPE_FLEET_MIN    2100
#define AT_MSG_TYPE_FLEET_MAX    2199
#define AT_MSG_TYPE_FC_MIN       2200
#define AT_MSG_TYPE_FC_MAX       2219
#define AT_MSG_TYPE_STELE_MIN    2300
#define AT_MSG_TYPE_STELE_MAX    2309
#define AT_MSG_TYPE_EXT_MAX      2309
/** @} */

/** @brief Ceiling on registered types across all features. */
#define AT_MSG_TYPE_REGISTRY_MAX 64

/** @brief How one registered message type is serialized across IPC.
 *
 *  A NULL @c to_proto / @c from_proto means "fixed-size raw copy of @c size
 *  bytes", which is what every social and ZTA payload is today. The decoder
 *  rejects a value shorter than @c size (see COPY_FIXED_PAYLOAD). */
typedef struct {
    /** The `Any.type_url`. Unique across core and extensions; stable forever. */
    const char *name;
    /** Payload bytes in `info.payload`; must be <= @ref AT_MSG_PAYLOAD_MAX. */
    size_t size;
    /** Serialize @p payload into a fresh smrt buffer at *@p data. */
    int (*to_proto)(const void *payload, void **data, size_t *data_len);
    /** Deserialize @p data into @p payload (AT_MSG_PAYLOAD_MAX bytes). */
    int (*from_proto)(const void *data, size_t data_len, void *payload);
    /** True iff the main process forwards this type, when it drains it from
     *  its own queue, to the attached app's queue. */
    bool app_bound;
} at_msg_vtable_t;

/**
 * @brief Register message type @p id.
 *
 * Call from a constructor (@ref AT_MSG_TYPE_REGISTER). The vtable is kept by
 * pointer, so it must have static storage.
 *
 * @return 0; -1 if @p id is outside the extension range, @p vt is malformed or
 *         oversized, or the id or name is already taken (by the core or by
 *         another extension); -2 if the registry is full. A refused
 *         registration is also logged, because it happens before main() where
 *         nothing else would see it.
 */
int at_msg_type_register(long id, const at_msg_vtable_t *vt);

/** @brief The vtable registered for @p id, or NULL. */
const at_msg_vtable_t *at_msg_type_lookup(long id);

/** @brief The registered id named @p name, or -1. Extensions only. */
long at_msg_type_by_name(const char *name);

/** @brief Number of registered types. */
size_t at_msg_type_count(void);

/** @brief The id of the @p i-th registered type, or -1 past the end. */
long at_msg_type_id_at(size_t i);

/** @brief Register @p id with vtable @p vt at load time.
 *
 *  Same constructor pattern as DEFINE_PROCESS (process_tracker.h). A static
 *  link drops a constructor whose translation unit nothing references, so
 *  each feature also exports an anchor symbol that the core's callers of the
 *  feature reference (at_zta_msg_types_link, for one). */
#define AT_MSG_TYPE_REGISTER(tag, id, vt)                                      \
    static void __attribute__((constructor)) at_msg_type_register_##tag(void)  \
    {                                                                          \
        (void)at_msg_type_register((id), (vt));                                \
    }

/** @brief Compile-time pin that payload type @p T fits the opaque arm. */
#define AT_MSG_ASSERT_FITS(T)                                                  \
    _Static_assert(sizeof(T) <= AT_MSG_PAYLOAD_MAX,                            \
                   #T " exceeds AT_MSG_PAYLOAD_MAX")

/** @brief Typed view of @p msg's opaque payload as a @p T.
 *
 *  @p msg is a `generic_msg_t *` (or `const generic_msg_t *`, which the
 *  const-qualified variant below preserves). Only for registered types; a
 *  core type is read through its named arm. */
#define AT_MSG_EXT(msg, T)       ((T *)(void *)(msg)->info.payload)
#define AT_MSG_EXT_CONST(msg, T) ((const T *)(const void *)(msg)->info.payload)

/**
 * @name App verbs
 *
 * The app reaches the core by sending a NET_MESSAGE whose `function` names a
 * verb; at_route_extern_msg forwards only verbs on an explicit allowlist, each
 * to one fixed process, so an app never gets the whole internal verb surface.
 * The core's own verbs are hard-wired there. A feature adds its verbs here.
 * @{
 */

/** @brief Ceiling on registered app verbs across all features. */
#define AT_APP_VERB_REGISTRY_MAX 64

/** @brief Allow app verb @p verb, forwarded only to process @p target.
 *
 *  Both strings must have static storage. @return 0; -1 if either is empty or
 *  @p verb is already registered; -2 if the registry is full. */
int at_app_verb_register(const char *verb, const char *target);

/** @brief The process @p verb is forwarded to, or NULL if nobody registered it. */
const char *at_app_verb_target(const char *verb);

/** @brief Register an app verb at load time (see @ref AT_MSG_TYPE_REGISTER). */
#define AT_APP_VERB_REGISTER(tag, verb, target)                                \
    static void __attribute__((constructor)) at_app_verb_register_##tag(void)  \
    {                                                                          \
        (void)at_app_verb_register((verb), (target));                          \
    }
/** @} */

/** @} */ /* end of internal_utilities */

#endif  // MSG_REGISTRY_H
