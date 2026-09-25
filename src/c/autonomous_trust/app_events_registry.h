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

#ifndef AT_APP_EVENTS_REGISTRY_H
#define AT_APP_EVENTS_REGISTRY_H

/** @addtogroup internal_utilities
 *  @{
 */

/**
 * @file app_events_registry.h
 * @brief How a feature adds event kinds to the flat app-event ABI.
 *
 * INTERNAL: for a feature linked into (or against) the core, never for an app.
 * at_app_events_poll translates the core's three app-facing message types
 * itself; for any other message it drains, it asks this registry for a
 * decoder keyed by the message's type. A feature registers one decoder per
 * app-bound message type it defines (Agora's libat_social is one), writes
 * its payload with @ref AT_APP_EVENT_EXT, and ships its own public header
 * (at_agora.h) for consumers.
 *
 * See doc/architecture/extensions.md.
 */

#include <stdbool.h>

#include "app_events.h"
#include "utilities/msg_types.h"

/** @brief Ceiling on registered decoders across all features. */
#define AT_APP_EVENT_DECODER_MAX 64

/** @brief Fill @p ev (already zeroed) from @p msg. Set @c ev->kind.
 *  @return 0 to deliver the event, non-zero to skip the message. */
typedef int (*at_app_event_decoder_t)(const generic_msg_t *msg, at_app_event_t *ev);

/** @brief Decode messages of type @p msg_type with @p fn.
 *  @return 0; -1 on a NULL decoder, a non-extension type or a duplicate;
 *          -2 if the registry is full. */
int at_app_event_decoder_register(long msg_type, at_app_event_decoder_t fn);

/** @brief The decoder for @p msg_type, or NULL. */
at_app_event_decoder_t at_app_event_decoder_lookup(long msg_type);

/** @brief Register a decoder at load time (see AT_MSG_TYPE_REGISTER). */
#define AT_APP_EVENT_DECODER_REGISTER(tag, msg_type, fn)                       \
    static void __attribute__((constructor))                                   \
    at_app_event_decoder_register_##tag(void)                                  \
    {                                                                          \
        (void)at_app_event_decoder_register((msg_type), (fn));                 \
    }

/** @brief Writable view of @p ev's payload as a @p T, for a decoder. */
#define AT_APP_EVENT_EXT(ev, T) ((T *)(void *)(ev)->data.payload)

/** @brief True iff queue name @p name survives the messaging layer intact.
 *  Shared by every flat entry point that takes a queue name. */
bool at_app_name_survives(const char *name);

/** @} */ /* end of internal_utilities */

#endif /* AT_APP_EVENTS_REGISTRY_H */
