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

#ifndef AT_EXTENSION_H
#define AT_EXTENSION_H

/** @addtogroup internal_processes
 *  @{
 */

/**
 * @file extension.h
 * @brief How an optional feature attaches its handlers to the core processes.
 *
 * A feature (first contact today; Agora, ZTA and the rest as they leave the
 * core) registers one @ref at_extension_t from a constructor. Each core
 * process's handler registration ends by asking the registry to let every
 * ENABLED extension register its verbs for that process -- so the core names
 * no feature, and a node that does not enable one is unaffected by it.
 *
 * Message types, app verbs, app-event decoders and transports have registries
 * of their own (msg_registry.h, app_events_registry.h, net_transport.h); this
 * one is only for process handlers and per-scenario reset.
 *
 * See doc/architecture/extensions.md.
 */

#include <stdbool.h>

#include "processes/processes.h"

/** @brief Ceiling on registered extensions. */
#define AT_EXTENSION_MAX 16

/** @brief One optional feature. All members but @c name may be NULL. */
typedef struct {
    /** Unique; for logs. */
    const char *name;
    /** Whether the feature is on. Called EVERY time handlers are registered,
     *  never cached: a gate may be read from the environment, and the
     *  conformance harness flips it between scenarios. NULL means always on. */
    bool (*enabled)(void);
    /** Register this feature's handlers on @p proc, which is the process named
     *  @p proc_name ("identity", "reputation", "negotiation", "network").
     *  Return 0, or non-zero on failure (logged; the other extensions still
     *  register). */
    int (*register_handlers)(process_t *proc, const char *proc_name);
    /** Drop all of the feature's process-global state (tests / conformance). */
    void (*reset)(void);
    /** The wire verbs this feature may receive UNENCRYPTED from a known peer,
     *  NULL-terminated; NULL for none. Declaring them grants nothing: the
     *  operator's unencrypted_verbs.cfg.json must name them, and an enabled
     *  extension whose verbs it does not name refuses the start
     *  (processes/plaintext_verbs.h). */
    const char *const *plaintext_verbs;
} at_extension_t;

/** @brief Register @p ext. Keeps the pointer, so it must have static storage.
 *  @return 0; -1 on a NULL/unnamed extension or a duplicate name; -2 if the
 *  registry is full. Refusals are printed to stderr (this runs before main). */
int at_extension_register(const at_extension_t *ext);

/** @brief Let every enabled extension register its handlers for @p proc.
 *  @return 0, or the number of extensions whose registration failed. */
int at_extensions_register_handlers(process_t *proc, const char *proc_name);

/** @brief Call every extension's @c reset, enabled or not. */
void at_extensions_reset(void);

/** @brief Number of registered extensions (tests). */
size_t at_extension_count(void);

/** @brief True iff an extension named @p name is registered, enabled or not. */
bool at_extension_present(const char *name);

/** @brief The extensions whose @c enabled says they are on now, in
 *  registration order; at most @p max into @p out. Returns how many. */
size_t at_extensions_enabled(const at_extension_t **out, size_t max);

/** @brief Register @p ext at load time (see AT_MSG_TYPE_REGISTER). */
#define AT_EXTENSION_REGISTER(tag, ext)                                        \
    static void __attribute__((constructor)) at_extension_register_##tag(void) \
    {                                                                          \
        (void)at_extension_register(ext);                                      \
    }

/** @} */ /* end of internal_processes */

#endif /* AT_EXTENSION_H */
