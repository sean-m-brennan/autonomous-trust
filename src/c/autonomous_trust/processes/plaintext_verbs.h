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

#ifndef AT_PLAINTEXT_VERBS_H
#define AT_PLAINTEXT_VERBS_H

/**
 * @file plaintext_verbs.h
 * @brief The optional half of the plaintext receive policy: which extension
 *        verbs a receiver accepts UNENCRYPTED from a peer it already knows.
 *
 * FEATURE_SPLIT_PLAN Phase 7, hook C5 (decision D8). The core's own plaintext
 * verbs are compiled into identity (ID_UNENCRYPTED_VERBS) and no configuration
 * adds to or removes from them, so no configuration can downgrade the core. An
 * optional feature's come from `<cfg_dir>/unencrypted_verbs.cfg.json`, read at
 * startup, of the form `{"verbs": ["first_contact_hello", ...]}`. A feature
 * only DECLARES which of its verbs may arrive in the clear
 * (at_extension_t.plaintext_verbs); the operator's file GRANTS them.
 *
 * The rules, decided 2026-10-02, mirrored by Python's plaintext_verbs.py:
 *  - no file: the core verbs only;
 *  - a malformed file refuses the start (not an object holding exactly
 *    "verbs", a list of at most @ref PLAINTEXT_VERBS_MAX distinct non-empty
 *    names of at most @ref PLAINTEXT_VERB_LEN characters);
 *  - a verb no ENABLED extension declares -- a core verb such as
 *    group_key_update, or a feature's verb with that feature off -- refuses;
 *  - an enabled extension whose declared verbs the file does not all name
 *    refuses, naming the file and the missing verbs.
 */

#include <stdbool.h>
#include <stddef.h>

#include "utilities/logger.h"

/** The file, in the node's configuration directory. */
#define PLAINTEXT_VERBS_FILENAME "unencrypted_verbs.cfg.json"
/** Most verbs the file may name. */
#define PLAINTEXT_VERBS_MAX 32
/** Longest verb name the file may hold. */
#define PLAINTEXT_VERB_LEN 64

/** Apply @p cfg_dir's file (NULL: get_cfg_dir) for the enabled extensions.
 *  @return 0, with the granted verbs in force; -1 after logging an ERROR that
 *  names the file and the fault, with the previous grant left in force. */
int plaintext_verbs_configure(const char *cfg_dir, logger_t *logger);

/** True iff the last successful configure granted @p verb. */
bool plaintext_verb_granted(const char *verb);

/** How many verbs the last successful configure granted. */
size_t plaintext_verbs_granted_count(void);

/** Back to the core verbs only (tests, conformance). */
void plaintext_verbs_reset(void);

#endif /* AT_PLAINTEXT_VERBS_H */
