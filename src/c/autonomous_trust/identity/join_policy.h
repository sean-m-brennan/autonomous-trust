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

/** @file The join-policy declaration (R+D.md §14.4,
 *  RD_14.4_HOSTILE_JOIN_PLAN.md): how a joiner treats the cohort it joins.
 *
 *  `{"version": 1, "enabled": true, "anchors": ["verified_contact", ...]}`,
 *  named by $AT_JOIN_POLICY. Opt-in (the user's call, D9): absent is inert,
 *  and a declaration that does not validate stops the node at start. The
 *  declaration chooses which anchor classes count (D6); an identity extension
 *  answers for each (id_ext.h, anchor_classes). Unknown keys are refused,
 *  "note" aside, since a misspelled key would turn part of it off without a
 *  word. The Python twin is core/_python/identity/join_policy.py; the two
 *  parse the same bytes into the same policy.
 */

#ifndef JOIN_POLICY_H
#define JOIN_POLICY_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/** Environment variable naming the declaration file. */
#define AT_JOIN_POLICY_ENV "AT_JOIN_POLICY"

/** Anchor classes, as bits. Names as on the wire of the declaration. */
/** A contact whose safety number was compared, or a device its operator
 *  vouched for ("verified_contact"). */
#define AT_ANCHOR_VERIFIED_CONTACT   (1u << 0)
/** A contact not (yet) verified: possession of a ticket only
 *  ("unverified_contact"). */
#define AT_ANCHOR_UNVERIFIED_CONTACT (1u << 1)
/** A ZTA credential chaining to one of our anchors, bound to the identity
 *  ("zta"). */
#define AT_ANCHOR_ZTA                (1u << 2)
/** A node under THIS node's operator key: a verified operator-key binding or
 *  a sibling device ("operator"). */
#define AT_ANCHOR_OPERATOR           (1u << 3)
#define AT_ANCHOR_ALL                (0xFu)

typedef struct {
    bool enabled;
    uint32_t anchors;   /* AT_ANCHOR_* bits declared */
} at_join_policy_t;

/** The class bit for @p name, or 0 when it names none. */
uint32_t at_join_policy_class(const char *name);

/** The declaration name of one class bit, or NULL. */
const char *at_join_policy_class_name(uint32_t bit);

/** Parse @p text (NUL-terminated JSON) into @p out; NULL text is the inert
 *  policy. @return true, or false with a reason in @p err (and @p out
 *  zeroed). */
bool at_join_policy_parse(const char *text, at_join_policy_t *out,
                          char *err, size_t err_len);

/** Read and parse the declaration at @p path. */
bool at_join_policy_load(const char *path, at_join_policy_t *out,
                         char *err, size_t err_len);

/** Load the declaration $AT_JOIN_POLICY names, or the inert policy when it is
 *  unset or empty. */
bool at_join_policy_load_env(at_join_policy_t *out, char *err, size_t err_len);

/** The declared classes of an enabled @p policy that no linked identity
 *  extension can answer (first_contact for contacts, zta for credentials,
 *  either for operator), as bits; 0 when all can be. */
uint32_t at_join_policy_missing_providers(const at_join_policy_t *policy);

#endif /* JOIN_POLICY_H */
