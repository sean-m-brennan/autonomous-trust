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
#ifndef AT_CONTACTS_AREA_CARD_H
#define AT_CONTACTS_AREA_CARD_H

/**
 * @file area_card.h
 * @brief Area cards: a person's opt-in "I am around here", filed at a hub.
 * C twin of Python contacts/area_card.py: same format, same checks in the
 * same order, same refusal reasons.
 *
 *     Card := holder over "at-area-card-v1|" + body
 *       body := {v, typename: "at-area-card", uuid, key, area, bucket, name,
 *                seq, expiry, identity}
 *
 * @c area is the geohash prefix a hub serves, @c bucket the holder's own
 * coarse bucket inside it, @c name what the holder calls themself, and
 * @c identity their public identity with the address blank: what a finder
 * addresses a contact request to. Nobody attests nearness, so a card carries
 * no attestation; the hub bounds it (network/net_hub.h).
 */

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "contacts/directory.h"
#include "identity/identity.h"

#define AT_AREA_CARD_DOMAIN "at-area-card-v1|"
#define AT_AREA_CARD_TYPENAME "at-area-card"
#define AT_AREA_CARD_VERSION 1
/** Shortest and longest area, and the longest bucket. Same as Python's. */
#define AT_AREA_MIN 2
#define AT_AREA_MAX 5
#define AT_AREA_BUCKET_MAX 5
/** Longest name, in UTF-8 bytes. Same as Python's NAME_MAX. */
#define AT_AREA_NAME_MAX 64
/** A card's default life, and the longest a hub accepts. Same as Python's. */
#define AT_AREA_DEFAULT_TTL_SECONDS 3600
#define AT_AREA_MAX_TTL_SECONDS (24 * 3600)
/** Where a node keeps its own listings, in its data dir. Same as Python's. */
#define AT_AREA_STATE_FILENAME "area.cfg.json"

/** @p in folded to lower case into @p out (room for @p max_len + 1): 0, or
 *  -1 when it is not a geohash prefix of @p min_len .. @p max_len chars. */
int at_area_normalize(const char *in, char *out, size_t out_len, size_t min_len,
                      size_t max_len);
/** True iff @p in is already a normalized area (AT_AREA_MIN..AT_AREA_MAX). */
bool at_area_is_area(const char *in);
/** True iff @p name is a card name: at most AT_AREA_NAME_MAX bytes, no
 *  control character. */
bool at_area_valid_name(const char *name);

/** Verify a card at @p now: well formed, signed by its own key, naming its
 *  holder's identity, unexpired. Same checks, same order, as Python
 *  AreaCard.verify. An at_dir_status_t. */
int at_area_card_verify(const at_dir_signed_t *card, double now);
/** Sign @p self's card for @p area. @p expiry 0 = @p now + the default life.
 *  AT_DIR_MALFORMED for an area, bucket or name no hub would take. */
int at_area_card_create(const identity_t *self, const char *area, const char *bucket,
                        const char *name, int64_t seq, long expiry, double now,
                        at_dir_signed_t *out);

/** Borrowed field accessors (NULL when absent). uuid/key/seq/expiry are the
 *  at_dir_* ones. */
const char *at_area_card_area(const at_dir_signed_t *card);
const char *at_area_card_bucket(const at_dir_signed_t *card);
const char *at_area_card_name(const at_dir_signed_t *card);

#endif /* AT_CONTACTS_AREA_CARD_H */
