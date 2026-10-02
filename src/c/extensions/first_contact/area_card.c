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

#include "first_contact/area_card.h"

#include <string.h>
#include <strings.h>

#include <sodium.h>

#include "identity/identity_priv.h"
#include "utilities/util.h"
#include "rendezvous/net_relay_rosters.h"   /* the area syntax */

int at_area_normalize(const char *in, char *out, size_t out_len, size_t min_len,
                      size_t max_len)
{
    return net_relay_area_normalize(in, out, out_len, min_len, max_len);
}

/* Already normalized, @p min_len .. @p max_len (Python: normalize_area(x) == x). */
static bool _is_prefix(const char *in, size_t min_len, size_t max_len)
{
    char folded[AT_AREA_MAX + 2];
    return in != NULL && max_len <= AT_AREA_MAX + 1
        && at_area_normalize(in, folded, sizeof(folded), min_len, max_len) == 0
        && strcmp(folded, in) == 0;
}

bool at_area_is_area(const char *in)
{
    return _is_prefix(in, AT_AREA_MIN, AT_AREA_MAX);
}

bool at_area_valid_name(const char *name)
{
    if (name == NULL || strlen(name) > AT_AREA_NAME_MAX)
        return false;
    for (const unsigned char *c = (const unsigned char *)name; *c != '\0'; c++)
        if (*c < 0x20 || *c == 0x7f)
            return false;
    return true;
}

static const char *_str(const at_dir_signed_t *obj, const char *field)
{
    return obj != NULL ? json_string_value(json_object_get(obj->body, field)) : NULL;
}

const char *at_area_card_area(const at_dir_signed_t *card) { return _str(card, "area"); }
const char *at_area_card_bucket(const at_dir_signed_t *card) { return _str(card, "bucket"); }
const char *at_area_card_name(const at_dir_signed_t *card) { return _str(card, "name"); }

static bool _positive_int(const json_t *body, const char *field, long long min)
{
    json_t *v = json_object_get(body, field);
    return json_is_integer(v) && json_integer_value(v) >= min;
}

int at_area_card_verify(const at_dir_signed_t *card, double now)
{
    if (card == NULL || card->body == NULL)
        return AT_DIR_MALFORMED;
    const json_t *b = card->body;
    const char *t = json_string_value(json_object_get(b, "typename"));
    json_t *v = json_object_get(b, "v");
    if (t == NULL || strcmp(t, AT_AREA_CARD_TYPENAME) != 0 || !json_is_integer(v)
        || json_integer_value(v) != AT_AREA_CARD_VERSION)
        return AT_DIR_MALFORMED;
    const char *area = at_area_card_area(card), *bucket = at_area_card_bucket(card);
    if (!_is_prefix(area, AT_AREA_MIN, AT_AREA_MAX)
        || !_is_prefix(bucket, 1, AT_AREA_BUCKET_MAX)
        || strncmp(bucket, area, strlen(area)) != 0)
        return AT_DIR_MALFORMED;
    if (!at_area_valid_name(at_area_card_name(card)))
        return AT_DIR_MALFORMED;
    if (!at_dir_is_hex_key(at_dir_key(card)) || at_dir_uuid(card) == NULL)
        return AT_DIR_MALFORMED;
    json_t *ident = json_object_get(b, "identity");
    const char *ident_type = json_string_value(json_object_get(ident, "typename"));
    const char *ident_uuid = json_string_value(json_object_get(ident, "uuid"));
    const char *ident_key = json_string_value(
        json_object_get(json_object_get(ident, "signature"), "hex_seed"));
    if (!json_is_object(ident) || ident_type == NULL || strcmp(ident_type, "identity") != 0
        || ident_uuid == NULL || ident_key == NULL)
        return AT_DIR_MALFORMED;
    if (!_positive_int(b, "seq", 1) || !_positive_int(b, "expiry", 1))
        return AT_DIR_MALFORMED;
    int rc = at_dir_check_sig(at_dir_key(card), AT_AREA_CARD_DOMAIN, card);
    if (rc != AT_DIR_OK)
        return rc;
    if (now >= (double)at_dir_expiry(card))
        return AT_DIR_EXPIRED;
    if (strcasecmp(ident_uuid, at_dir_uuid(card)) != 0
        || strcasecmp(ident_key, at_dir_key(card)) != 0)
        return AT_DIR_MISMATCH;
    return AT_DIR_OK;
}

int at_area_card_create(const identity_t *self, const char *area, const char *bucket,
                        const char *name, int64_t seq, long expiry, double now,
                        at_dir_signed_t *out)
{
    char a[AT_AREA_MAX + 1], bk[AT_AREA_BUCKET_MAX + 1];
    if (out != NULL)
        memset(out, 0, sizeof(*out));
    if (self == NULL || out == NULL
        || at_area_normalize(area, a, sizeof(a), AT_AREA_MIN, AT_AREA_MAX) != 0
        || at_area_normalize(bucket, bk, sizeof(bk), 1, AT_AREA_BUCKET_MAX) != 0
        || strncmp(bk, a, strlen(a)) != 0 || !at_area_valid_name(name))
        return AT_DIR_MALFORMED;
    if (expiry == 0)
        expiry = (long)now + AT_AREA_DEFAULT_TTL_SECONDS;
    char uu[UUID_STRING_LEN + 1];
    uuid_unparse_lower(self->uuid, uu);
    /* identity_t embeds public_identity_t at offset 0; the address is left
     * blank, as Python's create_card does. */
    json_t *ident = NULL;
    if (public_identity_to_json((const public_identity_t *)self, &ident) != 0 || ident == NULL)
        return AT_DIR_MALFORMED;
    json_object_set_new(ident, "address", json_string(""));
    json_t *body = json_pack("{s:i, s:s, s:s, s:s, s:s, s:s, s:s, s:I, s:I, s:o}",
                             "v", AT_AREA_CARD_VERSION, "typename", AT_AREA_CARD_TYPENAME,
                             "uuid", uu, "key", (const char *)self->signature.public_hex,
                             "area", a, "bucket", bk, "name", name,
                             "seq", (json_int_t)seq, "expiry", (json_int_t)expiry,
                             "identity", ident);
    return body != NULL ? at_dir_sign(self->signature.private, AT_AREA_CARD_DOMAIN, body, out)
                        : AT_DIR_MALFORMED;
}
