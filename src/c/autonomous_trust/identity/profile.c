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

#include <string.h>
#include <sodium.h>

#include "identity/profile.h"

/* ---- small helpers -------------------------------------------------------- */

/* Copy up to `bound` BYTES of UTF-8 from src into dst[bound+1], never splitting
 * a multibyte sequence: back off to the last byte that is not a UTF-8
 * continuation byte (0x80..0xBF) if the cut lands mid-sequence. dst is always
 * NUL-terminated. */
static void utf8_bounded_copy(char *dst, size_t bound, const char *src)
{
    if (src == NULL) { dst[0] = '\0'; return; }
    size_t n = strlen(src);
    if (n > bound) {
        n = bound;
        while (n > 0 && ((unsigned char)src[n] & 0xC0) == 0x80)
            n--;   /* src[n] is a continuation byte: this char started earlier */
    }
    memcpy(dst, src, n);
    dst[n] = '\0';
}

/* ASCII control characters (< 0x20) have no place in a display profile and,
 * unbounded, would let a signed field's JSON escaping (\uXXXX = 6 bytes each)
 * blow past the fixed app-boundary buffer and drop an otherwise-valid profile.
 * Forbidding them keeps escaping to <=2x (only " and \), so AT_PROFILE_JSON_MAX
 * always holds the worst case. */
static bool has_control_chars(const char *s)
{
    for (const unsigned char *p = (const unsigned char *)s; *p != '\0'; p++)
        if (*p < 0x20)
            return true;
    return false;
}

/* handle charset: [A-Za-z0-9_.-] only. */
static bool handle_charset_ok(const char *s)
{
    for (const unsigned char *p = (const unsigned char *)s; *p != '\0'; p++) {
        if (!((*p >= 'A' && *p <= 'Z') || (*p >= 'a' && *p <= 'z') ||
              (*p >= '0' && *p <= '9') || *p == '_' || *p == '.' || *p == '-'))
            return false;
    }
    return true;
}

/* Append a u32 little-endian length prefix + the string bytes to buf@*off. */
static size_t append_field(uint8_t *out, size_t outcap, size_t off, const char *s)
{
    if (off == (size_t)-1) return (size_t)-1;
    size_t len = (s != NULL) ? strlen(s) : 0;
    if (off + 4 + len > outcap) return (size_t)-1;
    out[off + 0] = (uint8_t)(len & 0xFF);
    out[off + 1] = (uint8_t)((len >> 8) & 0xFF);
    out[off + 2] = (uint8_t)((len >> 16) & 0xFF);
    out[off + 3] = (uint8_t)((len >> 24) & 0xFF);
    if (len > 0) memcpy(out + off + 4, s, len);
    return off + 4 + len;
}

/* ---- public API ----------------------------------------------------------- */

bool at_profile_is_empty(const at_profile_t *p)
{
    if (p == NULL) return true;
    return p->display_name[0] == '\0' && p->handle[0] == '\0' &&
           p->bio[0] == '\0' && p->avatar_ref[0] == '\0' && p->num_links == 0;
}

/* Pull one string field; on validate, reject if over-bound; else truncate. */
static int take_field(const json_t *obj, const char *key, bool validate,
                      size_t bound, char *dst)
{
    dst[0] = '\0';
    json_t *v = json_object_get(obj, key);
    if (!json_is_string(v)) return 0;   /* absent/non-string => empty, fine */
    const char *s = json_string_value(v);
    if (s == NULL || s[0] == '\0') return 0;
    if (validate) {
        if (strlen(s) > bound || has_control_chars(s)) return -1;  /* misbehaving peer */
        memcpy(dst, s, strlen(s) + 1);
    } else {
        utf8_bounded_copy(dst, bound, s);
        if (has_control_chars(dst)) dst[0] = '\0';   /* trusted input: drop it */
    }
    return 0;
}

int at_profile_from_json(const json_t *obj, bool validate, at_profile_t *out)
{
    if (out == NULL) return -1;
    memset(out, 0, sizeof(*out));
    if (!json_is_object(obj)) return validate ? -1 : 0;

    if (take_field(obj, "display_name", validate, AT_PROFILE_MAX_DISPLAY_NAME,
                   out->display_name) != 0) goto reject;
    if (take_field(obj, "handle", validate, AT_PROFILE_MAX_HANDLE,
                   out->handle) != 0) goto reject;
    if (out->handle[0] != '\0' && !handle_charset_ok(out->handle)) {
        if (validate) goto reject;
        out->handle[0] = '\0';   /* trusted input: just drop the bad handle */
    }
    if (take_field(obj, "bio", validate, AT_PROFILE_MAX_BIO,
                   out->bio) != 0) goto reject;
    if (take_field(obj, "avatar_ref", validate, AT_PROFILE_MAX_AVATAR_REF,
                   out->avatar_ref) != 0) goto reject;

    json_t *links = json_object_get(obj, "links");
    if (json_is_array(links)) {
        size_t n = json_array_size(links);
        if (validate && n > AT_PROFILE_MAX_LINKS) goto reject;
        for (size_t i = 0; i < n && out->num_links < AT_PROFILE_MAX_LINKS; i++) {
            json_t *lv = json_array_get(links, i);
            if (!json_is_string(lv)) { if (validate) goto reject; else continue; }
            const char *s = json_string_value(lv);
            if (s == NULL || s[0] == '\0') continue;
            if (validate) {
                if (strlen(s) > AT_PROFILE_MAX_LINK || has_control_chars(s)) goto reject;
                memcpy(out->links[out->num_links], s, strlen(s) + 1);
            } else {
                utf8_bounded_copy(out->links[out->num_links], AT_PROFILE_MAX_LINK, s);
                if (has_control_chars(out->links[out->num_links])) continue;
            }
            out->num_links++;
        }
    }
    return 0;

reject:
    memset(out, 0, sizeof(*out));
    return -1;
}

json_t *at_profile_to_json(const at_profile_t *p)
{
    if (p == NULL) return NULL;
    json_t *obj = json_object();
    if (obj == NULL) return NULL;
    if (p->display_name[0] != '\0')
        json_object_set_new(obj, "display_name", json_string(p->display_name));
    if (p->handle[0] != '\0')
        json_object_set_new(obj, "handle", json_string(p->handle));
    if (p->bio[0] != '\0')
        json_object_set_new(obj, "bio", json_string(p->bio));
    if (p->avatar_ref[0] != '\0')
        json_object_set_new(obj, "avatar_ref", json_string(p->avatar_ref));
    if (p->num_links > 0) {
        json_t *arr = json_array();
        if (arr != NULL) {
            for (uint8_t i = 0; i < p->num_links; i++)
                json_array_append_new(arr, json_string(p->links[i]));
            json_object_set_new(obj, "links", arr);
        }
    }
    return obj;
}

int at_profile_to_compact_str(const at_profile_t *p, char *out, size_t outcap)
{
    json_t *obj = at_profile_to_json(p);
    if (obj == NULL) return -1;
    char *s = json_dumps(obj, JSON_COMPACT | JSON_PRESERVE_ORDER);
    json_decref(obj);
    if (s == NULL) return -1;
    size_t len = strlen(s);
    if (len + 1 > outcap) { free(s); return -1; }
    memcpy(out, s, len + 1);
    free(s);
    return (int)len;
}

size_t at_profile_canonical(const uuid_t signer_uuid, const at_profile_t *p,
                            uint8_t *out, size_t outcap)
{
    if (p == NULL || out == NULL) return (size_t)-1;
    if (outcap < sizeof(uuid_t)) return (size_t)-1;
    memcpy(out, signer_uuid, sizeof(uuid_t));
    size_t off = sizeof(uuid_t);
    off = append_field(out, outcap, off, p->display_name);
    off = append_field(out, outcap, off, p->handle);
    off = append_field(out, outcap, off, p->bio);
    off = append_field(out, outcap, off, p->avatar_ref);
    if (off == (size_t)-1 || off + 4 > outcap) return (size_t)-1;
    uint32_t nl = p->num_links;
    out[off + 0] = (uint8_t)(nl & 0xFF);
    out[off + 1] = (uint8_t)((nl >> 8) & 0xFF);
    out[off + 2] = (uint8_t)((nl >> 16) & 0xFF);
    out[off + 3] = (uint8_t)((nl >> 24) & 0xFF);
    off += 4;
    for (uint8_t i = 0; i < p->num_links; i++)
        off = append_field(out, outcap, off, p->links[i]);
    return off;
}

/* A profile canonical buffer cannot exceed uuid + 5 length prefixes + the field
 * bounds + link prefixes; size generously on the stack. */
#define AT_PROFILE_CANON_MAX \
    (16 + 4 * 5 + AT_PROFILE_MAX_DISPLAY_NAME + AT_PROFILE_MAX_HANDLE + \
     AT_PROFILE_MAX_BIO + AT_PROFILE_MAX_AVATAR_REF + \
     AT_PROFILE_MAX_LINKS * (4 + AT_PROFILE_MAX_LINK) + 8)

int at_profile_sign(const unsigned char sk[crypto_sign_SECRETKEYBYTES],
                    const uuid_t signer_uuid, const at_profile_t *p,
                    char *sig_hex_out)
{
    if (sk == NULL || p == NULL || sig_hex_out == NULL) return -1;
    uint8_t canon[AT_PROFILE_CANON_MAX];
    size_t clen = at_profile_canonical(signer_uuid, p, canon, sizeof(canon));
    if (clen == (size_t)-1) return -1;
    unsigned char sig[crypto_sign_BYTES];
    if (crypto_sign_detached(sig, NULL, canon, clen, sk) != 0)
        return -1;
    sodium_bin2hex(sig_hex_out, AT_PROFILE_SIG_HEX_LEN + 1, sig, sizeof(sig));
    return 0;
}

bool at_profile_verify(const unsigned char pk[crypto_sign_PUBLICKEYBYTES],
                       const uuid_t signer_uuid, const at_profile_t *p,
                       const char *sig_hex)
{
    if (pk == NULL || p == NULL || sig_hex == NULL) return false;
    if (strlen(sig_hex) != AT_PROFILE_SIG_HEX_LEN) return false;
    unsigned char sig[crypto_sign_BYTES];
    size_t bin_len = 0;
    if (sodium_hex2bin(sig, sizeof(sig), sig_hex, strlen(sig_hex),
                       NULL, &bin_len, NULL) != 0 || bin_len != sizeof(sig))
        return false;
    uint8_t canon[AT_PROFILE_CANON_MAX];
    size_t clen = at_profile_canonical(signer_uuid, p, canon, sizeof(canon));
    if (clen == (size_t)-1) return false;
    return crypto_sign_verify_detached(sig, canon, clen, pk) == 0;
}
