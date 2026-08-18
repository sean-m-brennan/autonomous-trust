/* ******************
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
 * ****************** */

#include "jcs.h"

#include <jansson.h>
#include <math.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "ryu/ryu.h"

/* ---------------- growing buffer ---------------- */

typedef struct {
    char *buf;
    size_t len;
    size_t cap;
    int err;
} buf_t;

static int buf_reserve(buf_t *b, size_t n)
{
    if (b->err) return -1;
    if (b->len + n + 1 <= b->cap) return 0;
    size_t cap = b->cap ? b->cap * 2 : 64;
    while (cap < b->len + n + 1) cap *= 2;
    char *p = realloc(b->buf, cap);
    if (p == NULL) { b->err = 1; return -1; }
    b->buf = p;
    b->cap = cap;
    return 0;
}

static int buf_append(buf_t *b, const char *src, size_t n)
{
    if (buf_reserve(b, n) != 0) return -1;
    memcpy(b->buf + b->len, src, n);
    b->len += n;
    b->buf[b->len] = '\0';
    return 0;
}

static int buf_append_c(buf_t *b, char c)
{
    return buf_append(b, &c, 1);
}

static int buf_append_z(buf_t *b, const char *src)
{
    return buf_append(b, src, strlen(src));
}

/* ---------------- string emission (JCS §3.2.2.2) ---------------- */

/* Emit one Unicode code point as a \uXXXX escape (UTF-16 unit; for code
 * points >U+FFFF the caller is responsible for emitting a surrogate pair,
 * but JCS §3.2.2.2 only requires escaping for U+0000–U+001F, which are
 * all BMP). */
static int emit_uescape(buf_t *b, uint16_t code)
{
    char esc[7];
    snprintf(esc, sizeof(esc), "\\u%04x", code);
    return buf_append(b, esc, 6);
}

static int emit_string(buf_t *b, const char *s)
{
    if (buf_append_c(b, '"') != 0) return -1;
    for (const unsigned char *p = (const unsigned char *)s; *p; ++p) {
        unsigned char c = *p;
        switch (c) {
        case '"':  if (buf_append(b, "\\\"", 2) != 0) return -1; break;
        case '\\': if (buf_append(b, "\\\\", 2) != 0) return -1; break;
        case '\b': if (buf_append(b, "\\b", 2) != 0) return -1; break;
        case '\f': if (buf_append(b, "\\f", 2) != 0) return -1; break;
        case '\n': if (buf_append(b, "\\n", 2) != 0) return -1; break;
        case '\r': if (buf_append(b, "\\r", 2) != 0) return -1; break;
        case '\t': if (buf_append(b, "\\t", 2) != 0) return -1; break;
        default:
            if (c < 0x20) {
                if (emit_uescape(b, c) != 0) return -1;
            } else {
                /* Pass through UTF-8 verbatim; JCS does NOT escape >0x7F. */
                if (buf_append_c(b, (char)c) != 0) return -1;
            }
            break;
        }
    }
    return buf_append_c(b, '"');
}

/* ---------------- number emission (ES6 7.1.12.1 via Ryu) ---------------- */

/* Ryu emits scientific notation like "1.23E2" (capital E, no '+' on
 * positive exponents).  ES6 wants e.g. "123" for integer-valued, "0.0001"
 * for small, and "1e+21" for large.  This wrapper:
 *   - emits integer-valued doubles as decimal integers (no ".0")
 *   - falls through to Ryu for the rest, then post-processes to ES6 shape:
 *       'E' -> 'e'
 *       'e' followed by digits (no sign) -> 'e+' prefix
 *
 * For now the ES6 "small / large" cutoff matches Ryu's: anything Ryu
 * emits in scientific form, we keep in scientific form.  This matches
 * jcs.py for AT-relevant value ranges.  Document deviations if they appear.
 */
/* These specific float == comparisons are intentional: an exact-zero
 * check and an integer-round-trip check. Both are correct uses of
 * IEEE-754 equality; -Wfloat-equal flags the pattern, not the semantics. */
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wfloat-equal"

/* Convert Ryu's "M.MMMEsEE" (or "MMME+EE") representation into the
 * ES6/JCS canonical form per ECMA-262 §6.1.6.1.13 (ToString of a Number).
 *
 * The algorithm: extract the digit string (mantissa minus the point) and
 * the "n" of the spec where 10^(n-1) ≤ value's significand < 10^n.
 *   - k ≤ n ≤ 21: integer with (n-k) trailing zeros.
 *   - 0 < n ≤ 21: digits split by a '.' after position n.
 *   - -6 < n ≤ 0: "0." + (-n) leading zeros + digits.
 *   - otherwise:   scientific "d.dddde±E" (single-digit mantissa keeps no '.').
 */
static int es6_from_ryu(buf_t *b, const char *ryu, size_t n_in)
{
    /* sign */
    int neg = 0;
    size_t i = 0;
    if (n_in > 0 && ryu[0] == '-') { neg = 1; i = 1; }

    /* split mantissa and exponent at 'E' */
    const char *epos = memchr(ryu + i, 'E', n_in - i);
    size_t mantissa_end = epos != NULL ? (size_t)(epos - ryu) : n_in;

    /* collect digits (sans decimal point), tracking how many digits sit
     * after the point */
    char digits[40];
    size_t dlen = 0;
    int frac_digits = 0;
    int saw_point = 0;
    for (size_t j = i; j < mantissa_end; ++j) {
        char c = ryu[j];
        if (c == '.') { saw_point = 1; continue; }
        if (dlen >= sizeof(digits)) return -1;
        digits[dlen++] = c;
        if (saw_point) ++frac_digits;
    }

    /* Parse the exponent WITHIN n_in.  `ryu` is a counted buffer, not a C
     * string: d2s_buffered_n writes the digits and returns the length but does
     * NOT terminate (d2s_buffered is the variant that appends the NUL).  Calling
     * strtol here read past the written bytes into uninitialized stack, picking
     * up whatever leftover digits happened to follow — the garbage-exponent defect:
     * 12345.678 canonicalized as 1.2345678e+46 in ~3% of runs, mantissa always
     * right and only the exponent varying, because the real leading digit was
     * being concatenated with garbage.
     *
     * That matters far beyond a flaky test: JCS canonicalization is what wire
     * bytes are signed over, so a node doing this signs a byte string its
     * verifier will not reproduce.
     *
     * Parsed by hand rather than copying into a NUL-terminated scratch buffer,
     * so the bound is visible at the point of use and this function stays
     * correct for ANY counted input, not just one whose caller remembered to
     * terminate it. */
    int ryu_exp = 0;
    if (epos != NULL) {
        size_t ei = (size_t)(epos - ryu) + 1;
        int esign = 1;
        if (ei < n_in && (ryu[ei] == '+' || ryu[ei] == '-')) {
            if (ryu[ei] == '-') esign = -1;
            ++ei;
        }
        int mag = 0;
        for (; ei < n_in && ryu[ei] >= '0' && ryu[ei] <= '9'; ++ei) {
            /* A double's decimal exponent fits well inside 3 digits (|exp| <=
             * 324); anything longer is not a Ryu output and refusing beats
             * overflowing. */
            if (mag > 99999) return -1;
            mag = mag * 10 + (ryu[ei] - '0');
        }
        ryu_exp = esign * mag;
    }

    /* n in ES6 spec terms: position one past the leading digit, i.e. the
     * exponent such that 10^(n-1) ≤ significand < 10^n. */
    int adj_exp = ryu_exp - frac_digits;
    int n_spec = adj_exp + (int)dlen;
    int k = (int)dlen;

    /* Strip leading zeros from digits — Ryu shouldn't emit any (shortest
     * representation), but be defensive. */
    size_t leading_zeros = 0;
    while (leading_zeros < dlen - 1 && digits[leading_zeros] == '0') ++leading_zeros;
    if (leading_zeros > 0) {
        memmove(digits, digits + leading_zeros, dlen - leading_zeros);
        dlen -= leading_zeros;
        k = (int)dlen;
        n_spec = adj_exp + k;
    }

    char out[64];
    size_t oi = 0;
    if (neg) out[oi++] = '-';

    if (k <= n_spec && n_spec <= 21) {
        /* "digits" + (n-k) trailing zeros */
        memcpy(out + oi, digits, dlen); oi += dlen;
        for (int z = 0; z < n_spec - k; ++z) out[oi++] = '0';
    } else if (n_spec > 0 && n_spec <= 21) {
        /* split after position n */
        memcpy(out + oi, digits, (size_t)n_spec); oi += (size_t)n_spec;
        out[oi++] = '.';
        memcpy(out + oi, digits + n_spec, dlen - (size_t)n_spec);
        oi += dlen - (size_t)n_spec;
    } else if (n_spec > -6 && n_spec <= 0) {
        out[oi++] = '0';
        out[oi++] = '.';
        for (int z = 0; z < -n_spec; ++z) out[oi++] = '0';
        memcpy(out + oi, digits, dlen); oi += dlen;
    } else {
        /* scientific */
        out[oi++] = digits[0];
        if (k > 1) {
            out[oi++] = '.';
            memcpy(out + oi, digits + 1, dlen - 1); oi += dlen - 1;
        }
        out[oi++] = 'e';
        int ex = n_spec - 1;
        if (ex >= 0) out[oi++] = '+';
        else { out[oi++] = '-'; ex = -ex; }
        char tmp[12];
        int tn = snprintf(tmp, sizeof(tmp), "%d", ex);
        if (tn < 0 || (size_t)tn >= sizeof(tmp)) return -1;
        memcpy(out + oi, tmp, (size_t)tn); oi += (size_t)tn;
    }

    return buf_append(b, out, oi);
}

int jcs_es6_from_ryu_for_test(const char *ryu, size_t n_in,
                              char *out, size_t out_cap)
{
    buf_t b;
    memset(&b, 0, sizeof(b));
    int rc = es6_from_ryu(&b, ryu, n_in);
    int n = -1;
    if (rc == 0 && b.len <= out_cap) {
        memcpy(out, b.buf, b.len);
        n = (int)b.len;
    }
    free(b.buf);
    return n;
}

static int emit_number(buf_t *b, double v)
{
    if (isnan(v) || isinf(v)) {
        /* JSON has no NaN/Infinity; the implementation under test should
         * never emit these.  Fall back to "null" to make the divergence
         * visible at byte-compare time instead of crashing. */
        return buf_append_z(b, "null");
    }

    /* ES6 normalises -0 to "0". */
    if (v == 0.0) {
        return buf_append_c(b, '0');
    }

    /* Integer-valued doubles up to 2^53: emit as integer.  Below that
     * boundary the int64_t cast is exact. */
    if (v >= -9007199254740992.0 && v <= 9007199254740992.0) {
        double rounded = (double)(int64_t)v;
        if (rounded == v) {
            char tmp[32];
            int n = snprintf(tmp, sizeof(tmp), "%lld", (long long)v);
            if (n < 0 || (size_t)n >= sizeof(tmp)) return -1;
            return buf_append(b, tmp, (size_t)n);
        }
    }

    /* Non-integer: get Ryu's shortest, then reshape to ES6.
     *
     * NOTE: d2s_buffered_n returns a COUNTED buffer and does NOT terminate it
     * (d2s_buffered is the variant that appends the NUL). Everything downstream
     * must respect `n` — treating ryu_buf as a C string reads uninitialized
     * stack, which is exactly what the garbage-exponent defect was. */
    char ryu_buf[32];
    int n = d2s_buffered_n(v, ryu_buf);
    if (n <= 0 || (size_t)n >= sizeof(ryu_buf)) return -1;
    return es6_from_ryu(b, ryu_buf, (size_t)n);
}

#pragma GCC diagnostic pop

/* ---------------- key sort (UTF-8 byte order = UTF-16 for BMP) ---------------- */

static int cmp_keys(const void *a, const void *b)
{
    const char *ka = *(const char *const *)a;
    const char *kb = *(const char *const *)b;
    /* strcmp is byte-wise on unsigned-compared bytes via memcmp semantics
     * since C99; on platforms where char is signed this still works
     * because the underlying bytes are compared by `unsigned char`
     * cast inside strcmp per the standard. */
    return strcmp(ka, kb);
}

/* ---------------- recursive emit ---------------- */

static int emit_value(buf_t *b, json_t *v);

static int emit_object(buf_t *b, json_t *obj)
{
    if (buf_append_c(b, '{') != 0) return -1;

    size_t n = json_object_size(obj);
    if (n == 0) return buf_append_c(b, '}');

    /* Collect keys, sort, then emit in sorted order. */
    const char **keys = malloc(n * sizeof(*keys));
    if (keys == NULL) { b->err = 1; return -1; }
    size_t i = 0;
    const char *k;
    json_t *unused;
    json_object_foreach(obj, k, unused) {
        keys[i++] = k;
    }
    qsort(keys, n, sizeof(*keys), cmp_keys);

    for (i = 0; i < n; ++i) {
        if (i > 0 && buf_append_c(b, ',') != 0) { free(keys); return -1; }
        if (emit_string(b, keys[i]) != 0) { free(keys); return -1; }
        if (buf_append_c(b, ':') != 0) { free(keys); return -1; }
        if (emit_value(b, json_object_get(obj, keys[i])) != 0) {
            free(keys);
            return -1;
        }
    }
    free(keys);

    return buf_append_c(b, '}');
}

static int emit_array(buf_t *b, json_t *arr)
{
    if (buf_append_c(b, '[') != 0) return -1;
    size_t n = json_array_size(arr);
    for (size_t i = 0; i < n; ++i) {
        if (i > 0 && buf_append_c(b, ',') != 0) return -1;
        if (emit_value(b, json_array_get(arr, i)) != 0) return -1;
    }
    return buf_append_c(b, ']');
}

static int emit_value(buf_t *b, json_t *v)
{
    if (v == NULL) return buf_append_z(b, "null");
    switch (json_typeof(v)) {
    case JSON_OBJECT:  return emit_object(b, v);
    case JSON_ARRAY:   return emit_array(b, v);
    case JSON_STRING:  return emit_string(b, json_string_value(v));
    case JSON_TRUE:    return buf_append_z(b, "true");
    case JSON_FALSE:   return buf_append_z(b, "false");
    case JSON_NULL:    return buf_append_z(b, "null");
    case JSON_INTEGER: {
        char tmp[32];
        int n = snprintf(tmp, sizeof(tmp), "%lld",
                         (long long)json_integer_value(v));
        if (n < 0 || (size_t)n >= sizeof(tmp)) return -1;
        return buf_append(b, tmp, (size_t)n);
    }
    case JSON_REAL:    return emit_number(b, json_real_value(v));
    default:           return -1;
    }
}

/* ---------------- public API ---------------- */

int jcs_canonicalize(const char *json_utf8, size_t len, char **out, size_t *out_len)
{
    if (json_utf8 == NULL || out == NULL || out_len == NULL) return -1;

    json_error_t err;
    json_t *root = json_loadb(json_utf8, len, JSON_DECODE_ANY, &err);
    if (root == NULL) return -1;

    buf_t b = {0};
    int rc = emit_value(&b, root);
    json_decref(root);
    if (rc != 0 || b.err) {
        free(b.buf);
        return -1;
    }

    *out = b.buf;
    *out_len = b.len;
    return 0;
}
