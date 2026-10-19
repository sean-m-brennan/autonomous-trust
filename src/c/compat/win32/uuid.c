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

/* The util-linux libuuid calls AT makes, for Windows (uuid/uuid.h). */

#include <ctype.h>
#include <sodium.h>
#include <stdio.h>
#include <string.h>
#include <uuid/uuid.h>

#include "autonomous_trust/utilities/portable.h"

void uuid_generate_random(uuid_t out)
{
    randombytes_buf(out, sizeof(uuid_t));
    out[6] = (unsigned char)((out[6] & 0x0F) | 0x40);   /* version 4 */
    out[8] = (unsigned char)((out[8] & 0x3F) | 0x80);   /* RFC 4122 variant */
}

void uuid_generate(uuid_t out)
{
    uuid_generate_random(out);
}

void uuid_generate_sha1(uuid_t out, const uuid_t ns, const char *name, size_t len)
{
    at_uuid_generate_sha1(out, ns, name, len);
}

static int _hex(int c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

int uuid_parse(const char *in, uuid_t uu)
{
    if (in == NULL || strlen(in) != 36)
        return -1;
    int b = 0;
    for (int i = 0; i < 36;)
    {
        if (i == 8 || i == 13 || i == 18 || i == 23)
        {
            if (in[i] != '-')
                return -1;
            i++;
            continue;
        }
        int hi = _hex((unsigned char)in[i]), lo = _hex((unsigned char)in[i + 1]);
        if (hi < 0 || lo < 0)
            return -1;
        uu[b++] = (unsigned char)(hi << 4 | lo);
        i += 2;
    }
    return 0;
}

static void _unparse(const uuid_t uu, char *out, const char *digits)
{
    int o = 0;
    for (int b = 0; b < 16; b++)
    {
        if (b == 4 || b == 6 || b == 8 || b == 10)
            out[o++] = '-';
        out[o++] = digits[uu[b] >> 4];
        out[o++] = digits[uu[b] & 0x0F];
    }
    out[o] = '\0';
}

void uuid_unparse_lower(const uuid_t uu, char *out) { _unparse(uu, out, "0123456789abcdef"); }
void uuid_unparse_upper(const uuid_t uu, char *out) { _unparse(uu, out, "0123456789ABCDEF"); }
/* util-linux's default case is lower. */
void uuid_unparse(const uuid_t uu, char *out) { uuid_unparse_lower(uu, out); }

int uuid_compare(const uuid_t a, const uuid_t b)
{
    int c = memcmp(a, b, sizeof(uuid_t));
    return c < 0 ? -1 : c > 0 ? 1 : 0;
}

void uuid_copy(uuid_t dst, const uuid_t src) { memcpy(dst, src, sizeof(uuid_t)); }
void uuid_clear(uuid_t uu) { memset(uu, 0, sizeof(uuid_t)); }

int uuid_is_null(const uuid_t uu)
{
    for (size_t i = 0; i < sizeof(uuid_t); i++)
        if (uu[i] != 0)
            return 0;
    return 1;
}
