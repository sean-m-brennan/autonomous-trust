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

#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "portable.h"

/* SHA-1 (FIPS 180-4), only as the hash RFC 4122 names for version 5 UUIDs:
 * a name-to-identifier mapping, not a security primitive. */
typedef struct
{
    uint32_t h[5];
    uint64_t bytes;
    uint8_t block[64];
    size_t used;
} sha1_t;

static uint32_t rol(uint32_t x, int n)
{
    return (x << n) | (x >> (32 - n));
}

static void sha1_block(sha1_t *c, const uint8_t *p)
{
    uint32_t w[80];
    for (int i = 0; i < 16; i++)
        w[i] = (uint32_t)p[4 * i] << 24 | (uint32_t)p[4 * i + 1] << 16
             | (uint32_t)p[4 * i + 2] << 8 | (uint32_t)p[4 * i + 3];
    for (int i = 16; i < 80; i++)
        w[i] = rol(w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16], 1);

    uint32_t a = c->h[0], b = c->h[1], d = c->h[3], e = c->h[4], cc = c->h[2];
    for (int i = 0; i < 80; i++)
    {
        uint32_t f, k;
        if (i < 20)      { f = (b & cc) | (~b & d);           k = 0x5A827999; }
        else if (i < 40) { f = b ^ cc ^ d;                    k = 0x6ED9EBA1; }
        else if (i < 60) { f = (b & cc) | (b & d) | (cc & d); k = 0x8F1BBCDC; }
        else             { f = b ^ cc ^ d;                    k = 0xCA62C1D6; }
        uint32_t t = rol(a, 5) + f + e + k + w[i];
        e = d;
        d = cc;
        cc = rol(b, 30);
        b = a;
        a = t;
    }
    c->h[0] += a;
    c->h[1] += b;
    c->h[2] += cc;
    c->h[3] += d;
    c->h[4] += e;
}

static void sha1_init(sha1_t *c)
{
    static const uint32_t iv[5] = {0x67452301, 0xEFCDAB89, 0x98BADCFE,
                                   0x10325476, 0xC3D2E1F0};
    memcpy(c->h, iv, sizeof(iv));
    c->bytes = 0;
    c->used = 0;
}

static void sha1_update(sha1_t *c, const uint8_t *p, size_t n)
{
    c->bytes += n;
    while (n > 0)
    {
        size_t take = sizeof(c->block) - c->used;
        if (take > n)
            take = n;
        memcpy(c->block + c->used, p, take);
        c->used += take;
        p += take;
        n -= take;
        if (c->used == sizeof(c->block))
        {
            sha1_block(c, c->block);
            c->used = 0;
        }
    }
}

static void sha1_final(sha1_t *c, uint8_t out[20])
{
    uint64_t bits = c->bytes * 8;
    uint8_t pad = 0x80;
    sha1_update(c, &pad, 1);
    pad = 0;
    while (c->used != 56)
        sha1_update(c, &pad, 1);
    uint8_t len[8];
    for (int i = 0; i < 8; i++)
        len[i] = (uint8_t)(bits >> (56 - 8 * i));
    sha1_update(c, len, sizeof(len));
    for (int i = 0; i < 5; i++)
    {
        out[4 * i]     = (uint8_t)(c->h[i] >> 24);
        out[4 * i + 1] = (uint8_t)(c->h[i] >> 16);
        out[4 * i + 2] = (uint8_t)(c->h[i] >> 8);
        out[4 * i + 3] = (uint8_t)c->h[i];
    }
}

void at_uuid_generate_sha1(uuid_t out, const uuid_t ns, const char *name, size_t len)
{
    sha1_t c;
    uint8_t digest[20];
    sha1_init(&c);
    sha1_update(&c, ns, sizeof(uuid_t));
    sha1_update(&c, (const uint8_t *)name, len);
    sha1_final(&c, digest);
    memcpy(out, digest, sizeof(uuid_t));
    out[6] = (uint8_t)((out[6] & 0x0F) | 0x50);  /* version 5 */
    out[8] = (uint8_t)((out[8] & 0x3F) | 0x80);  /* RFC 4122 variant */
}

int at_tmp_path(char *out, size_t cap, const char *path)
{
    static atomic_ulong counter = 0;
    unsigned long n = atomic_fetch_add(&counter, 1);
    int w = snprintf(out, cap, "%s.tmp%d.%lu", path, (int)getpid(), n);
    return (w < 0 || (size_t)w >= cap) ? -1 : 0;
}

struct timespec at_file_mtim(const char *path, const struct stat *st)
{
#if defined(__APPLE__)
    (void)path;
    return st->st_mtimespec;
#elif defined(_WIN32)
    WIN32_FILE_ATTRIBUTE_DATA fa;
    if (path != NULL && GetFileAttributesExA(path, GetFileExInfoStandard, &fa))
    {
        /* 100 ns ticks since 1601-01-01. */
        uint64_t t = ((uint64_t)fa.ftLastWriteTime.dwHighDateTime << 32)
                     | fa.ftLastWriteTime.dwLowDateTime;
        struct timespec ts = {
            .tv_sec = (time_t)(t / 10000000ULL - 11644473600ULL),
            .tv_nsec = (long)(t % 10000000ULL) * 100,
        };
        return ts;
    }
    struct timespec ts = {.tv_sec = st->st_mtime, .tv_nsec = 0};
    return ts;
#else
    (void)path;
    return st->st_mtim;
#endif
}
