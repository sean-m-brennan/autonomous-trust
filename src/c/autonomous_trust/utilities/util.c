/********************
 *  Copyright 2025 Sean M. Brennan and contributors
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
#include <stddef.h>
#include <errno.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <stdio.h>

#include "util.h"

inline long min(long a, long b) { return ((a) < (b) ? a : b); }

inline long max(long a, long b) { return ((a) > (b) ? a : b); }

size_t at_strlcpy(char *dst, const char *src, size_t dst_len)
{
    if (src == NULL) {
        if (dst != NULL && dst_len > 0)
            dst[0] = '\0';
        return 0;
    }
    size_t src_len = strlen(src);
    if (dst == NULL || dst_len == 0)
        return src_len;
    size_t copy_len = (src_len < dst_len - 1) ? src_len : dst_len - 1;
    memcpy(dst, src, copy_len);
    dst[copy_len] = '\0';
    return src_len;
}

/* Frama-C: skipped — [string-loop] nested strstr + memmove loop */
char *strremove(char *str, const char *sub)
{
    char *p, *q, *r;
    if (*sub && (q = r = strstr(str, sub)) != NULL)
    {
        size_t len = strlen(sub);
        while ((r = strstr(p = r + len, sub)) != NULL)
        {
            memmove(q, p, r - p);
            q += r - p;
        }
        memmove(q, p, strlen(p) + 1);
    }
    return str;
}

/* Frama-C: skipped — [string-loop] for(*p;*p;p++) directory component walk */
int makedirs(char *path, mode_t mode)
{
    char tmp[MAX_FILENAME+1];
    char *p = NULL;

    strncpy(tmp, path, sizeof(tmp) - 1);
    tmp[sizeof(tmp) - 1] = '\0';
    size_t len = strlen(tmp);
    if (tmp[len - 1] == '/')
        tmp[len - 1] = 0;
    for (p = tmp + 1; *p; p++)
    {
        if (*p == '/')
        {
            *p = 0;
            int err = mkdir(tmp, mode);
            if (err != 0 && errno != EEXIST)
                return SYS_EXCEPTION();
            *p = '/';
        }
    }
    int err = mkdir(tmp, mode);
    if (err != 0 && errno != EEXIST)
        return SYS_EXCEPTION();
    return 0;
}

/* Frama-C: skipped — [string-loop] strlen + memcpy; WP cannot discharge separation/bounds */
int path_join(char *dest, size_t destlen,
                 const char *dir, const char *suffix)
{
    size_t dlen = strlen(dir);
    size_t slen = strlen(suffix);
    size_t total = dlen + 1 + slen;
    if (total >= destlen) {
        dest[0] = '\0';
        return -1;
    }
    memcpy(dest, dir, dlen);
    dest[dlen] = '/';
    memcpy(dest + dlen + 1, suffix, slen + 1);
    return (int)total;
}

#define compare_flt_pt(f1, f2, epsilon)              \
    (((f1 - epsilon) < f2) && ((f1 + epsilon) > f2)) \
        ? 0                                          \
        : ((f1 < f2) ? -1 : 1)

int compare_float_precision(float f1, float f2, float epsilon)
{
    return compare_flt_pt(f1, f2, epsilon);
}

int compare_double_precision(double f1, double f2, double epsilon)
{
    return compare_flt_pt(f1, f2, epsilon);
}
