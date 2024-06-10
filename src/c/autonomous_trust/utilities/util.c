/********************
 *  Copyright 2024 TekFive, Inc. and contributors
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
#include <sys/stat.h>
#include <sys/types.h>
#include <stdio.h>

#include "util.h"

inline int min(int a, int b) { return ((a) < (b) ? a : b); }

inline int max(int a, int b) { return ((a) > (b) ? a : b); }

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

int makedirs(char *path, mode_t mode)
{
    char tmp[256];
    char *p = NULL;

    snprintf(tmp, sizeof(tmp), "%s", path);
    size_t len = strlen(tmp);
    if (tmp[len - 1] == '/')
        tmp[len - 1] = 0;
    for (p = tmp + 1; *p; p++)
    {
        if (*p == '/')
        {
            *p = 0;
            int err = mkdir(tmp, mode);
            if (err != 0)
                return err;
            *p = '/';
        }
    }
    return mkdir(tmp, mode);
}

#define compare_flt_pt(f1, f2, epsilon)              \
    (((f1 - epsilon) < f2) && ((f1 + epsilon) > f2)) \
        ? 0                                          \
        : ((f1 < f2) ? -1 : 1)

int compare_float_precision(float f1, float f2, float, float epsilon)
{
    return compare_flt_pt(f1, f2, epsilon);
}

int compare_double_precision(double f1, double f2, double epsilon)
{
    return compare_flt_pt(f1, f2, epsilon);
}
