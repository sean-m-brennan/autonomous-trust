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

/* Windows stand-in for <uuid/uuid.h>: the libuuid AT links on POSIX. */
#ifndef AT_COMPAT_UUID_UUID_H
#define AT_COMPAT_UUID_UUID_H

#include <at_win32.h>

/* The util-linux libuuid API AT uses (uuid.c). Version 4 UUIDs from libsodium's
 * randombytes, version 5 from utilities/portable.c's SHA-1. */
typedef unsigned char uuid_t[16];

#ifndef UUID_STR_LEN
#define UUID_STR_LEN 37
#endif

void uuid_generate(uuid_t out);
void uuid_generate_random(uuid_t out);
void uuid_generate_sha1(uuid_t out, const uuid_t ns, const char *name, size_t len);
int  uuid_parse(const char *in, uuid_t uu);
void uuid_unparse(const uuid_t uu, char *out);
void uuid_unparse_lower(const uuid_t uu, char *out);
void uuid_unparse_upper(const uuid_t uu, char *out);
int  uuid_compare(const uuid_t a, const uuid_t b);
void uuid_copy(uuid_t dst, const uuid_t src);
void uuid_clear(uuid_t uu);
int  uuid_is_null(const uuid_t uu);

#endif /* AT_COMPAT_UUID_UUID_H */
