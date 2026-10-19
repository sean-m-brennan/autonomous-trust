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

#ifndef AT_PORTABLE_H
#define AT_PORTABLE_H

/** @addtogroup internal_utilities
 *  @{
 *
 *  What glibc + util-linux provide and Darwin spells differently or lacks.
 *  Include it where one of these is used; on Linux it changes nothing.
 */

#include <stddef.h>
#include <sys/stat.h>
#include <uuid/uuid.h>

#include <time.h>

/**
 * @brief A file's modification time, to the finest the platform keeps:
 *        st_mtim (POSIX 2008) on Linux, st_mtimespec on Darwin, and on
 *        Windows NTFS's 100 ns last-write time (the CRT's stat has whole
 *        seconds only, which would hide a rewrite within the same second from
 *        every mtime-checked cache).
 *
 * @param path The file @p st was stat'd from (Windows reads the time by name).
 * @param st   Its stat.
 */
struct timespec at_file_mtim(const char *path, const struct stat *st);

/**
 * @brief A name-based (version 5, SHA-1) UUID, as RFC 4122 §4.3 and
 *        util-linux's uuid_generate_sha1() make it.
 *
 * util-linux's libuuid has uuid_generate_sha1(); Darwin's (in libSystem) does
 * not, and Darwin's own SHA-1 (CommonCrypto CC_SHA1) is deprecated. So this is
 * built everywhere, and on Darwin uuid_generate_sha1 names it. Python's
 * uuid.uuid5(ns, name) gives the same bytes, which the cross-language
 * conformance cases rely on.
 */
void at_uuid_generate_sha1(uuid_t out, const uuid_t ns, const char *name, size_t len);

#ifdef __APPLE__
#define uuid_generate_sha1 at_uuid_generate_sha1
#endif

/**
 * @brief The temporary name to write @p path through before renaming it into
 *        place: `<path>.tmp<pid>.<n>`.
 *
 * Unique per call, not just per process: the subsystems of an in-process node
 * are threads of one process, and a pid alone no longer tells their writes
 * apart.
 * @return 0, or -1 if it does not fit in @p cap.
 */
int at_tmp_path(char *out, size_t cap, const char *path);

/** @} */ /* end of internal_utilities */

#endif /* AT_PORTABLE_H */
