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

/* Windows stand-in for <dlfcn.h>: dladdr for the one question AT asks it. */
#ifndef AT_COMPAT_DLFCN_H
#define AT_COMPAT_DLFCN_H

#include <at_win32.h>

typedef struct
{
    const char *dli_fname;   /* the module (DLL or EXE) holding the address */
    void       *dli_fbase;
    const char *dli_sname;   /* always NULL here */
    void       *dli_saddr;
} Dl_info;

/* GetModuleHandleEx(FROM_ADDRESS) + GetModuleFileName: what AT asks dladdr
 * for (identity/package_hash.c, the file its own code is in). */
int dladdr(const void *addr, Dl_info *info);

#endif /* AT_COMPAT_DLFCN_H */
