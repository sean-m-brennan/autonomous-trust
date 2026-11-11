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

#ifndef __FC_DLFCN_SPEC_H
#define __FC_DLFCN_SPEC_H

/* Frama-C's libc <dlfcn.h> stops at dlopen/dlsym; package_hash.c also
   needs the GNU dladdr() extension and its Dl_info result type. */
#ifdef __FRAMAC__
#include <dlfcn.h>

#ifndef __FC_DL_INFO_DEFINED
#define __FC_DL_INFO_DEFINED
typedef struct {
    const char *dli_fname;
    void *dli_fbase;
    const char *dli_sname;
    void *dli_saddr;
} Dl_info;

/*@
  requires \valid(info);
  assigns *info \from addr;
  ensures \result == 0 || \result != 0;
  ensures \result != 0 ==>
    (info->dli_fname == \null || \valid_read(info->dli_fname));
*/
extern int dladdr(const void *addr, Dl_info *info);
#endif
#endif

#endif
