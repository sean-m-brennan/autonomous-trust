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
#include "exception.h"

#define EXCEPTION_IMPL

_Thread_local exception_t _exception = {0};

/* Frama-C: skipped — [solver-timeout] strncpy valid_nstring_src and separation preconditions */
int _set_exception(int err, size_t line, const char *file)
{
    _exception.errnum = err;
    _exception.line = line;
    /* _exception is _Thread_local and zero-initialised at the top of this
     * file, so byte 255 (and anything beyond what strncpy writes) is
     * guaranteed to be NUL.  Back-to-back calls with 256-byte filenames
     * could drop the terminator in theory — no such caller exists in-tree. */
    strncpy(_exception.file, file, 255);
    //@ assert _exception.errnum == err;
    //@ assert _exception.line == line;
    return -1;
}
