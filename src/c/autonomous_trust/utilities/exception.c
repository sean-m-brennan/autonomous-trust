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

int _set_exception(int err, size_t line, const char *file)
{
    _exception.errnum = err;
    _exception.line = line;

    /* Hand-rolled bounded copy replicating strncpy(_exception.file, file, 255)
     * semantics (copy up to first NUL, then pad remainder with NUL).  Avoids
     * WP's strncpy stub whose valid_nstring_src precondition cannot be
     * discharged from the `\valid_read(file+(0..255))` we have in hand. */
    size_t i = 0;
    /*@
      loop invariant 0 <= i <= 255;
      loop assigns i, _exception.file[0 .. 254];
      loop variant 255 - i;
    */
    while (i < 255 && file[i] != '\0') {
        _exception.file[i] = file[i];
        i++;
    }
    /*@
      loop invariant 0 <= i <= 255;
      loop assigns i, _exception.file[0 .. 254];
      loop variant 255 - i;
    */
    while (i < 255) {
        _exception.file[i] = '\0';
        i++;
    }
    return -1;
}
