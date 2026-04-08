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

/*@
  requires file != \null;
  requires \valid_read(file + (0 .. MAX_FILENAME - 1)) ||
           (\exists size_t i; 0 <= i < MAX_FILENAME && file[i] == '\0');
  assigns _exception.errnum, _exception.line, _exception.file[0 .. MAX_FILENAME - 1];
  ensures _exception.errnum == err;
  ensures _exception.line == line;
  ensures \result == -1;
*/
int _set_exception(int err, size_t line, const char *file)
{
    _exception.errnum = err;
    _exception.line = line;
    strncpy(_exception.file, file, 255);
    //@ assert _exception.errnum == err;
    //@ assert _exception.line == line;
    return -1;
}
