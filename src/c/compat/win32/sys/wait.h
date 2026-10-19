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

/* Windows stand-in for <sys/wait.h>: no child processes on Windows. */
#ifndef AT_COMPAT_SYS_WAIT_H
#define AT_COMPAT_SYS_WAIT_H

#include <at_win32.h>

/* Windows nodes never fork (they run in-process), so nothing waits on a child;
 * these let the POSIX-only paths compile. */
#define WNOHANG 1
#define WIFEXITED(s)   1
#define WEXITSTATUS(s) (s)

#endif /* AT_COMPAT_SYS_WAIT_H */
