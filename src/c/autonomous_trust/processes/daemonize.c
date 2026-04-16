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

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdio.h>
#include <sys/wait.h>

#include "processes/processes.h"
#include "utilities/exception.h"

#if !defined(FORK)
#define FORK 2
#endif

#define MAX_CLOSE 8192


/*@
  requires data_dir != \null && \valid_read(data_dir);
  requires \valid(fd1);
  requires \valid(fd2);
  assigns *fd1, *fd2;
  behavior child:
    ensures \result == 0;
  behavior parent:
    ensures \result > 0;
  behavior failure:
    ensures \result < 0;
  disjoint behaviors;
*/
/* Frama-C: skipped — [syscall] fork, setsid, chdir, dup2, close */
int daemonize(char *data_dir, int flags, int *fd1, int *fd2)
{
    int io[2] = {0};
    int err = pipe(io);
    if (err != 0)
        return SYS_EXCEPTION();

    int pid = fork();
    if (pid < 0) {
        close(io[0]);
        close(io[1]);
        return SYS_EXCEPTION();
    }
    if (pid != 0) {  // parent
        close(io[1]);
#if FORK > 1
        pid_t gchild = -1;
        (void)!read(io[0], &gchild, sizeof(int));
        close(io[0]);
        if (gchild < 0)
            return EXCEPTION(abs(gchild));
        return gchild;
#else
        close(io[0]);
        return pid;
#endif
    }
    close(io[0]);

    if (setsid() == -1) { // lead new session
        err = -errno;
        (void)!write(io[1], &err, sizeof(int));
        close(io[1]);
        return SYS_EXCEPTION();
    }

#if FORK > 1
    pid = fork();
    if (pid < 0) {
        err = -errno;
        (void)!write(io[1], &err, sizeof(int));
        close(io[1]);
        return SYS_EXCEPTION();
    }
    if (pid != 0) {  // parent
        (void)!write(io[1], &pid, sizeof(int));
        close(io[1]);
        _exit(0);
    }
#endif
    close(io[1]);

    if (!(flags & NO_UMASK))
        umask(0); // clear

    if (!(flags & NO_CHDIR))
    {
        (void)!chdir(data_dir);
    }

    if (!(flags & NO_CLOSE_FILES)) // close all open files
    {
        int maxfd = sysconf(_SC_OPEN_MAX);
        if (maxfd == -1)
            maxfd = MAX_CLOSE;
        for (int f_d = 0; f_d < maxfd; f_d++) {
            if (f_d == STDIN_FILENO || f_d == STDOUT_FILENO || f_d == STDERR_FILENO)
                continue;
            close(f_d);
        }

        /* Redirect stdin to /dev/null instead of closing it.
         * Closing fd 0 leaves it available for reuse by socket() or open(),
         * which causes silent corruption when daemonize is called again with
         * NO_CLOSE_FILES — the unconditional close(STDIN_FILENO) would destroy
         * a socket that happened to get fd 0. */
        int devnull = open("/dev/null", O_RDONLY);
        if (devnull >= 0)
        {
            if (devnull != STDIN_FILENO)
            {
                dup2(devnull, STDIN_FILENO);
                close(devnull);
            }
        }
    }

    if (!(flags & (NO_STDOUT_REDIRECT | NO_STDERR_REDIRECT)))
    {
        int devnull_w = open("/dev/null", O_WRONLY);
        if (devnull_w == -1)
            return -1;
        if (!(flags & NO_STDOUT_REDIRECT))
        {
            *fd1 = dup2(devnull_w, STDOUT_FILENO);
            if (*fd1 == -1)
            {
                close(devnull_w);
                return -1;
            }
        }
        if (!(flags & NO_STDERR_REDIRECT))
        {
            *fd2 = dup2(devnull_w, STDERR_FILENO);
            if (*fd2 == -1)
            {
                close(devnull_w);
                return -1;
            }
        }
        if (devnull_w != STDOUT_FILENO && devnull_w != STDERR_FILENO)
            close(devnull_w);
    }
    return 0;
}
