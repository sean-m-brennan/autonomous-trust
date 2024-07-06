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

#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <stdio.h>
#include <sys/wait.h>

#include "processes/processes.h"
#include "utilities/exception.h"

#if !defined(FORK)
#define FORK 2
#endif

#define MAX_CLOSE 8192


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
        read(io[0], &gchild, sizeof(int));
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
        write(io[1], &err, sizeof(int));
        close(io[1]);
        return SYS_EXCEPTION();
    }

#if FORK > 1        
    pid = fork();
    if (pid < 0) {
        err = -errno;
        write(io[1], &err, sizeof(int));
        close(io[1]);
        return SYS_EXCEPTION();
    }
    if (pid != 0) {  // parent
        write(io[1], &pid, sizeof(int));
        close(io[1]);
        _exit(0);
    }
#endif
    close(io[1]);

    if (!(flags & NO_UMASK))
        umask(0); // clear

    if (!(flags & NO_CHDIR))
    {
        chdir(data_dir);
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
    }

    close(STDIN_FILENO);

#if 0 // FIXME
    if (!(flags & NO_STDOUT_REDIRECT & NO_STDERR_REDIRECT))
    {
        // point stdout and/or stderr to /dev/null

        int f_d = open("/dev/null", O_WRONLY);
        if (f_d == -1)
            return -1;
        if (!(flags & NO_STDOUT_REDIRECT))
        {
            if (*fd1 = dup2(f_d, STDOUT_FILENO) == -1)
                return -1;
            //*fd1 = f_d;
        }
        f_d = open("/dev/null", O_WRONLY);
        if (f_d == -1)
            return -1;
         if (!(flags & NO_STDERR_REDIRECT))
        {
            if (*fd2 = dup2(f_d, STDERR_FILENO) == -1)  // FIXME fd leaks?
                return -1;
            //*fd2 = f_d;
        }
    }
#endif
    return 0;
}
