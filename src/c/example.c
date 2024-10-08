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

#include <stdio.h>
#include <stdbool.h>
#include <signal.h>
#include <string.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <string.h>
#include <sys/wait.h>

#include "autonomous_trust.h"

#define LIMITED_RUN

#ifdef LIMITED_RUN
#define CONTINUE_RUN (loop < 200)
#else
#define CONTINUE_RUN true
#endif

int main(int argc, char *argv[])
{
    const long cadence = 500000L; // microseconds

    logger_t log = {0};
    logger_init(&log, DEBUG, NULL);

    char *q_out = (char *)"extern_to_at";
    char *q_in = (char *)"at_to_extern";
    queue_t from_at;
    if (messaging_init(q_in, &from_at) != 0)
        log_exception(&log);
    // queue_t to_at;
    // if (messaging_init(q_out, &to_at) != 0)
    //     log_exception(&log);

    // queue names are in reverse order (out here is in there)
    int at_pid = run_autonomous_trust(q_out, q_in, NULL, 0, DEBUG, NULL);
    if (at_pid <= 0)
    {
        log_error(&log, "Autonomous Trust (%d) failed to start: %s\n", at_pid, strerror(errno));
        return at_pid;
    }

    init_sig_handling(NULL);
    messaging_assign(&from_at);

    log_debug(&log, "AT example main (AT at %d)\n", at_pid);
    bool at_alive = true;
    size_t loop = 0;
    while (!stop_process && CONTINUE_RUN)
    {
        loop++;
        int err = kill(at_pid, 0);
        if (err == -1)
        {
            if (errno == ESRCH)
            {
                log_debug(&log, "AT exited\n");
                stop_process = true;
                at_alive = false;
            }
            else
            {
                SYS_EXCEPTION();
                log_exception(&log);
                // FIXME ??
            }
        }

        generic_msg_t buf;
        err = messaging_recv(&buf);
        if (err == -1)
            log_exception(&log);
        if (err == ENOMSG)
            goto snooze;

        bool do_send = false;
        // react to info
        if (do_send)
        {
            if (messaging_send(q_out, buf.type, &buf, true) != 0)
                log_exception(&log);
        }
        // do other things

    snooze:
        usleep(cadence);
    }
    if (at_alive)
    {
        log_debug(&log, "SIGINT to %d\n", at_pid);
        kill(at_pid, SIGINT);
    }
    log_debug(&log, "Example exit\n");
    return 0;
}
