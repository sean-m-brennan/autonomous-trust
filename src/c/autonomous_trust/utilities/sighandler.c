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
 *   limitations under the License.log
 *******************/

#include <signal.h>
#include <stdbool.h>

#include "utilities/logger.h"

bool stop_process = false;

bool propagate = false;

logger_t *_logger = NULL;

extern void reread_configs();

extern void user1_handler();

extern void user2_handler();

void handle_signal(int signum)
{
    if (_logger != NULL)
        log_debug(_logger, "Recvd signal %d\n", signum);
    switch (signum)
    {
    case SIGINT:
    case SIGQUIT:
    case SIGABRT:
        stop_process = true;
        break;
    case SIGHUP:
        reread_configs();
        break;
    case SIGUSR1:
        user1_handler();
        break;
    case SIGUSR2:
        user2_handler();
        break;
    case SIGILL:
    {
        const char *error = "Stack Overflow";
        if (_logger != NULL)
            log_error(_logger, "OS error: %s\n", error);
    }
    break;
    case SIGFPE:
    {
        const char *error = "Floating-point Exception";
        if (_logger != NULL)
            log_error(_logger, "OS error: %s\n", error);
    }
    break;
    default:
    {
        if (_logger != NULL)
            log_error(_logger, "Unhandled signal: %d\n", signum);
    }
    }
}

int init_sig_handling(logger_t *logger)
{
    _logger = logger;
    struct sigaction sa = {0};
    sa.sa_handler = handle_signal;
    return sigaction(SIGINT, &sa, NULL);
}
