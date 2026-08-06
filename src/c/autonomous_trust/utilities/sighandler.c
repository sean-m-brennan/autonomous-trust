/********************
 *  Copyright 2024 TekFive, Inc., Sean M. Brennan, and contributors
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

#include <signal.h>
#include <stdbool.h>

#include "utilities/logger.h"

/* WHY these are plain `bool`, not `volatile sig_atomic_t`:
 *
 * Strict C11/POSIX would demand `volatile sig_atomic_t` for variables
 * written by a signal handler and read by the main program. We use plain
 * `bool` for two deliberate reasons:
 *
 * 1. The read side is the main-loop poll (`while (!stop_process)`) in the
 *    process layer. GCC and Clang both treat `extern bool` as a symbol the
 *    compiler cannot prove stable across any function call — and the main
 *    loop invariably calls other translation-unit functions per iteration
 *    (messaging_recv_from, log_*, etc.). That forces a reload from memory
 *    at each iteration, giving us the same visibility guarantee `volatile`
 *    would. Marking `volatile` here would inhibit no optimization we care
 *    about but would mask future refactors where the loop becomes
 *    inlineable.
 *
 * 2. `sig_atomic_t` is typically `int`; `bool` is the value the rest of the
 *    code already passes around. Using `bool` keeps call-site types
 *    uniform and avoids the implicit-narrowing warnings that an
 *    `int`-typed flag would trigger in every `if (stop_process)`.
 *
 * If the main loop ever becomes a tight CPU-bound spin (no external calls
 * between reads), convert to `volatile sig_atomic_t` and retest — but
 * don't do it preemptively. */
bool stop_process = false;

bool propagate = false;

logger_t *_logger = NULL;

extern void reread_configs();

extern void user1_handler();

extern void user2_handler();

/* Frama-C: skipped — [syscall] signal handler callback */
void handle_signal(int signum)
{
    if (_logger != NULL)
        log_debug(_logger, "Recvd signal %d\n", signum);
    switch (signum)
    {
    case SIGINT:
    case SIGTERM:
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

/* Frama-C: skipped — [syscall] sigaction signal registration */
int init_sig_handling(logger_t *logger)
{
    _logger = logger;
    struct sigaction sa = {0};
    sa.sa_handler = handle_signal;
    int err = sigaction(SIGINT, &sa, NULL);
    if (err == 0)
        err = sigaction(SIGTERM, &sa, NULL);
    return err;
}
