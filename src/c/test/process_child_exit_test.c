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

/**
 * @file process_child_exit_test.c
 * @brief A forked subsystem must never RETURN through start_process
 *        (ISSUES §2.1.3), and daemonize must not leak its intermediate.
 *
 * The runner a subsystem is started with forks, and then RETURNS IN BOTH
 * PROCESSES: the daemon gets the new subsystem's pid, and the subsystem itself
 * gets its own run loop's value once that loop ends — which is at shutdown.
 * If the subsystem returns from `start_process` it resumes the daemon's
 * start-every-subsystem loop inside the subsystem process, so every exiting
 * subsystem forks a fresh generation on the way out. Measured live before the
 * fix: a node whose process set was stable at 10 for 24 s left **20 new
 * processes** behind after a clean shutdown, still logging identity and network
 * work for a node the operator believed was stopped.
 *
 * That is invisible to an ordinary unit test — nothing crashes, and the wrong
 * behavior only appears when a run loop *ends*. So this drives the real
 * `start_process` with a runner that forks and returns exactly the way the six
 * production runners do, and detects the fall-through by what reaches the far
 * side of the call: the original caller must arrive there once, and the forked
 * child must not arrive at all.
 */

#define DEBUG_TESTS 1
#include "test_setup.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/wait.h>
#include <pthread.h>

#include "processes/processes.h"
#include "structures/map.h"

/* Written by whoever reaches the far side of start_process. */
static int report_fd = -1;

/* The shape every production runner has: process_setup() forks inside it, so it
 * returns the child's pid in the caller and the run loop's result in the child.
 * No daemonize here — the fall-through has nothing to do with double-forking,
 * and a real daemonize would detach the child from this test's process group. */
static int forking_runner(process_t *proc, directory_t *queues,
                          queue_id_t signal, logger_t *logger)
{
    (void)proc; (void)queues; (void)signal; (void)logger;
    pid_t p = fork();
    if (p < 0)
        return -1;
    if (p != 0)
        return (int)p;   /* caller: the new subsystem's pid */
    /* child: stand in for a run loop that has just ended at shutdown */
    return 0;
}

DEFINE_TEST(test_a_forked_subsystem_does_not_return_into_the_start_loop)
{
    int fds[2];
    ck_assert_int_eq(pipe(fds), 0);
    report_fd = fds[1];

    map_t procs;
    ck_assert_ret_ok(map_init(&procs));
    pthread_mutex_t lock;
    ck_assert_int_eq(pthread_mutex_init(&lock, NULL), 0);
    map_t configs;
    ck_assert_ret_ok(map_init(&configs));   /* empty: process_init tolerates it */
    directory_t queues = {0};
    logger_t logger = {0};
    ck_assert_ret_ok(logger_init(&logger, CRITICAL, NULL));

    proc_context_t ctx = {
        .procs = &procs,
        .procs_lock = &lock,
        .queues = &queues,
        .logger = &logger,
    };

    pid_t caller = getpid();
    char pname[] = "fallthrough_probe";
    int rc = start_process(pname, forking_runner, &configs, NULL, &ctx);

    /* THE ASSERTION UNDER TEST is not `rc` — it is WHO GETS HERE.
     *
     * The guard below is not the check; it only keeps a failing run tidy. Without
     * the fix the forked child arrives here too and would otherwise go on to run
     * the remainder of this suite a second time (which is exactly what the
     * cascade does to the daemon's start loop, and what it looked like when this
     * test was first written). So the intruder records itself and leaves; the
     * pipe contents are the verdict. */
    if (getpid() != caller) {
        ssize_t cw = write(report_fd, "C", 1);
        (void)cw;
        close(report_fd);
        _exit(0);
    }
    ssize_t w = write(report_fd, "P", 1);
    (void)w;
    close(fds[1]);
    report_fd = -1;

    /* Read to EOF, not one read(): read() returns as soon as ANY byte is
     * available, so a single call sees only the first arrival and would pass
     * even while the bug is present. EOF is reached once both write ends are
     * closed — the parent's just above, the child's on _exit — so this cannot
     * race either way. */
    char seen[8] = {0};
    size_t got = 0;
    for (;;) {
        ssize_t n = read(fds[0], seen + got, sizeof(seen) - got - 1);
        if (n <= 0) break;
        got += (size_t)n;
        if (got >= sizeof(seen) - 1) break;
    }
    close(fds[0]);

    ck_assert_int_eq(rc, 0);
    /* Exactly the caller, and nobody else. "PC" (either order) means the forked
     * child returned and would have gone on to start the remaining subsystems. */
    ck_assert_str_eq(seen, "P");

    /* Reap whatever the runner forked, so the suite leaves no corpse of its own. */
    int status = 0;
    while (waitpid(-1, &status, WNOHANG) > 0) { }

    map_free(&procs);
    map_free(&configs);
    pthread_mutex_destroy(&lock);
}

/* daemonize()'s intermediate child _exit()s as soon as it has reported the
 * grandchild's pid, and used to be left unreaped — a live node held ten zombies
 * (one per subsystem plus the daemon's own) for its whole lifetime. Untidy on
 * its own, but a zombie also answers `kill(pid, 0) == 0`, so any liveness check
 * pointed at one reports it alive forever.
 *
 * Distinct from the case above and NOT its cause: the pids the daemon monitors
 * come back through daemonize's pipe and are the grandchildren, never these
 * intermediates. */
DEFINE_TEST(test_daemonize_reaps_its_intermediate)
{
    /* Fork first: daemonize() detaches and would take the test process with it. */
    int fds[2];
    ck_assert_int_eq(pipe(fds), 0);
    pid_t probe = fork();
    ck_assert(probe >= 0);
    if (probe == 0) {
        close(fds[0]);
        int fd1 = 0, fd2 = 0;
        char dir[] = "/tmp";
        int rc = daemonize(dir, NO_CHDIR | NO_CLOSE_FILES | NO_STDOUT_REDIRECT
                                 | NO_STDERR_REDIRECT, &fd1, &fd2);
        if (rc == 0)
            _exit(0);            /* the grandchild: nothing to do */
        if (rc < 0)
            _exit(2);
        /* The original caller. Any child of ours now is an unreaped
         * intermediate; with the fix there is none and waitpid says ECHILD. */
        int status = 0;
        pid_t left = waitpid(-1, &status, WNOHANG);
        char verdict = (left == -1 && errno == ECHILD) ? 'c' : 'z';
        ssize_t w = write(fds[1], &verdict, 1);
        (void)w;
        close(fds[1]);
        _exit(0);
    }
    close(fds[1]);
    char verdict = '?';
    ssize_t n = read(fds[0], &verdict, 1);
    close(fds[0]);
    int status = 0;
    waitpid(probe, &status, 0);
    while (waitpid(-1, &status, WNOHANG) > 0) { }

    ck_assert_int_eq((int)n, 1);
    /* 'z' = an intermediate was still waiting to be reaped. */
    ck_assert_int_eq(verdict, 'c');
}

RUN_TESTS(Process_Child_Exit,
          test_a_forked_subsystem_does_not_return_into_the_start_loop,
          test_daemonize_reaps_its_intermediate)
