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

#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/msg.h>
#include <errno.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <sys/time.h>

#define PROCESSES_IMPL
#include "processes/processes.h"
//#include "protobuf/processes.pb-c.h"
#include "config/configuration.h"
#include "structures/map_priv.h"
#include "utilities/msg_types_priv.h"
#include "utilities/util.h"

#define MAX_CLOSE 8192

const char *sig_quit = "quit";

const long cadence = 500000L; // microseconds


typedef bool (*msg_handler_t)(const process_t *proc, directory_t *queues, generic_msg_t *msg);

int process_init(process_t *proc, char *name, map_t *configurations, tracker_t *subsystems, logger_t *logger, array_t *dependencies)
{
    memset(proc->name, 0, PROC_NAME_LEN);
    memcpy(proc->name, name, PROC_NAME_LEN-1);
    // FIXME general config load/save
    data_t *cfg_dat;
    if (map_get(configurations, proc->name, &cfg_dat) != 0)
        return -1;
    config_t *cfg;
    if (data_object_ptr(cfg_dat, (void**)&cfg) != 0)
        return -1;
    memcpy(&proc->conf, cfg, sizeof(config_t));
    proc->configs = configurations; // FIXME copy?
    proc->subsystems = subsystems;
    proc->logger = logger;
    proc->dependencies = dependencies;
    return map_create(&proc->protocol.handlers); // FIXME protocol from config
}

inline int process_register_handler(const process_t *proc, char *func_name, handler_ptr_t handler)
{
    data_t *h_dat = object_ptr_data(handler, sizeof(handler_ptr_t));
    return map_set(proc->protocol.handlers, func_name, h_dat);
}

bool run_message_handlers(process_t *proc, directory_t *queues, long msgtype, generic_msg_t *msg)
{
    switch (msgtype)
    {
    case GROUP:
        proc->protocol.group = msg->info.group;
        return true;
    case PEER:
        memcpy(&proc->protocol.peers[proc->protocol.num_peers++], &msg->info.peer, sizeof(public_identity_t));
        return true;
    case PEER_CAPABILITIES:
        // pproc->peer_capabilities = message
        return true;
    default:
        net_msg_t *nmsg = &msg->info.net_msg;
        if (nmsg->process == proc->name)
        {
            data_t *h_dat;
            int err = map_get(proc->protocol.handlers, nmsg->function, &h_dat);
            if (err != 0)  // FIXME logging?
                return false;
            msg_handler_t handler;
            err = data_object_ptr(h_dat, (void*)&handler);
            if (err != 0)
                return false;
            return handler(proc, queues, msg);
        }
    }
    return false;
}

int daemonize(char *data_dir, int flags, int *fd1, int *fd2)
{
    int io[2] = {0};
    int err = pipe(io);
    if (err != 0)
        return SYS_EXCEPTION();

    int pid = fork();
    if (pid == -1) {
        close(io[0]);
        close(io[1]);
        return SYS_EXCEPTION();
    }
    if (pid != 0) {  // parent
        close(io[1]);
        int status;
        waitpid(pid, &status, 0);
        if (WIFEXITED(status) || WIFSIGNALED(status)) {
            pid_t gchild = -1;
            read(io[0], &gchild, sizeof(int));
            close(io[0]);
            return gchild;
        }
        close(io[0]);
        return ECHILD;
    }
    close(io[0]);

    if (setsid() == -1) { // lead new session
        close(io[1]);
        return SYS_EXCEPTION();
    }
        
    pid = fork();
    if (pid == -1) {
        close(io[1]);
        return SYS_EXCEPTION();
    }
    if (pid != 0) {  // parent
        write(io[1], &pid, sizeof(int));
        close(io[1]);
        _exit(0);
    }
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

bool keep_running(const process_t *proc, queue_t *sig_q, logger_t *logger)
{
    generic_msg_t buf = {0};
    if (gettimeofday((struct timeval *)&proc->start, NULL) != 0) {
        SYS_EXCEPTION();
        log_exception(logger);
    }
    while (buf.type != SIGNAL) {
        int err = messaging_recv_on(sig_q, &buf);
        signal_t *msg = &buf.info.signal;
        if (err == -1)
            log_exception(logger);
        if (err == ENOMSG)
            return true;
        if (buf.type != SIGNAL)
            log_error(logger, "Non-signal message on signal queue: %d\n", buf.type);
        else if (msg->descr == sig_quit)
            return false;
        else
            log_error(logger, "Unhandled signal: %d - '%s'\n", msg->sig, msg->descr);
    }
    return true;
}

long timeval_subtract(struct timeval *a, struct timeval *b)
{
    time_t extra = 0;
    suseconds_t usec = a->tv_usec - b->tv_usec;
    if (usec < 0)
    {
        extra = 1;
        usec = 1000L + usec;
    }
    time_t sec = a->tv_sec - b->tv_sec - extra;
    return (sec * 1000L) + usec;
}

void sleep_until(const process_t *proc, long how_long)
{
    struct timeval now;
    gettimeofday(&now, NULL);

    long delta = how_long - timeval_subtract(&now, (struct timeval *)&proc->start);
    if (delta > 0)
        usleep(delta);
}

int process_run(process_t *proc, directory_t *queues, queue_id_t signal, logger_t *logger)
{
    char data_path[MAX_FILENAME+1];
    get_data_dir(data_path);

    int fd1 = 0;
    int fd2 = 0;
    int err = daemonize(data_path, proc->flags, &fd1, &fd2);
    if (err != 0)
        return err;

    pid_t pid = getpid();
    log_debug(logger, "Child pid %d\n", pid);  // FIXME remove
    // FIXME message_init
    queue_t my_q;
    if (messaging_init(proc->name, &my_q) != 0)
        log_exception(logger);
    messaging_assign(&my_q);
    queue_t sig_q;
    if (messaging_init(signal, &sig_q) != 0)
        log_exception(logger);

    // FIXME pre-loop activity

    // handle messages
    array_t unprocessed;
    array_init(&unprocessed);
    while (keep_running(proc, &sig_q, logger))
    {
        sleep_until(proc, cadence);

        generic_msg_t buf = {0};
        err = messaging_recv(&buf);
        if (err == -1)
            ; // FIXME repair?
        if (err == ENOMSG)
                continue;
        if (!run_message_handlers(proc, queues, buf.type, &buf))
        {
            size_t size = message_size(buf.type);
            void *msg = calloc(1, size);
            if (msg == NULL)
                continue; // FIXME logging
            memcpy(msg, &buf.info, size);
            data_t *m_dat = object_ptr_data(msg, size);
            array_append(&unprocessed, m_dat);
        }
        // FIXME post-msg handling activity
    }
    array_free(&unprocessed);
    array_free(queues);
    if (fd1 > 0)
        close(fd1);
    if (fd2 > 0)
        close(fd2);

    return 0;
}
