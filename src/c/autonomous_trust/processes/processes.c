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

#define _GNU_SOURCE // for pthread_setname_np
#include <string.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/msg.h>
#include <errno.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/time.h>
#include <pthread.h>

#define PROCESSES_IMPL
#include "processes/processes.h"
// #include "protobuf/processes.pb-c.h"
#include "config/configuration.h"
#include "structures/map_priv.h"
#include "utilities/msg_types_priv.h"
#include "utilities/util.h"

const char *sig_quit = "quit";

const long cadence = 500000L; // microseconds

typedef bool (*msg_handler_t)(const process_t *proc, directory_t *queues, generic_msg_t *msg);

int process_init(process_t *proc, char *name, handler_ptr_t runner, map_t *configurations, tracker_t *subsystems, logger_t *logger, array_t *dependencies)
{
    memset(proc->name, 0, PROC_NAME_LEN);
    memcpy(proc->name, name, PROC_NAME_LEN - 1);
    // FIXME general config load/save
    config_t *cfg = NULL;
    data_t *cfg_dat = NULL;
    if (map_get(configurations, proc->name, &cfg_dat) != 0)
        return -1;
    if (data_object_ptr(cfg_dat, (void **)&cfg) != 0)
        return -1;
    memcpy(&proc->conf, cfg, sizeof(config_t));
    proc->configs = configurations;
    proc->subsystems = subsystems;
    proc->logger = logger;
    proc->dependencies = dependencies;
    proc->runner = runner;
    return map_create(&proc->protocol.handlers); // FIXME protocol from config
}

int _process_start(pid_t orig, char *pname, handler_ptr_t runner, map_t *configs, tracker_t *tracker,
                   map_t *procs, directory_t *queues, logger_t *logger)
{
    process_t *proc;
    if (orig > 0)
    {
        char pid_str[32] = {0};
        snprintf(pid_str, 31, "%d", orig);
        if (map_remove(procs, pid_str))
            return -1;

        data_t *proc_val;
        if (map_get(procs, pname, &proc_val))
            return -1;
        if (data_object_ptr(proc_val, (void **)&proc))
            return -1;
        log_info(logger, "Restart %s process\n", proc->name);
    }
    else
    {
        proc = smrt_create(sizeof(process_t)); // FIXME does this get freed?
        if (process_init(proc, pname, runner, configs, tracker, logger, NULL) != 0)
            return -1; // FIXME no such key in the map (EMAP_NOKEY)
    }

    char sig[SIG_NAME_LEN + 1] = {0};
    process_name_to_signal(pname, sig);

    pid_t pid = proc->runner(proc, queues, sig, logger); // FIXME ensure child does run fnctn
    if (pid == -1)
    {
        log_error(logger, "Error starting process '%s'\n", pname);
        return SYS_EXCEPTION();
    }

    // record pids for monitoring
    char pid_str[32] = {0};
    snprintf(pid_str, 31, "%d", pid);
    // data_t *key_val = string_data(pname, strlen(pname));
    data_t *proc_val = object_ptr_data(proc, sizeof(process_t));
    if (map_set(procs, pid_str, proc_val) != 0)
        return -1;
    return 0;
}

int start_process(char *pname, handler_ptr_t runner, map_t *configs, tracker_t *tracker,
                  map_t *procs, directory_t *queues, logger_t *logger)
{
    return _process_start(-1, pname, runner, configs, tracker, procs, queues, logger);
}

int restart_process(pid_t orig, char *pname, map_t *procs, directory_t *queues, logger_t *logger)
{
    return _process_start(orig, pname, NULL, NULL, NULL, procs, queues, logger);
}

void process_name_to_signal(const char *name, char *sig)
{
    snprintf(sig, SIG_NAME_LEN, "%s_s", name);
}

int set_process_name(const char *name_in)
{
    char name[PROC_NAME_LEN + 1] = {0};
    strncpy(name, name_in, PROC_NAME_LEN - 1);
    pthread_t tid = pthread_self();
    int err = pthread_setname_np(tid, name);
    if (err != 0)
        return EXCEPTION(err);
    return 0;
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
            if (err != 0) // FIXME logging?
                return false;
            msg_handler_t handler;
            err = data_object_ptr(h_dat, (void *)&handler);
            if (err != 0)
                return false;
            return handler(proc, queues, msg);
        }
    }
    return false;
}

bool keep_running(const process_t *proc, queue_t *sig_q, logger_t *logger)
{
    if (gettimeofday((struct timeval *)&proc->start, NULL) != 0)
    {
        SYS_EXCEPTION();
        log_exception(logger);
    }
    while (1)
    {
        signal_t msg = {0};
        long type = 0;
        int err = signal_recv(sig_q, &type, &msg);
        if (err == -1)
            log_exception(logger);
        else if (err == -2 && type != SIGNAL)
            log_error(logger, "Non-signal message on signal queue: %d\n", type);
        else if (err == ENOMSG)
            return true;
        else if (msg.descr == sig_quit)
            return false;
        else
            log_error(logger, "Unhandled signal: %d - '%s'\n", msg.sig, msg.descr);
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
    char data_path[MAX_FILENAME + 1];
    get_data_dir(data_path);

    int fd1 = 0;
    int fd2 = 0;
    int err = daemonize(data_path, proc->flags, &fd1, &fd2);
    if (err != 0)
        return err;

    pid_t pid = getpid();
    log_debug(logger, "Child pid %d\n", pid); // FIXME remove
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
            void *msg = smrt_create(size);
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
