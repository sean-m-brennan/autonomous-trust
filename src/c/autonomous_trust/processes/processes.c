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
#include "structures/map.h"
#include "utilities/msg_types_priv.h"
#include "utilities/probes.h"
#include "utilities/util.h"

const char *sig_quit = "quit";

const long cadence = 500000L; // microseconds

typedef bool (*msg_handler_t)(const process_t *proc, directory_t *queues, generic_msg_t *msg);

/*@
  requires \valid(proc);
  requires name != \null && \valid_read(name);
  requires \valid(configurations);
  assigns proc->name[0 .. PROC_NAME_LEN],
          proc->conf, proc->configs, proc->subsystems,
          proc->logger, proc->dependencies, proc->runner,
          proc->protocol.handlers;
  behavior success:
    ensures \result == 0;
  behavior failure:
    ensures \result != 0;
  disjoint behaviors;
*/
/* Frama-C: skipped — [solver-timeout] logging/snprintf preconditions */
int process_init(process_t *proc, char *name, handler_ptr_t runner, map_t *configurations, tracker_t *subsystems, logger_t *logger, array_t *dependencies)
{
    memset(proc->name, 0, PROC_NAME_LEN);
    memcpy(proc->name, name, PROC_NAME_LEN - 1);
    // Config loaded from per-process JSON files via load_all_configs()
    config_t *cfg = NULL;
    data_t *cfg_dat = NULL;
    memset(&proc->conf, 0, sizeof(config_t));
    if (map_get(configurations, proc->name, &cfg_dat) == 0)
    {
        if (data_object_ptr(cfg_dat, (void **)&cfg) == 0)
            memcpy(&proc->conf, cfg, sizeof(config_t));
    }
    proc->configs = configurations;
    proc->subsystems = subsystems;
    proc->logger = logger;
    proc->dependencies = dependencies;
    proc->runner = runner;
    if (pthread_rwlock_init(&proc->protocol.peers_rwlock, NULL) != 0)
        return -1;
    // TODO: Load protocol handler table from config to allow runtime customization
    return map_create(&proc->protocol.handlers);
}

/* Frama-C: skipped — [solver-timeout] process lifecycle preconditions */
int _process_start(pid_t orig, char *pname, handler_ptr_t runner, map_t *configs, tracker_t *tracker,
                   map_t *procs, pthread_mutex_t *procs_lock, directory_t *queues, logger_t *logger)
{
    process_t *proc;
    if (orig > 0)
    {
        char pid_str[32] = {0};
        snprintf(pid_str, 31, "%d", orig);
        if (procs_lock != NULL)
            pthread_mutex_lock(procs_lock);
        int rc = map_remove(procs, pid_str);
        data_t *proc_val = NULL;
        if (rc == 0)
            rc = map_get(procs, pname, &proc_val);
        if (procs_lock != NULL)
            pthread_mutex_unlock(procs_lock);
        if (rc != 0)
            return -1;
        if (data_object_ptr(proc_val, (void **)&proc))
            return -1;
        log_info(logger, "Restart %s process\n", proc->name);
    }
    else
    {
        proc = smrt_create(sizeof(process_t)); // freed via smrt_deref when process exits
        if (process_init(proc, pname, runner, configs, tracker, logger, NULL) != 0)
        {
            // process_init may fail if pname is not found in the configs map (EMAP_NOKEY);
            // the exception has already been set by the map_get call inside process_init
            return -1;
        }
    }

    char sig[SIG_NAME_LEN + 1] = {0};
    process_name_to_signal(pname, sig);

    pid_t pid = proc->runner(proc, queues, sig, logger);
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
    if (procs_lock != NULL)
        pthread_mutex_lock(procs_lock);
    int rc = map_set(procs, pid_str, proc_val);
    if (procs_lock != NULL)
        pthread_mutex_unlock(procs_lock);
    if (rc != 0)
        return -1;
    return 0;
}

int start_process(char *pname, handler_ptr_t runner, map_t *configs, tracker_t *tracker,
                  map_t *procs, pthread_mutex_t *procs_lock, directory_t *queues, logger_t *logger)
{
    return _process_start(-1, pname, runner, configs, tracker, procs, procs_lock, queues, logger);
}

int restart_process(pid_t orig, char *pname, map_t *procs, pthread_mutex_t *procs_lock, directory_t *queues, logger_t *logger)
{
    return _process_start(orig, pname, NULL, NULL, NULL, procs, procs_lock, queues, logger);
}

/*@
  requires name != \null && \valid_read(name);
  requires \valid(sig + (0 .. SIG_NAME_LEN));
  assigns sig[0 .. SIG_NAME_LEN];
*/
void process_name_to_signal(const char *name, char *sig)
{
    snprintf(sig, SIG_NAME_LEN, "%s_s", name);
}

/*@
  requires name_in != \null && \valid_read(name_in);
  assigns \nothing;
  behavior success:
    ensures \result == 0;
  behavior failure:
    ensures \result != 0;
  disjoint behaviors;
*/
/* Frama-C: skipped — [solver-timeout] strncpy preconditions */
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

/* Frama-C: skipped — [solver-timeout] logging/snprintf preconditions */
inline int process_register_handler(const process_t *proc, char *func_name, handler_ptr_t handler)
{
    data_t *h_dat = object_ptr_data(handler, sizeof(handler_ptr_t));
    return map_set(proc->protocol.handlers, func_name, h_dat);
}

/* Frama-C: skipped — [func-ptr] msg_handler_t callback dispatch */
bool run_message_handlers(process_t *proc, directory_t *queues, long msgtype, generic_msg_t *msg)
{
    switch (msgtype)
    {
    case GROUP:
        proc->protocol.group = msg->info.group;
        return true;
    case PEER:
        peers_write_lock(proc);
        if (proc->protocol.num_peers < DEFAULT_MAX_PEERS)
        {
            memcpy(&proc->protocol.peers[proc->protocol.num_peers], &msg->info.peer, sizeof(public_identity_t));
            proc->protocol.num_peers++;
        }
        peers_write_unlock(proc);
        return true;
    case PEER_RTT_UPDATE: {
        /* Net-proc → us: the authoritative RTT estimate for a peer. Look
         * up by uuid and stash into peer_rtt_ms[]. If the PEER_RTT_UPDATE
         * outran the PEER message, the peer isn't here yet — drop and
         * rely on net_proc's future re-emission (or accept stale RTT).
         * Scope of write lock is intentionally narrow: no callouts. */
        const peer_rtt_update_msg_t *rtt = &msg->info.peer_rtt_update;
        peers_write_lock(proc);
        bool matched = false;
        for (size_t i = 0; i < proc->protocol.num_peers; i++) {
            if (memcmp(proc->protocol.peers[i].uuid, rtt->peer_uuid, 16) == 0) {
                proc->protocol.peer_rtt_ms[i] = rtt->rtt_ms;
                matched = true;
                break;
            }
        }
        peers_write_unlock(proc);
        if (!matched)
            log_debug(proc->logger, "%s: rtt_update for unknown peer\n", proc->name);
        return true;
    }
    case PEER_CAPABILITIES:
        // pproc->peer_capabilities = message
        return true;
    default: {
        net_msg_t *nmsg = &msg->info.net_msg;
        if (strcmp(nmsg->process, proc->name) == 0)
        {
            data_t *h_dat;
            int err = map_get(proc->protocol.handlers, nmsg->function, &h_dat);
            if (err != 0)
            {
                log_warn(proc->logger, "%s: message handler returned error\n", proc->name);
                return false;
            }
            msg_handler_t handler;
            err = data_object_ptr(h_dat, (void *)&handler);
            if (err != 0)
            {
                log_warn(proc->logger, "%s: failed to extract handler for '%s'\n", proc->name, nmsg->function);
                return false;
            }
            return handler(proc, queues, msg);
        }
    } // default
    } // switch
    return false;
}

/* Frama-C: skipped — [syscall] IPC message queue read loop */
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
        else if (strcmp(msg.descr, sig_quit) == 0)
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

/* Frama-C: skipped —
 * [func-ptr] run_message_handlers dispatches via msg_handler_t [syscall] keep_running
 * reads from IPC message queue [solver-timeout] process_init/setup/start/loop/run:
 * complex lifecycle with fork/queue/snprintf/strncpy preconditions; set_process_name:
 * strncpy preconditions
 */
void sleep_until(const process_t *proc, long how_long)
{
    struct timeval now;
    gettimeofday(&now, NULL);

    long delta = how_long - timeval_subtract(&now, (struct timeval *)&proc->start);
    if (delta > 0)
        usleep(delta);
}

/* Frama-C: skipped — [solver-timeout] complex lifecycle preconditions */
int process_setup(process_t *proc, queue_id_t signal, logger_t *logger,
                  process_ctx_t *ctx)
{
    char data_path[MAX_FILENAME + 1];
    get_data_dir(data_path);

    ctx->fd1 = 0;
    ctx->fd2 = 0;
    int err = daemonize(data_path, proc->flags, &ctx->fd1, &ctx->fd2);
    if (err != 0)
        return err;

    pid_t pid = getpid();
    log_debug(logger, "Child pid %d\n", pid);
    if (messaging_init(proc->name, &ctx->my_q) != 0)
        log_exception(logger);
    messaging_assign(&ctx->my_q);
    if (messaging_init(signal, &ctx->sig_q) != 0)
        log_exception(logger);

    return 0;
}

/* Frama-C: skipped —
 * [func-ptr] run_message_handlers dispatches via msg_handler_t [syscall] keep_running
 * reads from IPC message queue [solver-timeout] process_init/setup/start/loop/run:
 * complex lifecycle with fork/queue/snprintf/strncpy preconditions; set_process_name:
 * strncpy preconditions
 */
int process_loop(process_t *proc, directory_t *queues, logger_t *logger,
                 process_ctx_t *ctx)
{
    array_t unprocessed;
    array_init(&unprocessed);
    while (keep_running(proc, &ctx->sig_q, logger))
    {
        sleep_until(proc, cadence);

        generic_msg_t buf = {0};
        int err = messaging_recv(&buf);
        if (err == -1) {
            log_debug(proc->logger, "%s: message receive error\n", proc->name);
            continue;
        }
        if (err == ENOMSG)
            continue;
        if (!run_message_handlers(proc, queues, buf.type, &buf))
        {
            /* Probe parity with Python's automate.py:517-521 unhandled-
             * message instrumentation. Layer is the proc name so the
             * tail tool can pivot per-process; reason is the message
             * type as a small int. */
            char type_buf[32];
            snprintf(type_buf, sizeof(type_buf), "type:%ld", buf.type);
            char layer[PROC_NAME_LEN + 16];
            snprintf(layer, sizeof(layer), "proc.%s", proc->name);
            probes_counter(layer, "unhandled", type_buf);
            /* Network messages carry a trace_id; emit a correlation
             * record so downstream tooling can follow the message
             * end-to-end. Mirrors Python automate.py:518 / repprocess.py:570 /
             * negprocess.py:348. */
            if (buf.type == NET_MESSAGE) {
                probes_trace_msg(buf.info.net_msg.trace_id,
                                 buf.info.net_msg.process,
                                 buf.info.net_msg.function,
                                 "unhandled", "proc", proc->name, NULL);
            }
            size_t size = message_size(buf.type);
            void *msg = smrt_create(size);
            if (msg == NULL)
            {
                log_debug(proc->logger, "%s: skipping unhandled message type %ld\n", proc->name, buf.type);
                continue;
            }
            memcpy(msg, &buf.info, size);
            data_t *m_dat = object_ptr_data(msg, size);
            array_append(&unprocessed, m_dat);
        }
        // Hook point for sub-process specific post-message activity (e.g. periodic tasks)
    }
    array_free(&unprocessed);
    array_free(queues);
    if (ctx->fd1 > 0)
        close(ctx->fd1);
    if (ctx->fd2 > 0)
        close(ctx->fd2);

    return 0;
}

int process_run(process_t *proc, directory_t *queues, queue_id_t signal, logger_t *logger)
{
    process_ctx_t ctx = {0};
    int err = process_setup(proc, signal, logger, &ctx);
    if (err != 0)
        return err;
    return process_loop(proc, queues, logger, &ctx);
}

/* Mirrors Python's Process.update queue-broadcast (processes.py:195-218).
 * Iterates the queue directory, skips the caller's own slot, and
 * messaging_send's @p msg to each. Per-queue failures are logged and
 * recorded as a `proc.update` / `queue_full` counter increment so the
 * scattered-drop pattern shows up in probe output. The Python version
 * uses `queue.put(block=True, timeout=q_cadence)` and catches Full;
 * the C `messaging_send(..., false)` is non-blocking and surfaces a
 * non-zero return on failure, which is the equivalent signal. */
int process_update(const process_t *proc, directory_t *queues,
                   generic_msg_t *msg)
{
    if (proc == NULL || queues == NULL || msg == NULL)
        return -1;
    size_t qsize = array_size(queues);
    int sent = 0;
    for (size_t i = 0; i < qsize; i++) {
        data_t *name_val = NULL;
        if (array_get(queues, (int)i, &name_val) != 0)
            continue;
        char *qname = NULL;
        if (data_string_ptr(name_val, &qname) != 0 || qname == NULL)
            continue;
        if (strcmp(qname, proc->name) == 0)
            continue;
        int rc = messaging_send(qname, msg->type, msg, false);
        if (rc != 0) {
            if (proc->logger != NULL)
                log_warn(proc->logger,
                         "process_update: send to %s failed (rc=%d)\n",
                         qname, rc);
            probes_counter("proc.update", "queue_full", qname);
            continue;
        }
        sent++;
    }
    return sent;
}
