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

#define _DEFAULT_SOURCE
#include <stdio.h>
#include <stdbool.h>
#include <errno.h>
#include <unistd.h>
#include <sys/types.h>
#include <unistd.h>
#include <sys/wait.h>
#include <string.h>
#include <signal.h>

#include "version.h"
#include "at_route_priv.h"
#include "utilities/message.h"
#include "utilities/msg_types_priv.h"
#include "utilities/logger.h"
#include "utilities/sighandler.h"
#include "config/configuration_priv.h"
#include "processes/processes.h"
#include "processes/process_tracker_priv.h"
#include "structures/array.h"
#include "structures/map.h"
#include "utilities/protobuf_shutdown.h"
#include "network/network.h"
#include "negotiation/negotiation.h"
#include "reputation/reputation.h"


/* Weak-placeholder signal hooks required by sighandler.c. Reserved for
 * future use (SIGHUP = reread config, SIGUSR1/2 = user-defined actions);
 * intentionally no-op today — sighandler.h documents this contract. */
void reread_configs() { /* reserved: SIGHUP — reload config at runtime */ }

void user1_handler() { /* reserved: SIGUSR1 — user-defined action */ }

void user2_handler() { /* reserved: SIGUSR2 — user-defined action */ }


int at_route_extern_msg(generic_msg_t *msg, logger_t *logger)
{
    if (msg == NULL)
        return -1;
    switch (msg->type)
    {
    case TASK:
        /* Route tasks to negotiation process */
        if (messaging_send("negotiation", TASK, msg, false) != 0)
            log_exception(logger);
        return 0;
    case TASK_STATUS:
        /* Route task status queries to negotiation */
        if (messaging_send("negotiation", TASK_STATUS, msg, false) != 0)
            log_exception(logger);
        return 0;
    case UPDATE_PROPOSAL:
        /* Route update proposals to fleet process */
        if (messaging_send("fleet", UPDATE_PROPOSAL, msg, false) != 0)
            log_exception(logger);
        return 0;
    case NET_MESSAGE:
    {
        /* An app may invoke only a small, explicit allowlist of local verbs,
         * each at a fixed set of processes. Forwarding a NET_MESSAGE to whatever
         * process it names would hand an app the whole internal verb surface. */
        const char *fn = msg->info.net_msg.function;
        if (fn != NULL && strcmp(fn, AT_APP_ROSTER_REQUEST) == 0)
        {
            /* All three carrier producers answer: identity holds the peer facts
             * (and now positions), reputation the scores, network the RTT. Each
             * copy is addressed to its own process, since dispatch matches
             * net_msg.process against proc->name. */
            static const char *const roster_targets[] = { "identity", "reputation", "network" };
            for (size_t i = 0; i < sizeof(roster_targets) / sizeof(*roster_targets); i++)
            {
                generic_msg_t fwd = *msg;
                snprintf(fwd.info.net_msg.process, sizeof(fwd.info.net_msg.process),
                         "%s", roster_targets[i]);
                if (messaging_send(roster_targets[i], NET_MESSAGE, &fwd, false) != 0)
                    log_exception(logger);
            }
            return 0;
        }
        if (fn != NULL && strcmp(fn, AT_APP_SET_POSITION) == 0)
        {
            /* Opt-in own-position: forwarded ONLY to identity, which owns the
             * position store and answers peers' directed position queries. */
            generic_msg_t fwd = *msg;
            snprintf(fwd.info.net_msg.process, sizeof(fwd.info.net_msg.process),
                     "%s", "identity");
            if (messaging_send("identity", NET_MESSAGE, &fwd, false) != 0)
                log_exception(logger);
            return 0;
        }
        if (fn != NULL && strcmp(fn, AT_APP_SET_PROFILE) == 0)
        {
            /* Opt-in own-profile (Increment 3): forwarded ONLY to identity,
             * which owns the profile store and signs/answers peers' directed
             * profile queries. */
            generic_msg_t fwd = *msg;
            snprintf(fwd.info.net_msg.process, sizeof(fwd.info.net_msg.process),
                     "%s", "identity");
            if (messaging_send("identity", NET_MESSAGE, &fwd, false) != 0)
                log_exception(logger);
            return 0;
        }
        if (fn != NULL && (strcmp(fn, AT_APP_CONNECT_REQUEST) == 0
                           || strcmp(fn, AT_APP_CONNECT_RESPOND) == 0))
        {
            /* Explicit connection verbs (Increment 5): forwarded ONLY to
             * identity, which owns the connection edge store and sends the
             * directed request / signed response. */
            generic_msg_t fwd = *msg;
            snprintf(fwd.info.net_msg.process, sizeof(fwd.info.net_msg.process),
                     "%s", "identity");
            if (messaging_send("identity", NET_MESSAGE, &fwd, false) != 0)
                log_exception(logger);
            return 0;
        }
        if (fn != NULL && strcmp(fn, AT_APP_SEND_DM) == 0)
        {
            /* Direct message (Increment 6): forwarded ONLY to identity, which
             * sends the directed encrypted peer_dm to the target peer. */
            generic_msg_t fwd = *msg;
            snprintf(fwd.info.net_msg.process, sizeof(fwd.info.net_msg.process),
                     "%s", "identity");
            if (messaging_send("identity", NET_MESSAGE, &fwd, false) != 0)
                log_exception(logger);
            return 0;
        }
        log_warn(logger, "AutonomousTrust: refused extern net_msg '%s'\n",
                 fn == NULL ? "(none)" : fn);
        return -1;
    }
    default:
        log_warn(logger, "AutonomousTrust: unexpected extern message type %ld\n",
                 msg->type);
        return -1;
    }
}


int at_route_queue_msg(array_t *unhandled, generic_msg_t *msg)
{
    if (unhandled == NULL || msg == NULL)
        return -1;
    /* By reference to the WHOLE struct: the drain switches on ->type, and
     * object_ptr_data stores the pointer as given (it copies nothing). */
    data_t *msg_dat = object_ptr_data(msg, sizeof(generic_msg_t));
    if (msg_dat == NULL)
        return -1;
    if (array_append(unhandled, msg_dat) != 0)
    {
        smrt_deref(msg_dat);
        return -1;
    }
    return 0;
}


int at_route_internal_msgs(array_t *unhandled, const char *q_out,
                           logger_t *logger)
{
    if (unhandled == NULL)
        return 0;
    int sent = 0;
    while (array_size(unhandled) > 0)
    {
        data_t *msg_dat = NULL;
        if (array_get(unhandled, 0, &msg_dat) != 0)
        {
            log_exception(logger);
            break;  // read error — abandon
        }

        /* Route internal messages by type */
        generic_msg_t *inner = NULL;
        data_object_ptr(msg_dat, (void **)&inner);
        if (inner != NULL)
        {
            switch (inner->type)
            {
            case TASK_STATUS:
                /* Task status updates go to negotiation */
                if (messaging_send("negotiation", TASK_STATUS, inner, false) != 0)
                    log_exception(logger);
                break;
            /* App-bound: sent as we drain, in FIFO order. Batching them into a
             * second array and sending one message after the loop is what
             * silently dropped every message but the last.
             *
             * TASK_RESULT joined this group when the C twin gained a scoring
             * path. It used to be forwarded to the reputation process "for
             * scoring", but nothing there ever handled it -- that process
             * dispatches net_msg payloads by function name plus its own
             * locally-submitted TRANSACTION_SCORE, so every result was
             * received and dropped. The score is now raised where the
             * requestor's own record of the task lives (neg_proc.c
             * handle_results, which submits the TRANSACTION_SCORE itself), and
             * this hop delivers the result to whoever asked for the work --
             * mirroring automate.py putting the TaskResult on the app's
             * external-feedback queue. */
            case TASK_RESULT:
            case TRANSACTION_SCORE:
            case UPDATE_ACCEPTED:
            case PEER_OBSERVED:
            case PEER_REPUTATION:
            case PEER_RTT_OBSERVED:
            case PEER_POSITION_OBSERVED:
            case PEER_PROFILE_OBSERVED:
                if (q_out == NULL)
                    break;   /* no app attached; nothing to do */
                if (messaging_send(q_out, (message_type_t)inner->type, inner, false) != 0)
                    log_exception(logger);
                else
                    sent++;
                break;
            default:
                break;
            }
        }
        if (array_remove(unhandled, msg_dat) != 0) {
            log_exception(logger);
            break;  // guard against infinite loop if remove fails
        }
        /* array_remove unlinks but does not free; without this the daemon
         * leaks one data_t per message routed. */
        smrt_deref(msg_dat);
    }
    return sent;
}


int register_queues(tracker_t *tracker, const char *main, directory_t *queues, directory_t *signals, logger_t *logger)
{
    // setup tracker which loads process implementations to run
    if (tracker_init(logger, tracker) != 0)
    {
        log_exception(logger);
        return -1;
    }
    char tracker_cfg[CFG_PATH_LEN + 1];
    if (tracker_config(tracker_cfg, sizeof(tracker_cfg)) < 0)
    {
        log_exception(logger);
        return -1;
    }
    if (read_config_file(tracker_cfg, tracker) != 0)
    {
        log_exception(logger);
        return -1;
    }

    // master lists of messaging/signalling queue keys
    if (array_init(queues) != 0)
    {
        log_exception(logger);
        return -1;
    }
    if (array_init(signals) != 0)
    {
        log_exception(logger);
        return -1;
    }
    array_t *process_names = map_keys(tracker->registry);
    size_t idx;
    data_t *name_val;
    int num_err = 0;

    if (array_copy(process_names, queues) != 0)
    {
        log_exception(logger);
        return -1;
    }

    // also a queue for the main interface process (i.e. this one)
    data_t *key_dat = string_data((char *)main, strlen(main));
    if (array_append(queues, key_dat) != 0)
    {
        log_exception(logger);
        num_err++;
    }

    array_for_each(process_names, idx, name_val) char *pname;
    if (data_string_ptr(name_val, &pname) != 0)
    {
        log_exception(logger);
        num_err++;
        continue;
    }

    char sname[SIG_NAME_LEN + 1];
    process_name_to_signal(pname, sname);
    data_t *s_dat = string_data(sname, sizeof(sname));
    if (array_append(signals, s_dat) != 0)
    {
        log_exception(logger);
        num_err++;
        continue;
    }
    array_end_for_each

    return num_err;
}


int run_autonomous_trust(char *q_in, char *q_out,
                         capability_t *capabilities, size_t cap_len,
                         log_level_t log_level, char log_file[])
{
    (void)capabilities; (void)cap_len;
    int error = 0;
    char cfg_dir[CFG_PATH_LEN + 1] = {0};
    get_cfg_dir(cfg_dir, sizeof(cfg_dir));
    char data_dir[CFG_PATH_LEN + 1] = {0};
    get_data_dir(data_dir, sizeof(data_dir));

    int fd1 = 0;
    int fd2 = 0;
    int flags = 0;
    if (log_file == NULL)
    {
        flags |= NO_STDERR_REDIRECT;
        /* Foreground: keep subsystem children's stderr too, so their logs
         * (id_proc admission/history handlers, net_proc, etc.) reach the
         * controlling terminal / container stream instead of /dev/null. */
        process_child_extra_flags |= NO_STDERR_REDIRECT;
    }
    int err = daemonize(data_dir, flags, &fd1, &fd2);
    if (err != 0)
        return err;

    const char *name = AT_MAIN_QUEUE;
    logger_t logger = {0};
    if (logger_init(&logger, log_level, log_file) != 0)
        return -1;
    log_info(&logger, "You are using\033[94m AutonomousTrust\033[00m v%s from\033[96m TekFive\033[00m.\n", VERSION);
    if (set_process_name(name) < 0)
        log_exception(&logger);
    init_sig_handling(&logger);
    pid_t my_pid = getpid();
    log_debug(&logger, "AT pid %d\n", my_pid);

    /* Write PID file so update process can signal us for restart */
    char pid_path[CFG_PATH_LEN + 32];
    if (path_join(pid_path, sizeof(pid_path), data_dir, "at_daemon.pid") < 0)
        pid_path[0] = '\0';
    FILE *pid_fp = (pid_path[0] != '\0') ? fopen(pid_path, "w") : NULL;
    if (pid_fp != NULL)
    {
        fprintf(pid_fp, "%d\n", my_pid);
        fclose(pid_fp);
    }
    else
        log_warn(&logger, "Could not write PID file %s: %s\n", pid_path, strerror(errno));

    map_t configs = {0};
    int ret = load_all_configs(cfg_dir, &configs, &logger);
    if (ret < 0)
        return ret;
    if (ret > 0)
        log_warn(&logger, "%d configuration(s) failed to load, continuing with partial config\n", ret);

    tracker_t tracker = {0};
    directory_t queues = {0};
    directory_t signals = {0};
    ret = register_queues(&tracker, name, &queues, &signals, &logger);
    if (ret < 0)
        return ret;
    if (ret > 0)
        log_warn(&logger, "%d queue registration(s) failed, continuing\n", ret);

    // spawn processes per tracker config
    map_key_t key = NULL;
    data_t *impl_val = NULL;
    map_t procs;
    if (map_init(&procs) != 0)
    {
        log_exception(&logger);
        return -1;
    }
    pthread_mutex_t procs_lock;
    if (pthread_mutex_init(&procs_lock, NULL) != 0)
    {
        SYS_EXCEPTION();
        log_exception(&logger);
        return -1;
    }
    proc_context_t proc_ctx = {
        .procs = &procs,
        .procs_lock = &procs_lock,
        .queues = &queues,
        .logger = &logger,
    };
    int num_err = 0;
    map_entries_for_each(tracker.registry, key, impl_val)
    {
        char *impl;
        if (data_string_ptr(impl_val, &impl) != 0)
        {
            log_exception(&logger);
            num_err++;
            continue;
        }
        handler_ptr_t runner = find_process(impl);
        if (runner == NULL)
        {
            log_error(&logger, "Invalid runner for %s (%s)\n", key, impl);
            continue;
        }

        log_info(&logger, "%s:  Starting %s:%s ...\n", name, key, impl);
        if (start_process(key, runner, &configs, &tracker, &proc_ctx))
        {
            log_exception_extra(&logger, " for process %s:%s\n", name, key);
            num_err++;
        }
    }
    map_end_for_each
    if (num_err > 0)
        log_warn(&logger, "%d of %zu process(es) failed to start\n", num_err, map_size(tracker.registry));

    queue_t my_q = {0};
    if (messaging_init(name, &my_q) != 0)
        log_exception(&logger);
    messaging_assign(&my_q);
    queue_t extern_q = {0};
    if (messaging_init(q_in, &extern_q) != 0)
        log_exception(&logger);

    log_info(&logger, "%s:                                          Ready.\n", name);
    pthread_mutex_lock(&procs_lock);
    size_t active = map_size(&procs);
    pthread_mutex_unlock(&procs_lock);
    array_t unhandled_msgs;
    if (array_init(&unhandled_msgs) != 0)
        log_exception(&logger);
    usleep(500000); /* 0.5s startup delay */
    while (!stop_process)
    {
        // monitor processes for early termination
        // two-phase sweep, mutate after iteration
        array_t dead_keys = {0};
        if (array_init(&dead_keys) != 0)
            log_exception(&logger);

        data_t *str_val = NULL;
        pthread_mutex_lock(&procs_lock);
        map_entries_for_each(&procs, key, str_val)
        {
            pid_t pid = atoi(key);
            err = kill(pid, 0);
            if (err == 0)
                continue;
            if (err == -1)
            {
                if (errno == ESRCH)
                {
                    data_t *key_dat = string_data((char *)key, strlen(key) + 1);
                    if (array_append(&dead_keys, key_dat) != 0)
                        log_exception(&logger);
                }
                else
                {
                    SYS_EXCEPTION();
                    log_exception(&logger);
                }
            }
        }
        map_end_for_each
        pthread_mutex_unlock(&procs_lock);

        // second phase, remove dead process keys
        int d_idx;
        data_t *dead_dat;
        array_for_each(&dead_keys, d_idx, dead_dat)
        {
            char *dead_key = NULL;
            if (data_string_ptr(dead_dat, &dead_key) != 0)
            {
                log_exception(&logger);
                continue;
            }
            pid_t dead_pid = (pid_t)atoi(dead_key);
            if (restart_process(dead_pid, dead_key, &proc_ctx))
            {
                log_exception_extra(&logger, " restarting process '%s'\n", dead_key);
                active--; // give up on this process
            }
        }
        array_end_for_each
        array_free(&dead_keys);

        if (active <= 0)
        {
            log_info(&logger, "%s: No remaining processes, exiting.\n", name);
            break;
        }

        // check for extern messages
        generic_msg_t task_msg = {0};
        ret = messaging_recv_on(&extern_q, &task_msg, NULL, false);
        if (ret == -1)
            log_exception(&logger);
        else if (ret == 0)
            at_route_extern_msg(&task_msg, &logger);

        // get results from internal procs
        generic_msg_t result_msg = {0};
        ret = messaging_recv(&result_msg);
        if (ret == -1)
            log_exception(&logger);
        else if (ret == 0)
        {
            /* Queued by reference; the drain below consumes it in this same
             * iteration, before result_msg is reused. */
            if (at_route_queue_msg(&unhandled_msgs, &result_msg) != 0)
                log_exception(&logger);
        }

        // Drain: process every pending message in FIFO order, removing as we go.
        at_route_internal_msgs(&unhandled_msgs, q_out, &logger);

        if (usleep(cadence) == -1)
        {
            if (errno != EINTR) {
                SYS_EXCEPTION();
                log_exception(&logger);
            }
        }
    }
    log_debug(&logger, "%s: Shutdown.\n", name);

    // signal_quit:
    log_debug(&logger, "Sending quit signal to sub-processes\n");
    data_t *k_val = NULL;
    int index = 0;
    generic_msg_t sig = {.type = SIGNAL, .info.signal = {.descr = {0}, .sig = -1}};
    /* descr was zero-initialised by the aggregate initialiser above, so
     * byte 31 is always NUL even when sig_quit is 31 chars long. */
    strncpy(sig.info.signal.descr, sig_quit, 31);
    array_for_each(&signals, index, k_val)
    {
        char *skey;
        if (data_string_ptr(k_val, &skey) != 0) {
            log_exception(&logger);
            continue;
        }
        if (messaging_send(skey, SIGNAL, &sig, true) < 0)  // may fail with ECONNREFUSED if process already exited
            log_exception_extra(&logger, " signalling %d - %s\n", index, skey);
    }
    array_end_for_each

    /* Wait up to shutdown_timeout_ms for sub-processes to exit cleanly;
     * SIGKILL any that do not respond in time. */
    {
        const int shutdown_timeout_ms = 5000;
        const int poll_interval_ms = 100;
        int waited_ms = 0;
        while (waited_ms < shutdown_timeout_ms)
        {
            bool any_alive = false;
            map_key_t pkey = NULL;
            data_t *pstr = NULL;
            pthread_mutex_lock(&procs_lock);
            map_entries_for_each(&procs, pkey, pstr)
            {
                if (kill((pid_t)atoi(pkey), 0) == 0)
                {
                    any_alive = true;
                    break;
                }
            }
            map_end_for_each
            pthread_mutex_unlock(&procs_lock);
            if (!any_alive)
                break;
            usleep(poll_interval_ms * 1000);
            waited_ms += poll_interval_ms;
        }

        map_key_t pkey = NULL;
        data_t *pstr = NULL;
        pthread_mutex_lock(&procs_lock);
        map_entries_for_each(&procs, pkey, pstr)
        {
            pid_t pid = (pid_t)atoi(pkey);
            if (kill(pid, 0) == 0)
            {
                log_warn(&logger, "Shutdown: pid %d did not exit; sending SIGKILL\n", pid);
                kill(pid, SIGKILL);
            }
        }
        map_end_for_each
        pthread_mutex_unlock(&procs_lock);
    }

        // cleanup:
        log_debug(&logger, "Cleanup complete\n");
    pthread_mutex_destroy(&procs_lock);
    array_free(&signals);
    array_free(&queues);
    tracker_free(&tracker);
    if (fd1 > 0)
        close(fd1);
    if (fd2 > 0)
        close(fd2);
    shutdown_protobuf_library();

    /* Clean up PID file */
    if (pid_path[0] != '\0')
        unlink(pid_path);

    return error;
}
