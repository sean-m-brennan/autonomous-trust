#include <string.h>
#include <strings.h>
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
#include "protobuf/processes.pb-c.h"
#include "config/serialization.h"
#include "config/configuration.h"
#include "structures/map_priv.h"
#include "utilities/util.h"

#define MAX_CLOSE 8192

const char *sig_quit = "quit";

const long cadence = 500000L; // microseconds


typedef bool (*msg_handler_t)(const process_t *proc, map_t *queues, message_t *msg);

int process_init(process_t *proc, char *name, map_t *configurations, tracker_t *subsystems, logger_t *logger, array_t *dependencies)
{
    bzero(proc->name, 256);
    memcpy(proc->name, name, min(strlen(name), 255));
    // FIXME general config load/save
    // configuration_t *cfg = map_get(configurations, proc->cfg_name);
    // memcpy(&proc->conf, cfg, cfg->size);
    proc->configs = configurations; // FIXME copy?
    proc->subsystems = subsystems;
    proc->logger = logger;
    proc->dependencies = dependencies;
    return map_create(&proc->protocol.handlers); // FIXME protocol from config
}

inline int process_register_handler(const process_t *proc, char *func_name, handler_ptr_t handler)
{
    data_t h_dat = odat(handler);
    return map_set(proc->protocol.handlers, func_name, &h_dat);
}

bool run_message_handlers(const process_t *proc, map_t *msgq_ids, long msgtype, message_t *msg)
{
    switch (msgtype)
    {
    case GROUP:
        // proc->group = message
        return true;
    case PEERS:
        // proc->peers = message
        return true;
    case CAPABILITIES:
        // proc->capabilities = message
        return true;
    case PEER_CAPABILITIES:
        // pproc->eer_capabilities = message
        return true;
    default:
        if (msg->process == proc->name)
        {
            data_t h_dat;
            map_get(proc->protocol.handlers, msg->function, &h_dat);
            msg_handler_t handler = h_dat.obj;
            return handler(proc, msgq_ids, msg);
        }
    }
    return false;
}

int daemonize(char *data_dir, int flags)
{
    int io[2];
    pipe(io);

    int pid = fork();
    if (pid == -1)  // error
        return -1;
    if (pid != 0) {  // parent
        int status;
        waitpid(pid, &status, 0);
        if (WIFEXITED(status) || WIFSIGNALED(status)) {
            pid_t gchild;
            read(io[0], &gchild, sizeof(int));
            return gchild;
        }
        return ECHILD;
    }

    if (setsid() == -1) // lead new session
        return -1;
        
    pid = fork();
    if (pid == -1)  // error
        return -1;
    if (pid != 0) {  // parent
        write(io[1], &pid, sizeof(int));
        _exit(0);
    }

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
        for (int fd = 0; fd < maxfd; fd++) {
            if (fd == STDIN_FILENO || fd == STDOUT_FILENO || fd == STDERR_FILENO)
                continue;
            close(fd);
        }
    }

    close(STDIN_FILENO);

    if (!(flags & NO_STDOUT_REDIRECT & NO_STDERR_REDIRECT))
    {
        // point stdout and/or stderr to /dev/null
        int fd = open("/dev/null", O_WRONLY);
        if (fd == -1)
            return -1;
        if (!(flags & NO_STDOUT_REDIRECT))
        {
            if (dup2(fd, STDOUT_FILENO) == -1)
                return -1;
        }
        if (!(flags & NO_STDERR_REDIRECT))
        {
            if (dup2(fd, STDERR_FILENO) == -1)
                return -1;
        }
    }
    return 0;
}

bool keep_running(const process_t *proc, int sig_id)
{
    signal_buf_t buf;
    gettimeofday((struct timeval *)&proc->start, NULL);
    ssize_t err = msgrcv(sig_id, &buf, sizeof(struct sig_s), SIGNAL, IPC_NOWAIT);
    if (err == -1)
    {
        if (errno == ENOMSG)
            return true;
        // return errno; // FIXME repair?
    }
    if (buf.info.signal == sig_quit)
        return false;
    // unhandled signal
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

int process_run(const process_t *proc, map_t *q_keys, msgq_key_t s_key)
{
    char data_path[256];
    get_data_dir(data_path);

    int err = daemonize(data_path, proc->flags);
    if (err != 0)
        return err;

    // establish connections to queues, signal
    map_t queues;
    err = map_init(&queues);
    if (err != 0)
        return err;
    array_t *keys = map_keys(q_keys);
    for (int i = 0; i < array_size(keys); i++)
    {
        data_t k_dat;
        int err = array_get(keys, i, &k_dat);
        if (err != 0)
            continue; // FIXME? error
        map_key_t key = k_dat.str;
        data_t mk_dat;
        err = map_get(q_keys, key, &mk_dat);
        if (err != 0)
            continue; // FIXME? error
        msgq_key_t mqk = mk_dat.intgr;

        int mq_id = msgget(mqk, 0666 | IPC_CREAT);
        if (mq_id == -1)
            return errno;
        data_t q_dat = idat(mq_id);
        err = map_set(&queues, key, &q_dat);
        if (err != 0)
            return err;
    }
    int signal = msgget(s_key, 0666 | IPC_CREAT);
    if (signal == -1)
        return errno;

    // FIXME pre-loop activity

    // handle messages
    array_t unprocessed;
    array_init(&unprocessed);
    while (keep_running(proc, signal))
    {
        sleep_until(proc, cadence);

        msgq_buf_t buf;
        queue_id_t q = fetch_msgq(&queues, (char *)proc->name);
        if (q < 0)
            ; // FIXME report error
        ssize_t err = msgrcv(q, &buf, sizeof(message_t), 0, IPC_NOWAIT);
        if (err == -1)
        {
            if (errno == ENOMSG)
                continue;
            return errno; // FIXME repair?
        }
        if (!run_message_handlers(proc, &queues, buf.mtype, &buf.info))
        {
            message_t *msg = calloc(1, sizeof(message_t));
            memcpy(msg, &buf.info, sizeof(message_t));
            data_t m_dat = odat(msg);
            array_append(&unprocessed, &m_dat);
        }
        // FIXME post-msg handling activity
    }
    array_free(&unprocessed);
    map_free(&queues);

    return 0;
}
