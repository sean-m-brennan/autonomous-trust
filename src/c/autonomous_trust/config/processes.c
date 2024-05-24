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

#include "config/processes.h"
#include "processes.pb-c.h"
#include "serialization.h"
#include "utilities/util.h"

#define MAX_CLOSE 8192

extern proc_map_t __start_process_table;
extern proc_map_t __stop_process_table;

const char *key = "processes";   // FIXME unused?
const char *level = "log-level"; // FIXME unused?
const char *sig_quit = "quit";

const long cadence = 500000L; // microseconds
// const float q_cadence = 0.01;
const int output_timeout = 1; // FIXME unused?
const int exit_timeout = 5;   // FIXME unused?

const char *default_tracker_filename = "subsystems.yaml";

handler_ptr_t find_process(const char *name)
{
    for (proc_map_t *entry = &__start_process_table; entry != &__stop_process_table; ++entry)
    {
        if (strncmp(entry->name, name, strlen(name) == 0))
            return entry->runner;
    }
    return NULL;
}

int find_process_name(const handler_ptr_t handler, char **name)
{
    if (handler == NULL)
        return EINVAL;
    for (proc_map_t *entry = &__start_process_table; entry != &__stop_process_table; ++entry)
    {
        if (entry->runner == handler)
            *name = entry->name;
    }
    return 0;
}

struct tracker_s
{
    map_t *registry;
    logger_t *logger;
};

int tracker_create(logger_t *logger, tracker_t **tracker_ptr)
{
    *tracker_ptr = calloc(1, sizeof(tracker_t));
    if (*tracker_ptr == NULL)
        ;
    return ENOMEM;
    tracker_t *tracker = *tracker_ptr;
    int err = map_create(&tracker->registry);
    if (err != 0)
        free(tracker);
    tracker->logger = logger;
    return err;
}

int tracker_from_file(const char *filename, logger_t *logger, tracker_t **tracker_ptr)
{
    int err = tracker_create(logger, tracker_ptr);
    tracker_t *tracker = *tracker_ptr;
    if (err != 0)
    {
        tracker_free(tracker);
        return err;
    }

    file_mapping_t mapping;
    ssize_t data_len = readable_file_mapping(filename, &mapping);
    if (data_len != 0)
        return data_len;

    ProcessTracker *msg = process_tracker__unpack(NULL, mapping.data_len, mapping.data);
    if (msg == NULL)
    {
        demap_file(&mapping);
        return ESER_UNPK;
    }
    for (unsigned i = 0; i < msg->n_registry; i++)
    {
        ProcessTracker__RegistryEntry *entry = msg->registry[i];
        handler_ptr_t handler = find_process(entry->value);
        if (handler == NULL)
            log_error(tracker->logger, "Unable to find process %s", entry->value);
        if (tracker_register_subsystem(tracker, entry->key, handler) != 0)
            log_error(tracker->logger, "Unable to register subsystem %s", entry->key);
    }
    process_tracker__free_unpacked(msg, NULL);
    return demap_file(&mapping);
}

int tracker_register_subsystem(const tracker_t *tracker, const char *name, const handler_ptr_t handler)
{
    // TODO processes plus what else?
    return map_set(tracker->registry, name, handler);
}


int tracker_to_file(const tracker_t *tracker, const char *filename)
{
    ProcessTracker msg = PROCESS_TRACKER__INIT;
    msg.n_registry = map_size(tracker->registry);
    msg.registry = calloc(msg.n_registry, sizeof(ProcessTracker__RegistryEntry));
    array_t *keys = map_keys(tracker->registry);
    for (size_t i = 0; i < msg.n_registry; i++)
    {
        char *impl_name;
        char *proc_name = array_get(keys, i);
        handler_ptr_t handler = map_get(tracker->registry, proc_name);
        if (find_process_name(handler, &impl_name) == 0)
        {
            msg.registry[i]->key = proc_name;
            msg.registry[i]->value = impl_name;
        }
    }

    file_mapping_t mapping;
    mapping.data_len = process_tracker__get_packed_size(&msg);
    int err = writeable_file_mapping(filename, &mapping);
    if (err != 0)
        return err;

    process_tracker__pack(&msg, mapping.data);
    free(msg.registry);
    return demap_file(&mapping);
}

void tracker_free(tracker_t *tracker)
{
    if (tracker != NULL)
    {
        if (tracker->registry != NULL)
            map_free(tracker->registry);
        free(tracker);
    }
}

int process_init(process_t *proc, char *name, char *proc_name, map_t *configurations, tracker_t *subsystems, logger_t *logger, array_t *dependencies)
{
    bzero(proc->cfg_name, 256);
    memcpy(proc->cfg_name, name, min(strlen(name), 255));
    bzero(proc->name, 256);
    memcpy(proc->name, proc_name, min(strlen(proc_name), 255));
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
    return map_set(proc->protocol.handlers, func_name, handler);
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
            handler_ptr_t handler = map_get(proc->protocol.handlers, msg->function);
            return handler(msgq_ids, msg);
        }
    }
    return false;
}

int daemonize(char *data_dir, int flags)
{
    switch (fork())
    {
    case -1:
        return -1; // error
    case 0:
        break; // child (continue)
    default:
        _exit(EXIT_SUCCESS); // parent (terminate)
    }
    if (setsid() == -1) // lead new session
        return -1;
    switch (fork())
    {
    case -1:
        return -1;
    case 0:
        break;
    default:
        _exit(EXIT_SUCCESS);
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
        for (int fd = 0; fd < maxfd; fd++)
            close(fd);
    }

    close(STDIN_FILENO);

    if (!(flags & NO_STDOUT_REDIRECT & NO_STDERR_REDIRECT))
    {
        // point stdout and/or stderr to /dev/null
        int fd = open("/dev/null", O_RDWR);
        if (fd == -1)
            return errno;
        if (!(flags & NO_STDOUT_REDIRECT))
        {
            if (dup2(STDOUT_FILENO, fd) != fd)
                return errno;
        }
        if (!(flags & NO_STDERR_REDIRECT))
        {
            if (dup2(STDERR_FILENO, fd) != fd)
                return errno;
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

inline long timeval_subtract(struct timeval *a, struct timeval *b)
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

int process_run(const process_t *proc, map_t *queues, msgq_key_t signal)
{
    char data_path[256];
    get_data_dir(data_path);

    int err = daemonize(data_path, proc->flags);
    if (err != 0)
        return err;

    // establish connections to queues, signal
    map_t *msgq_ids;
    err = map_create(&msgq_ids);
    if (err != 0)
        return err;
    array_t *keys = map_keys(queues);
    for (int i = 0; i < array_size(keys); i++)
    {
        map_key_t key = array_get(keys, i);
        msgq_key_t *mqk_ptr = map_get(queues, key);
        if (mqk_ptr == NULL)
            continue; // FIXME? error
        msgq_key_t mqk = *mqk_ptr;
        int mq_id = msgget(mqk, 0666 | IPC_CREAT);
        if (mq_id == -1)
            return errno;
        err = map_set(msgq_ids, key, &mq_id);
        if (err != 0)
            return err;
    }
    int sig_id = msgget(signal, 0666 | IPC_CREAT);
    if (sig_id == -1)
        return errno;

    // FIXME pre-loop activity

    // handle messages
    array_t *unprocessed;
    array_create(&unprocessed);
    while (keep_running(proc, sig_id))
    {
        sleep_until(proc, cadence);

        msgq_buf_t buf;
        ssize_t err = msgrcv(*((int *)map_get(msgq_ids, proc->name)), &buf, sizeof(message_t), 0, IPC_NOWAIT);
        if (err == -1)
        {
            if (errno == ENOMSG)
                continue;
            return errno; // FIXME repair?
        }
        if (!run_message_handlers(proc, msgq_ids, buf.mtype, &buf.info))
        {
            message_t *msg = calloc(1, sizeof(message_t));
            memcpy(msg, &buf.info, sizeof(message_t));
            array_append(unprocessed, msg);
        }
        // FIXME post-msg handling activity
    }
    array_free(unprocessed);
    map_free(msgq_ids);

    return 0;
}
