#include <stdbool.h>
#include <signal.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>

#include "autonomous_trust.h"


int main(int argc, char *argv[])
{
    const long cadence = 500000L; // microseconds
    char cfg_path[CFG_PATH_LEN];
    get_cfg_dir(cfg_path);

    logger_t logger;
    logger_init(&logger, INFO, NULL);

    msgq_key_t q_in = ftok(cfg_path, 598378467);
    msgq_key_t q_out = ftok(cfg_path, 842812652);
    int err = run_autonomous_trust(q_in, q_out, NULL, 0, INFO, NULL);
    if (err != 0)
    {
        log_error(&logger, "Autonomous Trust failed to start: %s\n", strerror(err));
        return err;
    }
    msgqnum_t to_at = msgq_create(q_in);
    msgqnum_t from_at = msgq_create(q_out);
    init_sig_handling(&logger);

    while (!stop_process)
    {
        msgq_buf_t buf;
        ssize_t err = msgrcv(from_at, &buf, sizeof(message_t), 0, IPC_NOWAIT);
        if (err == -1)
        {
            if (errno != ENOMSG)
                log_error(&logger, "Messaging error: %s\n", strerror(errno));
            continue;
        }
        bool do_send = false;
        // react to info
        if (do_send)
        {
            err = msgsnd(to_at, &buf, sizeof(message_t), buf.mtype);
        }
        // do other things
        usleep(cadence);
    }
    return 0;
}
