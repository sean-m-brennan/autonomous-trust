#include <stdbool.h>
#include <signal.h>
#include <string.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <string.h>
#include <sys/wait.h>

#include "autonomous_trust.h"


int main(int argc, char *argv[])
{
    const long cadence = 500000L; // microseconds

    msgq_key_t q_in = get_msgq_key("", "", 0);
    msgq_key_t q_out = get_msgq_key("", "", 0);
    int at_pid = run_autonomous_trust(q_in, q_out, NULL, 0, DEBUG, NULL);
    if (at_pid <= 0)
    {
        printf("Autonomous Trust (%d) failed to start: %s\n", at_pid, strerror(errno));
        return at_pid;
    }

    msgqnum_t to_at = msgq_create(q_in);
    msgqnum_t from_at = msgq_create(q_out);
    init_sig_handling(NULL);

    printf("AT example main (AT at %d)\n", at_pid);
    bool at_alive = true;
    while (!stop_process)
    {
        int status = 0;
        waitpid(at_pid, &status, WNOHANG);
        if (WIFEXITED(status) || WIFSIGNALED(status)) {
            printf("AT exited\n");
            stop_process = true;
            at_alive = false;
        }

        msgq_buf_t buf;
        ssize_t err = msgrcv(from_at, &buf, sizeof(message_t), 0, IPC_NOWAIT);
        if (err == -1)
        {
            if (errno != ENOMSG)
                printf("Messaging error: %s\n", strerror(errno));
            goto snooze;
        }
        bool do_send = false;
        // react to info
        if (do_send)
        {
            err = msgsnd(to_at, &buf, sizeof(message_t), buf.mtype);
        }
        // do other things

snooze:
        usleep(cadence);
    }
    if (at_alive)
        kill(at_pid, SIGINT);
    printf("Example exit\n");
    return 0;
}
