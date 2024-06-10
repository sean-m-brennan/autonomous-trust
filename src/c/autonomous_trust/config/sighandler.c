#include <signal.h>
#include <stdbool.h>

#include "utilities/logger.h"

bool stop_process = false;

bool propagate = false;

logger_t *_logger = NULL;

extern void reread_configs();

extern void user1_handler();

extern void user2_handler();

void handle_signal(int signum)
{
    switch (signum)
    {
    case SIGINT:
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
            log_error(_logger, "OS error: %s", error);
    }
    break;
    case SIGFPE:
    {
        const char *error = "Floating-point Exception";
        if (_logger != NULL)
            log_error(_logger, "OS error: %s", error);
    }
    break;
    }
}

int init_sig_handling(logger_t *logger)
{
    _logger = logger;
    struct sigaction sa = {0};
    sa.sa_handler = handle_signal;
    return sigaction(SIGINT, &sa, NULL);
}
