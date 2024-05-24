#include <stdio.h>
#include "autonomous_trust/utilities/logger.h"

void testLogging()
{
    logger_t logger;
    logger_init(&logger, DEBUG, NULL);
    log_debug(&logger, "Hello %s 1", "World");
    log_info(&logger, "Hello %s 2", "World");
    log_warn(&logger, "Hello %s 3", "World");
    log_error(&logger, "Hello %s 4", "World");
    log_critical(&logger, "Hello %s 5", "World");
    logger_init_local_time_res(&logger, WARNING, "/tmp/test.log", MICROSECONDS);
    log_debug(&logger, "Hello %s 6", "World");
    log_error(&logger, "Hello %s 7", "World");
}

int main(void)
{
    testLogging();
    return 0;
}
