#ifndef SIGHANDLER_H
#define SIGHANDLER_H

void reread_configs();

void user1_handler();

void user2_handler();

extern bool stop_process;

extern bool propagate;

/**
 * @brief Activate signal handling. Must predefine reread_configs(), user1_handler(), user2_handler(), even if they are empty.
 * 
 * @param logger Optional logger
 * @return int 
 */
int init_sig_handling(logger_t *logger);

#endif // SIGHANDLER_H
