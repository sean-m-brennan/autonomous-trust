#ifndef SIGHANDLER_H
#define SIGHANDLER_H

#ifdef __cplusplus
extern "C" {
#endif

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

#ifdef __cplusplus
} // extern "C"
#endif

#endif // SIGHANDLER_H
