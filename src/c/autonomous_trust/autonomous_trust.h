#ifndef AUTONOMOUS_TRUST_H
#define AUTONOMOUS_TRUST_H

#ifdef __cplusplus
extern "C" {
#endif

#define PUBLIC_INTERFACE
#include "version.h"
#include "utilities/message.h"
#include "utilities/logger.h"
#include "config/configuration.h"
#include "config/sighandler.h"

/**
 * @brief 
 * 
 * @param q_in 
 * @param q_out 
 * @param capabilities 
 * @param cap_len 
 * @param log_level 
 * @param log_file 
 * @return int 
 */
int run_autonomous_trust(msgq_key_t q_in, msgq_key_t q_out, 
                         void *capabilities, size_t cap_len, // FIXME from config file?
                         log_level_t log_level, char log_file[]);

#ifdef __cplusplus
} // extern "C"
#endif

#endif // AUTONOMOUS_TRUST_H
