#ifndef NEG_PROC_PRIV_H
#define NEG_PROC_PRIV_H

#include "processes/processes.h"

int negotiation_run(process_t *proc, directory_t *queues, queue_id_t signal, logger_t *logger);

#define ENEG_NOPEERS 243
DECLARE_ERROR(ENEG_NOPEERS, "No capable peers available");

#endif  /* NEG_PROC_PRIV_H */
