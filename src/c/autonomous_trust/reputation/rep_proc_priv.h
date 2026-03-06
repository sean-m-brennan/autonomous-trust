#ifndef REP_PROC_PRIV_H
#define REP_PROC_PRIV_H

#include "processes/processes.h"

int reputation_run(process_t *proc, directory_t *queues, queue_id_t signal, logger_t *logger);

#define EREP_PAXOS 253
DECLARE_ERROR(EREP_PAXOS, "Paxos consensus error");

#endif  /* REP_PROC_PRIV_H */
