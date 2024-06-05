#ifndef ID_PROC_H
#define ID_PROC_H

#include "processes/processes.h"

int identity_run(const process_t *proc, map_t *queues, msgq_key_t signal);


#endif // ID_PROC_H
