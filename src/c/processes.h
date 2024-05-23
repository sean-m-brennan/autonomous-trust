#ifndef PROCESSES_H
#define PROCESSES_H

#include "structures/hashtable.h"
#include "structures/array.h"
#include "config/configuration.h"

typedef struct process_s {
    char cfg_name[256];
    configuration_t config;

} process_t;

void process_name(process_t *proc, char *name);

/**
 * @brief Initialize a process (config, etc)
 * 
 * @param proc 
 * @param configurations 
 * @param subsystems 
 * @param dependencies 
 */
void process_init(process_t *proc, hashtable_t *configurations, tracker_t *subsystems, array_t *dependencies);

/**
 * @brief 
 * 
 * @param proc 
 * @return int 
 */
int process_run(const process_t *proc, queue, signal);

#endif // PROCESSES_H