#include <string.h>
#include <strings.h>

#include "processes.h"

void process_name(process_t *proc, char *name) {
    bzero(proc->cfg_name, 256);
    memcpy(proc->cfg_name, name, min(strlen(name), 255));
}

void process_init(const process_t *proc, hashtable_t *configurations, int subsystems, array_t *dependencies) {
    configuration_t *cfg = hashtable_get(configurations, proc->cfg_name);
    memcpy((void*)proc->config, cfg, cfg->size);
}


