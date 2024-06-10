#ifndef PROCESS_TRACKER_PRIV_H
#define PROCESS_TRACKER_PRIV_H

#include "processes/process_tracker.h"

int tracker_to_json(const void *data_struct, json_t **obj_ptr);

int tracker_from_json(const json_t *obj, void *data_struct);

#endif  // PROCESS_TRACKER_PRIV_H
