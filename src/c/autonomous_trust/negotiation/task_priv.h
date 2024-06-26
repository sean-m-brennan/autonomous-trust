#ifndef TASK_PRIV_H
#define TASK_PRIV_H

#include <stdbool.h>

#include "processes/capabilities_priv.h"
#include "structures/datetime_priv.h"
#include "structures/map_priv.h"
#include "structures/data_priv.h"
#include "negotiation/task.pb-c.h"
#include "task.h"

int task_to_proto(task_t *msg, size_t size, void **data_ptr, size_t *data_len_ptr);

int proto_to_task(uint8_t *data, size_t len, task_t *task);

#endif  // TASK_PRIV_H
