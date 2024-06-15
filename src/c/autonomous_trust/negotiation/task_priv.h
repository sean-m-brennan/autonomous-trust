#ifndef TASK_PRIV_H
#define TASK_PRIV_H

#include <stdbool.h>

#include "processes/capabilities_priv.h"
#include "structures/datetime.h"
#include "structures/map_priv.h"
#include "structures/data_priv.h"
#include "negotiation/task.pb-c.h"
#include "task.h"

struct task_s {
    capability_t capability;
    datetime_t when;
    timedelta_t duration;
    long timeout;
    thread_args_t;
    AutonomousTrust__Core__Negotiation__Task proto;
};

#endif  // TASK_PRIV_H
