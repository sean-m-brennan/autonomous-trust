#ifndef MSG_TYPES_PRIV_H
#define MSG_TYPES_PRIV_H

#include "msg_types.h"
#include "processes/capabilities_priv.h"
#include "negotiation/task_priv.h"

struct generic_msg_s
{
    long type;
    size_t size;
    size_t alt_size;
    union {
        signal_t signal;
        group_t group;
        public_identity_t peer;
        peer_capabilities_matrix_t peer_capabilities;
        task_t task;
        net_msg_t net_msg;  // FIXME specific protocols instead
    } info;
};

int generic_msg_to_proto(generic_msg_t *msg, void **data, size_t *data_len);

int proto_to_generic_msg(void *data, size_t data_len, generic_msg_t *msg);


#endif  // MSG_TYPES_PRIV_H
