#ifndef MSG_TYPES_PRIV_H
#define MSG_TYPES_PRIV_H

#include "msg_types.h"
#include "processes/capabilities_priv.h"
#include "negotiation/task_priv.h"

int generic_msg_to_proto(generic_msg_t *msg, void **data, size_t *data_len);

int proto_to_generic_msg(void *data, size_t data_len, generic_msg_t *msg);


#endif  // MSG_TYPES_PRIV_H
