#ifndef MSG_TYPES_PRIV_H
#define MSG_TYPES_PRIV_H

#include <jansson.h>

#include "structures/map_priv.h"
#include "structures/data_priv.h"
#include "structures/array_priv.h"

#include "utilities/msg_types.h"

int generic_msg_to_proto(generic_msg_t *msg, void **data, size_t *data_len);
int proto_to_generic_msg(void *data, size_t data_len, generic_msg_t *msg);

int net_msg_to_proto(const net_msg_t *msg, void **data_ptr, size_t *data_len_ptr);
int proto_to_net_msg(uint8_t *data, size_t len, net_msg_t *net_msg);

int net_msg_pack_json(net_msg_t *msg, json_t *json);
int net_msg_unpack_json(const net_msg_t *msg, json_t **json);

#endif  /* MSG_TYPES_PRIV_H */
