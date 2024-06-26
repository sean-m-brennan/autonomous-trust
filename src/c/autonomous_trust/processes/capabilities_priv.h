#ifndef CAPABILITIES_PRIV_H
#define CAPABILITIES_PRIV_H

#include "structures/array_priv.h"
#include "structures/map_priv.h"
#include "structures/data_priv.h"
#include "identity/identity.h"
#include "utilities/util.h"
#include "processes/capabilities.pb-c.h"
#include "capabilities.h"


int capability_sync_out(capability_t *capability, AutonomousTrust__Core__Processes__Capability *proto);

void capability_proto_free(AutonomousTrust__Core__Processes__Capability *proto);

int capability_sync_in(AutonomousTrust__Core__Processes__Capability *proto, capability_t *capability);

int peer_capabilities_to_proto(peer_capabilities_matrix_t *matrix, void **data_ptr, size_t *data_len_ptr);

int proto_to_peer_capabilities(uint8_t *data, size_t len, peer_capabilities_matrix_t *peer_capabilities);

#endif  // CAPABILITIES_PRIV_H
