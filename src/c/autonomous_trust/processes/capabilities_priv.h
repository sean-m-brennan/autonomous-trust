#ifndef CAPABILITIES_PRIV_H
#define CAPABILITIES_PRIV_H

#include "structures/map_priv.h"
#include "structures/data_priv.h"
#include "structures/array_priv.h"

#include "processes/capabilities.h"
#include "processes/capabilities.pb-c.h"

#include "utilities/allocation.h"
#include "utilities/exception.h"

int capability_sync_out(capability_t *capability,
                        AutonomousTrust__Core__Protobuf__Processes__Capability *proto);
void capability_proto_free(AutonomousTrust__Core__Protobuf__Processes__Capability *proto);
int capability_sync_in(AutonomousTrust__Core__Protobuf__Processes__Capability *proto,
                       capability_t *capability);
int capability_to_proto(capability_t *msg, void **data_ptr, size_t *data_len_ptr);
int proto_to_capability(uint8_t *data, size_t len, capability_t *capability);

int peer_capabilities_sync_out(peer_capabilities_matrix_t *map,
                               AutonomousTrust__Core__Protobuf__Processes__PeerCapabilities *proto);
void peer_capabilities_proto_free(AutonomousTrust__Core__Protobuf__Processes__PeerCapabilities *proto);
int peer_capabilities_to_proto(peer_capabilities_matrix_t *map, void **data_ptr, size_t *data_len_ptr);
int peer_capabilities_sync_in(AutonomousTrust__Core__Protobuf__Processes__PeerCapabilities *proto,
                              peer_capabilities_matrix_t *map);
int proto_to_peer_capabilities(uint8_t *data, size_t len, peer_capabilities_matrix_t *peer_capabilities);

#endif  /* CAPABILITIES_PRIV_H */
