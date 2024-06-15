#ifndef CAPABILITIES_PRIV_H
#define CAPABILITIES_PRIV_H

#include "structures/array_priv.h"
#include "structures/map_priv.h"
#include "structures/data_priv.h"
#include "identity/identity.h"
#include "utilities/util.h"
#include "processes/capabilities.pb-c.h"
#include "capabilities.h"


typedef struct {
    size_t argc;
    array_t argv;
    bool alloc;
} thread_args_t;

typedef void (*capability_function_t)(thread_args_t);

struct capability_s
{
    char name[CAP_NAMELEN];
    map_t arguments; // map of name to data_type_t
    bool local;
    capability_function_t function;
    AutonomousTrust__Core__Processes__Capability proto;
};


typedef struct {
    map_t peer_to_list;   // map of UUID string to array of capabilities
    AutonomousTrust__Core__Processes__PeerCapabilities proto;
} peer_capabilities_matrix_t;

int capability_sync_out(capability_t *capability);

int capability_sync_in(capability_t *capability);

int peer_capabilities_to_proto(peer_capabilities_matrix_t *matrix, void **data_ptr, size_t *data_len_ptr);

int proto_to_peer_capabilities(uint8_t *data, size_t len, peer_capabilities_matrix_t *peer_capabilities);

#endif  // CAPABILITIES_PRIV_H
