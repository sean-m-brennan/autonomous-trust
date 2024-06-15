/********************
 *  Copyright 2024 TekFive, Inc. and contributors
 *
 *   Licensed under the Apache License, Version 2.0 (the "License");
 *   you may not use this file except in compliance with the License.
 *   You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 *   Unless required by applicable law or agreed to in writing, software
 *   distributed under the License is distributed on an "AS IS" BASIS,
 *   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *   See the License for the specific language governing permissions and
 *   limitations under the License.
 *******************/

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "capabilities_priv.h"
#include "capability_table_priv.h"

int capability_init(capability_t *capability)
{
    AutonomousTrust__Core__Processes__Capability tmp = AUTONOMOUS_TRUST__CORE__PROCESSES__CAPABILITY__INIT;
    memcpy(&capability->proto, &tmp, sizeof(capability->proto));
    capability->proto.name = capability->name;
 
    capability->function = NULL;
    capability->local = false;
    return 0;
}

int capability_sync_out(capability_t *capability)
{
    proto_map_sync_out(&capability->arguments, capability->proto.arg_types);
    return 0;
}

int capability_sync_in(capability_t *capability)
{
    proto_map_sync_in(capability->proto.arg_types, &capability->arguments);
    return 0;
}

capability_t *find_capability(const char *name)
{
    for (int i=0; i<capability_table_size; i++) {
        capability_t *entry = &capability_table[i];
        if (strncmp(entry->name, name, strlen(name)) == 0)
            return entry;
    }
    return NULL;
}

int capability_to_proto(capability_t *msg, void **data_ptr, size_t *data_len_ptr)
{
    capability_sync_out(msg);
    *data_len_ptr = autonomous_trust__core__processes__capability__get_packed_size(&msg->proto);
    *data_ptr = malloc(*data_len_ptr);
    if (*data_ptr == NULL)
        return EXCEPTION(ENOMEM);
    autonomous_trust__core__processes__capability__pack(&msg->proto, *data_ptr);
    return 0;
}

int proto_to_capability(uint8_t *data, size_t len, capability_t *capability)
{
    AutonomousTrust__Core__Processes__Capability *msg =
        autonomous_trust__core__processes__capability__unpack(NULL, len, data);
    memcpy(&capability->proto, msg, sizeof(capability->proto));
    capability_sync_in(capability);
    free(msg);
    return 0;
}

int peer_capabilities_sync_out(peer_capabilities_matrix_t *matrix)
{
    size_t size = map_size(&matrix->peer_to_list);
    matrix->proto.listing = calloc(size, sizeof(AutonomousTrust__Core__Structures__DataMap__DataMapEntry));
    matrix->proto.n_listing = size;
    char *key;
    data_t *elt;
    size_t i = 0;
    map_entries_for_each(&matrix->peer_to_list, key, elt)
        AutonomousTrust__Core__Processes__PeerCapabilities__PeerCapacity *entry = matrix->proto.listing[i++];
        entry->peer = key;  // shared, do not free

        void *caps_ptr;
        if (data_object_ptr(elt, &caps_ptr) != 0)
            return -1;
        array_t * caps = caps_ptr;
        size_t asize = array_size(caps);
        entry->n_capability = asize;
        entry->capability = calloc(asize, sizeof(AutonomousTrust__Core__Processes__Capability));

        int index;
        data_t *cap_dat;
        array_for_each(caps, index, cap_dat)
            capability_t *cap;
            if (data_object_ptr(cap_dat, (void**)&cap) != 0)
                return -1;
            capability_sync_out(cap);
            entry->capability[index] = &cap->proto;
        array_end_for_each
    map_end_for_each
    return 0;
}

// FIXME free func

int peer_capabilities_to_proto(peer_capabilities_matrix_t *matrix, void **data_ptr, size_t *data_len_ptr)
{
    peer_capabilities_sync_out(matrix);
    *data_len_ptr = autonomous_trust__core__processes__peer_capabilities__get_packed_size(&matrix->proto);
    *data_ptr = malloc(*data_len_ptr);
    if (*data_ptr == NULL)
        return EXCEPTION(ENOMEM);
    autonomous_trust__core__processes__peer_capabilities__pack(&matrix->proto, *data_ptr);
    return 0;
}

int peer_capabilities_sync_in(peer_capabilities_matrix_t *matrix)
{
    for (int i=0; i<matrix->proto.n_listing; i++) {
        AutonomousTrust__Core__Processes__PeerCapabilities__PeerCapacity *pcaps = matrix->proto.listing[i];
        array_t *arr;
        if (array_create(&arr) != 0)
            return -1;

        for (int j=0; j<pcaps->n_capability; j++) {
            capability_t *cap = malloc(sizeof(capability_t));
            if (cap != NULL)
                return EXCEPTION(ENOMEM);
            memcpy(&cap->proto, pcaps->capability[j], sizeof(AutonomousTrust__Core__Processes__Capability));
            capability_sync_in(cap);
            data_t *cap_dat = object_ptr_data(cap, sizeof(capability_t));
            array_append(arr, cap_dat);
        }

        data_t *arr_dat = object_ptr_data(arr, sizeof(arr));
        if (arr_dat == NULL)
            return EXCEPTION(ENOMEM);
        char *key = malloc(strlen(pcaps->peer));
        strcpy(key, pcaps->peer);
        if (map_set(&matrix->peer_to_list, key, arr_dat) != 0)
            return -1;
    }
    return 0;
}

// FIXME free func

int proto_to_peer_capabilities(uint8_t *data, size_t len, peer_capabilities_matrix_t *peer_capabilities)
{
    AutonomousTrust__Core__Processes__PeerCapabilities *msg =
        autonomous_trust__core__processes__peer_capabilities__unpack(NULL, len, data);
    memcpy(&peer_capabilities->proto, msg, sizeof(peer_capabilities->proto));
    peer_capabilities_sync_in(peer_capabilities);
    free(msg);
    return 0;
}
