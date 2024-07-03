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

capability_t *find_capability(const char *name)
{
    for (int i = 0; i < capability_table_size; i++)
    {
        IGNORE_GCC_VER_DIAGNOSTIC(12, -Warray-bounds)
        capability_t *entry = &(capability_table[i]);
        END_IGNORE_GCC_DIAGNOSTIC
        if (strncmp(entry->name, name, strlen(name)) == 0)
            return entry;
    }
    return NULL;
}

int capability_sync_out(capability_t *capability, AutonomousTrust__Core__Processes__Capability *proto)
{
    proto->name = capability->name;
    map_sync_out(&capability->arguments, proto->arg_types);
    return 0;
}

void capability_proto_free(AutonomousTrust__Core__Processes__Capability *proto)
{
    map_proto_free(proto->arg_types);
}

int capability_sync_in(AutonomousTrust__Core__Processes__Capability *proto, capability_t *capability)
{
    strncpy(capability->name, proto->name, CAP_NAMELEN);
    map_sync_in(proto->arg_types, &capability->arguments);
    return 0;
}

int capability_to_proto(capability_t *msg, void **data_ptr, size_t *data_len_ptr)
{
    AutonomousTrust__Core__Processes__Capability proto;
    capability_sync_out(msg, &proto);
    *data_len_ptr = autonomous_trust__core__processes__capability__get_packed_size(&proto);
    *data_ptr = malloc(*data_len_ptr);
    if (*data_ptr == NULL)
        return EXCEPTION(ENOMEM);
    autonomous_trust__core__processes__capability__pack(&proto, *data_ptr);
    capability_proto_free(&proto);
    return 0;
}

int proto_to_capability(uint8_t *data, size_t len, capability_t *capability)
{
    AutonomousTrust__Core__Processes__Capability *msg =
        autonomous_trust__core__processes__capability__unpack(NULL, len, data);
    capability_sync_in(msg, capability);
    free(msg);
    return 0;
}

int peer_capabilities_sync_out(peer_capabilities_matrix_t *map, AutonomousTrust__Core__Processes__PeerCapabilities *proto)
{
    size_t size = map_size(map);
    proto->listing = calloc(size, sizeof(AutonomousTrust__Core__Structures__DataMap__DataMapEntry));
    proto->n_listing = size;
    char *key;
    data_t *elt;
    size_t i = 0;
    map_entries_for_each(map, key, elt)
        AutonomousTrust__Core__Processes__PeerCapabilities__PeerCapacity *entry = proto->listing[i++];
    entry->peer = key; // shared, do not free

    void *caps_ptr;
    if (data_object_ptr(elt, &caps_ptr) != 0)
        return -1;
    array_t *caps = caps_ptr;
    size_t asize = array_size(caps);
    entry->n_capability = asize;
    entry->capability = calloc(asize, sizeof(AutonomousTrust__Core__Processes__Capability));

    int index;
    data_t *cap_dat;
    array_for_each(caps, index, cap_dat)
        capability_t *cap;
    if (data_object_ptr(cap_dat, (void **)&cap) != 0)
        return -1;
    capability_sync_out(cap, entry->capability[index]);
    array_end_for_each
        map_end_for_each return 0;
}

void peer_capabilities_proto_free(AutonomousTrust__Core__Processes__PeerCapabilities *proto)
{
    for (int i = 0; i < proto->n_listing; i++)
    {
        AutonomousTrust__Core__Processes__PeerCapabilities__PeerCapacity *entry = proto->listing[i++];
        for (int j = 0; j < entry->n_capability; j++)
            capability_proto_free(entry->capability[j]);
    }
    free(proto->listing);
}

int peer_capabilities_to_proto(peer_capabilities_matrix_t *map, void **data_ptr, size_t *data_len_ptr)
{
    AutonomousTrust__Core__Processes__PeerCapabilities proto;
    peer_capabilities_sync_out(map, &proto);
    *data_len_ptr = autonomous_trust__core__processes__peer_capabilities__get_packed_size(&proto);
    *data_ptr = malloc(*data_len_ptr);
    if (*data_ptr == NULL)
        return EXCEPTION(ENOMEM);
    autonomous_trust__core__processes__peer_capabilities__pack(&proto, *data_ptr);
    peer_capabilities_proto_free(&proto);
    return 0;
}

int peer_capabilities_sync_in(AutonomousTrust__Core__Processes__PeerCapabilities *proto, peer_capabilities_matrix_t *map)
{
    for (int i = 0; i < proto->n_listing; i++)
    {
        AutonomousTrust__Core__Processes__PeerCapabilities__PeerCapacity *pcaps = proto->listing[i];
        array_t *arr;
        if (array_create(&arr) != 0)
            return -1;

        for (int j = 0; j < pcaps->n_capability; j++)
        {
            capability_t *cap = malloc(sizeof(capability_t));
            if (cap != NULL)
                return EXCEPTION(ENOMEM);
            capability_sync_in(pcaps->capability[j], cap);
            data_t *cap_dat = object_ptr_data(cap, sizeof(capability_t));
            array_append(arr, cap_dat);
        }

        data_t *arr_dat = object_ptr_data(arr, sizeof(arr));
        if (arr_dat == NULL)
            return EXCEPTION(ENOMEM);
        char *key = malloc(strlen(pcaps->peer));
        strcpy(key, pcaps->peer);
        if (map_set(map, key, arr_dat) != 0)
            return -1;
    }
    return 0;
}

int proto_to_peer_capabilities(uint8_t *data, size_t len, peer_capabilities_matrix_t *peer_capabilities)
{
    AutonomousTrust__Core__Processes__PeerCapabilities *msg =
        autonomous_trust__core__processes__peer_capabilities__unpack(NULL, len, data);
    peer_capabilities_sync_in(msg, peer_capabilities);
    free(msg);
    return 0;
}
