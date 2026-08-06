/********************
 *  Copyright 2024 TekFive, Inc., Sean M. Brennan, and contributors
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

#include <jansson.h>

#include "config/configuration.h"
#include "capabilities_priv.h"
#include "capability_table_priv.h"

/*@
  requires name != \null && \valid_read(name);
  assigns \nothing;
  ensures \result == \null || \valid(\result);
*/
/* TODO (divergence.md C14 follow-up): Python emits `peer.set/caps_*`
 * counter probes around capability-query traffic
 * (idprocess.py:884-977). The C side already covers
 * `peer.set/self_announce` and `peer.set/amnesia_caps_registered`; the
 * caps_query/response path inside `id_proc.c` doesn't yet emit the
 * matching `caps_query_sent`, `caps_response_sent`, `caps_response_*`
 * counters. Mirror those once the caps_query/response handlers land
 * the same shape Python uses. */
capability_t *find_capability(const char *name)
{
    for (int i = 0; i < capability_table_size; i++)
    {
        IGNORE_GCC_VER_DIAGNOSTIC(12, -Warray-bounds)
        IGNORE_GCC_VER_DIAGNOSTIC(12, -Wstringop-overread)
        capability_t *entry = &(capability_table[i]);
        if (strcmp(entry->name, name) == 0)
            return entry;
        END_IGNORE_GCC_DIAGNOSTIC
        END_IGNORE_GCC_DIAGNOSTIC
    }
    return NULL;
}

/* Frama-C: skipped — [func-ptr] indirect call through capability_function_t. */
int capability_execute(const capability_t *cap, thread_args_t args)
{
    if (cap == NULL || cap->function == NULL)
        return -1;
    cap->function(args);
    return 0;
}

/* Frama-C: skipped —
 * [alloc-pattern] capability_sync_out / peer_capabilities_sync_out: at_memcpy +
 * map_sync_out + array_size/array_get; capability_sync_in: map_sync_in.
 */
int capability_sync_out(capability_t *capability, AutonomousTrust__Core__Protobuf__Processes__Capability *proto)
{
    proto->name = capability->name;
    proto->arg_types = malloc(sizeof(AutonomousTrust__Core__Protobuf__Structures__DataMap));
    if (proto->arg_types == NULL)
        return EXCEPTION(ENOMEM);
    AutonomousTrust__Core__Protobuf__Structures__DataMap tmp =
        AUTONOMOUS_TRUST__CORE__PROTOBUF__STRUCTURES__DATA_MAP__INIT;
    memcpy(proto->arg_types, &tmp, sizeof(tmp));
    map_sync_out(&capability->arguments, proto->arg_types);
    proto->required_tier = capability->required_tier;
    proto->transaction_weight = capability->transaction_weight;
    return 0;
}

void capability_proto_free(AutonomousTrust__Core__Protobuf__Processes__Capability *proto)
{
    if (proto->arg_types != NULL) {
        map_proto_free(proto->arg_types);
        free(proto->arg_types);
    }
}

/* Frama-C: skipped —
 * [alloc-pattern] capability_sync_out / peer_capabilities_sync_out: at_memcpy +
 * map_sync_out + array_size/array_get; capability_sync_in: map_sync_in.
 */
int capability_sync_in(AutonomousTrust__Core__Protobuf__Processes__Capability *proto, capability_t *capability)
{
    strncpy(capability->name, proto->name, CAP_NAMELEN);
    map_sync_in(proto->arg_types, &capability->arguments);
    capability->required_tier = proto->required_tier;
    /* proto3 default 0 means "not set"; treat as weight 1 so peers
     * without the field on the wire interoperate. */
    capability->transaction_weight =
        proto->transaction_weight > 0 ? proto->transaction_weight : 1;
    return 0;
}

int capability_to_proto(capability_t *msg, void **data_ptr, size_t *data_len_ptr)
{
    AutonomousTrust__Core__Protobuf__Processes__Capability proto =
        AUTONOMOUS_TRUST__CORE__PROTOBUF__PROCESSES__CAPABILITY__INIT;
    capability_sync_out(msg, &proto);
    *data_len_ptr = autonomous_trust__core__protobuf__processes__capability__get_packed_size(&proto);
    *data_ptr = smrt_create(*data_len_ptr);
    if (*data_ptr == NULL)
        return EXCEPTION(ENOMEM);
    autonomous_trust__core__protobuf__processes__capability__pack(&proto, *data_ptr);
    capability_proto_free(&proto);
    return 0;
}

int proto_to_capability(uint8_t *data, size_t len, capability_t *capability)
{
    AutonomousTrust__Core__Protobuf__Processes__Capability *msg =
        autonomous_trust__core__protobuf__processes__capability__unpack(NULL, len, data);
    capability_sync_in(msg, capability);
    free(msg);
    return 0;
}

/* Frama-C: skipped —
 * [alloc-pattern] capability_sync_out / peer_capabilities_sync_out: at_memcpy +
 * map_sync_out + array_size/array_get; capability_sync_in: map_sync_in.
 */
int peer_capabilities_sync_out(peer_capabilities_matrix_t *map, AutonomousTrust__Core__Protobuf__Processes__PeerCapabilities *proto)
{
    size_t size = map_size(map);
    proto->listing = calloc(size, sizeof(AutonomousTrust__Core__Protobuf__Structures__DataMap__DataMapEntry));
    proto->n_listing = size;
    char *key;
    data_t *elt;
    size_t i = 0;
    map_entries_for_each(map, key, elt)
        AutonomousTrust__Core__Protobuf__Processes__PeerCapabilities__PeerCapacity *entry = proto->listing[i++];
    entry->peer = key; // shared, do not free

    void *caps_ptr;
    if (data_object_ptr(elt, &caps_ptr) != 0)
        return -1;
    array_t *caps = caps_ptr;
    size_t asize = array_size(caps);
    entry->n_capability = asize;
    entry->capability = calloc(asize, sizeof(AutonomousTrust__Core__Protobuf__Processes__Capability));

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

void peer_capabilities_proto_free(AutonomousTrust__Core__Protobuf__Processes__PeerCapabilities *proto)
{
    for (int i = 0; i < proto->n_listing; i++)
    {
        AutonomousTrust__Core__Protobuf__Processes__PeerCapabilities__PeerCapacity *entry = proto->listing[i];
        for (int j = 0; j < entry->n_capability; j++)
            capability_proto_free(entry->capability[j]);
    }
    free(proto->listing);
}

int peer_capabilities_to_proto(peer_capabilities_matrix_t *map, void **data_ptr, size_t *data_len_ptr)
{
    AutonomousTrust__Core__Protobuf__Processes__PeerCapabilities proto;
    peer_capabilities_sync_out(map, &proto);
    *data_len_ptr = autonomous_trust__core__protobuf__processes__peer_capabilities__get_packed_size(&proto);
    *data_ptr = smrt_create(*data_len_ptr);
    if (*data_ptr == NULL)
        return EXCEPTION(ENOMEM);
    autonomous_trust__core__protobuf__processes__peer_capabilities__pack(&proto, *data_ptr);
    peer_capabilities_proto_free(&proto);
    return 0;
}

int peer_capabilities_sync_in(AutonomousTrust__Core__Protobuf__Processes__PeerCapabilities *proto, peer_capabilities_matrix_t *map)
{
    for (int i = 0; i < proto->n_listing; i++)
    {
        AutonomousTrust__Core__Protobuf__Processes__PeerCapabilities__PeerCapacity *pcaps = proto->listing[i];
        array_t *arr;
        if (array_create(&arr) != 0)
            return -1;

        for (int j = 0; j < pcaps->n_capability; j++)
        {
            capability_t *cap = smrt_create(sizeof(capability_t));
            if (cap == NULL)
                return EXCEPTION(ENOMEM);
            capability_sync_in(pcaps->capability[j], cap);
            data_t *cap_dat = object_ptr_data(cap, sizeof(capability_t));
            array_append(arr, cap_dat);
        }

        data_t *arr_dat = object_ptr_data(arr, sizeof(arr));
        if (arr_dat == NULL)
            return EXCEPTION(ENOMEM);
        char *key = smrt_create(strlen(pcaps->peer) + 1);
        strcpy(key, pcaps->peer);
        if (map_set(map, key, arr_dat) != 0)
            return -1;
    }
    return 0;
}

int proto_to_peer_capabilities(uint8_t *data, size_t len, peer_capabilities_matrix_t *peer_capabilities)
{
    AutonomousTrust__Core__Protobuf__Processes__PeerCapabilities *msg =
        autonomous_trust__core__protobuf__processes__peer_capabilities__unpack(NULL, len, data);
    peer_capabilities_sync_in(msg, peer_capabilities);
    free(msg);
    return 0;
}

/*****************************
 * JSON serialization for peer capabilities configuration
 ****************************/

/* Frama-C: skipped —
 * [serialization] capability_to_json_obj, peer_capabilities_to_json: map_get +
 * json_string/array_append_new/object_set_new + data_integer/
 * data_string_ptr/data_object_ptr cascades (plus terminates_part from nested map+json
 * operations).
 */
static int capability_to_json_obj(const capability_t *cap, json_t **obj_ptr)
{
    *obj_ptr = json_object();
    json_t *obj = *obj_ptr;
    if (obj == NULL)
        return EXCEPTION(ENOMEM);

    if (json_object_set_new(obj, "name", json_string(cap->name)) != 0)
        return EXCEPTION(EJSN_OBJ_SET);

    /* Trust-tier metadata — mirrors Python Capability.to_dict (which
     * now emits required_tier + transaction_weight). Both fields are
     * always written; readers tolerate absence via 0 defaults. */
    json_object_set_new(obj, "required_tier", json_integer(cap->required_tier));
    json_object_set_new(obj, "transaction_weight", json_integer(cap->transaction_weight));

    /* Serialize arguments map as { arg_name: type_string, ... } */
    json_t *args = json_object();
    if (map_size((map_t *)&cap->arguments) > 0) {
        char *key;
        data_t *val;
        map_entries_for_each((map_t *)&cap->arguments, key, val)
            int type_val;
            if (data_integer(val, &type_val) == 0)
                json_object_set_new(args, key, json_integer(type_val));
        map_end_for_each
    }
    json_object_set_new(obj, "arguments", args);

    return 0;
}

/* Frama-C: skipped — capability_from_json_obj: strncpy + map_init. */
static int capability_from_json_obj(const json_t *obj, capability_t *cap)
{
    const char *name = json_string_value(json_object_get(obj, "name"));
    if (name == NULL)
        return -1;
    strncpy(cap->name, name, CAP_NAMELEN);
    cap->local = false;

    /* Trust-tier metadata: optional in JSON (absent → 0 / 1 defaults
     * via the 0 → 1 sentinel on transaction_weight). */
    json_t *rt = json_object_get(obj, "required_tier");
    cap->required_tier = (rt != NULL && json_is_integer(rt))
        ? (int)json_integer_value(rt) : 0;
    json_t *tw = json_object_get(obj, "transaction_weight");
    int w = (tw != NULL && json_is_integer(tw))
        ? (int)json_integer_value(tw) : 0;
    cap->transaction_weight = w > 0 ? w : 1;

    map_init(&cap->arguments);
    json_t *args = json_object_get(obj, "arguments");
    if (args != NULL && json_is_object(args)) {
        const char *arg_key;
        json_t *arg_val;
        json_object_foreach(args, arg_key, arg_val) {
            if (json_is_integer(arg_val)) {
                data_t *d = integer_data((int)json_integer_value(arg_val));
                char *k = smrt_create(strlen(arg_key) + 1);
                strcpy(k, arg_key);
                map_set(&cap->arguments, k, d);
            }
        }
    }

    return 0;
}

/* Frama-C: skipped —
 * [serialization] capability_to_json_obj, peer_capabilities_to_json: map_get +
 * json_string/array_append_new/object_set_new + data_integer/
 * data_string_ptr/data_object_ptr cascades (plus terminates_part from nested map+json
 * operations).
 */
int peer_capabilities_to_json(const void *data_struct, json_t **obj_ptr)
{
    const peer_capabilities_matrix_t *matrix = data_struct;
    *obj_ptr = json_object();
    json_t *obj = *obj_ptr;
    if (obj == NULL)
        return EXCEPTION(ENOMEM);

    if (json_object_set_new(obj, "typename", json_string("peer_capabilities")) != 0)
        return EXCEPTION(EJSN_OBJ_SET);

    json_t *peers = json_object();
    if (map_size((map_t *)matrix) > 0) {
        char *key;
        data_t *val;
        map_entries_for_each((map_t *)matrix, key, val)
            void *caps_ptr;
            if (data_object_ptr(val, &caps_ptr) != 0)
                continue;
            array_t *caps = caps_ptr;

            json_t *cap_arr = json_array();
            for (size_t i = 0; i < array_size(caps); i++) {
                data_t *cap_dat = NULL;
                if (array_get(caps, i, &cap_dat) != 0)
                    continue;
                capability_t *cap;
                if (data_object_ptr(cap_dat, (void **)&cap) != 0)
                    continue;
                json_t *cap_obj = NULL;
                if (capability_to_json_obj(cap, &cap_obj) == 0)
                    json_array_append_new(cap_arr, cap_obj);
            }
            json_object_set_new(peers, key, cap_arr);
        map_end_for_each
    }
    json_object_set_new(obj, "peers", peers);

    return 0;
}

int peer_capabilities_from_json(const json_t *obj, void *data_struct)
{
    peer_capabilities_matrix_t *matrix = data_struct;
    map_init(matrix);

    json_t *peers = json_object_get(obj, "peers");
    if (peers == NULL || !json_is_object(peers))
        return 0;  /* empty config is valid */

    const char *peer_uuid;
    json_t *cap_arr;
    json_object_foreach(peers, peer_uuid, cap_arr) {
        if (!json_is_array(cap_arr))
            continue;

        array_t *arr;
        if (array_create(&arr) != 0)
            return EXCEPTION(ENOMEM);

        for (size_t i = 0; i < json_array_size(cap_arr); i++) {
            json_t *cap_obj = json_array_get(cap_arr, i);
            capability_t *cap = smrt_create(sizeof(capability_t));
            if (cap == NULL)
                return EXCEPTION(ENOMEM);
            if (capability_from_json_obj(cap_obj, cap) != 0) {
                smrt_deref(cap);
                continue;
            }
            data_t *cap_dat = object_ptr_data(cap, sizeof(capability_t));
            array_append(arr, cap_dat);
        }

        data_t *arr_dat = object_ptr_data(arr, sizeof(array_t));
        if (arr_dat == NULL)
            return EXCEPTION(ENOMEM);
        char *key = smrt_create(strlen(peer_uuid) + 1);
        strcpy(key, peer_uuid);
        map_set(matrix, key, arr_dat);
    }
    return 0;
}

/* TODO (divergence.md H3 follow-up): `peer_capabilities_to_proto` and
 * `proto_to_peer_capabilities` already live above — wire them through
 * here so this config participates in PROTO mode. Same for the
 * standalone `capability` config in any future DECLARE_CONFIGURATION
 * for it (its proto converters `capability_to_proto` /
 * `proto_to_capability` also exist already). Blocked only on widening
 * the macro signature to take optional proto callbacks, or adding the
 * fields at runtime via find_configuration(). */
DECLARE_CONFIGURATION(peer_capabilities, sizeof(peer_capabilities_matrix_t),
                      peer_capabilities_to_json, peer_capabilities_from_json);

/*@
  requires my_uuid != \null && \valid_read(my_uuid);
  requires \valid(caps_out);
  allocates *caps_out;
  behavior success:
    ensures \result == 0;
    ensures *caps_out != \null;
  behavior failure:
    ensures \result != 0;
  disjoint behaviors;
*/
int build_local_capabilities(const char *my_uuid, array_t **caps_out)
{
    if (array_create(caps_out) != 0)
        return EXCEPTION(ENOMEM);

    for (size_t i = 0; i < capability_table_size; i++) {
        capability_t *src = &capability_table[i];
        if (!src->local)
            continue;
        capability_t *cap = smrt_create(sizeof(capability_t));
        if (cap == NULL)
            return EXCEPTION(ENOMEM);
        strncpy(cap->name, src->name, CAP_NAMELEN);
        map_init(&cap->arguments);
        cap->local = true;
        cap->function = NULL;  /* don't expose function pointer */
        cap->required_tier = src->required_tier;
        /* weight 0 in capability_table means "use default 1" — same
         * sentinel as the proto wire form. */
        cap->transaction_weight = src->transaction_weight > 0
            ? src->transaction_weight : 1;
        data_t *cap_dat = object_ptr_data(cap, sizeof(capability_t));
        array_append(*caps_out, cap_dat);
    }
    return 0;
}
