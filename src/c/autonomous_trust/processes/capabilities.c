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
#include "bootstrap/bootstrap_capabilities.h"
#include "capability_table_priv.h"
#include "utilities/util.h"
#include <stdio.h>

/*@
  requires name != \null && \valid_read(name);
  assigns \nothing;
  ensures \result == \null || \valid(\result);
*/
int capability_table_append(const char *name, capability_function_t fn,
                            capability_result_function_t res_fn)
{
    if (name == NULL || name[0] == '\0' || strlen(name) > CAP_NAMELEN) {
        fprintf(stderr, "capability_table_append: refusing a bad name\n");
        return -1;
    }
    if (find_capability(name) != NULL) {
        fprintf(stderr, "capability_table_append: %s already in the table\n", name);
        return -1;
    }
    if (capability_table_size >= CAPABILITY_TABLE_CAPACITY - 1) {   /* keep the sentinel */
        fprintf(stderr, "capability_table_append: table full, %s refused\n", name);
        return -1;
    }
    capability_t *row = &capability_table[capability_table_size];
    memset(row, 0, sizeof(*row));
    at_strlcpy(row->name, name, sizeof(row->name));
    row->local = true;
    row->function = fn;
    row->result_function = res_fn;
    capability_table_size++;
    capability_table[capability_table_size].name[0] = '\0';  /* sentinel */
    return 0;
}

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

/* Frama-C: skipped — [func-ptr] indirect call through
 * capability_result_function_t. */
int capability_execute_result(const capability_t *cap, const char *kwargs_json,
                             char *result_out, size_t result_len)
{
    if (cap == NULL || cap->result_function == NULL
        || result_out == NULL || result_len == 0)
        return -1;
    result_out[0] = '\0';
    return cap->result_function((kwargs_json != NULL) ? kwargs_json : "",
                                result_out, result_len);
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
    if (capability->arguments.items == NULL)
        map_init(&capability->arguments);
    if (proto->arg_types != NULL)
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
    /* a plain buffer the caller free()s; smrt_create is for headered structs */
    *data_ptr = malloc(*data_len_ptr > 0 ? *data_len_ptr : 1);
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
    if (msg == NULL)
        return -1;
    capability_sync_in(msg, capability);
    /* free_unpacked, not free: the name and argument map are allocations of
     * their own (capability_sync_in copies what it keeps). */
    autonomous_trust__core__protobuf__processes__capability__free_unpacked(msg, NULL);
    return 0;
}

/* Frama-C: skipped —
 * [alloc-pattern] capability_sync_out / peer_capabilities_sync_out: at_memcpy +
 * map_sync_out + array_size/array_get; capability_sync_in: map_sync_in.
 */
int peer_capabilities_sync_out(peer_capabilities_matrix_t *map, AutonomousTrust__Core__Protobuf__Processes__PeerCapabilities *proto)
{
    /* listing and each capability list are arrays of POINTERS to messages,
     * each of which needs its own allocation and init. Freed by
     * peer_capabilities_proto_free, also on a failure part way. */
    size_t size = map_size(map);
    proto->n_listing = 0;
    proto->listing = calloc(size > 0 ? size : 1, sizeof(*proto->listing));
    if (proto->listing == NULL)
        return EXCEPTION(ENOMEM);
    char *key;
    data_t *elt;
    int rc = 0;
    map_entries_for_each(map, key, elt)
        if (rc != 0 || proto->n_listing >= size)
            continue;
        void *caps_ptr = NULL;
        if (data_object_ptr(elt, &caps_ptr) != 0 || caps_ptr == NULL)
            continue;
        array_t *caps = caps_ptr;
        AutonomousTrust__Core__Protobuf__Processes__PeerCapabilities__PeerCapacity *entry =
            malloc(sizeof(*entry));
        if (entry == NULL) { rc = EXCEPTION(ENOMEM); continue; }
        AutonomousTrust__Core__Protobuf__Processes__PeerCapabilities__PeerCapacity einit =
            AUTONOMOUS_TRUST__CORE__PROTOBUF__PROCESSES__PEER_CAPABILITIES__PEER_CAPACITY__INIT;
        *entry = einit;
        entry->peer = key; // shared, do not free
        proto->listing[proto->n_listing++] = entry;
        size_t asize = array_size(caps);
        entry->capability = calloc(asize > 0 ? asize : 1, sizeof(*entry->capability));
        if (entry->capability == NULL) { rc = EXCEPTION(ENOMEM); continue; }
        for (size_t j = 0; j < asize; j++)
        {
            data_t *cap_dat = NULL;
            capability_t *cap = NULL;
            if (array_get(caps, (int)j, &cap_dat) != 0
                || data_object_ptr(cap_dat, (void **)&cap) != 0 || cap == NULL)
                continue;
            AutonomousTrust__Core__Protobuf__Processes__Capability *pc = malloc(sizeof(*pc));
            if (pc == NULL) { rc = EXCEPTION(ENOMEM); break; }
            AutonomousTrust__Core__Protobuf__Processes__Capability cinit =
                AUTONOMOUS_TRUST__CORE__PROTOBUF__PROCESSES__CAPABILITY__INIT;
            *pc = cinit;
            entry->capability[entry->n_capability++] = pc;
            if (capability_sync_out(cap, pc) != 0) { rc = -1; break; }
        }
    map_end_for_each
    return rc;
}

void peer_capabilities_proto_free(AutonomousTrust__Core__Protobuf__Processes__PeerCapabilities *proto)
{
    for (size_t i = 0; i < proto->n_listing; i++)
    {
        AutonomousTrust__Core__Protobuf__Processes__PeerCapabilities__PeerCapacity *entry = proto->listing[i];
        if (entry == NULL)
            continue;
        for (size_t j = 0; j < entry->n_capability; j++)
        {
            capability_proto_free(entry->capability[j]);
            free(entry->capability[j]);
        }
        free(entry->capability);
        free(entry);
    }
    free(proto->listing);
    proto->listing = NULL;
    proto->n_listing = 0;
}

int peer_capabilities_to_proto(peer_capabilities_matrix_t *map, void **data_ptr, size_t *data_len_ptr)
{
    AutonomousTrust__Core__Protobuf__Processes__PeerCapabilities proto =
        AUTONOMOUS_TRUST__CORE__PROTOBUF__PROCESSES__PEER_CAPABILITIES__INIT;
    if (peer_capabilities_sync_out(map, &proto) != 0)
    {
        peer_capabilities_proto_free(&proto);
        return -1;
    }
    *data_len_ptr = autonomous_trust__core__protobuf__processes__peer_capabilities__get_packed_size(&proto);
    /* a plain buffer the caller free()s; smrt_create is for headered structs */
    *data_ptr = malloc(*data_len_ptr > 0 ? *data_len_ptr : 1);
    if (*data_ptr == NULL)
    {
        peer_capabilities_proto_free(&proto);
        return EXCEPTION(ENOMEM);
    }
    autonomous_trust__core__protobuf__processes__peer_capabilities__pack(&proto, *data_ptr);
    peer_capabilities_proto_free(&proto);
    return 0;
}

/* Frama-C: skipped — [alloc-pattern] releases the embedded arguments map */
void capability_dtor(void *ptr)
{
    capability_t *cap = ptr;
    map_free(&cap->arguments);
}

/* A new heap capability named @p name (no arguments, tier 0, weight 1) that
 * releases its arguments map when its last reference goes. */
static capability_t *_capability_new(const char *name)
{
    capability_t *cap = smrt_create(sizeof(capability_t));
    if (cap == NULL)
        return NULL;
    cap->dtor = capability_dtor;
    map_init(&cap->arguments);
    if (name != NULL)
        at_strlcpy(cap->name, name, sizeof(cap->name));
    cap->transaction_weight = 1;
    return cap;
}

/* Append @p cap to @p arr, the array owning it from here. On failure the
 * capability is released. */
static int _append_owned_cap(array_t *arr, capability_t *cap)
{
    data_t *cap_dat = owned_smrt_data(cap, sizeof(capability_t));
    if (cap_dat == NULL)
    {
        smrt_deref(cap);
        return EXCEPTION(ENOMEM);
    }
    if (array_append(arr, cap_dat) != 0)
    {
        smrt_deref(cap_dat);
        return -1;
    }
    return 0;
}

/* Set @p map[@p peer] to @p arr, the matrix owning it from here. On failure
 * the array is released. */
static int _set_owned_caps(peer_capabilities_matrix_t *map, const char *peer,
                           array_t *arr)
{
    data_t *arr_dat = owned_array_data(arr);
    if (arr_dat == NULL)
    {
        array_free(arr);
        return EXCEPTION(ENOMEM);
    }
    /* map_set strdup's the key, so no copy of our own */
    if (map_set(map, (map_key_t)peer, arr_dat) != 0)
    {
        smrt_deref(arr_dat);
        return -1;
    }
    return 0;
}

int peer_capabilities_sync_in(AutonomousTrust__Core__Protobuf__Processes__PeerCapabilities *proto, peer_capabilities_matrix_t *map)
{
    for (size_t i = 0; i < proto->n_listing; i++)
    {
        AutonomousTrust__Core__Protobuf__Processes__PeerCapabilities__PeerCapacity *pcaps = proto->listing[i];
        if (pcaps == NULL || pcaps->peer == NULL)
            continue;
        array_t *arr;
        if (array_create(&arr) != 0)
            return -1;

        for (size_t j = 0; j < pcaps->n_capability; j++)
        {
            capability_t *cap = _capability_new(NULL);
            if (cap == NULL)
            {
                array_free(arr);
                return EXCEPTION(ENOMEM);
            }
            capability_sync_in(pcaps->capability[j], cap);
            if (_append_owned_cap(arr, cap) != 0)
            {
                array_free(arr);
                return -1;
            }
        }
        if (_set_owned_caps(map, pcaps->peer, arr) != 0)
            return -1;
    }
    return 0;
}

int proto_to_peer_capabilities(uint8_t *data, size_t len, peer_capabilities_matrix_t *peer_capabilities)
{
    if (map_init(peer_capabilities) != 0)
        return -1;
    AutonomousTrust__Core__Protobuf__Processes__PeerCapabilities *msg =
        autonomous_trust__core__protobuf__processes__peer_capabilities__unpack(NULL, len, data);
    if (msg == NULL)
        return -1;
    int rc = peer_capabilities_sync_in(msg, peer_capabilities);
    autonomous_trust__core__protobuf__processes__peer_capabilities__free_unpacked(msg, NULL);
    return rc;
}

int peer_capabilities_add(peer_capabilities_matrix_t *map, const char *peer,
                          const char *const *names, size_t n_names)
{
    array_t *arr;
    if (array_create(&arr) != 0)
        return -1;
    for (size_t i = 0; i < n_names; i++)
    {
        if (names[i] == NULL)
            continue;
        capability_t *cap = _capability_new(names[i]);
        if (cap == NULL || _append_owned_cap(arr, cap) != 0)
        {
            array_free(arr);
            return EXCEPTION(ENOMEM);
        }
    }
    return _set_owned_caps(map, peer, arr);
}

peer_capabilities_matrix_t *peer_capabilities_take(peer_capabilities_matrix_t *src)
{
    if (src == NULL || src->items == NULL)
        return NULL;
    map_t *m = smrt_create(sizeof(map_t));
    if (m == NULL)
        return NULL;
    smrt_ptr_t header = *(smrt_ptr_t *)m;
    memcpy(m, src, sizeof(map_t));
    *(smrt_ptr_t *)m = header;   /* keep the heap header smrt_create wrote */
    memset(src, 0, sizeof(*src));
    return m;
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

    if (cap->arguments.items == NULL)
        map_init(&cap->arguments);
    json_t *args = json_object_get(obj, "arguments");
    if (args != NULL && json_is_object(args)) {
        const char *arg_key;
        json_t *arg_val;
        json_object_foreach(args, arg_key, arg_val) {
            if (json_is_integer(arg_val)) {
                data_t *d = integer_data((int)json_integer_value(arg_val));
                /* map_set strdup's the key, so no copy of our own */
                map_set(&cap->arguments, (char *)arg_key, d);
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
            capability_t *cap = _capability_new(NULL);
            if (cap == NULL)
            {
                array_free(arr);
                return EXCEPTION(ENOMEM);
            }
            if (capability_from_json_obj(cap_obj, cap) != 0) {
                smrt_deref(cap);
                continue;
            }
            if (_append_owned_cap(arr, cap) != 0)
            {
                array_free(arr);
                return EXCEPTION(ENOMEM);
            }
        }

        if (_set_owned_caps(matrix, peer_uuid, arr) != 0)
            return EXCEPTION(ENOMEM);
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
        /* AT_BOOTSTRAP_DISABLED suppresses the three AT-core probe
         * capabilities, mirroring Python's gate on the registration call
         * itself (automate.py). A static table cannot skip its own rows, so
         * the gate is read here, where the table becomes an advertisement:
         * a node that will not answer a probe must not claim it can. */
        if (is_probe_capability(src->name) && !bootstrap_capabilities_enabled())
            continue;
        capability_t *cap = _capability_new(src->name);
        if (cap == NULL)
            return EXCEPTION(ENOMEM);
        cap->local = true;
        cap->function = NULL;  /* don't expose function pointer */
        /* Nor the result-producing one. smrt_create callocs, so this is
         * already NULL; set it beside `function` so the two stay obviously
         * paired and a later reader does not have to check the allocator to
         * know an advertised capability carries no callable. */
        cap->result_function = NULL;
        cap->required_tier = src->required_tier;
        /* weight 0 in capability_table means "use default 1" — same
         * sentinel as the proto wire form. */
        cap->transaction_weight = src->transaction_weight > 0
            ? src->transaction_weight : 1;
        if (_append_owned_cap(*caps_out, cap) != 0)
            return EXCEPTION(ENOMEM);
    }
    return 0;
}
