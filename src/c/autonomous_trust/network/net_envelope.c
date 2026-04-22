/********************
 *  Copyright 2025 Sean M. Brennan and contributors
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

#include <string.h>

#include "network/net_envelope.h"

int net_envelope_pack(const net_envelope_t *env,
                      const uint8_t *payload, size_t payload_len,
                      uint8_t *out_frame, size_t out_frame_cap,
                      size_t *out_frame_len)
{
    if (env == NULL || out_frame == NULL || out_frame_len == NULL)
        return -1;
    if (payload_len > 0 && payload == NULL)
        return -1;
    if (out_frame_cap < NET_ENV_HEADER_LEN + payload_len)
        return -1;

    out_frame[0] = env->version;
    out_frame[1] = (uint8_t)env->type;
    out_frame[2] = env->flags;
    out_frame[3] = env->hop_count;
    memcpy(out_frame + 4,  env->dst_uuid, 16);
    memcpy(out_frame + 20, env->src_uuid, 16);
    if (payload_len > 0)
        memcpy(out_frame + NET_ENV_HEADER_LEN, payload, payload_len);

    *out_frame_len = NET_ENV_HEADER_LEN + payload_len;
    return 0;
}

int net_envelope_unpack(const uint8_t *frame, size_t frame_len,
                        net_envelope_t *env_out,
                        const uint8_t **payload_out,
                        size_t *payload_len_out)
{
    if (frame == NULL || env_out == NULL ||
        payload_out == NULL || payload_len_out == NULL)
        return -1;
    if (frame_len < NET_ENV_HEADER_LEN)
        return -1;
    if (frame[0] != NET_ENV_VERSION)
        return -1;

    env_out->version   = frame[0];
    env_out->type      = (net_env_type_t)frame[1];
    env_out->flags     = frame[2];
    env_out->hop_count = frame[3];
    memcpy(env_out->dst_uuid, frame + 4,  16);
    memcpy(env_out->src_uuid, frame + 20, 16);

    *payload_out     = frame + NET_ENV_HEADER_LEN;
    *payload_len_out = frame_len - NET_ENV_HEADER_LEN;
    return 0;
}

int net_envelope_rewrite_header(const net_envelope_t *env,
                                uint8_t *frame, size_t frame_len)
{
    if (env == NULL || frame == NULL || frame_len < NET_ENV_HEADER_LEN)
        return -1;

    frame[0] = env->version;
    frame[1] = (uint8_t)env->type;
    frame[2] = env->flags;
    frame[3] = env->hop_count;
    memcpy(frame + 4,  env->dst_uuid, 16);
    memcpy(frame + 20, env->src_uuid, 16);
    return 0;
}

bool net_envelope_is_nil_uuid(const uuid_t uuid)
{
    static const unsigned char NIL[16] = {0};
    return memcmp(uuid, NIL, sizeof(NIL)) == 0;
}

net_env_disposition_t net_envelope_disposition(const net_envelope_t *env,
                                               const uuid_t my_uuid,
                                               const uuid_t my_group_uuid,
                                               bool am_gateway)
{
    if (env == NULL)
        return NET_ENV_DISPOSITION_DROP;

    switch (env->type) {
    case NET_ENV_TYPE_BROADCAST:
        return NET_ENV_DISPOSITION_LOCAL;

    case NET_ENV_TYPE_PEER:
        if (memcmp(env->dst_uuid, my_uuid, 16) == 0)
            return NET_ENV_DISPOSITION_LOCAL;
        if (am_gateway && env->hop_count < NET_ENV_MAX_HOPS)
            return NET_ENV_DISPOSITION_FORWARD;
        return NET_ENV_DISPOSITION_DROP;

    case NET_ENV_TYPE_GROUP:
        if (my_group_uuid != NULL &&
            !net_envelope_is_nil_uuid(my_group_uuid) &&
            memcmp(env->dst_uuid, my_group_uuid, 16) == 0)
            return NET_ENV_DISPOSITION_LOCAL;
        return NET_ENV_DISPOSITION_DROP;

    case NET_ENV_TYPE_UNKNOWN:
    default:
        return NET_ENV_DISPOSITION_DROP;
    }
}

bool net_envelope_should_forward_broadcast(const net_envelope_t *env,
                                           bool am_gateway)
{
    if (env == NULL || !am_gateway)
        return false;
    if (env->type != NET_ENV_TYPE_BROADCAST)
        return false;
    return env->hop_count < NET_ENV_MAX_HOPS;
}

uint64_t net_envelope_broadcast_fingerprint(const net_envelope_t *env,
                                            const uint8_t *payload,
                                            size_t payload_len)
{
    if (env == NULL)
        return 0;
    /* FNV-1a-64. The offset basis is non-zero, so a valid fingerprint can
     * never collide with the 0 sentinel this function returns on NULL. */
    uint64_t h = 0xcbf29ce484222325ULL;
    for (size_t i = 0; i < 16; i++) {
        h ^= (uint64_t)env->src_uuid[i];
        h *= 0x100000001b3ULL;
    }
    for (size_t i = 0; i < payload_len; i++) {
        h ^= (uint64_t)payload[i];
        h *= 0x100000001b3ULL;
    }
    return h;
}
