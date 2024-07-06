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

#include <stdbool.h>
#include <string.h>
#include <errno.h>

#include <uuid/uuid.h>
#include <sodium.h>
#include <jansson.h>

#include "algorithms/algorithms.h"
#include "config/configuration.h"
#include "utilities/exception.h"

#include "identity_priv.h"


int identity_init(uuid_t *uuid, char *address, char *fullname, identity_t *identity)
{
    if (uuid == NULL)
        uuid_generate((unsigned char *)identity->uuid);
    else
        memcpy(&identity->uuid, uuid, sizeof(uuid_t));

    strncpy(identity->address, address, ADDR_LEN);
    strncpy(identity->fullname, fullname, NAME_LEN);

    unsigned char *sseed = signature_generate();
    if (sseed == NULL)
        return -1;
    signature_init(&(identity->signature), sseed);
    free(sseed);

    unsigned char *eseed = encryptor_generate();
    if (eseed == NULL)
        return -1;
    encryptor_init(&identity->encryptor, eseed);
    free(eseed);

    return 0;
}

int identity_create(uuid_t *uuid, char *address, char *fullname, identity_t **ident)
{ // FIXME address + 4 names
    if (sodium_init() < 0)
    {
        exit(-1); // FIXME logging?
    }
    *ident = calloc(1, sizeof(identity_t));
    identity_t *identity = *ident;
    if (identity == NULL)
        return EXCEPTION(ENOMEM);

    return identity_init(uuid, address, fullname, identity);
}

int identity_publish(const identity_t *ident, public_identity_t **pub_copy)
{
    if (ident == NULL)
        return EINVAL;
    *pub_copy = malloc(sizeof(public_identity_t));
    public_identity_t *newIdent = *pub_copy;
    if (newIdent == NULL)
        return EXCEPTION(ENOMEM);

    unsigned char *sseed = signature_publish(&ident->signature);
    if (sseed == NULL)
        return -1;
    public_signature_init(&newIdent->signature, sseed);
    free(sseed);
    unsigned char *eseed = encryptor_publish(&ident->encryptor);
    if (eseed == NULL)
        return -1;
    public_encryptor_init(&newIdent->encryptor, eseed);
    free(eseed);

    //public_identity_init(newIdent);
    return 0;
}

int identity_sign(const identity_t *ident, const msg_str_t *in, msg_str_t *out)
{
    return crypto_sign(out->msg, &out->len, in->msg, in->len, ident->signature.private);
}

int identity_verify(const public_identity_t *ident, const msg_str_t *in, msg_str_t *out)
{
    return crypto_sign_open(out->msg, &out->len, in->msg, in->len, ident->signature.public);
}

int identity_encrypt(const identity_t *ident, const msg_str_t *in, const public_identity_t *whom, const unsigned char *nonce, unsigned char *cipher)
{
    return crypto_box_easy(cipher, in->msg, in->len, nonce, whom->encryptor.public, ident->encryptor.private);
}

int identity_decrypt(const identity_t *ident, const msg_str_t *cipher, const public_identity_t *whom, const unsigned char *nonce, unsigned char *out)
{
    return crypto_box_open_easy(out, cipher->msg, cipher->len, nonce, whom->encryptor.public, ident->encryptor.private);
}

int identity_to_json(const void *data_struct, json_t **obj_ptr)
{
    identity_t *ident = (identity_t *)data_struct;
    *obj_ptr = json_object();
    json_t *obj = *obj_ptr;
    if (obj == NULL)
        return ENOMEM;
    char uuid_str[UUID_STRING_LEN+1] = {0};
    uuid_unparse(ident->uuid, uuid_str);
    json_object_set(obj, "uuid", json_string(uuid_str));
    json_object_set(obj, "rank", json_integer(ident->rank));
    json_object_set(obj, "address", json_string((char *)ident->address));
    json_object_set(obj, "fullname", json_string(ident->fullname));
    json_object_set(obj, "nickname", json_string(ident->nickname));
    json_object_set(obj, "petname", json_string(ident->petname));

    json_t *sig = json_object();
    unsigned char *hex = signature_publish(&ident->signature); // encoded
    json_object_set(sig, "hex_seed", json_string((char *)hex));
    free(hex);
    json_object_set(obj, "signature", sig);

    json_t *encr = json_object();
    hex = encryptor_publish(&ident->encryptor); // encoded
    json_object_set(encr, "hex_seed", json_string((char *)hex));
    free(hex);
    json_object_set(obj, "encryptor", encr);

    return 0;
}

int identity_from_json(const json_t *obj, void *data_struct)
{
    identity_t *ident = (identity_t *)data_struct;
    json_t *uuid_obj = json_object_get(obj, "uuid");
    const char *uuid_str = json_string_value(uuid_obj);
    if (uuid_parse(uuid_str, ident->uuid) < 0)
        return -1;
    ident->rank = json_integer_value(json_object_get(obj, "rank"));
    strncpy(ident->fullname, (char *)json_string_value(json_object_get(obj, "fullname")), sizeof(ident->fullname)-1);
    strncpy(ident->nickname, (char *)json_string_value(json_object_get(obj, "nickname")), sizeof(ident->nickname)-1);
    strncpy(ident->petname, (char *)json_string_value(json_object_get(obj, "petname")), sizeof(ident->petname)-1);
    uint8_t *seed = (uint8_t *)json_object_get(json_object_get(obj, "signature"), "hex_seed");
    signature_init(&ident->signature, seed); // decoded
    seed = (uint8_t *)json_object_get(json_object_get(obj, "encryptor"), "hex_seed");
    encryptor_init(&ident->encryptor, seed); // decoded
    return 0;
}

DECLARE_CONFIGURATION(identity, sizeof(identity_t), identity_to_json, identity_from_json);

int public_identity_sync_out(public_identity_t *identity, AutonomousTrust__Core__Protobuf__Identity__Identity *proto)
{
    AutonomousTrust__Core__Protobuf__Identity__Identity tmp = AUTONOMOUS_TRUST__CORE__PROTOBUF__IDENTITY__IDENTITY__INIT;
    memcpy(proto, &tmp, sizeof(tmp)); // dumb initialization workaround
    proto->uuid.data = identity->uuid;
    proto->uuid.len = sizeof(uuid_t);
    proto->address = identity->address;
    proto->fullname = identity->fullname;

    proto->signature = malloc(sizeof(AutonomousTrust__Core__Protobuf__Identity__Signature));
    AutonomousTrust__Core__Protobuf__Identity__Signature tmp_s = AUTONOMOUS_TRUST__CORE__PROTOBUF__IDENTITY__SIGNATURE__INIT;
    memcpy(proto->signature, &tmp_s, sizeof(tmp_s));
    proto->signature->hex_seed.data = identity->signature.public_hex;
    proto->signature->hex_seed.len = crypto_sign_PUBLICKEYBYTES * 2;

    proto->encryptor = malloc(sizeof(AutonomousTrust__Core__Protobuf__Identity__Encryptor));
    AutonomousTrust__Core__Protobuf__Identity__Encryptor tmp_e = AUTONOMOUS_TRUST__CORE__PROTOBUF__IDENTITY__ENCRYPTOR__INIT;
    memcpy(proto->encryptor, &tmp_e, sizeof(tmp_e));
    proto->encryptor->hex_seed.data = identity->encryptor.public_hex;
    proto->encryptor->hex_seed.len = crypto_box_PUBLICKEYBYTES * 2;
    return 0;
}

int public_identity_sync_in(AutonomousTrust__Core__Protobuf__Identity__Identity *proto, public_identity_t *identity)
{
    memcpy(&identity->uuid, proto->uuid.data, sizeof(uuid_t));
    strncpy(identity->address, proto->address, ADDR_LEN);
    strncpy(identity->fullname, proto->fullname, NAME_LEN);
    memcpy(identity->signature.public_hex, proto->signature->hex_seed.data, crypto_sign_PUBLICKEYBYTES * 2);
    memcpy(identity->encryptor.public_hex, proto->encryptor->hex_seed.data, crypto_box_PUBLICKEYBYTES * 2);
    return 0;
}

void public_identity_proto_free(AutonomousTrust__Core__Protobuf__Identity__Identity *proto)
{
    free(proto->signature);
    free(proto->encryptor);
}

int peer_to_proto(public_identity_t *msg, void **data_ptr, size_t *data_len_ptr)
{
    AutonomousTrust__Core__Protobuf__Identity__Identity proto;
    public_identity_sync_out(msg, &proto);
    *data_len_ptr = autonomous_trust__core__protobuf__identity__identity__get_packed_size(&proto);
    *data_ptr = malloc(*data_len_ptr);
    if (*data_ptr == NULL)
        return EXCEPTION(ENOMEM);
    autonomous_trust__core__protobuf__identity__identity__pack(&proto, *data_ptr);
    public_identity_proto_free(&proto);
    return 0;
}

int proto_to_peer(uint8_t *data, size_t len, public_identity_t *peer)
{
    AutonomousTrust__Core__Protobuf__Identity__Identity *msg =
        autonomous_trust__core__protobuf__identity__identity__unpack(NULL, len, data);
    public_identity_sync_in(msg, peer);
    free(msg);
    return 0;
}

void identity_free(identity_t *ident)
{
    free(ident);
}
