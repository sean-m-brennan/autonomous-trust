#include <stdbool.h>
#include <string.h>
#include <errno.h>

#include <uuid/uuid.h>
#include <sodium.h>
#include <jansson.h>

#include "algorithms/algorithms.h"
#include "config/configuration.h"
#include "config/serialization.h"

#include "identity_priv.h"
#include "signature.i"
#include "encryptor.i"


int identity_create(unsigned char *address, identity_t **ident)
{ // FIXME address + 4 names
    if (sodium_init() < 0)
    {
        exit(-1); // FIXME logging?
    }
    *ident = calloc(1, sizeof(identity_t));
    identity_t *identity = *ident;
    if (identity == NULL)
        return ENOMEM;
    identity->address = address;
    signature_init(&(identity->signature), signature_generate(), identity->public_only);
    encryptor_init(&identity->encryptor, encryptor_generate(), identity->public_only);
    uuid_generate((unsigned char *)identity->uuid);
    return 0;
}

int identity_publish(const identity_t *ident, identity_t **pub_copy)
{
    if (ident == NULL)
        return EINVAL;
    *pub_copy = (identity_t *)malloc(sizeof(identity_t));
    identity_t *newIdent = *pub_copy;
    if (newIdent == NULL)
        return ENOMEM;
    memcpy(newIdent->uuid, ident->uuid, sizeof(uuid_t));
    newIdent->address = ident->address;
    newIdent->fullname = ident->fullname;
    newIdent->nickname = ident->nickname;
    newIdent->petname = ident->petname;
    newIdent->public_only = true;
    signature_init(&newIdent->signature, signature_publish(&ident->signature), true);
    encryptor_init(&newIdent->encryptor, signature_publish(&ident->signature), true);
    return 0;
}

int identity_sign(const identity_t *ident, const msg_str_t *in, msg_str_t *out)
{
    return crypto_sign(out->msg, &out->len, in->msg, in->len, ident->signature.private);
}

int identity_verify(const identity_t *ident, const msg_str_t *in, msg_str_t *out)
{
    return crypto_sign_open(out->msg, &out->len, in->msg, in->len, ident->signature.public);
}

int identity_encrypt(const identity_t *ident, const msg_str_t *in, const identity_t *whom, const unsigned char *nonce, unsigned char *cipher)
{
    return crypto_box_easy(cipher, in->msg, in->len, nonce, whom->encryptor.public, ident->encryptor.private);
}

int identity_decrypt(const identity_t *ident, const msg_str_t *cipher, const identity_t *whom, const unsigned char *nonce, unsigned char *out)
{
    return crypto_box_open_easy(out, cipher->msg, cipher->len, nonce, whom->encryptor.public, ident->encryptor.private);
}

int identity_to_json(const void *data_struct, json_t **obj_ptr)
{
    identity_t *ident = (identity_t*)data_struct;
    *obj_ptr = json_object();
    json_t *obj = *obj_ptr;
    if (obj == NULL)
        return ENOMEM;
    char uuid_str[37] = {0};
    uuid_unparse(ident->uuid, uuid_str);
    json_object_set(obj, "uuid", json_string(uuid_str));
    json_object_set(obj, "rank", json_integer(ident->rank));
    json_object_set(obj, "address", json_string((char*)ident->address));
    json_object_set(obj, "fullname", json_string(ident->fullname));
    json_object_set(obj, "nickname", json_string(ident->nickname));
    json_object_set(obj, "petname", json_string(ident->petname));
    json_object_set(obj, "public_only", json_boolean(ident->public_only));

    json_t *sig = json_object();
    unsigned char *hex = signature_publish(&ident->signature);
    json_object_set(sig, "hex_seed", json_string((char*)hex));
    free(hex);
    json_object_set(obj, "signature", sig);

    json_t *encr = json_object();
    hex = encryptor_publish(&ident->encryptor);
    json_object_set(encr, "hex_seed", json_string((char*)hex));
    free(hex);
    json_object_set(obj, "encryptor", encr);

    return 0;
}

int identity_from_json(const json_t *obj, void *data_struct)
{
    identity_t *ident = (identity_t*)data_struct;
    json_t *uuid_j = json_object_get(obj, "uuid");
    const char *uuid_str = json_string_value(uuid_j);
    int err = uuid_parse(uuid_str, ident->uuid);
    if (err < 0)
        return err;
    ident->rank = json_integer_value(json_object_get(obj, "rank"));
    ident->fullname = (char*)json_string_value(json_object_get(obj, "fullname"));
    ident->nickname = (char*)json_string_value(json_object_get(obj, "nickname"));
    ident->petname = (char*)json_string_value(json_object_get(obj, "petname"));
    ident->public_only = json_boolean_value(json_object_get(obj, "public_only"));
    uint8_t *seed = (uint8_t*)json_object_get(json_object_get(obj, "signature"), "hex_seed");
    signature_init(&ident->signature, seed, ident->public_only);
    seed = (uint8_t*)json_object_get(json_object_get(obj, "encryptor"), "hex_seed");
    encryptor_init(&ident->encryptor, seed, ident->public_only);
    return 0;
}

DECLARE_CONFIGURATION(identity, sizeof(identity_t), identity_to_json, identity_from_json);

void identity_free(identity_t *ident) {
    free(ident);
}
