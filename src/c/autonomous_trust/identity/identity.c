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

#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>

#include <uuid/uuid.h>
#include <sodium.h>
#include <jansson.h>

#include "algorithms/algorithms.h"
#include "config/configuration.h"
#include "utilities/exception.h"
#include "utilities/util.h"

#include "identity_priv.h"

static size_t _max_peers = DEFAULT_MAX_PEERS;

size_t peers_max_count(void)
{
    return _max_peers;
}

void peers_set_max_count(size_t count)
{
    if (count > 0 && count <= DEFAULT_MAX_PEERS)
        _max_peers = count;
}


/* Mint a LOCAL, arbitrary Zooko petname for a *received* identity.
 *
 * petname is local-only and never carried on the wire (see
 * public_identity_from_json / public_identity_sync_in), so a receiver must
 * assign its own when it learns a peer. We seed it from the online nickname's
 * local-part (the text before '@') for human readability, then append a random
 * suffix so the result is locally-unique and -- deliberately -- NOT equal to
 * any global identifier. Nothing may depend on a peer's petname matching its
 * roster/online name; peer matching keys off the online nickname. Mirrors
 * Python Identity.derive_local_petname. */
static void derive_local_petname(const char *nickname, char *out, size_t outlen)
{
    char local[NAME_LEN + 1] = {0};
    size_t n = 0;
    size_t cap = (NAME_LEN > 6) ? (NAME_LEN - 6) : 0;  /* room for "-NNNN" */
    if (nickname != NULL) {
        for (; n < cap && nickname[n] != '\0' && nickname[n] != '@'; n++)
            local[n] = nickname[n];
    }
    local[n] = '\0';
    if (n == 0)
        snprintf(local, sizeof(local), "peer");
    snprintf(out, outlen, "%s-%04u", local,
             (unsigned)randombytes_uniform(10000));
}


/* Frama-C: skipped — [solver-timeout] complex multi-step initialization */
int identity_init(uuid_t *uuid, const char *address, const char *nickname,
                  const char *petname, identity_t *identity)
{
    if (uuid == NULL)
        uuid_generate((unsigned char *)identity->uuid);
    else
        memcpy(&identity->uuid, uuid, sizeof(uuid_t));

    strncpy(identity->address, address, ADDR_LEN);
    strncpy(identity->nickname, nickname, NAME_LEN);
    strncpy(identity->petname, petname ? petname : "", NAME_LEN);

    unsigned char *sseed = signature_generate();
    if (sseed == NULL)
        return -1;
    int rc = signature_init(&(identity->signature), sseed, crypto_sign_SEEDBYTES * 2);
    free(sseed);
    if (rc != 0)
        return -1;

    unsigned char *eseed = encryptor_generate();
    if (eseed == NULL)
        return -1;
    rc = encryptor_init(&identity->encryptor, eseed, crypto_box_SEEDBYTES * 2);
    free(eseed);
    if (rc != 0)
        return -1;

    return 0;
}

/* Frama-C: skipped — [solver-timeout] smrt_ptr allocation postconditions */
int identity_create(uuid_t *uuid, const char *address, const char *nickname,
                    const char *petname, identity_t **ident)
{
    /* WHY we call sodium_init() here rather than from a one-shot bootstrap:
     *
     * libsodium's sodium_init() is documented as idempotent and thread-safe:
     * calling it repeatedly returns 1 (already initialized) after the first
     * successful call, and concurrent callers are serialized internally.
     * See https://libsodium.gitbook.io/doc/usage — "it is safe to call
     * sodium_init() multiple times, or from different threads".
     *
     * We therefore do not keep a library-wide `at_init()` function: every
     * entry point that needs crypto just calls sodium_init() defensively.
     * This avoids bootstrap ordering bugs when the library is embedded in
     * an application that does not know about AT's crypto dependency, and
     * keeps each public function self-sufficient.
     *
     * A negative return here means libsodium failed to seed its RNG (no
     * /dev/urandom, no getrandom, no CPU RDRAND) — unrecoverable; bail. */
    if (sodium_init() < 0)
    {
        // sodium_init() failed: libsodium could not be initialized
        return -1;
    }
    *ident = smrt_create(sizeof(identity_t));
    identity_t *identity = *ident;
    if (identity == NULL)
        return EXCEPTION(ENOMEM);

    return identity_init(uuid, address, nickname, petname, identity);
}

/* Frama-C: skipped — [solver-timeout] libsodium + hexlify preconditions */
int identity_publish(const identity_t *ident, public_identity_t **pub_copy)
{
    if (ident == NULL)
        return EINVAL;
    *pub_copy = smrt_create(sizeof(public_identity_t));
    public_identity_t *newIdent = *pub_copy;
    if (newIdent == NULL)
        return EXCEPTION(ENOMEM);

    memcpy(newIdent->uuid, ident->uuid, sizeof(uuid_t));
    strncpy(newIdent->address, ident->address, ADDR_LEN);
    newIdent->address[ADDR_LEN] = '\0';
    strncpy(newIdent->nickname, ident->nickname, NAME_LEN);
    newIdent->nickname[NAME_LEN] = '\0';
    strncpy(newIdent->petname, ident->petname, NAME_LEN);
    newIdent->petname[NAME_LEN] = '\0';

    unsigned char *sseed = signature_publish(&ident->signature);
    if (sseed == NULL)
        return -1;
    int rc = public_signature_init(&newIdent->signature, sseed,
                                    crypto_sign_PUBLICKEYBYTES * 2);
    free(sseed);
    if (rc != 0)
        return -1;
    unsigned char *eseed = encryptor_publish(&ident->encryptor);
    if (eseed == NULL)
        return -1;
    rc = public_encryptor_init(&newIdent->encryptor, eseed,
                                crypto_box_PUBLICKEYBYTES * 2);
    free(eseed);
    if (rc != 0)
        return -1;

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

/* Frama-C: skipped — [solver-timeout] libsodium decrypt preconditions */
int identity_decrypt(const identity_t *ident, const msg_str_t *cipher, const public_identity_t *whom, const unsigned char *nonce, unsigned char *out)
{
    return crypto_box_open_easy(out, cipher->msg, cipher->len, nonce, whom->encryptor.public, ident->encryptor.private);
}

/* Frama-C: skipped — [serialization] jansson JSON serialization */
/* Public-only identity serializer for wire payloads. Matches the
 * subset of identity_to_json that's safe to publish — same field shape
 * minus the locally-meaningful `rank` (which lives on `identity_t` past
 * the public_identity_t prefix). Used by id_proc.c when building the
 * peer-bundle inside the ID_HISTORY wire payload. */
int public_identity_to_json(const public_identity_t *p, json_t **obj_ptr)
{
    if (p == NULL || obj_ptr == NULL)
        return EINVAL;
    *obj_ptr = json_object();
    json_t *obj = *obj_ptr;
    if (obj == NULL)
        return ENOMEM;

    json_object_set_new(obj, "typename", json_string("identity"));
    char uuid_str[UUID_STRING_LEN + 1] = {0};
    uuid_unparse(p->uuid, uuid_str);
    json_object_set_new(obj, "uuid", json_string(uuid_str));
    json_object_set_new(obj, "address", json_string((const char *)p->address));
    json_object_set_new(obj, "nickname", json_string(p->nickname));
    /* petname is a Zooko local name: never emitted on the wire. Must match
       Python public_identity_to_canonical (identity.py), which also omits it,
       so the cross-runtime canonical form stays byte-identical. */

    json_t *sig = json_object();
    if (sig == NULL) return ENOMEM;
    unsigned char *hex = signature_publish(&p->signature);
    json_object_set_new(sig, "hex_seed", json_string((char *)hex));
    free(hex);
    json_object_set_new(obj, "signature", sig);

    json_t *encr = json_object();
    if (encr == NULL) return ENOMEM;
    hex = encryptor_publish(&p->encryptor);
    json_object_set_new(encr, "hex_seed", json_string((char *)hex));
    free(hex);
    json_object_set_new(obj, "encryptor", encr);
    return 0;
}

int public_identity_from_json(const json_t *obj, public_identity_t *p)
{
    if (obj == NULL || p == NULL)
        return EINVAL;
    memset(p, 0, sizeof(*p));
    const char *uuid_str = json_string_value(json_object_get(obj, "uuid"));
    if (uuid_str == NULL || uuid_parse(uuid_str, p->uuid) < 0)
        return -1;
    const char *s;
    if ((s = json_string_value(json_object_get(obj, "address"))) != NULL)
        strncpy(p->address, s, ADDR_LEN);
    if ((s = json_string_value(json_object_get(obj, "nickname"))) != NULL)
        strncpy(p->nickname, s, NAME_LEN);
    /* petname is local-only; never imported from the wire form (so a
       legacy/crafted key can't inject into local naming). The receiver mints
       its own local petname -- mirrors Python from_canonical. */
    derive_local_petname(p->nickname, p->petname, sizeof(p->petname));

    const char *sig_hex = json_string_value(
        json_object_get(json_object_get(obj, "signature"), "hex_seed"));
    if (sig_hex != NULL &&
        public_signature_init(&p->signature,
                              (const unsigned char *)sig_hex,
                              strlen(sig_hex)) != 0)
        return -1;
    const char *enc_hex = json_string_value(
        json_object_get(json_object_get(obj, "encryptor"), "hex_seed"));
    if (enc_hex != NULL &&
        public_encryptor_init(&p->encryptor,
                              (const unsigned char *)enc_hex,
                              strlen(enc_hex)) != 0)
        return -1;
    return 0;
}

int identity_to_json(const void *data_struct, json_t **obj_ptr)
{
    const identity_t *ident = data_struct;
    *obj_ptr = json_object();
    json_t *obj = *obj_ptr;
    if (obj == NULL)
        return EXCEPTION(ENOMEM);

    int err = json_object_set_new(obj, "typename", json_string("identity"));
    if (err != 0)
        return EXCEPTION(EJSN_OBJ_SET);

    char uuid_str[UUID_STRING_LEN+1] = {0};
    uuid_unparse(ident->uuid, uuid_str);
    json_object_set_new(obj, "uuid", json_string(uuid_str));
    json_object_set_new(obj, "rank", json_integer(ident->rank));
    json_object_set_new(obj, "address", json_string((char *)ident->address));
    json_object_set_new(obj, "nickname", json_string(ident->nickname));
    json_object_set_new(obj, "petname", json_string(ident->petname));

    json_t *sig = json_object();
    if (sig == NULL)
        return EXCEPTION(ENOMEM);
    unsigned char *hex = signature_publish(&ident->signature); // encoded
    json_object_set_new(sig, "hex_seed", json_string((char *)hex));
    free(hex);
    json_object_set_new(obj, "signature", sig);

    json_t *encr = json_object();
    if (encr == NULL)
        return EXCEPTION(ENOMEM);
    hex = encryptor_publish(&ident->encryptor); // encoded
    json_object_set_new(encr, "hex_seed", json_string((char *)hex));
    free(hex);
    json_object_set_new(obj, "encryptor", encr);

    return 0;
}

/* Frama-C: skipped — [serialization] jansson JSON deserialization */
int identity_from_json(const json_t *obj, void *data_struct)
{
    identity_t *ident = data_struct;
    json_t *uuid_obj = json_object_get(obj, "uuid");
    const char *uuid_str = json_string_value(uuid_obj);
    if (uuid_str == NULL || uuid_parse(uuid_str, ident->uuid) < 0)
        return -1;
    ident->rank = json_integer_value(json_object_get(obj, "rank"));
    const char *addr_str = json_string_value(json_object_get(obj, "address"));
    if (addr_str != NULL)
        strncpy(ident->address, addr_str, sizeof(ident->address)-1);
    const char *nickname_str = json_string_value(json_object_get(obj, "nickname"));
    if (nickname_str != NULL)
        strncpy(ident->nickname, nickname_str, sizeof(ident->nickname)-1);
    const char *petname_str = json_string_value(json_object_get(obj, "petname"));
    if (petname_str != NULL)
        strncpy(ident->petname, petname_str, sizeof(ident->petname)-1);
    const char *sig_hex = json_string_value(json_object_get(json_object_get(obj, "signature"), "hex_seed"));
    if (sig_hex != NULL
        && signature_init(&ident->signature,
                          (const unsigned char *)sig_hex, strlen(sig_hex)) != 0)
        return -1;
    const char *enc_hex = json_string_value(json_object_get(json_object_get(obj, "encryptor"), "hex_seed"));
    if (enc_hex != NULL
        && encryptor_init(&ident->encryptor,
                          (const unsigned char *)enc_hex, strlen(enc_hex)) != 0)
        return -1;
    return 0;
}

DECLARE_CONFIGURATION(identity, sizeof(identity_t), identity_to_json, identity_from_json);

/* Frama-C: skipped — [serialization] protobuf serialization */
int public_identity_sync_out(public_identity_t *identity, AutonomousTrust__Core__Protobuf__Identity__Identity *proto)
{
    AutonomousTrust__Core__Protobuf__Identity__Identity tmp = AUTONOMOUS_TRUST__CORE__PROTOBUF__IDENTITY__IDENTITY__INIT;
    memcpy(proto, &tmp, sizeof(tmp)); // dumb initialization workaround
    proto->uuid.data = identity->uuid;
    proto->uuid.len = sizeof(uuid_t);
    proto->address = identity->address;
    proto->nickname = identity->nickname;
    /* petname is a Zooko local name: never serialized. Leaving the proto field
       unset keeps it off the wire (proto3 omits empty), matching the Python
       twin (identity.py sync_to_message never sets it). */

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

#ifdef AT_ZTA_ENABLED
    if (identity->zta_credential_len > 0 && identity->zta_credential != NULL) {
        proto->zta_credential_hash.data = identity->zta_credential_hash;
        proto->zta_credential_hash.len = sizeof(identity->zta_credential_hash);
        proto->zta_issuer = identity->zta_issuer;
        proto->zta_credential.data = identity->zta_credential;
        proto->zta_credential.len = identity->zta_credential_len;
    }
#endif

    return 0;
}

/* Frama-C: skipped — [serialization] protobuf deserialization */
int public_identity_sync_in(AutonomousTrust__Core__Protobuf__Identity__Identity *proto, public_identity_t *identity)
{
    memcpy(&identity->uuid, proto->uuid.data, sizeof(uuid_t));
    strncpy(identity->address, proto->address, ADDR_LEN);
    strncpy(identity->nickname, proto->nickname, NAME_LEN);
    /* petname is a local-only Zooko name; never imported from the wire (so a
       crafted proto field 10 can't inject into local naming). The receiver
       mints its own -- mirrors Python sync_from_message. */
    derive_local_petname(identity->nickname, identity->petname,
                         sizeof(identity->petname));
    if (public_signature_init(&identity->signature, proto->signature->hex_seed.data,
                              proto->signature->hex_seed.len) != 0)
        return -1;
    if (public_encryptor_init(&identity->encryptor, proto->encryptor->hex_seed.data,
                              proto->encryptor->hex_seed.len) != 0)
        return -1;

#ifdef AT_ZTA_ENABLED
    memset(identity->zta_credential_hash, 0, sizeof(identity->zta_credential_hash));
    identity->zta_issuer[0] = '\0';
    identity->zta_credential = NULL;
    identity->zta_credential_len = 0;

    if (proto->zta_credential_hash.len > 0 && proto->zta_credential_hash.data != NULL) {
        size_t copy_len = proto->zta_credential_hash.len;
        if (copy_len > sizeof(identity->zta_credential_hash))
            copy_len = sizeof(identity->zta_credential_hash);
        memcpy(identity->zta_credential_hash, proto->zta_credential_hash.data, copy_len);
    }
    if (proto->zta_issuer != NULL)
        snprintf(identity->zta_issuer, sizeof(identity->zta_issuer), "%s", proto->zta_issuer);
    if (proto->zta_credential.len > 0 && proto->zta_credential.data != NULL) {
        if (proto->zta_credential.len > ZTA_CRED_MAX)
            return EXCEPTION(EINVAL);
        identity->zta_credential = malloc(proto->zta_credential.len);
        if (identity->zta_credential) {
            memcpy(identity->zta_credential, proto->zta_credential.data, proto->zta_credential.len);
            identity->zta_credential_len = proto->zta_credential.len;
        }
    }
#endif

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
    *data_ptr = smrt_create(*data_len_ptr);
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
    if (msg == NULL)
        return -1;
    public_identity_sync_in(msg, peer);
    autonomous_trust__core__protobuf__identity__identity__free_unpacked(msg, NULL);
    return 0;
}

/* Frama-C: skipped —
 * [solver-timeout] identity lifecycle + serialization: smrt_ptr allocation
 * postconditions, JSON/protobuf encode/decode, libsodium decrypt preconditions
 * identity_free: 4x sodium_memzero accumulates state; smrt_deref precondition times out
 * (9 warnings)
 */
void identity_free(identity_t *ident)
{
    if (ident == NULL)
        return;
    /* Zero sensitive key material before releasing memory */
    sodium_memzero(ident->signature.private, sizeof(ident->signature.private));
    sodium_memzero(ident->signature.public, sizeof(ident->signature.public));
    sodium_memzero(ident->encryptor.private, sizeof(ident->encryptor.private));
    sodium_memzero(ident->encryptor.public, sizeof(ident->encryptor.public));
    smrt_deref(ident);
}
