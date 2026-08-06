/********************
 *  Copyright 2023 TekFive, Inc., Sean M. Brennan, and contributors
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
#include "utilities/b64.h"

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

    /* The opt-in guardian identity travels with the published copy, because this
       is the copy that becomes an outgoing announce — without it a C node could
       hold a binding and never advertise one. (operator_bound deliberately does
       NOT ride here: in C it crosses in the separate attestation payload. The
       guardian key rides in BOTH, for the same reason it must not be half
       present: a published identity naming no guardian while the attestation
       named one would be two answers to one question.)

       A node's OWN key needs no verification flag: it holds a binding because
       an operator signed one for it. */
    if (!at_operator_pubkey_empty(ident->operator_pubkey)
        && ident->operator_key_binding != NULL
        && ident->operator_key_binding_len > 0) {
        memcpy(newIdent->operator_pubkey, ident->operator_pubkey,
               sizeof(newIdent->operator_pubkey));
        newIdent->operator_key_binding = malloc(ident->operator_key_binding_len);
        if (newIdent->operator_key_binding == NULL)
            return EXCEPTION(ENOMEM);
        memcpy(newIdent->operator_key_binding, ident->operator_key_binding,
               ident->operator_key_binding_len);
        newIdent->operator_key_binding_len = ident->operator_key_binding_len;
    }

    return 0;
}

bool at_operator_pubkey_empty(const uint8_t pubkey[crypto_sign_PUBLICKEYBYTES])
{
    if (pubkey == NULL)
        return true;
    /* Not memcmp against a zero buffer: this is not a secret comparison, and an
       explicit loop keeps the "all-zero means absent" rule readable at the one
       place it is defined. */
    for (size_t i = 0; i < crypto_sign_PUBLICKEYBYTES; i++)
        if (pubkey[i] != 0)
            return false;
    return true;
}

int operator_binding_preimage(const public_identity_t *ident,
                              const uint8_t operator_pubkey[crypto_sign_PUBLICKEYBYTES],
                              uint8_t out[OPERATOR_BINDING_PREIMAGE_LEN])
{
    if (ident == NULL || operator_pubkey == NULL || out == NULL)
        return EINVAL;
    uint8_t *p = out;
    memcpy(p, OPERATOR_BINDING_TAG, OPERATOR_BINDING_TAG_LEN);
    p += OPERATOR_BINDING_TAG_LEN;
    memcpy(p, ident->uuid, UUID_LEN);
    p += UUID_LEN;
    memcpy(p, ident->signature.public, crypto_sign_PUBLICKEYBYTES);
    p += crypto_sign_PUBLICKEYBYTES;
    memcpy(p, operator_pubkey, crypto_sign_PUBLICKEYBYTES);
    return 0;
}

int zta_binding_preimage(const public_identity_t *ident,
                         const uint8_t *cred, size_t cred_len,
                         uint8_t out[ZTA_BINDING_PREIMAGE_LEN])
{
    if (ident == NULL || cred == NULL || cred_len == 0 || out == NULL)
        return EINVAL;
    uint8_t *p = out;
    memcpy(p, ZTA_BINDING_TAG, ZTA_BINDING_TAG_LEN);
    p += ZTA_BINDING_TAG_LEN;
    memcpy(p, ident->uuid, UUID_LEN);
    p += UUID_LEN;
    memcpy(p, ident->signature.public, crypto_sign_PUBLICKEYBYTES);
    p += crypto_sign_PUBLICKEYBYTES;
    /* Over the bytes we were handed, never the advertised hash. */
    crypto_hash_sha256(p, cred, cred_len);
    return 0;
}

#ifdef AT_ZTA_ENABLED
void public_identity_zta_credentials_clear(public_identity_t *ident)
{
    if (ident == NULL)
        return;
    for (size_t i = 0; i < ZTA_MAX_CREDENTIALS; i++) {
        free(ident->zta_credentials[i].der);
        free(ident->zta_credentials[i].binding);
    }
    memset(ident->zta_credentials, 0, sizeof(ident->zta_credentials));
    ident->num_zta_credentials = 0;
}

int public_identity_add_zta_credential(public_identity_t *ident,
                                       const uint8_t *der, size_t der_len,
                                       const uint8_t *binding, size_t binding_len,
                                       const char *issuer)
{
    if (ident == NULL || der == NULL || der_len == 0 || der_len > ZTA_CRED_MAX)
        return EINVAL;
    if (binding_len > ZTA_BINDING_MAX) {
        /* Refuse the oversized binding, keep the credential: the two are
           separately sourced, and dropping a good credential because someone
           padded its signature would turn a bounds check into a denial of
           service against the honest case. */
        binding = NULL;
        binding_len = 0;
    }
    uint8_t fp[crypto_hash_sha256_BYTES];
    crypto_hash_sha256(fp, der, der_len);
    for (size_t i = 0; i < ident->num_zta_credentials; i++) {
        zta_credential_t *e = &ident->zta_credentials[i];
        if (e->der == NULL || e->der_len != der_len)
            continue;
        uint8_t efp[crypto_hash_sha256_BYTES];
        crypto_hash_sha256(efp, e->der, e->der_len);
        if (memcmp(fp, efp, sizeof(fp)) != 0)
            continue;
        /* Same credential. Adopt a binding if this copy has one and the stored
           copy does not — the singular wire fields cannot carry one. */
        if (binding != NULL && binding_len > 0
            && (e->binding == NULL || e->binding_len == 0)) {
            uint8_t *b = malloc(binding_len);
            if (b != NULL) {
                memcpy(b, binding, binding_len);
                e->binding = b;
                e->binding_len = binding_len;
            }
        }
        if (e->issuer[0] == '\0' && issuer != NULL && issuer[0] != '\0')
            at_strlcpy(e->issuer, issuer, sizeof(e->issuer));
        return 0;
    }
    if (ident->num_zta_credentials >= ZTA_MAX_CREDENTIALS)
        return ENOSPC;
    zta_credential_t *slot = &ident->zta_credentials[ident->num_zta_credentials];
    memset(slot, 0, sizeof(*slot));
    slot->der = malloc(der_len);
    if (slot->der == NULL)
        return ENOMEM;
    memcpy(slot->der, der, der_len);
    slot->der_len = der_len;
    if (binding != NULL && binding_len > 0) {
        slot->binding = malloc(binding_len);
        if (slot->binding != NULL) {
            memcpy(slot->binding, binding, binding_len);
            slot->binding_len = binding_len;
        }
    }
    if (issuer != NULL)
        at_strlcpy(slot->issuer, issuer, sizeof(slot->issuer));
    ident->num_zta_credentials++;
    return 0;
}

void public_identity_add_zta_anchor(public_identity_t *ident, const char *name)
{
    if (ident == NULL || name == NULL || name[0] == '\0')
        return;
    for (size_t i = 0; i < ident->num_zta_anchors; i++)
        if (strcmp(ident->zta_anchors[i], name) == 0)
            return;
    if (ident->num_zta_anchors >= ZTA_MAX_ANCHORS)
        return;
    at_strlcpy(ident->zta_anchors[ident->num_zta_anchors], name,
               ZTA_ANCHOR_NAME_LEN);
    ident->num_zta_anchors++;
}

bool public_identity_has_zta_anchor(const public_identity_t *ident,
                                    const char *name)
{
    if (ident == NULL || name == NULL || name[0] == '\0')
        return false;
    for (size_t i = 0; i < ident->num_zta_anchors; i++)
        if (strcmp(ident->zta_anchors[i], name) == 0)
            return true;
    return false;
}
#endif /* AT_ZTA_ENABLED */

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

    /* Operator-attended signal + the ZTA binding that backs it (ethne D8/Q9).
       Emitted ONLY when non-default so a plain (non-operator) peer's canonical
       form is byte-identical to before (backward-compat), matching the Python
       public_identity_to_canonical omit-when-default rule. Bytes are base64
       (VARIANT_ORIGINAL == Python base64.b64encode). */
    if (p->operator_bound)
        json_object_set_new(obj, "operator_bound", json_true());
    if (p->operator_attested_at > 0.0)
        json_object_set_new(obj, "operator_attested_at",
                            json_real(p->operator_attested_at));
    /* The opt-in guardian identity. Emitted only when a key is actually bound,
       so a node that declines is byte-identical to one built before these fields
       existed — which is the whole of AT's side of the anonymity guarantee.
       Kept OUTSIDE the ZTA guard (like operator_bound) so the serialized form
       does not depend on a build flag. */
    if (!at_operator_pubkey_empty(p->operator_pubkey)) {
        size_t klen = b64_encoded_len(sizeof(p->operator_pubkey));
        char *kb64 = malloc(klen);
        if (kb64 == NULL) return ENOMEM;
        base64_encode(p->operator_pubkey, sizeof(p->operator_pubkey), kb64, klen);
        json_object_set_new(obj, "operator_pubkey", json_string(kb64));
        free(kb64);
    }
    if (p->operator_key_binding_len > 0 && p->operator_key_binding != NULL) {
        size_t blen = b64_encoded_len(p->operator_key_binding_len);
        char *bb64 = malloc(blen);
        if (bb64 == NULL) return ENOMEM;
        base64_encode(p->operator_key_binding, p->operator_key_binding_len,
                      bb64, blen);
        json_object_set_new(obj, "operator_key_binding", json_string(bb64));
        free(bb64);
    }
#ifdef AT_ZTA_ENABLED
    if (p->zta_issuer[0] != '\0')
        json_object_set_new(obj, "zta_issuer", json_string(p->zta_issuer));
    if (p->zta_credential_len > 0 && p->zta_credential != NULL) {
        size_t hlen = b64_encoded_len(sizeof(p->zta_credential_hash));
        char *hb64 = malloc(hlen);
        if (hb64 == NULL) return ENOMEM;
        base64_encode(p->zta_credential_hash, sizeof(p->zta_credential_hash),
                      hb64, hlen);
        json_object_set_new(obj, "zta_credential_hash", json_string(hb64));
        free(hb64);
        size_t clen = b64_encoded_len(p->zta_credential_len);
        char *cb64 = malloc(clen);
        if (cb64 == NULL) return ENOMEM;
        base64_encode(p->zta_credential, p->zta_credential_len, cb64, clen);
        json_object_set_new(obj, "zta_credential", json_string(cb64));
        free(cb64);
    }
#endif
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

    /* Operator-attended signal + ZTA binding (all optional; p was memset to 0
       above so absent keys default false/0/empty). Mirror of the encoder and of
       Python public_identity_from_canonical. */
    p->operator_bound = json_is_true(json_object_get(obj, "operator_bound"));
    json_t *oa = json_object_get(obj, "operator_attested_at");
    p->operator_attested_at = json_is_number(oa) ? json_number_value(oa) : 0.0;
    /* The opt-in guardian claim, imported as a CLAIM only: a key of the wrong
       length is dropped whole rather than zero-padded (a truncated ed25519 key
       is a different key). Verification has not happened yet: on a STORED peer a
       non-empty key means verified, and the admission gate is what zeroes an
       unverified claim. */
    const char *kb64 = json_string_value(json_object_get(obj, "operator_pubkey"));
    if (kb64 != NULL) {
        size_t declen = b64_decoded_len_s(strlen(kb64), kb64);
        if (declen == sizeof(p->operator_pubkey))
            base64_decode(kb64, strlen(kb64), p->operator_pubkey, declen);
    }
    const char *bb64 = json_string_value(json_object_get(obj, "operator_key_binding"));
    if (bb64 != NULL) {
        size_t declen = b64_decoded_len_s(strlen(bb64), bb64);
        if (declen > 0 && declen <= OPERATOR_BINDING_MAX) {
            p->operator_key_binding = malloc(declen);
            if (p->operator_key_binding != NULL) {
                base64_decode(bb64, strlen(bb64), p->operator_key_binding, declen);
                p->operator_key_binding_len = declen;
            }
        }
    }
#ifdef AT_ZTA_ENABLED
    const char *iss = json_string_value(json_object_get(obj, "zta_issuer"));
    if (iss != NULL)
        snprintf(p->zta_issuer, sizeof(p->zta_issuer), "%s", iss);
    const char *hb64 = json_string_value(json_object_get(obj, "zta_credential_hash"));
    if (hb64 != NULL)
        base64_decode(hb64, strlen(hb64),
                      p->zta_credential_hash, sizeof(p->zta_credential_hash));
    const char *cb64 = json_string_value(json_object_get(obj, "zta_credential"));
    if (cb64 != NULL) {
        size_t declen = b64_decoded_len_s(strlen(cb64), cb64);
        if (declen > 0 && declen <= ZTA_CRED_MAX) {
            p->zta_credential = malloc(declen);
            if (p->zta_credential != NULL) {
                base64_decode(cb64, strlen(cb64), p->zta_credential, declen);
                p->zta_credential_len = declen;
            }
        }
    }
#endif
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

    /* The node's OWN opt-in guardian identity, so it survives a restart. C never
       signs a binding — there is no PIV in C, by design (see
       doc/architecture/operator-attended.md) — so a fielded C node is given the
       pair here, produced once by the operator's own tooling against this node's
       uuid and signing key. Written only when present, so an unbound node's
       identity.cfg.json is unchanged. */
    if (!at_operator_pubkey_empty(ident->operator_pubkey)
        && ident->operator_key_binding != NULL
        && ident->operator_key_binding_len > 0) {
        size_t klen = b64_encoded_len(sizeof(ident->operator_pubkey));
        char *kb64 = malloc(klen);
        size_t blen = b64_encoded_len(ident->operator_key_binding_len);
        char *bb64 = malloc(blen);
        if (kb64 != NULL && bb64 != NULL) {
            base64_encode(ident->operator_pubkey, sizeof(ident->operator_pubkey),
                          kb64, klen);
            base64_encode(ident->operator_key_binding,
                          ident->operator_key_binding_len, bb64, blen);
            json_object_set_new(obj, "operator_pubkey", json_string(kb64));
            json_object_set_new(obj, "operator_key_binding", json_string(bb64));
        }
        free(kb64);
        free(bb64);
    }

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

    /* The node's own guardian pair, if an operator provisioned one. Both halves or
       neither: a key with no binding cannot be verified by any peer, so advertising
       it would only produce "does not verify" warnings across the cohort. A
       wrong-length key or an oversized binding is dropped the same way it is on the
       wire. */
    const char *okb64 = json_string_value(json_object_get(obj, "operator_pubkey"));
    const char *obb64 = json_string_value(
        json_object_get(obj, "operator_key_binding"));
    if (okb64 != NULL && obb64 != NULL) {
        size_t klen = b64_decoded_len_s(strlen(okb64), okb64);
        size_t blen = b64_decoded_len_s(strlen(obb64), obb64);
        if (klen == sizeof(ident->operator_pubkey)
            && blen > 0 && blen <= OPERATOR_BINDING_MAX) {
            uint8_t *binding = malloc(blen);
            if (binding != NULL) {
                base64_decode(okb64, strlen(okb64), ident->operator_pubkey, klen);
                base64_decode(obb64, strlen(obb64), binding, blen);
                free(ident->operator_key_binding);
                ident->operator_key_binding = binding;
                ident->operator_key_binding_len = blen;
            }
        }
    }
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

    /* Operator-attended signal (proto fields 12-13; parity with Python
       sync_to_message). Proto3 scalars are always present, so set them
       unconditionally (default false/0 round-trips cleanly). */
    proto->operator_bound = identity->operator_bound;
    proto->operator_attested_at = identity->operator_attested_at;

    /* The opt-in guardian identity (proto fields 14-15). Unlike the scalars
       above, these are set only when a key is bound: proto3 omits empty bytes,
       so a node that declines puts nothing on the wire at all — the wire form of
       the anonymity guarantee. Both travel or neither does; a key with no
       binding is unverifiable and a binding with no key names nothing. */
    if (!at_operator_pubkey_empty(identity->operator_pubkey)
        && identity->operator_key_binding != NULL
        && identity->operator_key_binding_len > 0) {
        proto->operator_pubkey.data = identity->operator_pubkey;
        proto->operator_pubkey.len = sizeof(identity->operator_pubkey);
        proto->operator_key_binding.data = identity->operator_key_binding;
        proto->operator_key_binding.len = identity->operator_key_binding_len;
    }

#ifdef AT_ZTA_ENABLED
    if (identity->zta_credential_len > 0 && identity->zta_credential != NULL) {
        proto->zta_credential_hash.data = identity->zta_credential_hash;
        proto->zta_credential_hash.len = sizeof(identity->zta_credential_hash);
        proto->zta_issuer = identity->zta_issuer;
        proto->zta_credential.data = identity->zta_credential;
        proto->zta_credential.len = identity->zta_credential_len;
    }
    /* The full credential set (field 16). Unlike every other field here this one
       ALLOCATES — protobuf-c models a repeated message as an array of pointers,
       so there is nothing on the identity to borrow. public_identity_proto_free
       releases it, which is why that function already exists. The credential
       BYTES are still borrowed; only the little wrappers are ours. */
    if (identity->num_zta_credentials > 0) {
        size_t n = identity->num_zta_credentials;
        proto->zta_credentials = calloc(n, sizeof(*proto->zta_credentials));
        if (proto->zta_credentials != NULL) {
            size_t emitted = 0;
            for (size_t i = 0; i < n; i++) {
                const zta_credential_t *c = &identity->zta_credentials[i];
                if (c->der == NULL || c->der_len == 0)
                    continue;
                AutonomousTrust__Core__Protobuf__Identity__ZtaCredential *pc =
                    malloc(sizeof(*pc));
                if (pc == NULL)
                    break;
                autonomous_trust__core__protobuf__identity__zta_credential__init(pc);
                pc->der.data = c->der;
                pc->der.len = c->der_len;
                if (c->binding != NULL && c->binding_len > 0) {
                    pc->binding.data = c->binding;
                    pc->binding.len = c->binding_len;
                }
                pc->issuer = (char *)c->issuer;
                proto->zta_credentials[emitted++] = pc;
            }
            proto->n_zta_credentials = emitted;
            if (emitted == 0) {
                free(proto->zta_credentials);
                proto->zta_credentials = NULL;
            }
        }
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

    /* Operator-attended signal (proto fields 12-13); parity with Python
       sync_from_message. */
    identity->operator_bound = proto->operator_bound;
    identity->operator_attested_at = proto->operator_attested_at;

    /* The guardian claim (proto fields 14-15), imported as a CLAIM. Wrong-length
       key: dropped whole, never truncated into a different key. Oversized
       binding: rejected outright, like an oversized credential. Verification is
       our receiver's job and has not happened yet. */
    memset(identity->operator_pubkey, 0, sizeof(identity->operator_pubkey));
    identity->operator_key_binding = NULL;
    identity->operator_key_binding_len = 0;
    if (proto->operator_pubkey.len == sizeof(identity->operator_pubkey)
        && proto->operator_pubkey.data != NULL)
        memcpy(identity->operator_pubkey, proto->operator_pubkey.data,
               sizeof(identity->operator_pubkey));
    if (proto->operator_key_binding.len > 0
        && proto->operator_key_binding.data != NULL) {
        if (proto->operator_key_binding.len > OPERATOR_BINDING_MAX)
            return EXCEPTION(EINVAL);
        identity->operator_key_binding = malloc(proto->operator_key_binding.len);
        if (identity->operator_key_binding) {
            memcpy(identity->operator_key_binding,
                   proto->operator_key_binding.data,
                   proto->operator_key_binding.len);
            identity->operator_key_binding_len = proto->operator_key_binding.len;
        }
    }

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

    /* The credential LIST (field 16). Seeded with the primary first so a peer
       predating field 16 still yields a one-entry list and the admission gate has
       a single shape to iterate — and so the primary keeps its slot when the
       repeated field also carries it. add_zta_credential dedups by fingerprint
       and adopts the field-16 copy's binding onto the primary, which matters
       because fields 6-8 have nowhere to carry one.

       Note the asymmetry with the singular field above: an oversized entry HERE
       is skipped rather than failing the whole deserialization. One bad element
       in a list should not discard the peer's good credentials; an oversized
       singular credential is the peer's only one, so there is nothing to salvage.

       ZEROED, NOT FREED, deliberately: the lines above drop `zta_credential` by
       assigning NULL rather than freeing it, so this function's standing contract
       is that the target identity is fresh. Freeing here would honor a contract
       that does not exist and would free garbage on an uninitialized struct. A
       caller REUSING an identity must call public_identity_zta_credentials_clear
       first — the same obligation it already has for the singular field. */
    memset(identity->zta_credentials, 0, sizeof(identity->zta_credentials));
    identity->num_zta_credentials = 0;
    if (identity->zta_credential != NULL && identity->zta_credential_len > 0)
        public_identity_add_zta_credential(identity, identity->zta_credential,
                                           identity->zta_credential_len,
                                           NULL, 0, identity->zta_issuer);
    for (size_t i = 0; i < proto->n_zta_credentials; i++) {
        const AutonomousTrust__Core__Protobuf__Identity__ZtaCredential *pc =
            proto->zta_credentials[i];
        if (pc == NULL || pc->der.data == NULL || pc->der.len == 0
            || pc->der.len > ZTA_CRED_MAX)
            continue;
        public_identity_add_zta_credential(identity, pc->der.data, pc->der.len,
                                           pc->binding.data, pc->binding.len,
                                           pc->issuer);
    }
    /* Anchors are OUR finding about this peer, never theirs about themselves:
       a fresh deserialization has proved nothing yet. */
    memset(identity->zta_anchors, 0, sizeof(identity->zta_anchors));
    identity->num_zta_anchors = 0;
#endif

    return 0;
}

void public_identity_proto_free(AutonomousTrust__Core__Protobuf__Identity__Identity *proto)
{
    free(proto->signature);
    free(proto->encryptor);
#ifdef AT_ZTA_ENABLED
    /* Only the wrappers sync_out allocated; their `der`/`binding` point into the
       identity and are not ours to free. */
    for (size_t i = 0; i < proto->n_zta_credentials; i++)
        free(proto->zta_credentials[i]);
    free(proto->zta_credentials);
    proto->zta_credentials = NULL;
    proto->n_zta_credentials = 0;
#endif
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
