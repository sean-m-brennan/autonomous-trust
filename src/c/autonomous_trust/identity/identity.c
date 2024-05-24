#include <stdbool.h>
#include <string.h>
#include <errno.h>

#include <uuid/uuid.h>
#include <sodium.h>

#include "../algorithms/algorithms.h"
#include "identity.h"

#include "hexlify.i"
#include "signature.i"
#include "encryptor.i"

struct identity_s
{
    uuid_t uuid;
    int rank;
    unsigned char *address;
    char *fullname;
    char *nickname;
    char *petname;
    signature_t signature;
    encryptor_t encryptor;
    bool public_only;
    block_impl_t block;
};

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

int identity_sign(const identity_t *ident, const message_t *in, message_t *out)
{
    return crypto_sign(out->msg, &out->len, in->msg, in->len, ident->signature.private);
}

int identity_verify(const identity_t *ident, const message_t *in, message_t *out)
{
    return crypto_sign_open(out->msg, &out->len, in->msg, in->len, ident->signature.public);
}

int identity_encrypt(const identity_t *ident, const message_t *in, const identity_t *whom, const unsigned char *nonce, unsigned char *cipher)
{
    return crypto_box_easy(cipher, in->msg, in->len, nonce, whom->encryptor.public, ident->encryptor.private);
}

int identity_decrypt(const identity_t *ident, const message_t *cipher, const identity_t *whom, const unsigned char *nonce, unsigned char *out)
{
    return crypto_box_open_easy(out, cipher->msg, cipher->len, nonce, whom->encryptor.public, ident->encryptor.private);
}

void identity_free(identity_t *ident) {
    free(ident);
}
