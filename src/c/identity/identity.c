#include <stdbool.h>
#include <uuid.h>
#include <sodium.h>

#include "algorithms/algorithms.h"
#include "identity.h"


void hexlify(unsigned char *buf, size_t len, unsigned char *result) {
    const char *hexdigits = "0123456789abcdef";
    size_t rlen = len * 2;
    size_t i, j;
    unsigned char c;
    for (i = j = 0; i < len; ++i) {
        assert((j + 1) < rlen);
        c = buf[i];
        result[j++] = hexdigits[c >> 4];
        result[j++] = hexdigits[c & 0x0f];
    }
    assert(j == rlen);
    return result;
}

void unhexlify(unsigned char *buf, size_t len, unsigned char *result) {
    unsigned char digitvalue[256] = {
        37, 37, 37, 37, 37, 37, 37, 37, 37, 37, 37, 37, 37, 37, 37, 37,
        37, 37, 37, 37, 37, 37, 37, 37, 37, 37, 37, 37, 37, 37, 37, 37,
        37, 37, 37, 37, 37, 37, 37, 37, 37, 37, 37, 37, 37, 37, 37, 37,
        0,  1,  2,  3,  4,  5,  6,  7,  8,  9,  37, 37, 37, 37, 37, 37,
        37, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24,
        25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 37, 37, 37, 37, 37,
        37, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24,
        25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 37, 37, 37, 37, 37,
        37, 37, 37, 37, 37, 37, 37, 37, 37, 37, 37, 37, 37, 37, 37, 37,
        37, 37, 37, 37, 37, 37, 37, 37, 37, 37, 37, 37, 37, 37, 37, 37,
        37, 37, 37, 37, 37, 37, 37, 37, 37, 37, 37, 37, 37, 37, 37, 37,
        37, 37, 37, 37, 37, 37, 37, 37, 37, 37, 37, 37, 37, 37, 37, 37,
        37, 37, 37, 37, 37, 37, 37, 37, 37, 37, 37, 37, 37, 37, 37, 37,
        37, 37, 37, 37, 37, 37, 37, 37, 37, 37, 37, 37, 37, 37, 37, 37,
        37, 37, 37, 37, 37, 37, 37, 37, 37, 37, 37, 37, 37, 37, 37, 37,
        37, 37, 37, 37, 37, 37, 37, 37, 37, 37, 37, 37, 37, 37, 37, 37,
    };
    size_t rlen = len / 2;
    size_t i, j;
    for (i=j=0; i < len; i += 2) {
        unsigned int top = digitvalue[buf[i]];
        unsigned int bot = digitvalue[buf[i+1]];
        if (top >= 16 || bot >= 16) {
            // FIXME error "Non-hexadecimal digit found"
        }
        result[j++] = (top << 4) + bot;
    }
    return result;
}



typedef struct
{
    unsigned char private[crypto_sign_SECRETKEYBYTES];
    unsigned char public[crypto_sign_PUBLICKEYBYTES];
    unsigned char public_hex[crypto_sign_PUBLICKEYBYTES * 2];
} signature_t;

void signature_init(signature_t *sig, unsigned char *hex_seed, bool public_only) {
    if (public_only) {
        bzero(sig->private, crypto_sign_SECRETKEYBYTES);
        unsigned char seed[crypto_sign_PUBLICKEYBYTES * 2];
        unhexlify(hex_seed, crypto_sign_PUBLICKEYBYTES * 2, seed);
        memcpy(sig->public, seed, crypto_sign_PUBLICKEYBYTES);
    }
    else {
        unsigned char seed[crypto_sign_SEEDBYTES];
        unhexlify(hex_seed, crypto_sign_SEEDBYTES * 2, seed);
        crypto_sign_seed_keypair(sig->public, sig->private, seed);
    }
    hexlify(sig->public, crypto_sign_PUBLICKEYBYTES, sig->public_hex);
    free(hex_seed);
}

unsigned char *signature_publish(signature_t *sig) {
    unsigned char *hex = (unsigned char*)malloc(crypto_sign_PUBLICKEYBYTES * 2);
    memcpy(hex, sig->public_hex, crypto_sign_PUBLICKEYBYTES * 2);
    return hex;
}

unsigned char *signature_generate() {
    unsigned char *key = (unsigned char*)malloc(crypto_sign_SEEDBYTES);
    randombytes(key, crypto_sign_SEEDBYTES);
    unsigned char hex = (unsigned char*)malloc(crypto_sign_SEEDBYTES * 2);
    hexlify(key, crypto_sign_SEEDBYTES, hex);
    free(key);
    return hex;
}



typedef struct
{
    unsigned char private[crypto_box_SECRETKEYBYTES];
    unsigned char public[crypto_box_PUBLICKEYBYTES];
    unsigned char public_hex[crypto_box_PUBLICKEYBYTES * 2];
} encryptor_t;

void encryptor_init(encryptor_t *encr, unsigned char *hex_seed, bool public_only) {
    if (public_only) {
        bzero(encr->private, crypto_box_SECRETKEYBYTES);
        unsigned char seed[crypto_box_PUBLICKEYBYTES * 2];
        unhexlify(hex_seed, crypto_box_PUBLICKEYBYTES * 2, seed);
        memcpy(encr->public, seed, crypto_box_PUBLICKEYBYTES);
    }
    else {
        unsigned char seed[crypto_sign_SEEDBYTES];
        unhexlify(hex_seed, crypto_box_SEEDBYTES * 2, seed);
        crypto_box_seed_keypair(encr->public, encr->private, seed);
    }
    hexlify(encr->public, crypto_box_PUBLICKEYBYTES, encr->public_hex);
    free(hex_seed);
}

unsigned char *encryptor_publish(encryptor_t *encr) {
    unsigned char *hex = (unsigned char*)malloc(crypto_box_PUBLICKEYBYTES * 2);
    memcpy(hex, encr->public_hex, crypto_box_PUBLICKEYBYTES * 2);
    return hex;
}

unsigned char *encryptor_generate() {
     unsigned char *key = (unsigned char*)malloc(crypto_box_SEEDBYTES);
    randombytes(key, crypto_box_SEEDBYTES);
    unsigned char hex = (unsigned char*)malloc(crypto_box_SEEDBYTES * 2);
    hexlify(key, crypto_box_SEEDBYTES, hex);
    free(key);
    return hex;
}


struct identityStruct
{
    uuid_t uuid;
    int rank;
    char *address;
    char *fullname;
    char *nickname;
    signature_t signature;
    encryptor_t encryptor;
    char *petname;
    bool public_only;
    block_impl_t block;
};

void identity_init(identity_t * ident) {  // FIXME address + 4 names
    if (sodium_init() < 0)
        exit(-1);  // FIXME logging?
    signature_init(&(ident->signature), singature_generate(), ident->public_only);
    encryptor_init(&ident->encryptor, encryptor_generate(), ident->public_only);
    uuid_generate(ident->uuid);
}

identity_t *identity_publish(identity_t *ident) {
    identity_t *newIdent = (identity_t*)malloc(sizeof(identity_t));
    if (newIdent == NULL)
        return NULL;
    if (ident == NULL)
        return NULL;
    else {
        memcpy(newIdent->uuid, ident->uuid, sizeof(uuid_t));
        newIdent->address = ident->address;
        newIdent->fullname = ident->fullname;
        newIdent->nickname = ident->nickname;
        newIdent->petname = ident->petname;
        newIdent->public_only = true;
        signature_init(&newIdent->signature, signature_publish(&ident->signature), true);
        encryptor_init(&newIdent->encryptor, signature_publish(&ident->signature), true);
    }
}

int identity_sign(identity_t *ident, const message_t *in, message_t *out) {
    return crypto_sign(out->msg, &out->len, in->msg, in->len, ident->signature.private);
}

int identity_verify(identity_t *ident, const message_t *in, message_t *out) {
    return crypto_sign_open(out->msg, &out->len, in->msg, in->len, ident->signature.public);
}

int identity_encrypt(identity_t *ident, const message_t *in, identity_t *whom, unsigned char *nonce, unsigned char *cipher) {
    return crypto_box_easy(cipher, in->msg, in->len, nonce, whom->encryptor.public, ident->encryptor.private);
}

int identity_decrypt(identity_t *ident, const message_t *cipher, identity_t *whom, unsigned char *nonce, unsigned char *out) {
    return crypto_box_open_easy(out, cipher->msg, cipher->len, nonce, whom->encryptor.public, ident->encryptor.private);
}

