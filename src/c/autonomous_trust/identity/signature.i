#ifndef SIGNATURE_I
#define SIGNATURE_I

#include <stdbool.h>
#include <sodium.h>
#include "identity_priv.h"
#include "utilities/exception.h"
#include "hexlify.i"


void signature_init(signature_t *sig, const unsigned char *hex_seed, bool public_only) {
    if (public_only) {
        bzero(sig->private, crypto_sign_SECRETKEYBYTES);
        unhexlify(hex_seed, crypto_sign_PUBLICKEYBYTES * 2, (unsigned char*)sig->public);
    }
    else {
        unsigned char seed[crypto_sign_SEEDBYTES];
        unhexlify(hex_seed, crypto_sign_SEEDBYTES * 2, seed);
        crypto_sign_seed_keypair((unsigned char*)sig->public, (unsigned char*)sig->private, seed);
    }
    hexlify(sig->public, crypto_sign_PUBLICKEYBYTES, (unsigned char*)sig->public_hex);
}

unsigned char *signature_publish(const signature_t *sig) {
    unsigned char *hex = malloc(crypto_sign_PUBLICKEYBYTES * 2);
    if (hex == NULL) {
        EXCEPTION(ENOMEM);
        return NULL;
    }
    memcpy(hex, sig->public_hex, crypto_sign_PUBLICKEYBYTES * 2);
    return hex;
}

unsigned char *signature_generate() {
    unsigned char key[crypto_sign_SEEDBYTES];
    randombytes(key, crypto_sign_SEEDBYTES);
    unsigned char *hex = malloc(crypto_sign_SEEDBYTES * 2);
    if (hex == NULL) {
        EXCEPTION(ENOMEM);
        return NULL;
    }
    hexlify(key, crypto_sign_SEEDBYTES, hex);
    return hex;
}

#endif // SIGNATURE_I
