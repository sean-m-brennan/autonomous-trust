#ifndef SIGNATURE_I
#define SIGNATURE_I

#include <stdbool.h>
#include <sodium/crypto_sign.h>


typedef struct
{
    unsigned char private[crypto_sign_SECRETKEYBYTES];
    unsigned char public[crypto_sign_PUBLICKEYBYTES];
    unsigned char public_hex[crypto_sign_PUBLICKEYBYTES * 2];
} signature_t;

void signature_init(const signature_t *sig, const unsigned char *hex_seed, bool public_only) {
    if (public_only) {
        bzero((void*)sig->private, crypto_sign_SECRETKEYBYTES);
        unsigned char seed[crypto_sign_PUBLICKEYBYTES * 2];
        unhexlify(hex_seed, crypto_sign_PUBLICKEYBYTES * 2, seed);
        memcpy((void*)sig->public, seed, crypto_sign_PUBLICKEYBYTES);
    }
    else {
        unsigned char seed[crypto_sign_SEEDBYTES];
        unhexlify(hex_seed, crypto_sign_SEEDBYTES * 2, seed);
        crypto_sign_seed_keypair((unsigned char*)sig->public, (unsigned char*)sig->private, seed);
    }
    hexlify(sig->public, crypto_sign_PUBLICKEYBYTES, (unsigned char*)sig->public_hex);
    free((void*)hex_seed);
}

unsigned char *signature_publish(const signature_t *sig) {
    unsigned char *hex = (unsigned char*)malloc(crypto_sign_PUBLICKEYBYTES * 2);
    memcpy(hex, sig->public_hex, crypto_sign_PUBLICKEYBYTES * 2);
    return hex;
}

unsigned char *signature_generate() {
    unsigned char *key = (unsigned char*)malloc(crypto_sign_SEEDBYTES);
    randombytes(key, crypto_sign_SEEDBYTES);
    unsigned char *hex = (unsigned char*)malloc(crypto_sign_SEEDBYTES * 2);
    hexlify(key, crypto_sign_SEEDBYTES, hex);
    free((void*)key);
    return hex;
}

#endif // SIGNATURE_I
