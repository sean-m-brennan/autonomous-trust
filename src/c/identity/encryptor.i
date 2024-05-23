#ifndef ENCRYPTOR_I
#define ENCRYPTOR_I

#include <stdbool.h>
#include <sodium/crypto_box.h>


typedef struct
{
    unsigned char private[crypto_box_SECRETKEYBYTES];
    unsigned char public[crypto_box_PUBLICKEYBYTES];
    unsigned char public_hex[crypto_box_PUBLICKEYBYTES * 2];
} encryptor_t;

void encryptor_init(const encryptor_t *encr, const unsigned char *hex_seed, bool public_only) {
    if (public_only) {
        bzero((void*)encr->private, crypto_box_SECRETKEYBYTES);
        unsigned char seed[crypto_box_PUBLICKEYBYTES * 2];
        unhexlify(hex_seed, crypto_box_PUBLICKEYBYTES * 2, seed);
        memcpy((void*)encr->public, seed, crypto_box_PUBLICKEYBYTES);
    }
    else {
        unsigned char seed[crypto_box_SEEDBYTES];
        unhexlify(hex_seed, crypto_box_SEEDBYTES * 2, seed);
        crypto_box_seed_keypair((unsigned char*)encr->public, (unsigned char*)encr->private, seed);
    }
    hexlify(encr->public, crypto_box_PUBLICKEYBYTES, (unsigned char*)encr->public_hex);
    free((void*)hex_seed);
}

unsigned char *encryptor_publish(const encryptor_t *encr) {
    unsigned char *hex = (unsigned char*)malloc(crypto_box_PUBLICKEYBYTES * 2);
    memcpy(hex, encr->public_hex, crypto_box_PUBLICKEYBYTES * 2);
    return hex;
}

unsigned char *encryptor_generate() {
     unsigned char *key = (unsigned char*)malloc(crypto_box_SEEDBYTES);
    randombytes(key, crypto_box_SEEDBYTES);
    unsigned char *hex = (unsigned char*)malloc(crypto_box_SEEDBYTES * 2);
    hexlify(key, crypto_box_SEEDBYTES, hex);
    free((void*)key);
    return hex;
}

#endif // ENCRYPTOR_I
