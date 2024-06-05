#ifndef IDENTITY_PRIV_H
#define IDENTITY_PRIV_H

#include <uuid/uuid.h>
#include <sodium.h>
#include <jansson.h>

#include "algorithms/algorithms.h"
#include "identity/identity.h"

typedef struct
{
    unsigned char private[crypto_sign_SECRETKEYBYTES];
    unsigned char public[crypto_sign_PUBLICKEYBYTES];
    unsigned char public_hex[crypto_sign_PUBLICKEYBYTES * 2];
} signature_t;

typedef struct
{
    unsigned char private[crypto_box_SECRETKEYBYTES];
    unsigned char public[crypto_box_PUBLICKEYBYTES];
    unsigned char public_hex[crypto_box_PUBLICKEYBYTES * 2];
} encryptor_t;

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

int identity_to_json(const void *data_struct, json_t **obj_ptr);

int identity_from_json(const json_t *obj, void *data_struct);

#endif // IDENTITY_PRIV_H
