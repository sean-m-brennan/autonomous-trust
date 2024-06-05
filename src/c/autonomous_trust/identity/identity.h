#ifndef IDENTITY_H
#define IDENTITY_H

#include <stdlib.h>
#include "config/configuration.h"

typedef struct identity_s identity_t;

typedef struct
{
    unsigned char *msg;
    unsigned long long len; 
} msg_str_t;  // FIXME separate file

/***/
int identity_create(unsigned char *address, identity_t **ident);

/**
 * @brief 
 * 
 * @param ident 
 * @param pub_copy 
 * @return int 
 */
int identity_publish(const identity_t *ident, identity_t **pub_copy);

/**
 * @brief 
 * 
 * @param ident 
 * @param in 
 * @param out 
 * @return int 
 */
int identity_sign(const identity_t *ident, const msg_str_t *in, msg_str_t *out);

/**
 * @brief 
 * 
 * @param ident 
 * @param in 
 * @param out 
 * @return int 
 */
int identity_verify(const identity_t *ident, const msg_str_t *in, msg_str_t *out);

/**
 * @brief 
 * 
 * @param ident 
 * @param in 
 * @param whom 
 * @param nonce 
 * @param cipher 
 * @return int 
 */
int identity_encrypt(const identity_t *ident, const msg_str_t *in, const identity_t *whom, const unsigned char *nonce, unsigned char *cipher);

/**
 * @brief 
 * 
 * @param ident 
 * @param cipher 
 * @param whom 
 * @param nonce 
 * @param out 
 * @return int 
 */
int identity_decrypt(const identity_t *ident, const msg_str_t *cipher, const identity_t *whom, const unsigned char *nonce, unsigned char *out);

/**
 * @brief 
 * 
 * @param ident 
 */
void identity_free(identity_t *ident);

int identity_to_json(const void *data_struct, json_t **obj_ptr);

int identity_from_json(const json_t *obj, void *data_struct);

#endif // IDENTITY_H