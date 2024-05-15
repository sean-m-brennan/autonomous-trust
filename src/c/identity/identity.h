#ifndef IDENTITY_H
#define IDENTITY_H

#include <stdlib.h>

struct identityStruct;

typedef struct identityStruct identity_t;

typedef struct
{
    unsigned char *msg;
    unsigned long long len; 
} message_t;


/**
 * @brief 
 * 
 * @param ident 
 * @param msg 
 * @return int 
 */
int identity_sign(identity_t *ident, message_t *in, message_t *out);

/**
 * @brief 
 * 
 * @param ident 
 * @param msg 
 * @param sig 
 * @return int 
 */
int identity_verify(identity_t *ident, message_t *in, message_t *out);

/**
 * @brief 
 * 
 * @param ident 
 * @param msg 
 * @param whom 
 * @param nonce 
 * @return int 
 */
int identity_encrypt(identity_t *ident, const message_t *in, identity_t *whom, unsigned char *nonce, unsigned char *cipher);

/**
 * @brief 
 * 
 * @param ident 
 * @param msg 
 * @param whom 
 * @param nonce 
 * @return int 
 */
int identity_decrypt(identity_t *ident, const message_t *cipher, identity_t *whom, unsigned char *nonce, unsigned char *out);

/**
 * @brief 
 * 
 * @param ident 
 * @return identity_t* 
 */
identity_t *identity_publish(identity_t *ident);

#endif // IDENTITY_H