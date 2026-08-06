/**
 * @file sodium_stubs.h
 * @brief ACSL-annotated stub declarations for libsodium functions used by
 *        AutonomousTrust.  These stubs allow Frama-C/WP to reason about
 *        calls into libsodium without analysing the library itself.
 *
 * Only functions actually referenced in src/c/autonomous_trust/ are stubbed.
 *
 * Copyright 2026 TekFive, Inc., Sean M. Brennan, and contributors
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef SODIUM_STUBS_H
#define SODIUM_STUBS_H

#include <stddef.h>
#include <stdint.h>

/* ================================================================
 * Constants — mirror the real libsodium values so Frama-C can
 * evaluate buffer-size expressions.
 * ================================================================ */

#ifndef crypto_sign_BYTES
#define crypto_sign_BYTES          64U
#endif
#ifndef crypto_sign_PUBLICKEYBYTES
#define crypto_sign_PUBLICKEYBYTES 32U
#endif
#ifndef crypto_sign_SECRETKEYBYTES
#define crypto_sign_SECRETKEYBYTES 64U
#endif
#ifndef crypto_sign_SEEDBYTES
#define crypto_sign_SEEDBYTES      32U
#endif

#ifndef crypto_box_PUBLICKEYBYTES
#define crypto_box_PUBLICKEYBYTES  32U
#endif
#ifndef crypto_box_SECRETKEYBYTES
#define crypto_box_SECRETKEYBYTES  32U
#endif
#ifndef crypto_box_SEEDBYTES
#define crypto_box_SEEDBYTES       32U
#endif
#ifndef crypto_box_NONCEBYTES
#define crypto_box_NONCEBYTES      24U
#endif
#ifndef crypto_box_MACBYTES
#define crypto_box_MACBYTES        16U
#endif

#ifndef crypto_generichash_BYTES
#define crypto_generichash_BYTES   32U
#endif

#ifndef crypto_shorthash_BYTES
#define crypto_shorthash_BYTES     8U
#endif
#ifndef crypto_shorthash_KEYBYTES
#define crypto_shorthash_KEYBYTES  16U
#endif

#ifndef sodium_base64_VARIANT_ORIGINAL
#define sodium_base64_VARIANT_ORIGINAL 1
#endif

/* ================================================================
 * Initialisation
 * ================================================================ */

/*@
  assigns \nothing;
  ensures \result >= -1;
  ensures \result == 0 || \result == 1 || \result == -1;
  // 0  = success (first call)
  // 1  = already initialised
  // -1 = failure
*/
int sodium_init(void);

/* ================================================================
 * Signing – Ed25519
 * ================================================================ */

/*@
  requires \valid(pk + (0 .. crypto_sign_PUBLICKEYBYTES - 1));
  requires \valid(sk + (0 .. crypto_sign_SECRETKEYBYTES - 1));
  assigns pk[0 .. crypto_sign_PUBLICKEYBYTES - 1],
          sk[0 .. crypto_sign_SECRETKEYBYTES - 1];
  ensures \result == 0;
*/
int crypto_sign_keypair(unsigned char *pk, unsigned char *sk);

/*@
  requires \valid(pk + (0 .. crypto_sign_PUBLICKEYBYTES - 1));
  requires \valid(sk + (0 .. crypto_sign_SECRETKEYBYTES - 1));
  requires \valid_read(seed + (0 .. crypto_sign_SEEDBYTES - 1));
  assigns pk[0 .. crypto_sign_PUBLICKEYBYTES - 1],
          sk[0 .. crypto_sign_SECRETKEYBYTES - 1];
  ensures \result == 0;
*/
int crypto_sign_seed_keypair(unsigned char *pk, unsigned char *sk,
                             const unsigned char *seed);

/*@
  requires \valid(sig + (0 .. crypto_sign_BYTES - 1));
  requires siglen_p == \null || \valid(siglen_p);
  requires \valid_read(m + (0 .. mlen - 1));
  requires \valid_read(sk + (0 .. crypto_sign_SECRETKEYBYTES - 1));
  assigns sig[0 .. crypto_sign_BYTES - 1];
  assigns *siglen_p \from m[0 .. mlen - 1], sk[0 .. crypto_sign_SECRETKEYBYTES - 1];
  ensures \result == 0 || \result == -1;
  ensures \result == 0 ==>
    (siglen_p != \null ==> *siglen_p == crypto_sign_BYTES);
*/
int crypto_sign_detached(unsigned char *sig,
                         unsigned long long *siglen_p,
                         const unsigned char *m,
                         unsigned long long mlen,
                         const unsigned char *sk);

/*@
  requires \valid_read(sig + (0 .. crypto_sign_BYTES - 1));
  requires \valid_read(m + (0 .. mlen - 1));
  requires \valid_read(pk + (0 .. crypto_sign_PUBLICKEYBYTES - 1));
  assigns \nothing;
  ensures \result == 0 || \result == -1;
*/
int crypto_sign_verify_detached(const unsigned char *sig,
                                const unsigned char *m,
                                unsigned long long mlen,
                                const unsigned char *pk);

/*@
  requires \valid(sm + (0 .. mlen + crypto_sign_BYTES - 1));
  requires smlen_p == \null || \valid(smlen_p);
  requires \valid_read(m + (0 .. mlen - 1));
  requires \valid_read(sk + (0 .. crypto_sign_SECRETKEYBYTES - 1));
  assigns sm[0 .. mlen + crypto_sign_BYTES - 1];
  assigns *smlen_p \from mlen;
  ensures \result == 0;
  ensures smlen_p != \null ==> *smlen_p == mlen + crypto_sign_BYTES;
*/
int crypto_sign(unsigned char *sm,
                unsigned long long *smlen_p,
                const unsigned char *m,
                unsigned long long mlen,
                const unsigned char *sk);

/*@
  requires \valid(m + (0 .. smlen - 1));
  requires mlen_p == \null || \valid(mlen_p);
  requires \valid_read(sm + (0 .. smlen - 1));
  requires \valid_read(pk + (0 .. crypto_sign_PUBLICKEYBYTES - 1));
  assigns m[0 .. smlen - 1];
  assigns *mlen_p \from smlen;
  ensures \result == 0 || \result == -1;
  ensures \result == 0 ==>
    (mlen_p != \null ==> *mlen_p <= smlen - crypto_sign_BYTES);
*/
int crypto_sign_open(unsigned char *m,
                     unsigned long long *mlen_p,
                     const unsigned char *sm,
                     unsigned long long smlen,
                     const unsigned char *pk);

/* ================================================================
 * Public-key encryption – Curve25519-XSalsa20-Poly1305
 * ================================================================ */

/*@
  requires \valid(pk + (0 .. crypto_box_PUBLICKEYBYTES - 1));
  requires \valid(sk + (0 .. crypto_box_SECRETKEYBYTES - 1));
  requires \valid_read(seed + (0 .. crypto_box_SEEDBYTES - 1));
  assigns pk[0 .. crypto_box_PUBLICKEYBYTES - 1],
          sk[0 .. crypto_box_SECRETKEYBYTES - 1];
  ensures \result == 0;
*/
int crypto_box_seed_keypair(unsigned char *pk, unsigned char *sk,
                            const unsigned char *seed);

/*@
  requires \valid(c + (0 .. mlen + crypto_box_MACBYTES - 1));
  requires \valid_read(m + (0 .. mlen - 1));
  requires \valid_read(n + (0 .. crypto_box_NONCEBYTES - 1));
  requires \valid_read(pk + (0 .. crypto_box_PUBLICKEYBYTES - 1));
  requires \valid_read(sk + (0 .. crypto_box_SECRETKEYBYTES - 1));
  assigns c[0 .. mlen + crypto_box_MACBYTES - 1];
  ensures \result == 0 || \result == -1;
*/
int crypto_box_easy(unsigned char *c,
                    const unsigned char *m,
                    unsigned long long mlen,
                    const unsigned char *n,
                    const unsigned char *pk,
                    const unsigned char *sk);

/*@
  requires clen >= crypto_box_MACBYTES;
  requires \valid(m + (0 .. clen - crypto_box_MACBYTES - 1));
  requires \valid_read(c + (0 .. clen - 1));
  requires \valid_read(n + (0 .. crypto_box_NONCEBYTES - 1));
  requires \valid_read(pk + (0 .. crypto_box_PUBLICKEYBYTES - 1));
  requires \valid_read(sk + (0 .. crypto_box_SECRETKEYBYTES - 1));
  assigns m[0 .. clen - crypto_box_MACBYTES - 1];
  ensures \result == 0 || \result == -1;
*/
int crypto_box_open_easy(unsigned char *m,
                         const unsigned char *c,
                         unsigned long long clen,
                         const unsigned char *n,
                         const unsigned char *pk,
                         const unsigned char *sk);

/* ================================================================
 * Generic hashing – BLAKE2b
 * ================================================================ */

/*@
  requires outlen > 0 && outlen <= 64;
  requires \valid(out + (0 .. outlen - 1));
  requires inlen == 0 || \valid_read(in + (0 .. inlen - 1));
  requires key == \null || \valid_read(key + (0 .. keylen - 1));
  assigns out[0 .. outlen - 1];
  ensures \result == 0 || \result == -1;
*/
int crypto_generichash_blake2b(unsigned char *out, size_t outlen,
                               const unsigned char *in, unsigned long long inlen,
                               const unsigned char *key, size_t keylen);

/* Streaming interface for BLAKE2b */
typedef struct crypto_generichash_blake2b_state {
    unsigned char opaque[384];
} crypto_generichash_blake2b_state;

/*@
  requires \valid(state);
  requires outlen > 0 && outlen <= 64;
  requires key == \null || \valid_read(key + (0 .. keylen - 1));
  assigns *state;
  ensures \result == 0 || \result == -1;
*/
int crypto_generichash_blake2b_init(crypto_generichash_blake2b_state *state,
                                    const unsigned char *key, size_t keylen,
                                    size_t outlen);

/*@
  requires \valid(state);
  requires inlen == 0 || \valid_read(in + (0 .. inlen - 1));
  assigns *state;
  ensures \result == 0 || \result == -1;
*/
int crypto_generichash_blake2b_update(crypto_generichash_blake2b_state *state,
                                      const unsigned char *in,
                                      unsigned long long inlen);

/*@
  requires \valid(state);
  requires outlen > 0 && outlen <= 64;
  requires \valid(out + (0 .. outlen - 1));
  assigns out[0 .. outlen - 1];
  assigns *state;
  ensures \result == 0 || \result == -1;
*/
int crypto_generichash_blake2b_final(crypto_generichash_blake2b_state *state,
                                     unsigned char *out, size_t outlen);

/* ================================================================
 * Short hashing – SipHash-2-4 (used by map_t)
 * ================================================================ */

/*@
  requires \valid(out + (0 .. crypto_shorthash_BYTES - 1));
  requires \valid_read(in + (0 .. inlen - 1));
  requires \valid_read(k + (0 .. crypto_shorthash_KEYBYTES - 1));
  assigns out[0 .. crypto_shorthash_BYTES - 1];
  ensures \result == 0;
*/
int crypto_shorthash(unsigned char *out,
                     const unsigned char *in,
                     unsigned long long inlen,
                     const unsigned char *k);

/*@
  requires \valid(k + (0 .. crypto_shorthash_KEYBYTES - 1));
  assigns k[0 .. crypto_shorthash_KEYBYTES - 1];
*/
void crypto_shorthash_keygen(unsigned char *k);

/* ================================================================
 * Utility — memory wiping
 * ================================================================ */

/*@
  requires len > 0;
  requires \valid((unsigned char *)pnt + (0 .. len - 1));
  assigns ((unsigned char *)pnt)[0 .. len - 1];
  ensures \forall size_t i; 0 <= i < len ==>
    ((unsigned char *)pnt)[i] == 0;
*/
void sodium_memzero(void *pnt, size_t len);

/*@
  requires \valid_read((const unsigned char *)b1_ + (0 .. len - 1));
  requires \valid_read((const unsigned char *)b2_ + (0 .. len - 1));
  assigns \nothing;
  ensures \result == 0 || \result != 0;
*/
int sodium_memcmp(const void *b1_, const void *b2_, size_t len);

/* ================================================================
 * Utility — hex encoding/decoding
 * ================================================================ */

/*@
  requires hex_maxlen >= bin_len * 2 + 1;
  requires \valid(hex + (0 .. hex_maxlen - 1));
  requires \valid_read(bin + (0 .. bin_len - 1));
  assigns hex[0 .. bin_len * 2];
  ensures hex[bin_len * 2] == '\0';
  ensures \result == hex;
*/
char *sodium_bin2hex(char *hex, size_t hex_maxlen,
                     const unsigned char *bin, size_t bin_len);

/*@
  requires \valid(bin + (0 .. bin_maxlen - 1));
  requires \valid_read(hex + (0 .. hex_len - 1));
  requires bin_len == \null || \valid(bin_len);
  requires hex_end == \null || \valid(hex_end);
  assigns bin[0 .. bin_maxlen - 1];
  assigns *bin_len \from hex[0 .. hex_len - 1];
  assigns *hex_end \from hex, hex_len;
  ensures \result == 0 || \result == -1;
*/
int sodium_hex2bin(unsigned char *bin, size_t bin_maxlen,
                   const char *hex, size_t hex_len,
                   const char *ignore, size_t *bin_len,
                   const char **hex_end);

/* ================================================================
 * Utility — base64 encoding/decoding
 * ================================================================ */

/*@
  requires variant == sodium_base64_VARIANT_ORIGINAL;
  assigns \nothing;
  ensures \result >= 1;
*/
size_t sodium_base64_encoded_len(size_t bin_len, int variant);

/*@
  requires b64_maxlen >= (4 * ((bin_len + 2) / 3)) + 1;
  requires \valid(b64 + (0 .. b64_maxlen - 1));
  requires bin_len > 0;
  requires \valid_read(bin + (0 .. bin_len - 1));
  assigns b64[0 .. b64_maxlen - 1];
*/
char *sodium_bin2base64(char *b64, size_t b64_maxlen,
                        const unsigned char *bin, size_t bin_len,
                        int variant);

/*@
  requires bin_maxlen > 0;
  requires \valid(bin + (0 .. bin_maxlen - 1));
  requires b64_len > 0;
  requires \valid_read(b64 + (0 .. b64_len - 1));
  requires bin_len == \null || \valid(bin_len);
  requires b64_end == \null || \valid(b64_end);
  assigns bin[0 .. bin_maxlen - 1];
  assigns *bin_len;
  assigns *b64_end;
  behavior with_bin_len:
    assumes bin_len != \null;
    ensures *bin_len <= bin_maxlen;
  behavior with_b64_end:
    assumes b64_end != \null;
    ensures \valid_read(*b64_end);
  ensures \result == 0 || \result == -1;
*/
int sodium_base642bin(unsigned char *bin, size_t bin_maxlen,
                      const char *b64, size_t b64_len,
                      const char *ignore, size_t *bin_len,
                      const char **b64_end, int variant);

/* ================================================================
 * Random bytes
 * ================================================================ */

/*@
  requires size > 0;
  requires \valid((unsigned char *)buf + (0 .. size - 1));
  assigns ((unsigned char *)buf)[0 .. size - 1];
*/
void randombytes_buf(void *buf, size_t size);

/*@
  requires size > 0;
  requires \valid(buf + (0 .. size - 1));
  assigns buf[0 .. size - 1];
*/
void randombytes(unsigned char *buf, unsigned long long size);

/*@
  assigns \nothing;
  ensures \result >= 0;
*/
uint32_t randombytes_random(void);

/*@
  requires upper_bound > 0;
  assigns \nothing;
  ensures \result < upper_bound;
*/
uint32_t randombytes_uniform(uint32_t upper_bound);

#endif /* SODIUM_STUBS_H */
