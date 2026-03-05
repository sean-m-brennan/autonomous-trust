#ifndef B64_H
#define B64_H

#include <stddef.h>
#include <sodium.h>

static inline size_t b64_encoded_len(size_t input_len)
{
    return sodium_base64_encoded_len(input_len, sodium_base64_VARIANT_ORIGINAL);
}

static inline size_t b64_decoded_len(size_t enc_len, char last_char)
{
    size_t len = (enc_len / 4) * 3;
    if (last_char == '=')
        len--;
    return len;
}

static inline void base64_encode(const unsigned char *src, size_t src_len,
                                  char *dst, size_t dst_len)
{
    sodium_bin2base64(dst, dst_len, src, src_len, sodium_base64_VARIANT_ORIGINAL);
}

static inline void base64_decode(const char *src, size_t src_len,
                                  unsigned char *dst, size_t dst_len)
{
    size_t bin_len = 0;
    sodium_base642bin(dst, dst_len, src, src_len, NULL, &bin_len, NULL,
                      sodium_base64_VARIANT_ORIGINAL);
}

#endif  /* B64_H */
