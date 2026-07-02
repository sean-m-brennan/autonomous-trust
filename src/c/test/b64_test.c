/********************
 *  Copyright 2026 TekFive, Inc., Sean M. Brennan, and contributors
 *
 *   Licensed under the Apache License, Version 2.0 (the "License");
 *   you may not use this file except in compliance with the License.
 *   You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 *   Unless required by applicable law or agreed to in writing, software
 *   distributed under the License is distributed on an "AS IS" BASIS,
 *   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *   See the License for the specific language governing permissions and
 *   limitations under the License.
 *******************/

#define DEBUG_TESTS 1
#include "test_setup.h"

#include <string.h>
#include <sodium.h>

#include "autonomous_trust/utilities/b64.h"

DEFINE_TEST(test_b64_encode_decode)
{
    ck_assert(sodium_init() >= 0);

    const unsigned char input[] = "Hello, World!";
    size_t input_len = strlen((const char *)input);

    size_t enc_len = b64_encoded_len(input_len);
    ck_assert(enc_len > input_len);

    char *encoded = malloc(enc_len);
    ck_assert_ptr_nonnull(encoded);
    base64_encode(input, input_len, encoded, enc_len);

    /* Encoded string should differ from input */
    ck_assert(strcmp(encoded, (const char *)input) != 0);
    /* Known base64 for "Hello, World!" is "SGVsbG8sIFdvcmxkIQ==" */
    ck_assert_str_eq(encoded, "SGVsbG8sIFdvcmxkIQ==");

    /* Decode back */
    size_t dec_len = b64_decoded_len(strlen(encoded), encoded[strlen(encoded)-1]);
    unsigned char *decoded = malloc(dec_len + 1);
    ck_assert_ptr_nonnull(decoded);
    memset(decoded, 0, dec_len + 1);
    base64_decode(encoded, strlen(encoded), decoded, dec_len);

    ck_assert_mem_eq(decoded, input, input_len);

    free(encoded);
    free(decoded);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_b64_binary_data)
{
    ck_assert(sodium_init() >= 0);

    /* Test with raw binary data */
    unsigned char binary[] = {0x00, 0xFF, 0xDE, 0xAD, 0xBE, 0xEF, 0x01, 0x02};
    size_t bin_len = sizeof(binary);

    size_t enc_len = b64_encoded_len(bin_len);
    char *encoded = malloc(enc_len);
    ck_assert_ptr_nonnull(encoded);
    base64_encode(binary, bin_len, encoded, enc_len);

    size_t dec_len = b64_decoded_len(strlen(encoded), encoded[strlen(encoded)-1]);
    unsigned char *decoded = malloc(dec_len);
    ck_assert_ptr_nonnull(decoded);
    base64_decode(encoded, strlen(encoded), decoded, dec_len);

    ck_assert_mem_eq(decoded, binary, bin_len);

    free(encoded);
    free(decoded);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_b64_empty)
{
    ck_assert(sodium_init() >= 0);

    /* Empty input */
    size_t enc_len = b64_encoded_len(0);
    char *encoded = malloc(enc_len);
    ck_assert_ptr_nonnull(encoded);
    base64_encode((const unsigned char *)"", 0, encoded, enc_len);
    /* Empty base64 should be empty string (just null terminator) */
    ck_assert_uint_eq(strlen(encoded), 0);

    free(encoded);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_b64_single_byte)
{
    ck_assert(sodium_init() >= 0);

    /* Single byte */
    unsigned char one = 0x42;
    size_t enc_len = b64_encoded_len(1);
    char *encoded = malloc(enc_len);
    ck_assert_ptr_nonnull(encoded);
    base64_encode(&one, 1, encoded, enc_len);
    ck_assert(strlen(encoded) > 0);

    /* Decode back */
    size_t dec_len = b64_decoded_len(strlen(encoded), encoded[strlen(encoded)-1]);
    unsigned char decoded = 0;
    base64_decode(encoded, strlen(encoded), &decoded, dec_len);
    ck_assert_int_eq(decoded, 0x42);

    free(encoded);
}
END_TEST_DEFINITION()

RUN_TESTS(Base64, test_b64_encode_decode, test_b64_binary_data,
          test_b64_empty, test_b64_single_byte)
