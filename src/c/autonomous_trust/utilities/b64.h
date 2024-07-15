#ifndef B64_H
#define B64_H

#include <stdint.h>
#include <stdlib.h>
#include <stdbool.h>

size_t b64_encoded_len(size_t size);
int32_t base64_encode(const uint8_t* in, size_t data_length, char* result, size_t max_result_length);

size_t b64_decoded_len(size_t size, uint8_t last_byte);
int32_t base64_decode(const char* in, size_t in_len, uint8_t* out, size_t max_out_len);

#endif  // B64_H
