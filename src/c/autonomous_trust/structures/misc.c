#include <string.h>

#include <b64/cencode.h>
#include <b64/cdecode.h>

size_t base64_output_size(size_t in_size)
{
    double size = 1.4 * in_size;
    return (int)size;
}

int bytes_decode(void *in, size_t in_size, void *out, size_t out_size)
{
    base64_decodestate state;
    base64_init_decodestate(&state);
    base64_decode_block((const char *)in, in_size, (char *)out, &state);
    return 0;
}

int bytes_encode(void *in, void *out, size_t size)
{ // note: use base64_output_size() to determine size
    base64_encodestate state;
    base64_init_encodestate(&state);
    base64_encode_block((const char *)in, size, (char *)out, &state);
    base64_encode_blockend((char *)out, &state);
    return 0;
}
