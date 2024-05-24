#ifndef HEXLIFY_I
#define HEXLIFY_I

#include <stdlib.h>
#include <errno.h>

void hexlify(const unsigned char *buf, size_t len, unsigned char *result) {
    const char *hexdigits = "0123456789abcdef";
    for (size_t i=0, j=0; i < len; ++i) {
        result[j++] = hexdigits[buf[i] >> 4];
        result[j++] = hexdigits[buf[i] & 0x0f];
    }
}

int unhexlify(const unsigned char *buf, size_t len, unsigned char *result) {
    unsigned char digitvalue[256] = {
        37, 37, 37, 37, 37, 37, 37, 37, 37, 37, 37, 37, 37, 37, 37, 37,
        37, 37, 37, 37, 37, 37, 37, 37, 37, 37, 37, 37, 37, 37, 37, 37,
        37, 37, 37, 37, 37, 37, 37, 37, 37, 37, 37, 37, 37, 37, 37, 37,
        0,  1,  2,  3,  4,  5,  6,  7,  8,  9,  37, 37, 37, 37, 37, 37,
        37, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24,
        25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 37, 37, 37, 37, 37,
        37, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24,
        25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 37, 37, 37, 37, 37,
        37, 37, 37, 37, 37, 37, 37, 37, 37, 37, 37, 37, 37, 37, 37, 37,
        37, 37, 37, 37, 37, 37, 37, 37, 37, 37, 37, 37, 37, 37, 37, 37,
        37, 37, 37, 37, 37, 37, 37, 37, 37, 37, 37, 37, 37, 37, 37, 37,
        37, 37, 37, 37, 37, 37, 37, 37, 37, 37, 37, 37, 37, 37, 37, 37,
        37, 37, 37, 37, 37, 37, 37, 37, 37, 37, 37, 37, 37, 37, 37, 37,
        37, 37, 37, 37, 37, 37, 37, 37, 37, 37, 37, 37, 37, 37, 37, 37,
        37, 37, 37, 37, 37, 37, 37, 37, 37, 37, 37, 37, 37, 37, 37, 37,
        37, 37, 37, 37, 37, 37, 37, 37, 37, 37, 37, 37, 37, 37, 37, 37,
    };
    for (size_t i=0, j=0; i < len; i += 2) {
        unsigned int top = digitvalue[buf[i]];
        unsigned int bot = digitvalue[buf[i+1]];
        if (top >= 16 || bot >= 16) {
            return EINVAL;
        }
        result[j++] = (top << 4) + bot;
    }
    return 0;
}

#endif // HEXLIFY_I
