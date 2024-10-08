// Copyright (c) 2001-2024 Python Software Foundation; All Rights Reserved
// Derived from CPython repo: cpython/Python/pystrhex.c and cpython/Modules/binascii.c

/*
 * PSF LICENSE AGREEMENT FOR PYTHON 3.12.3
 * 
 * 1. This LICENSE AGREEMENT is between the Python Software Foundation ("PSF"), and
 *    the Individual or Organization ("Licensee") accessing and otherwise using Python
 *    3.12.3 software in source or binary form and its associated documentation.
 * 
 * 2. Subject to the terms and conditions of this License Agreement, PSF hereby
 *    grants Licensee a nonexclusive, royalty-free, world-wide license to reproduce,
 *    analyze, test, perform and/or display publicly, prepare derivative works,
 *    distribute, and otherwise use Python 3.12.3 alone or in any derivative
 *    version, provided, however, that PSF's License Agreement and PSF's notice of
 *    copyright, i.e., "Copyright © 2001-2023 Python Software Foundation; All Rights
 *    Reserved" are retained in Python 3.12.3 alone or in any derivative version
 *    prepared by Licensee.
 * 
 * 3. In the event Licensee prepares a derivative work that is based on or
 *    incorporates Python 3.12.3 or any part thereof, and wants to make the
 *    derivative work available to others as provided herein, then Licensee hereby
 *    agrees to include in any such work a brief summary of the changes made to Python
 *    3.12.3.
 * 
 * 4. PSF is making Python 3.12.3 available to Licensee on an "AS IS" basis.
 *    PSF MAKES NO REPRESENTATIONS OR WARRANTIES, EXPRESS OR IMPLIED.  BY WAY OF
 *    EXAMPLE, BUT NOT LIMITATION, PSF MAKES NO AND DISCLAIMS ANY REPRESENTATION OR
 *    WARRANTY OF MERCHANTABILITY OR FITNESS FOR ANY PARTICULAR PURPOSE OR THAT THE
 *    USE OF PYTHON 3.12.3 WILL NOT INFRINGE ANY THIRD PARTY RIGHTS.
 * 
 * 5. PSF SHALL NOT BE LIABLE TO LICENSEE OR ANY OTHER USERS OF PYTHON 3.12.3
 *    FOR ANY INCIDENTAL, SPECIAL, OR CONSEQUENTIAL DAMAGES OR LOSS AS A RESULT OF
 *    MODIFYING, DISTRIBUTING, OR OTHERWISE USING PYTHON 3.12.3, OR ANY DERIVATIVE
 *    THEREOF, EVEN IF ADVISED OF THE POSSIBILITY THEREOF.
 * 
 * 6. This License Agreement will automatically terminate upon a material breach of
 *    its terms and conditions.
 * 
 * 7. Nothing in this License Agreement shall be deemed to create any relationship
 *    of agency, partnership, or joint venture between PSF and Licensee.  This License
 *    Agreement does not grant permission to use PSF trademarks or trade name in a
 *    trademark sense to endorse or promote products or services of Licensee, or any
 *    third party.
 * 
 * 8. By copying, installing or otherwise using Python 3.12.3, Licensee agrees
 *    to be bound by the terms and conditions of this License Agreement.
 */

#ifndef HEXLIFY_C
#define HEXLIFY_C

#include <stdlib.h>
#include <errno.h>

void hexlify(const unsigned char *buf, size_t len, unsigned char *result)
{
    const char *hexdigits = "0123456789abcdef";
    for (size_t i=0, j=0; i < len; ++i) {
        result[j++] = hexdigits[buf[i] >> 4];
        result[j++] = hexdigits[buf[i] & 0x0f];
    }
}

int unhexlify(const unsigned char *buf, size_t len, unsigned char *result)
{
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

#endif // HEXLIFY_C
