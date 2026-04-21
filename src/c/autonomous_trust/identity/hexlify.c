/********************
 *  Copyright 2025 Sean M. Brennan and contributors
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

#include <string.h>
#include <sodium.h>
#include "identity_priv.h"

/* Frama-C: skipped — [solver-timeout] loop assert on hex encoding */
void hexlify(const unsigned char *buf, size_t len, unsigned char *result)
{
    sodium_bin2hex((char *)result, len * 2 + 1, buf, len);
    //@ assert result[len * 2] == '\0';
}

int unhexlify(const unsigned char *buf, size_t len, unsigned char *result)
{
    if (buf == NULL || result == NULL)
        return -1;
    /* Early NUL inside the first `len` bytes ⇒ hex string is truncated.
     * This is a bounded read: we never touch buf[len] or later. */
    if (strnlen((const char *)buf, len) < len)
        return -1;
    size_t bin_len = 0;
    return sodium_hex2bin(result, len / 2, (const char *)buf, len,
                          NULL, &bin_len, NULL);
}
