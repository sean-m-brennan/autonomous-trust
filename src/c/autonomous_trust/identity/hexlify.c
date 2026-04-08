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

#include <sodium.h>
#include "identity_priv.h"

/*@
  requires len > 0;
  requires \valid_read(buf + (0 .. len - 1));
  requires \valid(result + (0 .. len * 2));
  assigns result[0 .. len * 2];
  ensures result[len * 2] == '\0';
*/
void hexlify(const unsigned char *buf, size_t len, unsigned char *result)
{
    sodium_bin2hex((char *)result, len * 2 + 1, buf, len);
    //@ assert result[len * 2] == '\0';
}

/*@
  requires len > 0;
  requires len % 2 == 0;
  requires \valid_read(buf + (0 .. len - 1));
  requires \valid(result + (0 .. len / 2 - 1));
  assigns result[0 .. len / 2 - 1];
  behavior success:
    ensures \result == 0;
  behavior failure:
    ensures \result != 0;
  disjoint behaviors;
*/
int unhexlify(const unsigned char *buf, size_t len, unsigned char *result)
{
    size_t bin_len = 0;
    return sodium_hex2bin(result, len / 2, (const char *)buf, len,
                          NULL, &bin_len, NULL);
}
