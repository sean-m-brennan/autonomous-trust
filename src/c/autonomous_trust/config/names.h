/********************
 *  Copyright 2024 TekFive, Inc., Sean M. Brennan, and contributors
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

#ifndef NAMES_H
#define NAMES_H

/** @addtogroup internal_config
 *  @{
 */

#include <stddef.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/*@
  requires out == \null || \valid(out + (0 .. out_len - 1));
  requires out_len >= 4;
  assigns out[0 .. out_len - 1];
  behavior null_out:
    assumes out == \null || out_len < 4;
    ensures \result == -1;
  behavior success:
    assumes out != \null && out_len >= 4;
    ensures \result == 0 || \result == -1;
  disjoint behaviors;
*/
int random_name(char *out, size_t out_len, char sep, bool capitalize);

#ifdef __cplusplus
} // extern "C"
#endif


/** @} */ /* end of internal_config */

#endif  // NAMES_H
