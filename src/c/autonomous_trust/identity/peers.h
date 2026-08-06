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

#ifndef PEERS_H
#define PEERS_H

/** @addtogroup internal_identity
 *  @{
 */

#include <jansson.h>
#include "structures/map.h"
#include "identity.h"

#define LEVELS 3
#define VALUES 10
#define PEERS_MID_LEVEL (LEVELS / 2)

typedef struct {
    map_t hierarchy[LEVELS];
    map_t valuations[VALUES];
} peers_t;

int peers_to_json(const void *data_struct, json_t **obj_ptr);
int peers_from_json(const json_t *obj, void *data_struct);

/*@
  requires \valid(peers);
  assigns \nothing;
  ensures \result == \null || \valid(\result);
*/
const public_identity_t *peers_find_by_uuid(peers_t *peers, const uuid_t uuid);

/*@
  requires \valid(peers);
  requires address != \null && \valid_read(address);
  assigns \nothing;
  ensures \result == \null || \valid(\result);
*/
const public_identity_t *peers_find_by_address(peers_t *peers, const char *address);

/*@
  requires \valid(peers);
  requires n > 0;
  requires \valid(out + (0 .. n - 1));
  requires \valid(out_count);
  assigns out[0 .. n - 1], *out_count;
  ensures \result == 0;
  ensures *out_count >= 0 && *out_count <= n;
*/
int peers_find_top_n(peers_t *peers, int n, const public_identity_t **out, int *out_count);

/*@
  requires \valid(peers);
  requires \valid(who);
  requires level >= -1 && level < LEVELS;
  assigns peers->hierarchy[0 .. LEVELS - 1],
          peers->valuations[0 .. VALUES - 1];
  behavior success:
    ensures \result == 0;
  behavior failure:
    ensures \result != 0;
  disjoint behaviors;
*/
int peers_add(peers_t *peers, const public_identity_t *who, int level);

/*@
  requires \valid(peers);
  requires \valid(who);
  assigns peers->hierarchy[0 .. LEVELS - 1],
          peers->valuations[0 .. VALUES - 1];
  ensures \result == 0;
*/
int peers_delete(peers_t *peers, const public_identity_t *who);

/*@
  requires \valid(peers);
  requires \valid(who);
  assigns peers->valuations[0 .. VALUES - 1];
  ensures \result == 0 || \result != 0;
*/
int peers_promote(peers_t *peers, const public_identity_t *who);

/*@
  requires \valid(peers);
  requires \valid(who);
  assigns peers->hierarchy[0 .. LEVELS - 1],
          peers->valuations[0 .. VALUES - 1];
  ensures \result == 0;
*/
int peers_demote(peers_t *peers, const public_identity_t *who);

/*@
  requires \valid(peers);
  assigns \nothing;
  ensures \result >= 0;
*/
int peers_count(peers_t *peers);

/*@
  requires peers == \null || \valid(peers);
  behavior null_peers:
    assumes peers == \null;
    assigns \nothing;
  behavior valid_peers:
    assumes peers != \null;
    assigns peers->hierarchy[0 .. LEVELS - 1],
            peers->valuations[0 .. VALUES - 1];
  disjoint behaviors;
  complete behaviors;
*/
void peers_free(peers_t *peers);


/** @} */ /* end of internal_identity */

#endif  // PEERS_H
