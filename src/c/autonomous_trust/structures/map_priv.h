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

#ifndef MAP_PRIV_H
#define MAP_PRIV_H

#include <stddef.h>

#include <sodium.h>
#include <jansson.h>

#include "map.h"
#include "array_priv.h"
#include "structures/map.pb-c.h"

struct map_s
{
    smrt_ptr_t;
    map_item_t *items;
    size_t length;
    size_t capacity;
    array_t keys;
    unsigned char hashkey[crypto_shorthash_KEYBYTES];
};

/*@ predicate map_valid(map_t *m) =
      \valid(m) &&
      m->items != \null &&
      m->capacity > 0 &&
      m->length <= m->capacity &&
      \valid(m->items + (0 .. m->capacity - 1));
*/

/*@ type invariant map_length_bounded(struct map_s m) =
      m.items != \null ==> m.length <= m.capacity;
*/


/*@
  requires map_valid(map);
  requires \valid(dmap);
  assigns dmap->map, dmap->n_map;
  behavior success:
    ensures \result == 0;
    ensures dmap->n_map == map->length;
  behavior failure:
    ensures \result != 0;
  complete behaviors;
  disjoint behaviors;
*/
int map_sync_out(map_t *map, AutonomousTrust__Core__Protobuf__Structures__DataMap *dmap);

/*@
  requires \valid(dmap);
  assigns dmap->map;
  frees dmap->map;
  ensures dmap->map == \null;
*/
void map_proto_free(AutonomousTrust__Core__Protobuf__Structures__DataMap *dmap);

/*@
  requires \valid(dmap);
  requires map_valid(map);
  assigns map->items[0 .. map->capacity - 1], map->length, map->capacity, map->keys;
  behavior success:
    ensures \result == 0;
  behavior failure:
    ensures \result != 0;
  complete behaviors;
  disjoint behaviors;
*/
int map_sync_in(AutonomousTrust__Core__Protobuf__Structures__DataMap *dmap, map_t *map);

/*@
  requires \valid(data_struct);
  requires \valid(obj_ptr);
  assigns *obj_ptr;
  behavior success:
    ensures \result == 0;
    ensures *obj_ptr != \null;
  behavior failure:
    ensures \result != 0;
  complete behaviors;
  disjoint behaviors;
*/
int map_to_json(const void *data_struct, json_t **obj_ptr);

/*@
  requires \valid_read(obj);
  requires \valid(data_struct);
  assigns ((map_t *)data_struct)->length,
          ((map_t *)data_struct)->capacity,
          ((map_t *)data_struct)->items,
          ((map_t *)data_struct)->keys,
          ((map_t *)data_struct)->hashkey[0 .. crypto_shorthash_KEYBYTES - 1];
  behavior success:
    ensures \result == 0;
    ensures ((map_t *)data_struct)->length <= ((map_t *)data_struct)->capacity;
  behavior failure:
    ensures \result != 0;
  complete behaviors;
  disjoint behaviors;
*/
int map_from_json(const json_t *obj, void *data_struct);

#endif  // MAP_PRIV_H
