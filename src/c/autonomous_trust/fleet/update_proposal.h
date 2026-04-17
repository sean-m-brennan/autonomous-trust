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

#ifndef UPDATE_PROPOSAL_H
#define UPDATE_PROPOSAL_H

/** @addtogroup internal_fleet
 *  @{
 */

#include <stdbool.h>
#include <stdint.h>
#include <uuid/uuid.h>
#include <jansson.h>

#define UPDATE_VERSION_LEN 64
#define UPDATE_HASH_LEN    32
#define UPDATE_SIG_LEN     64
#define UPDATE_ARCH_LEN    16

typedef struct {
    char version[UPDATE_VERSION_LEN + 1];
    uint8_t artifact_hash[UPDATE_HASH_LEN];
    uuid_t signer_uuid;
    char target_arch[UPDATE_ARCH_LEN + 1];
    double min_proposer_reputation;
    uuid_t proposal_uuid;
    uint8_t signature[UPDATE_SIG_LEN];
} update_proposal_t;

/*@
  requires \valid(prop);
  assigns \nothing;
  ensures \result != \null || \result == \null;
*/
json_t *update_proposal_to_json(const update_proposal_t *prop);

/*@
  requires json != \null;
  requires \valid(prop);
  assigns *prop;
  ensures \result == 0 || \result == -1;
*/
int update_proposal_from_json(const json_t *json, update_proposal_t *prop);

/*@
  requires \valid(prop);
  requires \valid_read(sk + (0 .. crypto_sign_SECRETKEYBYTES - 1));
  assigns prop->signature[0 .. UPDATE_SIG_LEN - 1];
  ensures \result == 0 || \result == -1;
*/
int update_proposal_sign(update_proposal_t *prop, const uint8_t *sk);

/*@
  requires \valid(prop);
  requires \valid_read(pk + (0 .. crypto_sign_PUBLICKEYBYTES - 1));
  assigns \nothing;
  ensures \result == 0 || \result == -1;
*/
int update_proposal_verify(const update_proposal_t *prop, const uint8_t *pk);


/** @} */ /* end of internal_fleet */

#endif /* UPDATE_PROPOSAL_H */
