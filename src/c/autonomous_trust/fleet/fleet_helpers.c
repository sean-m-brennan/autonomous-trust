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

/**
 * fleet_helpers.c — pure, dependency-free helper functions for fleet_proc.
 *
 * Kept in a separate translation unit so that unit tests can link only
 * update_proposal.c + fleet_helpers.c without pulling in the full
 * process/messaging infrastructure that fleet_proc.c depends upon.
 */

#include <stdbool.h>
#include <stdint.h>

#include "fleet/update_proposal.h"
#include "fleet/fleet_proc.h"

bool fleet_validate_proposal(const update_proposal_t *prop, const uint8_t *signer_pk)
{
    if (prop == NULL || signer_pk == NULL)
        return false;
    return update_proposal_verify(prop, signer_pk) == 0;
}

bool fleet_check_reputation_threshold(double peer_reputation, double min_threshold)
{
    return peer_reputation >= min_threshold;
}

bool fleet_should_accept_proposal(const update_proposal_t *prop,
                                  const uint8_t *signer_pk,
                                  double proposer_reputation)
{
    if (!fleet_validate_proposal(prop, signer_pk))
        return false;
    return fleet_check_reputation_threshold(proposer_reputation, prop->min_proposer_reputation);
}
