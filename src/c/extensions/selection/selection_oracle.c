/********************
 *  Copyright 2026 TekFive, Inc., Sean M. Brennan, and contributors
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

/* Selective assignment scores nothing, so it only declares itself, which is
 * what lets a node honour $AT_SELECTION. The C twin of Python
 * selection/oracle.py. */

#include "at_selection.h"
#include "negotiation/neg_oracle.h"

static const neg_oracle_t selection_oracle = { .name = "selection" };

static void __attribute__((constructor)) selection_oracle_register(void)
{
    (void)neg_oracle_register(&selection_oracle);
}

void at_selection_live_link(void);

void at_selection_link(void) { at_selection_live_link(); }
