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
 ********************/
#ifndef CONFIGURATION_PRIV_H
#define CONFIGURATION_PRIV_H

#include "structures/map_priv.h"
#include "structures/data_priv.h"

#include "config/configuration.h"

config_t *find_configuration(const char *name);

#endif  /* CONFIGURATION_PRIV_H */
