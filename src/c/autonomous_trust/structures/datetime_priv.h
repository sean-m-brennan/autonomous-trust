/********************
 *  Copyright 2024 TekFive, Inc. and contributors
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

#ifndef DATETIME_PRIV_H
#define DATETIME_PRIV_H

#include "datetime.h"
#include "structures/datetime.pb-c.h"

int datetime_sync_out(datetime_t *dt, AutonomousTrust__Core__Structures__DateTime *proto);

int datetime_sync_in(AutonomousTrust__Core__Structures__DateTime *proto, datetime_t *dt);


int timedelta_sync_out(timedelta_t *td, AutonomousTrust__Core__Structures__TimeDelta *proto);

int timedelta_sync_in(AutonomousTrust__Core__Structures__TimeDelta *proto, timedelta_t *td);

#endif  // DATETIME_PRIV_H
