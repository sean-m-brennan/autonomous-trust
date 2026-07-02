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

/* Frama-C stub wrapper: redirect <sodium.h> to ACSL-annotated stubs.
   Since -I stubs/ precedes -I $CONDA_PREFIX/include, this file is
   found first, preventing Frama-C from parsing the real libsodium. */
#ifndef SODIUM_H
#define SODIUM_H
#include "sodium_stubs.h"
#endif /* SODIUM_H */
