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
/* The conformance adapters extensions register with at_conformance_adapter()
 * (extensions/at_extension.cmake): the table is generated at configure time
 * (conformance_registry.c in the build tree) and read by runner.c's dispatch
 * after its built-in protocols. */
#ifndef AT_CONFORMANCE_REGISTRY_H
#define AT_CONFORMANCE_REGISTRY_H

#include "scenario_loader.h"
#include "case_result.h"

typedef struct {
    const char *protocol;
    void (*run)(const at_case_t *c, at_case_result_t *out);
} at_conf_adapter_t;

/** NULL-terminated. */
extern const at_conf_adapter_t at_conf_ext_adapters[];

#endif /* AT_CONFORMANCE_REGISTRY_H */
