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

#ifndef AT_CONFORMANCE_CASE_RESULT_H
#define AT_CONFORMANCE_CASE_RESULT_H

#include <stddef.h>

#include <jansson.h>

typedef enum {
    AT_PASS = 0,
    AT_FAIL = 1,
    AT_SKIP = 2,
} at_status_t;

typedef struct {
    char *case_id;       /**< owns. */
    at_status_t status;
    int duration_ms;
    char *detail;        /**< owns; NULL-able. */
    char *reason_class;  /**< owns; NULL-able. */
    int rejected_at_step;/**< -1 if not applicable. */
} at_case_result_t;

void at_case_result_init(at_case_result_t *r, const char *case_id);
void at_case_result_set_pass(at_case_result_t *r, int duration_ms);
void at_case_result_set_fail(at_case_result_t *r, int duration_ms,
                             const char *reason_class, const char *detail);
void at_case_result_set_skip(at_case_result_t *r, const char *detail);
void at_case_result_free(at_case_result_t *r);

/** Build the JSON object for one case result. Caller owns the returned ref. */
json_t *at_case_result_to_json(const at_case_result_t *r);

#endif /* AT_CONFORMANCE_CASE_RESULT_H */
