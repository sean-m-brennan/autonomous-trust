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

#include "case_result.h"

#include <stdlib.h>
#include <string.h>

static char *xstrdup_n(const char *s) {
    if (s == NULL) return NULL;
    size_t n = strlen(s) + 1;
    char *r = malloc(n);
    if (r == NULL) return NULL;
    memcpy(r, s, n);
    return r;
}

void at_case_result_init(at_case_result_t *r, const char *case_id) {
    memset(r, 0, sizeof(*r));
    r->case_id = xstrdup_n(case_id);
    r->rejected_at_step = -1;
    r->status = AT_SKIP;
}

void at_case_result_set_pass(at_case_result_t *r, int duration_ms) {
    r->status = AT_PASS;
    r->duration_ms = duration_ms;
    free(r->detail); r->detail = NULL;
    free(r->reason_class); r->reason_class = NULL;
}

void at_case_result_set_fail(at_case_result_t *r, int duration_ms,
                             const char *reason_class, const char *detail) {
    r->status = AT_FAIL;
    r->duration_ms = duration_ms;
    free(r->reason_class);
    r->reason_class = xstrdup_n(reason_class);
    free(r->detail);
    r->detail = xstrdup_n(detail);
}

void at_case_result_set_skip(at_case_result_t *r, const char *detail) {
    r->status = AT_SKIP;
    free(r->detail);
    r->detail = xstrdup_n(detail);
}

void at_case_result_free(at_case_result_t *r) {
    if (r == NULL) return;
    free(r->case_id);
    free(r->detail);
    free(r->reason_class);
    memset(r, 0, sizeof(*r));
}

json_t *at_case_result_to_json(const at_case_result_t *r) {
    json_t *obj = json_object();
    json_object_set_new(obj, "case_id", json_string(r->case_id ? r->case_id : ""));
    const char *status =
        r->status == AT_PASS ? "pass" :
        r->status == AT_FAIL ? "fail" : "skip";
    json_object_set_new(obj, "status", json_string(status));
    if (r->duration_ms > 0) {
        json_object_set_new(obj, "duration_ms", json_integer(r->duration_ms));
    }
    if (r->detail != NULL) {
        json_object_set_new(obj, "detail", json_string(r->detail));
    }
    if (r->reason_class != NULL) {
        json_object_set_new(obj, "reason_class", json_string(r->reason_class));
    }
    if (r->rejected_at_step >= 0) {
        json_object_set_new(obj, "rejected_at_step", json_integer(r->rejected_at_step));
    }
    return obj;
}
