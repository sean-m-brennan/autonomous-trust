/* ******************
 *  Copyright 2026 Sean M. Brennan and contributors
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
 * ****************** */

/* Cross-language parity test for the C JCS canonicalizer.
 *
 * Each fixture is an (input, expected) pair where `expected` is the byte
 * output of Python's `jcs.canonicalize(json.loads(input))`. This test
 * fails if the C side diverges from the Python reference, catching drift
 * between the two implementations before it leaks into the conformance
 * corpus's byte-pinned scenarios.
 *
 * Reference vectors are generated in lockstep with
 * src/autonomous-trust/conformance/harness/common/tests/test_canonical.py;
 * keep both in sync when adding edge cases. */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "test_setup.h"

#include "../conformance/jcs.h"

typedef struct {
    const char *name;
    const char *input;
    const char *expected;
} jcs_case_t;

static const jcs_case_t CASES[] = {
    {"plain object",
     "{\"b\": 2, \"a\": 1}",
     "{\"a\":1,\"b\":2}"},
    {"nested objects",
     "{\"outer\": {\"z\": 1, \"a\": {\"y\": 2, \"x\": 3}}}",
     "{\"outer\":{\"a\":{\"x\":3,\"y\":2},\"z\":1}}"},
    {"integer-valued float",
     "{\"n\": 1.0}",
     "{\"n\":1}"},
    {"plain float 0.8",
     "{\"n\": 0.8}",
     "{\"n\":0.8}"},
    {"small float 0.1",
     "{\"n\": 0.1}",
     "{\"n\":0.1}"},
    {"negative zero",
     "{\"n\": -0.0}",
     "{\"n\":0}"},
    {"utf-8 string",
     "{\"s\": \"h\\u00e9llo\"}",
     "{\"s\":\"h\xc3\xa9llo\"}"},
    {"array order preserved",
     "[3, 1, 2]",
     "[3,1,2]"},
    {"booleans and null",
     "{\"t\": true, \"f\": false, \"n\": null}",
     "{\"f\":false,\"n\":null,\"t\":true}"},
    {"control char in string",
     "{\"s\": \"a\\u0001b\"}",
     "{\"s\":\"a\\u0001b\"}"},
    {"large int near 2^53",
     "{\"n\": 9007199254740991}",
     "{\"n\":9007199254740991}"},
    {"small float 0.0001",        "{\"n\":0.0001}",   "{\"n\":0.0001}"},
    {"small float 1e-5",          "{\"n\":1e-5}",     "{\"n\":0.00001}"},
    {"small float 1e-6",          "{\"n\":1e-6}",     "{\"n\":0.000001}"},
    {"small float 1e-7 -> sci",   "{\"n\":1e-7}",     "{\"n\":1e-7}"},
    {"large float 1e20 -> int",   "{\"n\":1e20}",     "{\"n\":100000000000000000000}"},
    {"large float 1e21 -> sci",   "{\"n\":1e21}",     "{\"n\":1e+21}"},
    {"midrange 12345.678",        "{\"n\":12345.678}","{\"n\":12345.678}"},
    {"negative 0.5",              "{\"n\":-0.5}",     "{\"n\":-0.5}"},
};

DEFINE_TEST(test_jcs_parity)
{
    int fails = 0;
    for (size_t i = 0; i < sizeof(CASES) / sizeof(CASES[0]); ++i) {
        const jcs_case_t *tc = &CASES[i];
        char *out = NULL;
        size_t out_len = 0;
        int rc = jcs_canonicalize(tc->input, strlen(tc->input), &out, &out_len);
        if (rc != 0) {
            fprintf(stderr, "%s: jcs_canonicalize returned %d\n", tc->name, rc);
            ++fails;
            continue;
        }
        if (out_len != strlen(tc->expected) ||
            memcmp(out, tc->expected, out_len) != 0) {
            fprintf(stderr, "%s:\n  expected: %s\n  actual:   %s\n",
                    tc->name, tc->expected, out);
            ++fails;
        }
        free(out);
    }
    ck_assert_int_eq(fails, 0);
}
END_TEST_DEFINITION()

RUN_TESTS(jcs_test, test_jcs_parity)
