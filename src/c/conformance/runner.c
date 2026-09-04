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

/** @file Conformance runner — C harness entry point.
 *
 *  Usage: conformance_runner <corpus_json_root> <results_out_path>
 *
 *  - corpus_json_root: directory containing index.json + scenarios/ + vectors/,
 *    produced by `python -m tools.corpus_to_json`.
 *  - results_out_path: where to write the per-run results JSON. Format
 *    matches the Python harness so the diff tool can compare apples to
 *    apples.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <jansson.h>
#include <sodium.h>

#include "scenario_loader.h"
#include "case_result.h"
#include "adapters/network.h"
#include "adapters/identity.h"
#include "adapters/agreement.h"
#include "adapters/negotiation.h"
#include "adapters/reputation.h"
#include "adapters/bootstrap.h"
#include "adapters/physics.h"
#include "adapters/calibration.h"
#include "adapters/certificate.h"

/* Adapters that handle kind:negative need the JSON corpus root to resolve
 * `based_on` references; one runner invocation processes one root, so a
 * process-global is the simplest plumbing. */
static const char *g_corpus_json_root = NULL;
const char *at_runner_corpus_json_root(void) { return g_corpus_json_root; }

/* Adapter dispatch keyed on protocol. Every adapter knows what kinds it
 * handles and emits skip for anything else. */
static void dispatch(const at_case_t *c, at_case_result_t *out) {
    if (strcmp(c->protocol, "network") == 0) {
        at_network_run(c, out);
    } else if (strcmp(c->protocol, "identity") == 0) {
        at_identity_run(c, out);
    } else if (strcmp(c->protocol, "agreement") == 0) {
        at_agreement_run(c, out);
    } else if (strcmp(c->protocol, "negotiation") == 0) {
        at_negotiation_run(c, out);
    } else if (strcmp(c->protocol, "reputation") == 0) {
        at_reputation_run(c, out);
    } else if (strcmp(c->protocol, "bootstrap") == 0) {
        at_bootstrap_run(c, out);
    } else if (strcmp(c->protocol, "physics") == 0) {
        at_physics_run(c, out);
    } else if (strcmp(c->protocol, "certificate") == 0) {
        at_certificate_run(c, out);
    } else if (strcmp(c->protocol, "calibration") == 0) {
        at_calibration_run(c, out);
    } else {
        char detail[160];
        snprintf(detail, sizeof(detail),
                 "no C adapter for protocol %s (kind=%s)",
                 c->protocol, c->kind);
        at_case_result_set_skip(out, detail);
    }
}

static const char *iso8601_now(char *buf, size_t n) {
    time_t t = time(NULL);
    struct tm tm;
    gmtime_r(&t, &tm);
    strftime(buf, n, "%Y-%m-%dT%H:%M:%SZ", &tm);
    return buf;
}

static int write_results(const char *path,
                         const at_case_result_t *results, size_t n) {
    json_t *report = json_object();
    json_object_set_new(report, "implementation", json_string("c"));
    /* Implementation version: leave as "unknown" for now; CI can stamp the
     * git sha externally if needed. */
    json_object_set_new(report, "implementation_version", json_string("unknown"));
    json_object_set_new(report, "schema_version", json_string("1"));
    char ts[32];
    iso8601_now(ts, sizeof(ts));
    json_object_set_new(report, "started_at", json_string(ts));

    json_t *cases = json_array();
    for (size_t i = 0; i < n; i++) {
        json_array_append_new(cases, at_case_result_to_json(&results[i]));
    }
    json_object_set_new(report, "cases", cases);

    int rc = json_dump_file(report, path, JSON_INDENT(2));
    json_decref(report);
    return rc;
}

int main(int argc, char **argv) {
    if (argc < 3) {
        fprintf(stderr, "usage: %s <corpus_json_root> <results_out_path>\n", argv[0]);
        return 2;
    }
    if (sodium_init() < 0) {
        fprintf(stderr, "sodium_init failed\n");
        return 1;
    }

    const char *corpus = argv[1];
    const char *results_path = argv[2];
    g_corpus_json_root = corpus;

    at_case_t *cases = NULL;
    size_t n = 0;
    if (at_load_corpus(corpus, &cases, &n) != 0) {
        fprintf(stderr, "failed to load corpus from %s\n", corpus);
        return 1;
    }

    at_case_result_t *results = calloc(n, sizeof(at_case_result_t));
    if (results == NULL) {
        fprintf(stderr, "oom\n");
        return 1;
    }

    size_t pass = 0, fail = 0, skip = 0;
    for (size_t i = 0; i < n; i++) {
        at_case_result_init(&results[i], cases[i].case_id);
        dispatch(&cases[i], &results[i]);
        switch (results[i].status) {
            case AT_PASS: pass++; break;
            case AT_FAIL: fail++; break;
            case AT_SKIP: skip++; break;
        }
    }

    if (write_results(results_path, results, n) != 0) {
        fprintf(stderr, "failed to write results to %s\n", results_path);
    } else {
        printf("wrote %s: %zu cases, %zu pass, %zu fail, %zu skip\n",
               results_path, n, pass, fail, skip);
    }

    /* Print failed cases inline for quick visibility. */
    for (size_t i = 0; i < n; i++) {
        if (results[i].status == AT_FAIL) {
            fprintf(stderr, "  FAIL %s: %s\n",
                    results[i].case_id,
                    results[i].detail ? results[i].detail : "(no detail)");
        }
    }

    int exit_code = (fail > 0) ? 1 : 0;

    for (size_t i = 0; i < n; i++) {
        at_case_result_free(&results[i]);
        at_case_free(&cases[i]);
    }
    free(results);
    free(cases);
    return exit_code;
}
