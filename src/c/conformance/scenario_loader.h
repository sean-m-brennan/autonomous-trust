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

#ifndef AT_CONFORMANCE_LOADER_H
#define AT_CONFORMANCE_LOADER_H

/** @file Scenario / vector loader (C harness).
 *
 *  Reads JSON mirrors of the conformance corpus produced by
 *  `tools/corpus_to_json.py`. The C harness never touches YAML directly;
 *  the Python preprocessor is the single parser of the on-disk format.
 */

#include <stdbool.h>
#include <stddef.h>

#include <jansson.h>

/** A single corpus case in the form the C runner consumes. */
typedef struct {
    char *case_id;     /**< owns the heap. e.g. "network/ed25519-rfc8032-test1#df625b" */
    char *kind;        /**< owns. one of: scenario|wire_vector|crypto_vector|negative|agreement_vector */
    char *protocol;    /**< owns. one of: identity|reputation|negotiation|network|agreement */
    char *name;        /**< owns. */
    char *source_path; /**< owns. relative to corpus root, original .yaml path */
    json_t *data;      /**< borrowed reference into a parent root_obj. */
    json_t *_root;     /**< owns. holds data alive; free via json_decref. */
} at_case_t;

/** Load the index.json and every case it lists.
 *
 *  @param json_root  Root of the JSON corpus mirror (the directory that
 *                    holds `index.json` plus `scenarios/` and `vectors/`).
 *  @param[out] cases Newly allocated array of cases (caller frees each via
 *                    at_case_free() and `free(cases)`).
 *  @param[out] n     Count of cases written.
 *  @return 0 on success, non-zero on I/O or parse failure.
 */
int at_load_corpus(const char *json_root, at_case_t **cases, size_t *n);

/** Release heap fields and the underlying JSON root. */
void at_case_free(at_case_t *c);

/** Return the corpus root passed to the last successful at_load_corpus()
 *  call, or NULL if no corpus has been loaded.  Lifetime is bounded by
 *  the next at_load_corpus() call (the returned pointer is owned by the
 *  loader and stays valid until then). */
const char *at_corpus_root(void);

/** Load a testdata file by its corpus-relative path.  On success returns
 *  0, sets *out to a newly-malloc'd buffer holding @p out_len bytes, and
 *  the caller must free(*out).  Refuses paths that escape the corpus
 *  root via `..` segments. */
int at_load_testdata_bytes(const char *rel_path, char **out, size_t *out_len);

#endif /* AT_CONFORMANCE_LOADER_H */
