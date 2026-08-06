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

#ifndef AT_CONFORMANCE_NEGATIVE_H
#define AT_CONFORMANCE_NEGATIVE_H

/** @file Negative-case runner for the C conformance harness.
 *
 *  Mirrors `src/autonomous-trust/conformance/harness/common/negative_runner.py`.
 *  A negative case takes a clean wire buffer produced for some step of a
 *  base scenario, mutates it deterministically, and asks
 *  net_message_from_wire() to refuse the result. The expected refusal
 *  category is pinned in `expected.reason_class`.
 *
 *  v1 supports flip_byte/signature and truncate/wire_bytes; other ops
 *  trigger skip.
 */

#include <stddef.h>
#include <stdint.h>

#include <jansson.h>

#include "case_result.h"
#include "scenario_loader.h"

/** Resolve a `based_on` YAML path (relative to the corpus root) to the
 *  on-disk JSON path inside the C harness's corpus mirror.
 *
 *  @param corpus_json_root  Base of the JSON corpus mirror.
 *  @param based_on          e.g. "scenarios/identity/new-node-admission.yaml".
 *  @param[out] out_path     Heap-allocated; caller free()s.
 *  @return 0 on success.
 */
int at_neg_resolve_based_on(const char *corpus_json_root, const char *based_on,
                            char **out_path);

/** Load a single corpus case JSON file (the precompiled mirror).
 *  @param[out] out_root  jansson root; caller json_decref()s.
 *  @return 0 on success.
 */
int at_neg_load_base_case(const char *path, json_t **out_root);

/** Apply one mutation directive to a JSON wire buffer.
 *
 *  @param in_buf   Input bytes (clean wire form).
 *  @param in_len   Length of @p in_buf.
 *  @param mutation Mutation directive (object with op/target/index/value).
 *  @param[out] out_buf  Heap-allocated mutated bytes; caller free()s.
 *  @param[out] out_len  Length of @p *out_buf.
 *  @return 0 on success; -1 if the mutation is malformed; -2 if v1 doesn't
 *          support the op (caller should treat as skip).
 */
int at_neg_apply_mutation(const uint8_t *in_buf, size_t in_len,
                          json_t *mutation, uint8_t **out_buf, size_t *out_len);

/** Return the reason_class implied by the mutation's intent.
 *  Mirrors Python's classify_op(). Returns a static string; never NULL.
 */
const char *at_neg_classify_op(json_t *mutation);

/** Run a kind:negative case end-to-end and write the observed reason_class
 *  to @p out_result. Protocol-agnostic: the caller passes the case data
 *  and the result struct; this routine handles based_on resolution,
 *  identity minting, message construction, mutation, parse, and
 *  comparison against expected.reason_class.
 *
 *  @return 0 on success (out_result populated with PASS or FAIL),
 *          -1 on internal setup failure.
 */
int at_neg_run_wire(const at_case_t *c, at_case_result_t *out_result);

#endif /* AT_CONFORMANCE_NEGATIVE_H */
