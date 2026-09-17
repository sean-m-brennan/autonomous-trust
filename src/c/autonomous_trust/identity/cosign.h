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

/**
 * @file cosign.h
 * @brief Detached co-signing exchange: wire JSON round-trip (Phase 3 P3.3).
 *
 * A staff roll act — admitting, expelling, designating a machine, moving or
 * releasing its guardian — is decided by several people who are not at the same
 * keyboard. The record travels; the KEYS DO NOT. One node exports the canonical
 * bytes, every required signer signs those bytes on their own node, and the
 * authoring node reassembles the signatures onto the payload.
 *
 * Two directed, ENCRYPTED peer→peer messages carry that, exactly like a DM:
 * crypto_box authenticates the sender, so there is no extra Ed25519 signature on
 * the envelope and no canonical byte form for the message itself.
 *
 * **The core verifies nothing about what is being signed, and cannot.** @c bytes
 * is opaque Ethne canonical CBOR, carried as hex; the core holds no Ethne, just
 * as it holds no verifier for a business page bundle. What it does do is bound
 * and shape-check the fields, so a malformed ask is refused here rather than
 * surfacing as a payload that reproduces to nothing.
 *
 * **What deliberately does NOT cross: the description.** The wording of what a
 * record commits to is derived on the SIGNER's node, from the bytes it is about
 * to sign (`ethne_describe`). If the asking node supplied the sentence as well
 * as the payload, it would choose both what you sign and what you are told you
 * are signing — a friendly wording over hostile bytes, with a real signature on
 * the end. That is the exact failure the detached seam exists to prevent, moved
 * one layer up, so the wording is never carried.
 */

#ifndef AUTONOMOUS_TRUST_IDENTITY_COSIGN_H
#define AUTONOMOUS_TRUST_IDENTITY_COSIGN_H

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include <jansson.h>

/* Max hex characters of the exported canonical bytes (excluding NUL), so half
 * this many bytes of CBOR. MUST match AT_COSIGN_BYTES_LEN
 * (utilities/msg_types.h), AT_APP_COSIGN_BYTES_LEN (app_events.h),
 * COSIGN_BYTES_HEX_MAX in the agora ethne_ffi crate, and AGORA_COSIGN_BYTES_MAX
 * in the shim / cohort ctypes.
 *
 * MEASURED against real exchanges, not guessed (see
 * `the_wire_bound_holds_for_a_realistic_exchange` in ethne_ffi): a membership
 * admission runs 666 hex; a guardian designation carrying a real observation
 * runs 2142 for a small polity, and 4192 for a majority of thirty staff with a
 * long rationale. What moves the number is almost entirely the EVIDENCE, about
 * 372 hex per additional reading in the cited observation — which is why an
 * exchange cites an observation scoped to the member in question rather than a
 * whole peer-table sweep. The authoring side refuses an oversized exchange
 * outright: truncating a payload whose entire purpose is to be reproduced byte
 * for byte would produce a signature over nothing. */
#define AT_COSIGN_BYTES_MAX 6144
/* Max bytes of a polity DID (same width as a business polity DID). */
#define AT_COSIGN_DID_MAX 95
/* Exchange content id as Ethne prints it: "b3:" + 64 lowercase hex. */
#define AT_COSIGN_CID_MAX 67
/* An Ed25519 signature as lowercase hex (64 bytes -> 128 chars). */
#define AT_COSIGN_SIG_MAX 128
/* A record-class or op token ("membership", "guardian", "designate", …). */
#define AT_COSIGN_TOKEN_MAX 15

/* Copy @p in into @p out (capacity @p out_sz including the NUL), truncated to at
 * most @p max bytes AND to fit @p out_sz. Always NUL-terminates when
 * @p out_sz > 0. Returns bytes written (excluding NUL); NULL @p in yields "". */
size_t at_cosign_bound(const char *in, char *out, size_t out_sz, size_t max);

/* Whether @p s is a plausible exported payload: non-empty, at most
 * AT_COSIGN_BYTES_MAX characters, an EVEN number of them, and all lowercase
 * hex. An odd or non-hex string never came from an exporter, and a truncated one
 * reproduces to nothing, so both are refused rather than carried. */
bool at_cosign_bytes_ok(const char *s);

/* Whether (@p record, @p op) name an exchange this build understands:
 * "membership" with admit/expel, or "guardian" with designate/rotate/release.
 * A voluntary departure is self-signed by one person and never exchanged. */
bool at_cosign_op_ok(const char *record, const char *op);

/* Build a NEW json object (caller decrefs) holding
 * {"record","op","polity","cid","bytes","seq","ts"}, each field bound-truncated.
 * Returns NULL on allocation error or if the op/bytes are not well formed. */
json_t *at_cosign_request_to_json(const char *record, const char *op,
                                  const char *polity, const char *cid,
                                  const char *bytes, int64_t seq, double ts);

/* Parse a peer_cosign_request payload. Requires an integer seq, a numeric ts,
 * string fields, a known (record, op) and well-formed bytes; on success each
 * out buffer is filled (bound-truncated, always NUL-terminated). Returns 0 on
 * success, non-zero on a malformed payload. Unknown keys are ignored. */
int at_cosign_request_from_json(const json_t *obj,
                                char *record_out, size_t record_sz,
                                char *op_out, size_t op_sz,
                                char *polity_out, size_t polity_sz,
                                char *cid_out, size_t cid_sz,
                                char *bytes_out, size_t bytes_sz,
                                int64_t *seq_out, double *ts_out);

/* Build a NEW json object (caller decrefs) holding
 * {"cid","signer","sig","seq","ts"}. The signature is the signer's detached
 * Ed25519 over the exported bytes, as lowercase hex; @p signer is the signer's
 * did:key, which EMBEDS its public key — so the assembling node needs no
 * registry to check it, and the core needs none to carry it. */
json_t *at_cosign_sig_to_json(const char *cid, const char *signer,
                              const char *sig, int64_t seq, double ts);

/* Parse a peer_cosign_sig payload {"cid","signer","sig","seq","ts"}. Returns 0
 * on success, non-zero on a malformed payload. */
int at_cosign_sig_from_json(const json_t *obj,
                            char *cid_out, size_t cid_sz,
                            char *signer_out, size_t signer_sz,
                            char *sig_out, size_t sig_sz,
                            int64_t *seq_out, double *ts_out);

#endif /* AUTONOMOUS_TRUST_IDENTITY_COSIGN_H */
