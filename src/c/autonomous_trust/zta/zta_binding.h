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

#ifndef ZTA_BINDING_H
#define ZTA_BINDING_H

/** @addtogroup internal_zta
 *  @{
 */

/**
 * @file
 * @brief The ZTA credential binding: which node a credential authorizes, and the
 *        proof (ISSUES §1.5). C twin of Python `identity/zta_binding.py`.
 *
 * A chain-valid certificate says nothing about *who may present it*. That is the
 * whole of §1.5: a credential lifted from another peer's clear-text `announce`
 * chains to the agency CA exactly as well under a different uuid, so the admission
 * gate had no way to tell holder from thief and fell back on first-use-wins. TOFU
 * is not a weakness of ZTA; it is what is left when the credential->identity
 * binding is *inferred* rather than *asserted*. Assert it and the ambiguity goes.
 *
 * Three mechanisms assert it and any one suffices (@ref zta_identity_is_bound):
 *
 *  - **Holder-asserted**, the general case. The credential's own private key signs
 *    @ref zta_binding_preimage. Needs nothing from the issuer, which is what makes
 *    bridging foreign agency CAs possible at all — AT cannot ask another agency to
 *    mint certificates on its terms, only to be presented by a holder who can
 *    prove possession. Shape follows TLS 1.3 `CertificateVerify`, DPoP (RFC 9449),
 *    WebAuthn.
 *  - **CA-asserted**: a URI SAN naming the node, SPIFFE/IDevID style. Stronger
 *    where AT controls issuance, and unavailable where it does not.
 *  - **Operator-key binding**: already a signature by the credential's key over
 *    bytes naming the node, so it answers this question too.
 *
 * The three are not equal and the difference is worth stating rather than glossing:
 * the holder signature covers the uuid AND the node's signing key, while a SAN
 * names only the uuid, so a SAN match leans on the existing Sybil uuid/key-collision
 * checks to stop a peer announcing a victim's uuid under its own key. All three
 * close the §1.5 threat, which is a credential moving to a *different* identity.
 *
 * **Durable, not a live challenge-response.** No nonce, deliberately, and for the
 * same reason operator attestation is consumer-pull: a binding must verify offline
 * and through a relay under DDIL, with no round trip to the peer or the CA. A
 * nonce-free pre-image is replayable in *time*, which costs nothing — it authorizes
 * exactly one identity, forever, which is precisely what it is for.
 */

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "identity/identity.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Whether the holder of @p cred's private key authorized @p ident to
 *        present it (the holder-asserted binding).
 *
 * Answers only that one question. The caller must separately establish that the
 * credential chains to a configured anchor and is unrevoked — a binding by a
 * credential that chains nowhere authorizes nothing.
 *
 * Absence and forgery are deliberately NOT distinguished by the return value.
 * They differ enormously in meaning, so the admission gate distinguishes them
 * itself by asking whether a binding was offered at all: unbound is a provisioning
 * state, a bad binding is evidence of forgery, and they earn different verdicts.
 *
 * @return false on a missing or oversized binding, an empty credential, or a
 *         signature that does not verify.
 */
bool zta_verify_binding(const public_identity_t *ident,
                        const uint8_t *cred, size_t cred_len,
                        const uint8_t *binding, size_t binding_len);

/**
 * @brief Whether @p cred itself names @p ident in a URI SAN (the CA-asserted
 *        binding), rendering @p san_format with the node's uuid.
 *
 * @param san_format `printf` format taking one `%s` (the canonical lower-case
 *        uuid), e.g. @ref ZTA_SAN_URI_FORMAT. NULL or empty disables the check,
 *        which is how a deployment says "holder-asserted signatures only".
 */
bool zta_san_binds_identity(const uint8_t *cred, size_t cred_len,
                            const public_identity_t *ident,
                            const char *san_format);

/**
 * @brief Whether an *operator-key* binding also serves as this credential's
 *        binding. It does, and not by coincidence.
 *
 * The operator pre-image is
 *
 *     OPERATOR_BINDING_TAG || uuid || node signing key || operator_pubkey
 *
 * signed by the **credential's** private key. The question this module asks — did
 * the credential's holder authorize this node to present it — is answered by any
 * signature from that key over bytes naming this node, and those bytes name it. A
 * node already carrying a verifying operator-key binding has therefore already
 * proven entitlement, and demanding a second signature would cost another operator
 * session for nothing.
 *
 * Narrower than it looks, so worth being plain: it only helps a node that opted in
 * to publishing a guardian key. Opting in is a persistent pseudonym linking that
 * operator's nodes, which AT will not require, so most nodes still need a
 * credential binding of their own.
 *
 * @param operator_pubkey The CLAIMED guardian key, passed explicitly because the
 *        admission gate moves it aside and zeroes the peer's own copy before
 *        anything is verified.
 */
bool zta_operator_binding_binds_identity(const public_identity_t *ident,
                                         const uint8_t *cred, size_t cred_len,
                                         const uint8_t *operator_pubkey,
                                         const uint8_t *binding,
                                         size_t binding_len);

/**
 * @brief Whether @p cred is bound to @p ident by ANY accepted mechanism.
 *
 * Ordered cheapest-and-strongest first: the holder-asserted signature covers the
 * signing key as well as the uuid and is a single local verify; the SAN path parses
 * the certificate again; the operator route parses it and builds a second pre-image,
 * and applies only to a node that opted in to a guardian key.
 *
 * The operator arguments are explicit for the same reason as above — by the time
 * this runs the peer's own copy of the claimed key is already cleared, so the
 * caller must hand over what it moved aside.
 */
bool zta_identity_is_bound(const public_identity_t *ident,
                           const uint8_t *cred, size_t cred_len,
                           const uint8_t *binding, size_t binding_len,
                           const char *san_format,
                           const uint8_t *operator_pubkey,
                           const uint8_t *operator_binding,
                           size_t operator_binding_len);

#ifdef __cplusplus
} /* extern "C" */
#endif

/** @} */ /* end of internal_zta */

#endif /* ZTA_BINDING_H */
