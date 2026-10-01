# ******************
#  Copyright 2026 TekFive, Inc., Sean M. Brennan, and contributors
#
#   Licensed under the Apache License, Version 2.0 (the "License");
#   you may not use this file except in compliance with the License.
#   You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
#   Unless required by applicable law or agreed to in writing, software
#   distributed under the License is distributed on an "AS IS" BASIS,
#   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#   See the License for the specific language governing permissions and
#   limitations under the License.
# ******************
"""Verifying an operator-key binding (FEATURE_SPLIT_PLAN Phase 6). The binding
format, its pre-image and its bounds are the core's
(``autonomous_trust.core.identity.operator_binding``); checking one is ZTA's,
on its admission path, because it needs an operator-class credential. Without
this extension a binding is never verified, so no peer is credited with a
guardian key -- the fail-safe the core's ``operator_bound`` already takes.
"""
from __future__ import annotations

from typing import Optional

from autonomous_trust.core.identity.operator_binding import (
    OPERATOR_BINDING_MAX, OPERATOR_PUBKEY_LEN, operator_binding_preimage)

from .signature import verify_cert_signature


def verify_operator_binding(identity, cert_der: bytes,
                            operator_pubkey: Optional[bytes] = None,
                            binding: Optional[bytes] = None) -> bool:
    """Whether `identity`'s advertised guardian key is bound to it by the holder
    of `cert_der`'s private key.

    The caller must already have established that `cert_der` is **operator-class**
    (chains to the distinct operator anchor) — this answers only "did that
    credential's holder sign *this* node's key". Both are required: a chain without
    a binding names no human, and a binding whose credential is not operator-class
    is a human with no standing to name one.

    Returns False (never raises) for a missing key or binding, a wrong-length key,
    an oversized binding, or a signature that does not verify. Absence and forgery
    are distinguished by the *caller's* logging, not by the return value: for the
    guardian edge both mean "no guardian recorded".
    """
    key = operator_pubkey if operator_pubkey is not None else getattr(
        identity, 'operator_pubkey', b'') or b''
    sig = binding if binding is not None else getattr(
        identity, 'operator_key_binding', b'') or b''
    if len(key) != OPERATOR_PUBKEY_LEN:
        return False
    if not sig or len(sig) > OPERATOR_BINDING_MAX:
        return False
    if not cert_der:
        return False
    try:
        pre = operator_binding_preimage(identity, key)
    except (ValueError, AttributeError, TypeError):
        return False
    return verify_cert_signature(cert_der, pre, sig)
