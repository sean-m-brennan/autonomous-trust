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
"""Direct messages (Increment 6).

A DM is a single directed, ENCRYPTED, one-way peer->peer text message carrying
{text, seq, ts}. crypto_box authenticates the sender on the wire, so — UNLIKE
the connection accept — there is NO signature and NO canonical byte form: the
payload is plain JSON. So the twin of the C dm_test.c here pins the only shared
contract: the body bound (bound_dm_text, matching C at_dm_bound_text /
AT_DM_TEXT_MAX), and that the peer_dm verb is never accepted in plaintext.

The freshness/replay gate and the deliver-to-app path are exercised end-to-end
by the conformance scenarios (dm-*.yaml, both runtimes).
"""
from autonomous_trust.core import capabilities


def test_body_within_bound_is_kept_whole():
    assert capabilities.bound_dm_text('hello there') == 'hello there'
    assert capabilities.bound_dm_text('') == ''


def test_body_over_bound_is_truncated():
    big = 'x' * (capabilities.DM_TEXT_MAX + 64)
    out = capabilities.bound_dm_text(big)
    assert len(out.encode('utf-8')) == capabilities.DM_TEXT_MAX


def test_bound_dm_text_never_splits_a_utf8_char():
    # A body of multi-byte chars truncated at the byte bound must stay valid
    # UTF-8 (never a half char) — mirrors _clamp_bytes' char-safe truncation.
    big = 'é' * capabilities.DM_TEXT_MAX  # 2 bytes each -> well over the bound
    out = capabilities.bound_dm_text(big)
    assert len(out.encode('utf-8')) <= capabilities.DM_TEXT_MAX
    out.encode('utf-8').decode('utf-8')  # would raise if a char were split


def test_non_string_body_is_empty():
    assert capabilities.bound_dm_text(None) == ''
    assert capabilities.bound_dm_text(123) == ''


def test_dm_verb_not_in_unencrypted_allowlist():
    from autonomous_trust.core.identity.protocol import (IdentityProtocol,
                                                         UNENCRYPTED_VERBS)
    assert IdentityProtocol.dm not in UNENCRYPTED_VERBS
