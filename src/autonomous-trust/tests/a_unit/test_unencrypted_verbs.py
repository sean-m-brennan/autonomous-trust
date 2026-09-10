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
"""
Plaintext acceptance from a KNOWN peer, bounded by an allowlist.

The point-to-point receive path attributes a frame by source address and then
decrypts it. Once a peer is in the listing, every frame from it takes the decrypt
branch -- so verbs the protocol sends in plaintext by design (`encrypt=False`),
which by definition cannot be decrypted, were dropped. Measured: 1-3 drops per
two-peer run, all of them `access_granted`, and it cost 3-peer convergence
outright (`test_harness_three_peers_converge` failed with peers 1 and 2 each
missing peer 0; adding the fallback made it pass).

The gate is deliberately narrow. Plaintext acceptance is not new -- the
unknown-sender branch has always tried a plaintext parse first -- but a peer in
the listing must not be able to downgrade an arbitrary message to plaintext and
have it honored. Three conditions, all required: it parses, its own `encrypt`
flag is false, and the verb is in `UNENCRYPTED_VERBS`. The refusal cases below
are the load-bearing half of this file.
"""
from __future__ import annotations

import ast
import os
from unittest.mock import MagicMock

import pytest

from autonomous_trust.core.identity.protocol import (
    IdentityProtocol,
    UNENCRYPTED_VERBS,
)
from autonomous_trust.core.network.netprocess import NetworkProcess
from autonomous_trust.core.reputation import ReputationProtocol


def _envelope(function, encrypt=False, process='identity'):
    """A minimal JSON wire envelope, the shape Message.parse accepts."""
    return ('{"process":"%s","function":"%s","encrypt":%s,"data":"e30="}'
            % (process, function, 'false' if not encrypt else 'true'))


def _proc():
    proc = MagicMock(spec=NetworkProcess)
    proc.logger = MagicMock()
    proc._msg_to_queue = MagicMock()
    return proc


def _peer():
    peer = MagicMock()
    peer.nickname = 'peer-1'
    peer.address = '127.0.0.3'
    return peer


def _accept(proc, raw):
    return NetworkProcess._accept_unencrypted(proc, raw, _peer(), {})


class TestAllowlistedVerbsAreAccepted:
    @pytest.mark.parametrize('verb', sorted(UNENCRYPTED_VERBS))
    def test_each_allowlisted_verb_is_delivered(self, verb):
        proc = _proc()
        assert _accept(proc, _envelope(verb)) is True
        proc._msg_to_queue.assert_called_once()
        # Delivered without signature validation, as the unknown-sender branch
        # does for the same messages.
        assert proc._msg_to_queue.call_args.kwargs.get('validate') is False

    def test_access_granted_specifically(self):
        """The verb actually observed being dropped. Named explicitly because
        `accept`'s wire form is 'access_granted', which is easy to miss when
        reading the allowlist."""
        assert IdentityProtocol.accept == 'access_granted'
        proc = _proc()
        assert _accept(proc, _envelope('access_granted')) is True


class TestEverythingElseIsRefused:
    def test_non_allowlisted_identity_verb_is_refused(self):
        """A handshake-adjacent verb that is NOT sent in plaintext must not be
        acceptable in plaintext just because it came from a known peer."""
        proc = _proc()
        assert _accept(proc, _envelope(IdentityProtocol.history)) is False
        proc._msg_to_queue.assert_not_called()

    @pytest.mark.parametrize('verb', [
        IdentityProtocol.update,        # group_key_update
        IdentityProtocol.vote,          # vote_on_peer
        IdentityProtocol.confirm,       # peer_accepted
        IdentityProtocol.tier_update,
        ReputationProtocol.rep_req,
        ReputationProtocol.rep_resp,
    ])
    def test_downgrade_of_sensitive_verbs_is_refused(self, verb):
        """The attack the allowlist exists to stop: a peer in the listing
        sending a security-relevant verb as plaintext."""
        proc = _proc()
        assert _accept(proc, _envelope(verb)) is False
        proc._msg_to_queue.assert_not_called()

    def test_verb_claiming_encryption_is_refused(self):
        """An envelope whose own flag says encrypted, that nonetheless failed to
        decrypt, is corrupt / stale-keyed / forged -- not a plaintext message.
        Refused even though the verb is allowlisted."""
        proc = _proc()
        raw = _envelope(IdentityProtocol.accept, encrypt=True)
        assert _accept(proc, raw) is False
        proc._msg_to_queue.assert_not_called()

    def test_unparseable_bytes_are_refused(self):
        """Real ciphertext: must not be mistaken for a plaintext frame."""
        proc = _proc()
        assert _accept(proc, b'\x80\x81\x82 not an envelope') is False
        proc._msg_to_queue.assert_not_called()

    def test_empty_payload_is_refused(self):
        proc = _proc()
        assert _accept(proc, b'') is False
        proc._msg_to_queue.assert_not_called()


class TestAllowlistMatchesTheSendSites:
    """Drift detector. An `encrypt=False` send whose verb is missing from the
    allowlist is dropped by the receiver once the peer is known -- silently, on
    a path that only surfaces in multi-peer convergence. That is exactly how the
    original defect hid, so pin the two against each other."""

    def _unencrypted_sends(self):
        """Every `Message(CfgIds.x, IdentityProtocol.verb, ..., encrypt=False)`
        in the identity process, resolved to its wire verb. Scans idprocess.py
        and first_contact.py (the opt-in 1:1 handshake sends hello/hello_ack
        plaintext from that module)."""
        id_dir = os.path.join(
            os.path.dirname(os.path.dirname(os.path.dirname(
                os.path.abspath(__file__)))),
            'autonomous_trust', 'core', '_python', 'identity')
        found = {}
        for fname in ('idprocess.py', 'first_contact.py'):
            tree = ast.parse(open(os.path.join(id_dir, fname)).read())
            self._scan_sends(tree, found)
        return found

    @staticmethod
    def _scan_sends(tree, found):
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            fname = getattr(node.func, 'id', None) or getattr(node.func, 'attr', None)
            if fname != 'Message':
                continue
            plaintext = any(
                kw.arg == 'encrypt'
                and isinstance(kw.value, ast.Constant)
                and kw.value.value is False
                for kw in node.keywords)
            if not plaintext or len(node.args) < 2:
                continue
            verb_node = node.args[1]
            # Only resolve the IdentityProtocol.<attr> form; anything else is
            # reported rather than silently skipped.
            if (isinstance(verb_node, ast.Attribute)
                    and getattr(verb_node.value, 'id', None) == 'IdentityProtocol'):
                verb = getattr(IdentityProtocol, verb_node.attr, None)
                if verb is not None:
                    found[verb] = verb_node.attr
            else:
                found[ast.dump(verb_node)[:40]] = '<unresolved>'
        return found

    def test_every_plaintext_send_is_allowlisted(self):
        sends = self._unencrypted_sends()
        assert sends, 'found no encrypt=False sends -- the scan broke, not the code'
        missing = {v: n for v, n in sends.items() if v not in UNENCRYPTED_VERBS}
        assert not missing, (
            'these verbs are sent with encrypt=False but are not in '
            'UNENCRYPTED_VERBS, so a known peer will silently drop them: %r'
            % missing)

    def test_allowlist_carries_no_verb_nobody_sends(self):
        """The other direction: an allowlist entry with no corresponding
        plaintext send is dead permission and should be removed."""
        sends = set(self._unencrypted_sends())
        stale = set(UNENCRYPTED_VERBS) - sends
        assert not stale, (
            'allowlisted but never sent as plaintext (dead permission): %r'
            % sorted(stale))
