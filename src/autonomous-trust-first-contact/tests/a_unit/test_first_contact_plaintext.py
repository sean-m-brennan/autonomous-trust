# ******************
#  Copyright 2023 TekFive, Inc., Sean M. Brennan, and contributors
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
"""First contact's verbs, and the plaintext they are sent in.

Moved from the core's test suite, which no longer imports this distribution:
the protocol pin (from test_identity_protocol.py), first contact's half of the
plaintext-verbs file (test_plaintext_verbs.py), and its half of the known-peer
plaintext allowlist (test_unencrypted_verbs.py). The core files keep the rules
themselves, exercised with a stand-in extension.
"""
import ast
import json
import os
from unittest.mock import MagicMock

import pytest

from autonomous_trust.core import plaintext_verbs as pv
from autonomous_trust.core.extensions import configure_plaintext_verbs
from autonomous_trust.core.identity.protocol import (CORE_UNENCRYPTED_VERBS,
                                                     IdentityProtocol)
from autonomous_trust.core.network.netprocess import NetworkProcess
from autonomous_trust.first_contact import first_contact
from autonomous_trust.first_contact.fc_protocol import FirstContactProtocol

FC = first_contact.EXTENSION
FC_VERBS = sorted(FC.plaintext_verbs)


@pytest.fixture(autouse=True)
def _reset():
    pv.reset()
    yield
    pv.reset()


def _write(tmp_path, doc):
    text = doc if isinstance(doc, str) else json.dumps(doc)
    (tmp_path / pv.FILENAME).write_text(text)


# ----- The protocol ---------------------------------------------------------

def test_first_contact_protocol_verbs():
    """First contact's own verbs (first_contact/fc_protocol.py), registered on
    the identity process by its extension: the 1:1 handshake (hello,
    hello_ack; opt-in via AT_FIRST_CONTACT, see first-contact.md), its
    reachability record (reach_record), the directory contact
    (contact_request, contact_accept on the wire; dir_result, dir_status
    local IPC from the network process), area hubs (hub_result,
    hub_status, local IPC from the network process), one human's several
    devices (device_cert, device_announce) and their shared address book
    (contacts_sync). The wire strings did not change in the move, and none
    is still an IdentityProtocol verb."""
    values = list(FirstContactProtocol)
    assert len(values) == 12
    assert FirstContactProtocol.hello == 'first_contact_hello'
    assert FirstContactProtocol.device_announce == 'device_announce'
    assert not set(values) & set(IdentityProtocol)


# ----- The plaintext-verbs file ----------------------------------------------

def test_first_contact_declares_exactly_its_five_verbs():
    assert set(FC_VERBS) == {
        FirstContactProtocol.hello, FirstContactProtocol.hello_ack,
        FirstContactProtocol.contact_request, FirstContactProtocol.contact_accept,
        FirstContactProtocol.device_announce}
    assert not set(FC_VERBS) & CORE_UNENCRYPTED_VERBS


def test_the_file_grants_first_contacts_verbs(tmp_path):
    _write(tmp_path, {'verbs': FC_VERBS})
    assert pv.configure(str(tmp_path), [FC]) == frozenset(FC_VERBS)
    assert pv.active() == CORE_UNENCRYPTED_VERBS | set(FC_VERBS)
    assert pv.is_unencrypted(FirstContactProtocol.hello)


def test_no_file_with_first_contact_on_refuses_naming_its_verbs(tmp_path):
    with pytest.raises(pv.PlaintextVerbsError) as err:
        pv.configure(str(tmp_path), [FC])
    text = str(err.value)
    assert pv.FILENAME in text and 'no such file' in text
    for verb in FC_VERBS:
        assert verb in text


def test_the_start_check_reads_only_enabled_extensions(tmp_path, monkeypatch):
    """configure_plaintext_verbs (called by extensions.check_config at start)
    asks enabled(): first contact off, its verbs in the file, refuses."""
    _write(tmp_path, {'verbs': FC_VERBS})
    monkeypatch.setenv('AT_FIRST_CONTACT', '1')
    assert configure_plaintext_verbs(str(tmp_path)) == frozenset(FC_VERBS)
    monkeypatch.setenv('AT_FIRST_CONTACT', '0')
    with pytest.raises(pv.PlaintextVerbsError):
        configure_plaintext_verbs(str(tmp_path))


# ----- Plaintext from a known peer ---------------------------------------------

def _envelope(function, encrypt=False, process='identity'):
    """A minimal JSON wire envelope, the shape Message.parse accepts."""
    return ('{"process":"%s","function":"%s","encrypt":%s,"data":"e30="}'
            % (process, function, 'false' if not encrypt else 'true'))


def _accept(raw):
    proc = MagicMock(spec=NetworkProcess)
    proc.logger = MagicMock()
    proc._msg_to_queue = MagicMock()
    peer = MagicMock()
    peer.nickname = 'peer-1'
    peer.address = '127.0.0.3'
    return NetworkProcess._accept_unencrypted(proc, raw, peer, {})


@pytest.mark.parametrize('verb', FC_VERBS)
def test_a_granted_first_contact_verb_is_accepted(tmp_path, verb):
    _write(tmp_path, {'verbs': FC_VERBS})
    pv.configure(str(tmp_path), [FC])
    assert _accept(_envelope(verb)) is True


@pytest.mark.parametrize('verb', FC_VERBS)
def test_a_first_contact_verb_is_refused_without_the_file(verb):
    """First contact's verbs are plaintext only because the file grants them;
    the core's are compiled in."""
    assert _accept(_envelope(verb)) is False
    assert _accept(_envelope(IdentityProtocol.accept)) is True


class TestAllowlistMatchesTheSendSites:
    """Drift detector for first contact's own sends. An `encrypt=False` send
    whose verb is in neither the core's plaintext verbs nor first contact's
    declared ones is dropped by a receiver once the peer is known -- silently,
    on a path that only surfaces in multi-peer convergence. The core's own
    send sites are pinned the same way in the core's test_unencrypted_verbs.py.
    """

    def _unencrypted_sends(self):
        fc_dir = os.path.dirname(os.path.abspath(first_contact.__file__))
        found = {}
        for name in ('first_contact.py', 'directory_contact.py',
                     'device_contact.py'):
            tree = ast.parse(open(os.path.join(fc_dir, name)).read())
            for node in ast.walk(tree):
                if not isinstance(node, ast.Call):
                    continue
                fname = (getattr(node.func, 'id', None)
                         or getattr(node.func, 'attr', None))
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
                owner = {'IdentityProtocol': IdentityProtocol,
                         'FirstContactProtocol': FirstContactProtocol}.get(
                    getattr(getattr(verb_node, 'value', None), 'id', None))
                if isinstance(verb_node, ast.Attribute) and owner is not None:
                    verb = getattr(owner, verb_node.attr, None)
                    if verb is not None:
                        found[verb] = verb_node.attr
                        continue
                found[ast.dump(verb_node)[:40]] = '<unresolved>'
        return found

    def test_every_plaintext_send_is_allowlisted(self):
        sends = self._unencrypted_sends()
        assert sends, 'found no encrypt=False sends -- the scan broke, not the code'
        allowed = CORE_UNENCRYPTED_VERBS | set(FC_VERBS)
        missing = {v: n for v, n in sends.items() if v not in allowed}
        assert not missing, (
            'these verbs are sent with encrypt=False but are neither core '
            'plaintext verbs nor first contact\'s declared ones, so a known peer '
            'will silently drop them: %r' % missing)

    def test_every_declared_verb_is_sent(self):
        """The other direction: a declared verb first contact never sends in
        plaintext is dead permission and should be removed."""
        stale = set(FC_VERBS) - set(self._unencrypted_sends())
        assert not stale, (
            'declared plaintext but never sent as plaintext (dead permission): '
            '%r' % sorted(stale))
