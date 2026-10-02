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
"""The roster app verbs (roster.py): rendezvous's since FEATURE_SPLIT_PLAN
Phase 7b (D10), moved from first contact's area_contact. Mirrors C's
test_the_roster_app_verbs_answer_with_rendezvous_events."""
import json
import logging
import queue
import types

import pytest
from nacl.encoding import HexEncoder
from nacl.signing import SigningKey

from autonomous_trust.core.config import Configuration
from autonomous_trust.core.system import CfgIds
from autonomous_trust.core._python.extensions import all_extensions
from autonomous_trust.rendezvous._python import relay_rosters as rosters
from autonomous_trust.rendezvous._python import roster

HINT = 'relay://00000000-0000-4000-8000-000000000001:%s@198.51.100.1:27790' % ('ab' * 16)


@pytest.fixture(autouse=True)
def _isolate(monkeypatch, tmp_path):
    monkeypatch.setenv(Configuration.ROOT_VARIABLE_NAME, str(tmp_path))


@pytest.fixture
def node():
    q = {CfgIds.main: queue.Queue()}
    proc = types.SimpleNamespace(logger=logging.getLogger('test-roster'), q_cadence=0.1,
                                 identity=None)

    def app(fn, body, sender=None):
        fn(proc, q, types.SimpleNamespace(from_whom=sender, obj=json.dumps(body)))
        events = []
        while not q[CfgIds.main].empty():
            events.append(q[CfgIds.main].get_nowait())
        return events
    return app


def _signed(seq):
    sk = SigningKey(b'\x52' * 32)
    seed = HexEncoder.encode(bytes(sk)).decode()
    return rosters.sign_roster(seed, seq, [HINT]), sk.verify_key.encode(HexEncoder).decode()


def test_install_and_remove_answer_with_roster_events(node):
    text, key = _signed(2)
    [ev] = node(roster.handle_app_roster_install, {'ref': 'i', 'roster': text})
    assert isinstance(ev, roster.RosterEvent)
    assert (ev.kind, ev.ref, ev.issuer, ev.seq) == (roster.EVENT_ROSTER_INSTALLED, 'i', key, 2)
    assert rosters.pinned_issuers() == [key]
    forged = json.loads(text)
    forged['body'] = forged['body'].replace('"seq":2', '"seq":3')
    [ev] = node(roster.handle_app_roster_install, {'ref': 'j', 'roster': json.dumps(forged)})
    assert (ev.kind, ev.reason) == (roster.EVENT_ROSTER_REFUSED, 'invalid')
    [ev] = node(roster.handle_app_roster_install, {'ref': 'x' * 64, 'roster': text})
    assert (ev.kind, ev.reason) == (roster.EVENT_ROSTER_REFUSED, 'bad_request')
    [ev] = node(roster.handle_app_roster_remove, {'ref': 'k', 'issuer': 'not-a-key'})
    assert (ev.kind, ev.reason) == (roster.EVENT_ROSTER_REFUSED, 'bad_request')
    [ev] = node(roster.handle_app_roster_remove, {'ref': 'k', 'issuer': key.upper()})
    assert (ev.kind, ev.issuer, ev.count) == (roster.EVENT_ROSTER_REMOVED, key, 1)
    assert rosters.pinned_issuers() == []
    [ev] = node(roster.handle_app_roster_remove, {'ref': 'k', 'issuer': key})
    assert ev.count == 0


def test_a_roster_verb_from_the_wire_is_refused(node):
    text, _key = _signed(2)
    peer = types.SimpleNamespace(uuid='12345678-0000-4000-8000-000000000000')
    assert node(roster.handle_app_roster_install, {'ref': 'i', 'roster': text}, peer) == []
    assert rosters.pinned_issuers() == []


def test_rendezvous_declares_the_verbs_for_identity():
    [rdv] = [e for e in all_extensions() if e.name == 'rendezvous']
    assert dict(rdv.app_verbs) == {roster.APP_ROSTER_INSTALL: CfgIds.identity,
                                   roster.APP_ROSTER_REMOVE: CfgIds.identity}
