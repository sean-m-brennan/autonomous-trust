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
"""Opt-in coarse position exchange (Increment 2, the "with-distance" feature).

Exercises the identity-process handlers (idprocess.py handle_position_query /
handle_position_response / _send_position_query / _geohash_valid) against a
lightweight stub — no sockets, no subprocess — the same style as
test_first_contact_handshake.py. Pins the behavior the C twin (id_proc.c) must
match and the conformance corpus asserts cross-runtime:

  * STRICTLY OPT-IN: an empty own_geohash answers nothing (no disclosure).
  * opted-in: a freshness-stamped {'pos','seq'} response is emitted.
  * round-trip: a valid response is stored, surfaced via get_peer_position.
  * replay/unstamped responses are refused (freshness gate).
  * an invalid/oversized geohash is dropped, never stored.
"""
import logging
import queue
import threading
import types

import pytest

from autonomous_trust.core.identity import Identity
from autonomous_trust.core.identity.idprocess import IdentityProcess
from autonomous_trust.core.identity.protocol import IdentityProtocol, UNENCRYPTED_VERBS
from autonomous_trust.core.system import CfgIds
from autonomous_trust.core.config import to_json_string, from_json_string
from autonomous_trust.core.freshness import Freshness


def _identity(name, addr):
    return Identity.initialize(name, name, addr)


class StubProc:
    """Minimal stand-in for IdentityProcess: just what the position handlers
    touch. The real (unbound) handlers are invoked with this as ``self``."""
    def __init__(self, identity, own_geohash=''):
        self.name = CfgIds.identity
        self.identity = identity
        self.logger = logging.getLogger('test-position')
        self.q_cadence = 1.0
        self.lock = threading.Lock()
        self.freshness = Freshness(self.name, self.logger)
        self.own_geohash = own_geohash
        self.peer_positions = {}
        self.exceptions = []

    # staticmethod on the real class; expose it so the handlers resolve it.
    _geohash_valid = staticmethod(IdentityProcess._geohash_valid)
    _GEOHASH_MAX_LEN = IdentityProcess._GEOHASH_MAX_LEN

    def report_exception(self, err, where):
        self.exceptions.append((where, err))

    # Bind the real handlers as methods on the stub.
    handle_position_query = IdentityProcess.handle_position_query
    handle_position_response = IdentityProcess.handle_position_response
    _send_position_query = IdentityProcess._send_position_query
    get_peer_position = IdentityProcess.get_peer_position


def _queues():
    return {CfgIds.network: queue.Queue()}


def _inbound(from_identity, obj, function):
    """A parsed inbound message: the handlers read .from_whom, .obj, .function."""
    return types.SimpleNamespace(from_whom=from_identity.publish(),
                                 obj=obj, function=function)


@pytest.fixture
def alice():
    return _identity('alice@ex', '10.0.0.1')


@pytest.fixture
def bob():
    return _identity('bob@ex', '10.0.0.2')


# -- geohash validation (mirror the C _geohash_valid table) ------------------
@pytest.mark.parametrize('gh,ok', [
    ('u4pruy', True),      # ordinary geohash
    ('9', True),           # single digit is a (coarse) valid bucket
    ('bcd', True),
    ('u4pruydqqvj', True),  # 11 chars, under the 12 bound
    ('', False),           # empty = opted out, not a valid shared value
    ('a', False),          # 'a' excluded from the geohash alphabet
    ('i', False),          # 'i' excluded
    ('l', False),          # 'l' excluded
    ('o', False),          # 'o' excluded
    ('U4P', False),        # uppercase not in the lowercase alphabet
    ('u4 pr', False),      # space invalid
    ('u4pruydqqvjxy', False),  # 13 chars, over the 12 bound
])
def test_geohash_valid(gh, ok):
    assert IdentityProcess._geohash_valid(gh) is ok


def test_geohash_valid_rejects_non_str():
    assert IdentityProcess._geohash_valid(None) is False
    assert IdentityProcess._geohash_valid(123) is False


# -- opt-in default: opted out answers nothing -------------------------------
def test_query_opted_out_answers_nothing(alice, bob):
    proc = StubProc(alice, own_geohash='')   # the DEFAULT
    q = _queues()
    msg = _inbound(bob, '', IdentityProtocol.position_query)
    assert proc.handle_position_query(q, msg) is True
    assert q[CfgIds.network].empty(), 'opted-out node must disclose nothing'


def test_query_wrong_verb_declines(alice, bob):
    proc = StubProc(alice, own_geohash='u4pruy')
    q = _queues()
    msg = _inbound(bob, '', IdentityProtocol.caps_query)
    assert proc.handle_position_query(q, msg) is False


# -- opted in: emits a stamped response --------------------------------------
def test_query_opted_in_responds_stamped(alice, bob):
    proc = StubProc(alice, own_geohash='u4pruy')
    q = _queues()
    msg = _inbound(bob, '', IdentityProtocol.position_query)
    assert proc.handle_position_query(q, msg) is True
    reply = q[CfgIds.network].get_nowait()
    assert reply.function == IdentityProtocol.position_response
    body = from_json_string(reply.obj)
    assert body['pos'] == 'u4pruy'
    assert isinstance(body['seq'], int) and body['seq'] > 0


# -- round-trip: a valid response is stored ----------------------------------
def test_response_round_trip_stores_position(alice, bob):
    recv = StubProc(alice)
    q = _queues()
    payload = to_json_string({'pos': 'u4pruy', 'seq': 5})
    msg = _inbound(bob, payload, IdentityProtocol.position_response)
    assert recv.handle_position_response(q, msg) is True
    assert recv.get_peer_position(bob.uuid) == 'u4pruy'


def test_response_wrong_verb_declines(alice, bob):
    recv = StubProc(alice)
    q = _queues()
    payload = to_json_string({'pos': 'u4pruy', 'seq': 5})
    msg = _inbound(bob, payload, IdentityProtocol.caps_response)
    assert recv.handle_position_response(q, msg) is False


# -- replay / unstamped refused ----------------------------------------------
def test_response_replay_refused(alice, bob):
    recv = StubProc(alice)
    q = _queues()
    # First (seq 5) accepted.
    recv.handle_position_response(
        q, _inbound(bob, to_json_string({'pos': 'u4pruy', 'seq': 5}),
                    IdentityProtocol.position_response))
    assert recv.get_peer_position(bob.uuid) == 'u4pruy'
    # A captured earlier stamp (seq 4) must NOT overwrite the fresh value.
    recv.handle_position_response(
        q, _inbound(bob, to_json_string({'pos': 'spoofed', 'seq': 4}),
                    IdentityProtocol.position_response))
    assert recv.get_peer_position(bob.uuid) == 'u4pruy'


def test_response_unstamped_refused(alice, bob):
    recv = StubProc(alice)
    q = _queues()
    recv.handle_position_response(
        q, _inbound(bob, to_json_string({'pos': 'u4pruy'}),
                    IdentityProtocol.position_response))
    assert recv.get_peer_position(bob.uuid) == ''


# -- invalid geohash dropped -------------------------------------------------
def test_response_invalid_geohash_dropped(alice, bob):
    recv = StubProc(alice)
    q = _queues()
    recv.handle_position_response(
        q, _inbound(bob, to_json_string({'pos': 'not a geohash!', 'seq': 9}),
                    IdentityProtocol.position_response))
    assert recv.get_peer_position(bob.uuid) == ''


def test_response_non_dict_body_ignored(alice, bob):
    recv = StubProc(alice)
    q = _queues()
    recv.handle_position_response(
        q, _inbound(bob, to_json_string(['not', 'a', 'dict']),
                    IdentityProtocol.position_response))
    assert recv.get_peer_position(bob.uuid) == ''


# -- directed query send -----------------------------------------------------
def test_send_position_query_emits(alice, bob):
    proc = StubProc(alice)
    q = _queues()
    proc._send_position_query(q, bob.publish())
    sent = q[CfgIds.network].get_nowait()
    assert sent.function == IdentityProtocol.position_query


# -- the position verbs are NOT plaintext pre-admission verbs -----------------
def test_position_verbs_not_in_unencrypted_allowlist():
    """They travel to admitted peers over the encrypted group channel, like
    caps_query — never as pre-admission plaintext, so they must stay OUT of the
    allowlist (kept in lockstep with the C ID_UNENCRYPTED_VERBS)."""
    assert IdentityProtocol.position_query not in UNENCRYPTED_VERBS
    assert IdentityProtocol.position_response not in UNENCRYPTED_VERBS
