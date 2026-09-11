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
"""Opt-in SIGNED agora.profile exchange (Increment 3).

Mirrors test_position_exchange.py against a lightweight stub, and pins the
behavior the C twin (id_proc.c / profile.c) must match and the conformance
corpus asserts cross-runtime:

  * STRICTLY OPT-IN: an empty own_profile answers nothing.
  * opted-in: a freshness-stamped {'profile','sig','seq'} response is emitted,
    signed over the canonical form with the node's identity key.
  * round-trip: a valid, correctly-signed response is stored + surfaced.
  * replay/unstamped refused (freshness gate).
  * a BAD SIGNATURE is dropped, never stored (the new integrity surface).
  * an over-bound / bad-charset / control-char field is dropped.

The CANONICAL + SIGNATURE vectors below are the cross-language lockstep guard:
the C profile_test.c asserts the SAME literals, so a one-byte divergence in
either runtime's canonical serialization fails both suites.
"""
import logging
import queue
import threading
import types

import pytest

from nacl.signing import SigningKey
from nacl.encoding import HexEncoder

from autonomous_trust.core.identity import Identity
from autonomous_trust.core.identity.idprocess import IdentityProcess
from autonomous_trust.core.identity.protocol import IdentityProtocol, UNENCRYPTED_VERBS
from autonomous_trust.core.system import CfgIds
from autonomous_trust.core.config import to_json_string
from autonomous_trust.core.freshness import Freshness
from autonomous_trust.core import capabilities


def _identity(name, addr):
    return Identity.initialize(name, name, addr)


class StubProc:
    """Minimal stand-in for IdentityProcess: just what the profile handlers
    touch. The real (unbound) handlers are invoked with this as ``self``."""
    def __init__(self, identity, own_profile=None):
        self.name = CfgIds.identity
        self.identity = identity
        self.logger = logging.getLogger('test-profile')
        self.q_cadence = 1.0
        self.lock = threading.Lock()
        self.freshness = Freshness(self.name, self.logger)
        self.own_profile = dict(own_profile or {})
        self.peer_profiles = {}
        self.exceptions = []

    def report_exception(self, err, where):
        self.exceptions.append((where, err))

    handle_profile_query = IdentityProcess.handle_profile_query
    handle_profile_response = IdentityProcess.handle_profile_response
    _send_profile_query = IdentityProcess._send_profile_query
    get_peer_profile = IdentityProcess.get_peer_profile


def _queues():
    return {CfgIds.network: queue.Queue()}


def _inbound(from_identity, obj, function):
    return types.SimpleNamespace(from_whom=from_identity.publish(),
                                 obj=obj, function=function)


def _signed_response(sender_identity, profile, seq):
    """A {'profile','sig','seq'} payload signed by sender_identity's key over
    (sender uuid, profile) — exactly what handle_profile_query emits."""
    sig = capabilities.profile_sign(sender_identity.signature.private,
                                    sender_identity.uuid, profile)
    return to_json_string({'profile': profile, 'sig': sig, 'seq': seq})


@pytest.fixture
def alice():
    return _identity('alice@ex', '10.0.0.1')


@pytest.fixture
def bob():
    return _identity('bob@ex', '10.0.0.2')


REF_PROFILE = {
    'display_name': 'José \U0001f680',
    'handle': 'jose_b',
    'bio': 'hi there',
    'avatar_ref': 'https://x/a.png',
    'links': ['https://a.example', 'https://b.example'],
}
REF_CANON_HEX = (
    '000102030405060708090a0b0c0d0e0f0a0000004a6f73c3a920f09f9a80060000006a6f'
    '73655f620800000068692074686572650f00000068747470733a2f2f782f612e706e6702'
    '0000001100000068747470733a2f2f612e6578616d706c65110000006874747073'
    '3a2f2f622e6578616d706c65')
REF_PK_HEX = '79b5562e8fe654f94078b112e8a98ba7901f853ae695bed7e0e3910bad049664'
REF_SIG_HEX = (
    '2f89d11b9c247ff49a657895f7765dc79464fa5e2acc1a10fa08f29e750ea41872330da4'
    '4324e948d072efb83aa7329f2cbde4d3b3c077eaaef621c0f57afc01')


# -- THE cross-language lockstep vector (must equal C profile_test.c) ---------
def test_canonical_matches_pinned_vector():
    uuid_bytes = bytes(range(16))
    assert capabilities.profile_canonical(uuid_bytes, REF_PROFILE).hex() == REF_CANON_HEX


def test_signature_matches_pinned_vector_and_verifies():
    seed = bytes(range(1, 33))
    sk = SigningKey(seed)
    # same keypair derivation as C crypto_sign_seed_keypair
    assert sk.verify_key.encode(encoder=HexEncoder).decode() == REF_PK_HEX
    uuid_bytes = bytes(range(16))
    sig = capabilities.profile_sign(sk, uuid_bytes, REF_PROFILE)
    assert sig == REF_SIG_HEX   # Ed25519 deterministic => byte-stable, cross-runtime
    assert capabilities.profile_verify(sk.verify_key, uuid_bytes, REF_PROFILE, sig)


# -- field validation (mirror C at_profile_from_json validate=true) ----------
@pytest.mark.parametrize('profile,ok', [
    ({'display_name': 'Ok'}, True),
    ({}, True),                                   # empty valid (opted out)
    ({'handle': 'jose_b'}, True),
    ({'handle': 'a' * 33}, False),                # over 32-byte bound
    ({'handle': 'has space'}, False),             # bad charset
    ({'bio': 'a\x01b'}, False),                   # control char
    ({'display_name': 'x' * 65}, False),          # over 64-byte bound
    ({'links': ['a', 'b', 'c', 'd', 'e']}, False),  # >4 links
    ({'links': ['a' * 129]}, False),              # link over 128-byte bound
    ({'links': [1, 2]}, False),                   # non-string link
])
def test_profile_valid_bounded(profile, ok):
    assert capabilities.profile_valid_bounded(profile) is ok


def test_sanitize_truncates_and_drops():
    dirty = {'display_name': 'x' * 100, 'handle': 'bad space',
             'bio': 'a\x01b', 'links': ['ok', 'y' * 200]}
    clean = capabilities.sanitize_profile(dirty)
    assert len(clean['display_name'].encode()) <= 64
    assert 'handle' not in clean            # bad charset dropped
    assert 'bio' not in clean               # control char dropped
    assert clean['links'][0] == 'ok'
    assert len(clean['links'][1].encode()) <= 128


# -- opt-in default: opted out answers nothing -------------------------------
def test_query_opted_out_answers_nothing(alice, bob):
    proc = StubProc(alice, own_profile={})    # the DEFAULT
    q = _queues()
    msg = _inbound(bob, '', IdentityProtocol.profile_query)
    assert proc.handle_profile_query(q, msg) is True
    assert q[CfgIds.network].empty(), 'opted-out node must disclose nothing'


def test_query_wrong_verb_declines(alice, bob):
    proc = StubProc(alice, own_profile={'display_name': 'A'})
    q = _queues()
    msg = _inbound(bob, '', IdentityProtocol.caps_query)
    assert proc.handle_profile_query(q, msg) is False


# -- opted in: emits a stamped + signed response, verifiable by the peer ------
def test_query_opted_in_responds_signed(alice, bob):
    proc = StubProc(alice, own_profile={'display_name': 'Alice', 'handle': 'al'})
    q = _queues()
    msg = _inbound(bob, '', IdentityProtocol.profile_query)
    assert proc.handle_profile_query(q, msg) is True
    reply = q[CfgIds.network].get_nowait()
    assert reply.function == IdentityProtocol.profile_response
    from autonomous_trust.core.config import from_json_string
    body = from_json_string(reply.obj)
    assert body['profile']['display_name'] == 'Alice'
    assert isinstance(body['seq'], int) and body['seq'] > 0
    # The signature must verify against ALICE's (the sender's) key.
    assert capabilities.profile_verify(
        alice.publish().signature.public, alice.uuid,
        body['profile'], body['sig'])


# -- round-trip: a valid signed response is stored ---------------------------
def test_response_round_trip_stores_profile(alice, bob):
    recv = StubProc(alice)
    q = _queues()
    profile = {'display_name': 'Bob', 'handle': 'bob'}
    msg = _inbound(bob, _signed_response(bob, profile, 5),
                   IdentityProtocol.profile_response)
    assert recv.handle_profile_response(q, msg) is True
    assert recv.get_peer_profile(bob.uuid) == profile


def test_response_wrong_verb_declines(alice, bob):
    recv = StubProc(alice)
    q = _queues()
    msg = _inbound(bob, _signed_response(bob, {'handle': 'bob'}, 5),
                   IdentityProtocol.caps_response)
    assert recv.handle_profile_response(q, msg) is False


# -- BAD SIGNATURE dropped (the new integrity surface) -----------------------
def test_response_bad_signature_dropped(alice, bob):
    recv = StubProc(alice)
    q = _queues()
    payload = to_json_string(
        {'profile': {'handle': 'bob'}, 'sig': '00' * 64, 'seq': 7})
    recv.handle_profile_response(
        q, _inbound(bob, payload, IdentityProtocol.profile_response))
    assert recv.get_peer_profile(bob.uuid) == {}


def test_response_signed_by_wrong_key_dropped(alice, bob):
    """A profile bob relays but that carol signed for HER uuid must not verify
    as bob's: the signer uuid is bound into the canonical bytes."""
    carol = _identity('carol@ex', '10.0.0.3')
    recv = StubProc(alice)
    q = _queues()
    profile = {'handle': 'bob'}
    # carol signs (carol.uuid, profile), but the message arrives from bob.
    sig = capabilities.profile_sign(carol.signature.private,
                                    carol.uuid, profile)
    payload = to_json_string({'profile': profile, 'sig': sig, 'seq': 8})
    recv.handle_profile_response(
        q, _inbound(bob, payload, IdentityProtocol.profile_response))
    assert recv.get_peer_profile(bob.uuid) == {}


# -- replay / unstamped refused ----------------------------------------------
def test_response_replay_refused(alice, bob):
    recv = StubProc(alice)
    q = _queues()
    good = {'handle': 'bob'}
    recv.handle_profile_response(
        q, _inbound(bob, _signed_response(bob, good, 5),
                    IdentityProtocol.profile_response))
    assert recv.get_peer_profile(bob.uuid) == good
    # An earlier stamp (seq 4), even validly signed, must not overwrite.
    spoof = {'handle': 'spoofed'}
    recv.handle_profile_response(
        q, _inbound(bob, _signed_response(bob, spoof, 4),
                    IdentityProtocol.profile_response))
    assert recv.get_peer_profile(bob.uuid) == good


def test_response_unstamped_refused(alice, bob):
    recv = StubProc(alice)
    q = _queues()
    profile = {'handle': 'bob'}
    sig = capabilities.profile_sign(bob.signature.private, bob.uuid, profile)
    payload = to_json_string({'profile': profile, 'sig': sig})  # no seq
    recv.handle_profile_response(
        q, _inbound(bob, payload, IdentityProtocol.profile_response))
    assert recv.get_peer_profile(bob.uuid) == {}


# -- over-bound field dropped even if signed ---------------------------------
def test_response_overbound_field_dropped(alice, bob):
    recv = StubProc(alice)
    q = _queues()
    bad = {'handle': 'a' * 33}   # over bound; a misbehaving peer
    recv.handle_profile_response(
        q, _inbound(bob, _signed_response(bob, bad, 9),
                    IdentityProtocol.profile_response))
    assert recv.get_peer_profile(bob.uuid) == {}


def test_response_non_dict_body_ignored(alice, bob):
    recv = StubProc(alice)
    q = _queues()
    recv.handle_profile_response(
        q, _inbound(bob, to_json_string(['not', 'a', 'dict']),
                    IdentityProtocol.profile_response))
    assert recv.get_peer_profile(bob.uuid) == {}


# -- directed query send -----------------------------------------------------
def test_send_profile_query_emits(alice, bob):
    proc = StubProc(alice)
    q = _queues()
    proc._send_profile_query(q, bob.publish())
    sent = q[CfgIds.network].get_nowait()
    assert sent.function == IdentityProtocol.profile_query


# -- the profile verbs are NOT plaintext pre-admission verbs ------------------
def test_profile_verbs_not_in_unencrypted_allowlist():
    assert IdentityProtocol.profile_query not in UNENCRYPTED_VERBS
    assert IdentityProtocol.profile_response not in UNENCRYPTED_VERBS
