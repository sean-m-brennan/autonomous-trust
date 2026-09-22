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
"""Detached co-signing (Phase 3 P3.3).

A staff roll act decided by several people who are not at the same keyboard: the
record's exported bytes travel, their private keys do not. Both messages are
directed and ENCRYPTED, so crypto_box authenticates each end — there is no
signature on the envelope and no canonical byte form for the MESSAGE.

What there IS to pin is what the runtime REFUSES, and that is the whole contract
this file exists for. The bytes exist to be reproduced EXACTLY: the signatures
are over them, so a payload that arrives truncated, odd-length or not-hex
verifies against nothing at all. That is strictly worse than a refused ask,
because it spends somebody's attention and yields a signature over a record
nobody can rebuild. Twin of C test/cosign_test.c; these refusals were also
checked line-for-line against the real compiled C (identity/cosign.c) over a
shared 86-case table during P3.3 S6.

The freshness/replay gate and the deliver-to-app path are exercised end-to-end by
the conformance scenarios (cosign-*.yaml, both runtimes).
"""
from autonomous_trust.core import capabilities

DID = 'did:key:z6Mk' + 'q' * 40
CID = 'b3:' + 'ab' * 32
SIG = 'ab' * 64


def hexstr(n):
    return ''.join('0123456789abcdef'[i % 16] for i in range(n))


# --- bounds ----------------------------------------------------------------- #

def test_bound_keeps_a_short_field_whole():
    assert capabilities.cosign_bound('membership',
                                     capabilities.COSIGN_TOKEN_MAX) == 'membership'


def test_bound_truncates_at_the_byte_bound():
    out = capabilities.cosign_bound('d' * 200, capabilities.COSIGN_DID_MAX)
    assert len(out.encode('utf-8')) == capabilities.COSIGN_DID_MAX


def test_bound_of_a_non_string_is_empty():
    # The C NULL case: at_cosign_bound writes "" rather than reading NULL.
    assert capabilities.cosign_bound(None, 15) == ''
    assert capabilities.cosign_bound(123, 15) == ''


# --- the payload shape check ------------------------------------------------ #

def test_well_formed_payload_accepted_up_to_the_bound():
    assert capabilities.cosign_bytes_ok(hexstr(666))
    assert capabilities.cosign_bytes_ok(hexstr(capabilities.COSIGN_BYTES_MAX))


def test_payload_no_exporter_produced_is_refused():
    assert not capabilities.cosign_bytes_ok('')            # empty
    assert not capabilities.cosign_bytes_ok(None)          # absent
    assert not capabilities.cosign_bytes_ok(hexstr(665))   # odd -> truncated
    assert not capabilities.cosign_bytes_ok('AB' * 8)      # uppercase hex
    assert not capabilities.cosign_bytes_ok('zz' * 8)      # not hex at all
    assert not capabilities.cosign_bytes_ok('ab cd')       # whitespace


def test_oversized_payload_is_refused_not_truncated():
    # Truncating a payload whose entire purpose is byte-exact reproduction would
    # produce a signature over nothing, so the ask is refused outright.
    assert not capabilities.cosign_bytes_ok(
        hexstr(capabilities.COSIGN_BYTES_MAX + 2))


# --- which acts are exchanged at all ---------------------------------------- #

def test_known_exchanges_accepted():
    assert capabilities.cosign_op_ok('membership', 'admit')
    assert capabilities.cosign_op_ok('membership', 'expel')
    assert capabilities.cosign_op_ok('guardian', 'designate')
    assert capabilities.cosign_op_ok('guardian', 'rotate')
    assert capabilities.cosign_op_ok('guardian', 'release')


def test_departure_is_never_exchanged():
    # A voluntary departure is self-signed by the one person leaving. There is
    # nobody to collect from, so there is no exchange for it.
    assert not capabilities.cosign_op_ok('membership', 'depart')


def test_unknown_or_crossed_ops_refused():
    assert not capabilities.cosign_op_ok('guardian', 'admit')
    assert not capabilities.cosign_op_ok('polity', 'admit')
    assert not capabilities.cosign_op_ok('Membership', 'admit')  # case-exact
    assert not capabilities.cosign_op_ok('membership', 'Admit')
    assert not capabilities.cosign_op_ok(None, 'admit')
    assert not capabilities.cosign_op_ok('membership', None)


# --- the request envelope --------------------------------------------------- #

def test_request_round_trips_through_the_wire_body():
    env = capabilities.cosign_request_to_json('membership', 'admit', DID, CID,
                                              hexstr(666), 7, 1758150000.0)
    assert env is not None
    back = capabilities.cosign_request_from_json(env)
    assert back == env


def test_request_refuses_an_unknown_act_or_bad_payload():
    for bad in (
        capabilities.cosign_request_to_json('membership', 'depart', DID, CID,
                                            hexstr(666), 7, 1.0),
        capabilities.cosign_request_to_json('polity', 'admit', DID, CID,
                                            hexstr(666), 7, 1.0),
        capabilities.cosign_request_to_json('membership', 'admit', DID, CID,
                                            hexstr(665), 7, 1.0),
        capabilities.cosign_request_to_json('membership', 'admit', DID, '',
                                            hexstr(666), 7, 1.0),
    ):
        assert bad is None


def test_request_fields_are_bound_truncated():
    env = capabilities.cosign_request_to_json('membership', 'admit', 'd' * 200,
                                              CID + 'ffffffff', hexstr(8), 1,
                                              1.0)
    assert len(env['polity']) == capabilities.COSIGN_DID_MAX
    assert len(env['cid']) == capabilities.COSIGN_CID_MAX


def test_an_overlong_record_token_truncates_into_an_unknown_act():
    # Truncation happens BEFORE the op check, so a token that only looks right
    # for its first 15 characters is refused rather than silently accepted.
    assert capabilities.cosign_request_to_json('membership-and-more', 'admit',
                                               DID, CID, hexstr(8), 1,
                                               1.0) is None


def test_parse_refuses_a_mistyped_or_missing_stamp():
    good = capabilities.cosign_request_to_json('membership', 'admit', DID, CID,
                                               hexstr(8), 3, 1.0)
    for key, value in (('seq', '3'), ('seq', 3.5), ('seq', True),
                       ('ts', '1.0'), ('ts', True)):
        bad = dict(good)
        bad[key] = value
        assert capabilities.cosign_request_from_json(bad) is None
    for key in ('record', 'op', 'polity', 'cid', 'bytes', 'seq', 'ts'):
        bad = dict(good)
        del bad[key]
        assert capabilities.cosign_request_from_json(bad) is None
    assert capabilities.cosign_request_from_json(None) is None
    assert capabilities.cosign_request_from_json('not an object') is None


def test_the_description_is_never_carried():
    # THE point of the two-phase seam: the wording of what a record commits to is
    # derived on the SIGNER's node from the bytes it is about to sign. A field
    # for it here would let the ASKING node choose both what you sign and what
    # you are told you are signing — a friendly sentence over hostile bytes, with
    # a real signature on the end.
    env = capabilities.cosign_request_to_json('membership', 'expel', DID, CID,
                                              hexstr(666), 7, 1.0)
    assert 'description' not in env
    smuggled = dict(env)
    smuggled['description'] = 'a harmless-sounding admission'
    parsed = capabilities.cosign_request_from_json(smuggled)
    assert parsed is not None and 'description' not in parsed


# --- the signature envelope ------------------------------------------------- #

def test_signature_round_trips_through_the_wire_body():
    env = capabilities.cosign_sig_to_json(CID, DID, SIG, 9, 1758150001.0)
    assert env is not None
    assert capabilities.cosign_sig_from_json(env) == env


def test_signature_refuses_an_empty_field():
    assert capabilities.cosign_sig_to_json('', DID, SIG, 9, 1.0) is None
    assert capabilities.cosign_sig_to_json(CID, '', SIG, 9, 1.0) is None
    assert capabilities.cosign_sig_to_json(CID, DID, '', 9, 1.0) is None
    assert capabilities.cosign_sig_to_json(CID, DID, None, 9, 1.0) is None


def test_signature_parse_refuses_a_mistyped_stamp():
    good = capabilities.cosign_sig_to_json(CID, DID, SIG, 9, 1.0)
    for key, value in (('seq', '9'), ('seq', True), ('ts', '1.0')):
        bad = dict(good)
        bad[key] = value
        assert capabilities.cosign_sig_from_json(bad) is None
    assert capabilities.cosign_sig_from_json(None) is None


def test_no_private_key_field_exists_on_either_envelope():
    # The keys do not travel: that is the whole reason the exchange is detached.
    # Only the signer's did:key — which embeds its PUBLIC key, so the assembling
    # node needs no registry — and the detached signature come back.
    req = capabilities.cosign_request_to_json('guardian', 'rotate', DID, CID,
                                              hexstr(64), 1, 1.0)
    sig = capabilities.cosign_sig_to_json(CID, DID, SIG, 1, 1.0)
    assert set(req) == {'record', 'op', 'polity', 'cid', 'bytes', 'seq', 'ts'}
    assert set(sig) == {'cid', 'signer', 'sig', 'seq', 'ts'}


# --- the wire ---------------------------------------------------------------- #

def test_cosign_verbs_not_in_unencrypted_allowlist():
    from autonomous_trust.core.identity.protocol import (IdentityProtocol,
                                                         UNENCRYPTED_VERBS)
    assert IdentityProtocol.cosign_request not in UNENCRYPTED_VERBS
    assert IdentityProtocol.cosign_sig not in UNENCRYPTED_VERBS


# --- the exchange, end to end through the real handlers ---------------------- #
# The stand-in borrows the REAL (unbound) IdentityProcess methods, so the send
# side, the shape gate and the per-sender replay guard are exercised as the node
# runs them. Modelled on test_profile_exchange.py's StubProc.
import logging       # noqa: E402
import queue         # noqa: E402
import threading     # noqa: E402
import types         # noqa: E402

import pytest        # noqa: E402

from autonomous_trust.core.identity import Identity          # noqa: E402
from autonomous_trust.core.identity.idprocess import IdentityProcess  # noqa: E402
from autonomous_trust.core.identity.protocol import IdentityProtocol  # noqa: E402
from autonomous_trust.core.system import CfgIds              # noqa: E402
from autonomous_trust.core.config import to_json_string, from_json_string  # noqa: E402
from autonomous_trust.core.freshness import Freshness        # noqa: E402

BYTES_HEX = hexstr(666)


class _Peers:
    def __init__(self, known):
        self._known = {str(i.uuid): i for i in known}

    def find_by_uuid(self, uuid):
        return self._known.get(str(uuid))


class StubProc:
    """Minimal stand-in for IdentityProcess: just what the co-signing path
    touches. The real (unbound) methods are invoked with this as ``self``."""

    def __init__(self, identity, known_peers=()):
        self.name = CfgIds.identity
        self.identity = identity
        self.logger = logging.getLogger('test-cosign')
        self.q_cadence = 1.0
        self.lock = threading.Lock()
        self.freshness = Freshness(self.name, self.logger)
        self.peers = _Peers(known_peers)
        self.last_cosign_request = {}
        self.last_cosign_sig = {}
        self.exceptions = []
        # Phase 4 P4.1: the co-sign handler now asks whether the asker is
        # blocked, so the stub needs the state that question reads.
        self.social_blocks = set()

    def report_exception(self, err, where):
        self.exceptions.append((where, err))

    request_cosign = IdentityProcess.request_cosign
    return_cosign = IdentityProcess.return_cosign
    handle_cosign_request = IdentityProcess.handle_cosign_request
    handle_cosign_sig = IdentityProcess.handle_cosign_sig
    get_last_cosign_request = IdentityProcess.get_last_cosign_request
    get_last_cosign_sig = IdentityProcess.get_last_cosign_sig
    _is_blocked = IdentityProcess._is_blocked
    _is_blocked_locked = IdentityProcess._is_blocked_locked


def test_a_blocked_peer_cannot_ask_us_to_cosign(alice, bob):
    """Phase 4 P4.1. A co-sign ask is directed and lands in front of a person
    as a decision to make, so a blocked peer must not be able to place one.

    This says nothing about whether the record is valid or whether this node is
    a required signer -- both remain Ethne's questions, answered app-side. It
    says only that THIS person will not be asked by THAT one."""
    asker = StubProc(bob, [alice])
    q = _queues()
    asker.request_cosign(q, [str(alice.uuid)], 'membership', 'admit', DID, CID,
                         BYTES_HEX)
    raw = q[CfgIds.network].get_nowait().obj

    signer = StubProc(alice, [bob])
    signer.social_blocks.add(str(bob.uuid))
    msg = _inbound(bob, raw, IdentityProtocol.cosign_request)
    assert signer.handle_cosign_request({}, msg) is True
    # Nothing recorded: the ask never reached the signer's surface.
    assert signer.get_last_cosign_request(str(bob.uuid)) == {}


@pytest.fixture
def alice():
    return Identity.initialize('alice@ex', 'alice@ex', '10.0.0.1')


@pytest.fixture
def bob():
    return Identity.initialize('bob@ex', 'bob@ex', '10.0.0.2')


def _queues():
    return {CfgIds.network: queue.Queue()}


def _inbound(from_identity, obj, function):
    return types.SimpleNamespace(from_whom=from_identity.publish(), obj=obj,
                                 function=function)


def test_ask_reaches_the_peer_encrypted_and_stamped(alice, bob):
    proc = StubProc(alice, [bob])
    q = _queues()
    assert proc.request_cosign(q, [str(bob.uuid)], 'membership', 'admit', DID,
                               CID, BYTES_HEX) == 1
    msg = q[CfgIds.network].get_nowait()
    assert msg.function == IdentityProtocol.cosign_request
    # Directed and ENCRYPTED, like a DM: crypto_box authenticates the asker, so
    # the envelope carries no signature of its own.
    assert msg.encrypt is True
    body = from_json_string(msg.obj)
    assert body['bytes'] == BYTES_HEX and body['op'] == 'admit'
    assert body['seq'] > 0 and body['ts'] > 0
    assert 'description' not in body
    assert proc.exceptions == []


def test_one_stamp_covers_every_copy_of_one_ask(alice, bob):
    carol = Identity.initialize('carol@ex', 'carol@ex', '10.0.0.3')
    proc = StubProc(alice, [bob, carol])
    q = _queues()
    assert proc.request_cosign(q, [str(bob.uuid), str(carol.uuid)],
                               'guardian', 'rotate', DID, CID, BYTES_HEX) == 2
    seqs = {from_json_string(q[CfgIds.network].get_nowait().obj)['seq']
            for _ in range(2)}
    assert len(seqs) == 1  # the same ask, not two


def test_an_unknown_act_never_reaches_the_wire(alice, bob):
    proc = StubProc(alice, [bob])
    q = _queues()
    # A voluntary departure is self-signed; there is nobody to collect from.
    assert proc.request_cosign(q, [str(bob.uuid)], 'membership', 'depart', DID,
                               CID, BYTES_HEX) == 0
    # ...and a payload no exporter produced is refused before anybody is
    # interrupted to look at it.
    assert proc.request_cosign(q, [str(bob.uuid)], 'membership', 'admit', DID,
                               CID, hexstr(665)) == 0
    assert q[CfgIds.network].empty()


def test_an_unknown_peer_is_skipped_not_guessed(alice, bob):
    stranger = Identity.initialize('dave@ex', 'dave@ex', '10.0.0.4')
    proc = StubProc(alice, [bob])
    q = _queues()
    assert proc.request_cosign(q, [str(bob.uuid), str(stranger.uuid)],
                               'membership', 'expel', DID, CID, BYTES_HEX) == 1
    assert q[CfgIds.network].qsize() == 1


def test_inbound_ask_is_recorded_and_a_replay_refused(alice, bob):
    asker = StubProc(bob, [alice])
    q = _queues()
    asker.request_cosign(q, [str(alice.uuid)], 'membership', 'admit', DID, CID,
                         BYTES_HEX)
    raw = q[CfgIds.network].get_nowait().obj

    signer = StubProc(alice, [bob])
    msg = _inbound(bob, raw, IdentityProtocol.cosign_request)
    assert signer.handle_cosign_request({}, msg) is True
    got = signer.get_last_cosign_request(bob.uuid)
    assert got['bytes'] == BYTES_HEX and got['op'] == 'admit'
    # The same ask again is a replay: the stamp does not advance, so it is
    # refused rather than re-surfaced to whoever is being asked to sign.
    signer.last_cosign_request.clear()
    assert signer.handle_cosign_request({}, msg) is True
    assert signer.get_last_cosign_request(bob.uuid) == {}
    assert signer.exceptions == []


def test_inbound_ask_with_a_payload_no_exporter_produced_is_dropped(alice, bob):
    signer = StubProc(alice, [bob])
    body = capabilities.cosign_request_to_json('membership', 'admit', DID, CID,
                                               BYTES_HEX, 3, 1.0)
    body['bytes'] = BYTES_HEX[:-1]  # truncated in flight -> reproduces nothing
    msg = _inbound(bob, to_json_string(body), IdentityProtocol.cosign_request)
    assert signer.handle_cosign_request({}, msg) is True
    assert signer.get_last_cosign_request(bob.uuid) == {}


def test_signature_returns_to_the_authoring_node(alice, bob):
    signer = StubProc(alice, [bob])
    q = _queues()
    assert signer.return_cosign(q, str(bob.uuid), CID, DID, SIG) is True
    msg = q[CfgIds.network].get_nowait()
    assert msg.function == IdentityProtocol.cosign_sig
    assert msg.encrypt is True

    author = StubProc(bob, [alice])
    assert author.handle_cosign_sig(
        {}, _inbound(alice, msg.obj, IdentityProtocol.cosign_sig)) is True
    got = author.get_last_cosign_sig(alice.uuid)
    # What comes back is the did:key (which EMBEDS the public key) and the
    # detached signature. The private key never moved — that is the whole point.
    assert got['signer'] == DID and got['sig'] == SIG
    assert author.exceptions == []


def test_signature_to_an_unknown_peer_is_refused(alice, bob):
    stranger = Identity.initialize('erin@ex', 'erin@ex', '10.0.0.5')
    signer = StubProc(alice, [bob])
    q = _queues()
    assert signer.return_cosign(q, str(stranger.uuid), CID, DID, SIG) is False
    assert q[CfgIds.network].empty()


def test_handlers_decline_a_verb_that_is_not_theirs(alice, bob):
    proc = StubProc(alice, [bob])
    assert proc.handle_cosign_request(
        {}, _inbound(bob, '{}', IdentityProtocol.dm)) is False
    assert proc.handle_cosign_sig(
        {}, _inbound(bob, '{}', IdentityProtocol.cosign_request)) is False
