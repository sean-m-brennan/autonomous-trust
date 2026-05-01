# ******************
#  Copyright 2025 Sean M. Brennan and contributors
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
Regression tests for the foundational AT-core fixes that were each
discovered the hard way during Stage-3b debugging. Each test pins one
behavior so a future refactor can't silently regress it.

Background lives in
`memory/project_debug_tooling_plan.md` (Stage 3 brief) and
`memory/project_federal_demo_progress.md` (the bug list these came from).
"""
from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from autonomous_trust.core.identity import Identity
from autonomous_trust.core.identity.history.history import IdentityObj
from autonomous_trust.core.algorithms.authority import AgreementByAuthority


class _ConcreteAuthority(AgreementByAuthority):
    """Test stand-in: AgreementByAuthority is abstract on _pre_verify.
    The fix being regression-tested lives in `threshold_rank` and
    `_count_vote`, neither of which depends on `_pre_verify`."""
    def _pre_verify(self, blob, proof, sig):
        return True


def _make_identity(nick: str = 'tester', addr: str = '10.0.0.1',
                   rank: int = 0) -> Identity:
    ident = Identity.initialize(f'{nick}@x', nick, addr)
    if rank:
        ident._rank = rank
    return ident


# ---------------------------------------------------------------------------
# Identity rank wire roundtrip — protobuf field must survive serialize/parse
# ---------------------------------------------------------------------------

@pytest.mark.parametrize('rank', [0, 1, 7, 255])
def test_identity_rank_survives_wire_roundtrip(rank):
    """`_rank` is set by sync_to_message and read by sync_from_message.
    A regression that drops `rank` from the protobuf (or its handler)
    silently flattens every voter to rank 0, which then makes any
    non-zero `threshold_rank` policy reject everyone."""
    src = _make_identity(rank=rank)
    assert src._rank == rank

    raw = src.to_wire_bytes()
    revived = Identity.from_wire_bytes(raw)

    assert revived._rank == rank, \
        f'rank dropped on wire roundtrip: src={rank} revived={revived._rank}'
    assert revived.uuid == src.uuid
    # AgreementVoter.rank reads through to _rank — both should agree.
    assert revived.rank == rank


# ---------------------------------------------------------------------------
# AgreementByAuthority(threshold_rank=0) must approve all voters
# ---------------------------------------------------------------------------

def test_authority_threshold_zero_admits_every_voter():
    """The IdentityByAuthority constructor passes `threshold_rank=0`
    explicitly. Earlier implementations derived a non-zero threshold
    (top 1/3 by rank), which silently rejected any voter at rank 0 —
    i.e. every voter, since rank propagation was broken at the same
    time. Pin the explicit-0 behavior so the cutoff doesn't drift."""
    me = _make_identity('me', '10.0.0.1')
    a = _make_identity('a', '10.0.0.2', rank=0)
    b = _make_identity('b', '10.0.0.3', rank=0)
    c = _make_identity('c', '10.0.0.4', rank=99)

    auth = _ConcreteAuthority.__new__(_ConcreteAuthority)
    _ConcreteAuthority.__init__(auth, me, [a, b, c], threshold_rank=0)
    assert auth.threshold_rank == 0

    proof = MagicMock(approval=True)
    # Every voter (any rank ≥ 0) must round-trip approval=True.
    for voter in (a, b, c):
        result_rank, approved = auth._count_vote(None, proof, voter)
        assert result_rank == voter.rank
        assert approved is True, \
            f'threshold_rank=0 rejected voter {voter.nickname} at rank {voter.rank}'


def test_authority_explicit_threshold_filters_below_cutoff():
    """Companion test: an explicit non-zero threshold still rejects
    below-rank voters. Guards against a future fix to the above test
    accidentally short-circuiting `_count_vote`."""
    me = _make_identity('me', '10.0.0.1')
    low = _make_identity('low', '10.0.0.2', rank=0)
    high = _make_identity('high', '10.0.0.3', rank=5)

    auth = _ConcreteAuthority.__new__(_ConcreteAuthority)
    _ConcreteAuthority.__init__(auth, me, [low, high], threshold_rank=3)
    assert auth.threshold_rank == 3

    proof = MagicMock(approval=True)
    _, approved_low = auth._count_vote(None, proof, low)
    _, approved_high = auth._count_vote(None, proof, high)
    assert approved_low is False, 'rank<threshold must not count toward approval'
    assert approved_high is True


def test_authority_derived_threshold_when_none():
    """Default threshold_rank=None derives `top 1/3 by rank` cutoff."""
    me = _make_identity('me', '10.0.0.1')
    voters = [_make_identity(f'v{i}', f'10.0.0.{i+2}', rank=i)
              for i in range(9)]  # ranks 0..8

    auth = _ConcreteAuthority.__new__(_ConcreteAuthority)
    _ConcreteAuthority.__init__(auth, me, voters, threshold_rank=None)
    # Top 1/3 of 9 = 3 voters; cutoff index = 3-1 = 2 in sorted-desc.
    # Sorted desc: [8,7,6,5,4,3,2,1,0] → index 2 = 6.
    assert auth.threshold_rank == 6


# ---------------------------------------------------------------------------
# verify_object must use the voter's public key, not the subject's
# ---------------------------------------------------------------------------

def test_verify_object_uses_voter_signature_not_subject():
    """A vote on `subject` is signed by `voter` (proof.uuid). Earlier
    code looked up the subject's key for verification, which only
    worked when subject == voter (i.e. self-votes). For peer-on-peer
    votes the verification silently passed nonsense or failed
    spuriously. Pin: lookup uses proof.uuid, falls back through
    `myself`, then through `_peers.find_by_uuid`."""
    from autonomous_trust.core.identity.history.history import IdentityHistory

    # Build a real signed payload by `voter` over a string, then ask
    # verify_object to validate it using the wrong (subject) key —
    # must fail — and the right (voter) key — must succeed.
    voter = _make_identity('voter', '10.0.0.2')
    subject = _make_identity('subject', '10.0.0.3')

    proof = MagicMock(uuid=voter.uuid, approval=True)
    proof.to_string = lambda: 'proof-bytes'
    sig_msg = b'proof-bytes'
    raw_sig = voter.sign(sig_msg)
    # _process_id wire shape: (msg, sig) tuple, both hex-encoded by
    # Identity.sign (HexEncoder).
    sig_tuple = (raw_sig.message, raw_sig.signature)

    blob = MagicMock(spec=IdentityObj)
    blob.identity = subject
    blob.validate.return_value = True

    history = IdentityHistory.__new__(IdentityHistory)
    history.logger = MagicMock()
    history.myself = MagicMock(uuid='other-uuid')

    # Right key path: peers contains voter → lookup hits voter.
    peers = MagicMock()
    peers.find_by_uuid.side_effect = (
        lambda uid: voter if uid == voter.uuid else None)
    history._peers = peers
    assert history.verify_object(blob, proof, sig_tuple) is True

    # Wrong key path: peers returns subject for voter's uuid → verify
    # fails because the signature wasn't made by subject.
    peers.find_by_uuid.side_effect = lambda uid: subject
    assert history.verify_object(blob, proof, sig_tuple) is False

    # Unknown voter path: lookup misses → reject (don't fall through).
    peers.find_by_uuid.side_effect = lambda uid: None
    assert history.verify_object(blob, proof, sig_tuple) is False


# ---------------------------------------------------------------------------
# recv_peer must accept unknown bootstrap senders (blacklist-only gate)
# ---------------------------------------------------------------------------

def test_tcp_recv_peer_accepts_unknown_sender():
    """The bootstrap path needs `recv_peer` to deliver bytes from
    senders that aren't in `self.peers` yet — a joining peer's first
    inbound is the welcomer's identity:accept, which arrives before
    the welcomer is registered. The earlier `accept_peer_message` gate
    returned None for unknown senders, killing bootstrap silently.
    Current contract: only own-address and blacklisted addrs return
    None; everything else is delivered."""
    from autonomous_trust.core.network.tcp import TCPNetworkProcess

    nproc = TCPNetworkProcess.__new__(TCPNetworkProcess)
    nproc.my_address = '10.0.0.1'
    nproc._rejected_addresses = set()

    # Listener socket: accept() yields a client socket; _recv reads
    # the length prefix + body. Stub _recv to short-circuit so we
    # don't have to forge a TCP framing on a mock.
    fake_payload = b'identity:accept-from-stranger'
    client = MagicMock()
    listener = MagicMock()
    listener.accept.return_value = (client, ('10.0.0.99', 5555))
    nproc.recv_ptp_sock = listener

    with patch.object(TCPNetworkProcess, '_recv', return_value=fake_payload):
        msg, addr, port = nproc.recv_peer()
    assert msg == fake_payload
    assert addr == '10.0.0.99'
    assert port == 5555

    # Self-address must return None tuple.
    listener.accept.return_value = (client, ('10.0.0.1', 5555))
    with patch.object(TCPNetworkProcess, '_recv', return_value=fake_payload):
        result = nproc.recv_peer()
    assert result == (None, None, None)

    # Blacklisted must return (None, addr, port).
    nproc._rejected_addresses.add('10.0.0.66')
    listener.accept.return_value = (client, ('10.0.0.66', 5555))
    msg, addr, port = nproc.recv_peer()
    assert msg is None
    assert addr == '10.0.0.66'


def test_tcp_recv_raises_peer_disconnect_on_clean_close():
    """A peer that closes mid-handshake (returns b'' on first recv)
    raises PeerDisconnect — distinct from TransmissionError so the
    listener can log the routine event at debug level. Earlier, every
    such close logged at ERROR and dirtied the inspector-onboarding
    log timeline."""
    from autonomous_trust.core.network.tcp import (
        TCPNetworkProcess, PeerDisconnect)

    nproc = TCPNetworkProcess.__new__(TCPNetworkProcess)
    sock = MagicMock()
    sock.recv.return_value = b''  # clean close
    with pytest.raises(PeerDisconnect):
        nproc._recv(sock)


def test_tcp_recv_group_accepts_unknown_sender():
    """Same relaxation as recv_peer — the group socket gate is
    blacklist-only; group decryption downstream still requires
    sender ∈ group.addresses."""
    from autonomous_trust.core.network.tcp import TCPNetworkProcess

    nproc = TCPNetworkProcess.__new__(TCPNetworkProcess)
    nproc.my_address = '10.0.0.1'
    nproc._rejected_addresses = set()

    fake_payload = b'group-broadcast-payload'
    client = MagicMock()
    listener = MagicMock()
    listener.accept.return_value = (client, ('10.0.0.50', 5556))
    nproc.recv_grp_sock = listener

    with patch.object(TCPNetworkProcess, '_recv', return_value=fake_payload):
        msg, addr, port = nproc.recv_group()
    assert msg == fake_payload
    assert addr == '10.0.0.50'


# ---------------------------------------------------------------------------
# track_recv_error must defensively init the unknown_peer stat entry.
# Surfaced 2026-05-01 by tests/diag/harness — first-error in a receiver
# thread crashed the listener for the rest of the run.
# ---------------------------------------------------------------------------

def test_track_recv_error_handles_missing_unknown_peer():
    from autonomous_trust.core.network.netprocess import (
        NetworkProcess, NetStat)

    nproc = NetworkProcess.__new__(NetworkProcess)
    nproc.statistics = {}
    nproc.unknown_peer = '0'
    # Pre-condition: key not present
    assert nproc.unknown_peer not in nproc.statistics
    # Must not raise KeyError
    nproc.track_recv_error()
    assert nproc.unknown_peer in nproc.statistics
    assert isinstance(nproc.statistics[nproc.unknown_peer], NetStat)
    # Idempotent — second call increments err count, not re-init.
    stat_before = nproc.statistics[nproc.unknown_peer]
    nproc.track_recv_error()
    assert nproc.statistics[nproc.unknown_peer] is stat_before


# ---------------------------------------------------------------------------
# _encr_recv must NOT die on BlockingIOError.
# When fd-passing through forkserver leaves a socket in non-blocking
# mode without Python-level timeout tracking, recvfrom raises EAGAIN.
# The receiver thread used to crash via the catch-all + track_recv_error
# KeyError. Both halves of the fix matter; this test pins the loop.
# ---------------------------------------------------------------------------

def test_encr_recv_survives_blocking_io_error():
    from autonomous_trust.core.network.netprocess import NetworkProcess

    nproc = NetworkProcess.__new__(NetworkProcess)
    nproc.stop = False
    nproc.statistics = {}
    nproc.unknown_peer = '0'
    nproc.socket_timeout = 0.001
    # peers is a @property on NetworkProcess; back it via the protocol.
    nproc.protocol = MagicMock()
    nproc.protocol.peers.find_by_address.return_value = None
    nproc.pests = {}
    nproc.annoy_limit = 100
    nproc.logger = MagicMock()

    call_count = {'n': 0}

    def fake_recv():
        call_count['n'] += 1
        if call_count['n'] <= 3:
            raise BlockingIOError(11, 'Resource temporarily unavailable')
        # After surviving 3 EAGAIN, deliver one good message and stop.
        nproc.stop = True
        return (b'payload', '10.0.0.5', 5555)

    fake_recv.__name__ = 'recv_peer'
    msg_queue: list = []

    class _DequeShim:
        def append(self, item):
            msg_queue.append(item)

    nproc._encr_recv(fake_recv, _DequeShim())

    # Loop didn't crash; it survived all 3 EAGAINs and delivered the
    # one real message after.
    assert call_count['n'] == 4
    assert msg_queue == [(b'payload', '10.0.0.5')]


# ---------------------------------------------------------------------------
# unknown_receiver mirrors the same survivability for the broadcast leg.
# ---------------------------------------------------------------------------

def test_unknown_receiver_survives_blocking_io_error():
    from autonomous_trust.core.network.netprocess import NetworkProcess

    nproc = NetworkProcess.__new__(NetworkProcess)
    nproc.stop = False
    nproc.socket_timeout = 0.001
    nproc.unknown_messages = []
    nproc.logger = MagicMock()

    call_count = {'n': 0}

    def fake_recv_any():
        call_count['n'] += 1
        if call_count['n'] <= 2:
            raise BlockingIOError(11, 'Resource temporarily unavailable')
        nproc.stop = True
        return (b'broadcast', '10.0.0.99', 5555)

    nproc.recv_any = fake_recv_any
    nproc.unknown_receiver()
    assert call_count['n'] == 3
    assert nproc.unknown_messages == [(b'broadcast', '10.0.0.99')]


# ---------------------------------------------------------------------------
# NetworkProcess.process must re-establish receiver-socket timeouts in
# the worker subprocess. Pickling through forkserver fd-passing keeps
# the OS-level non-blocking flag but loses the Python-level timeout
# state — without this rebinding, recvfrom raises EAGAIN on the very
# first call.
# ---------------------------------------------------------------------------

def test_process_rebinds_receiver_socket_timeouts():
    from autonomous_trust.core.network.netprocess import NetworkProcess

    nproc = NetworkProcess.__new__(NetworkProcess)
    nproc.socket_timeout = 0.1

    captured: dict = {'ptp': None, 'grp': None, 'cast': None}

    def make_sock(name):
        s = MagicMock()
        s.settimeout.side_effect = (
            lambda v, _name=name: captured.__setitem__(_name, v))
        return s

    nproc.recv_ptp_sock = make_sock('ptp')
    nproc.recv_grp_sock = make_sock('grp')
    nproc.recv_cast_sock = make_sock('cast')

    # Stub everything process() touches after the timeout-rebind so the
    # call returns quickly.
    nproc.diplomat = False
    nproc.ping = None
    nproc.stop = True  # short-circuit any post-rebind branches
    nproc.keep_running = MagicMock(return_value=False)
    # Make the receiver-thread targets cheap no-ops.
    nproc.peer_receiver = lambda: None
    nproc.group_receiver = lambda: None
    nproc.unknown_receiver = lambda: None
    nproc.mystery_handler = lambda *_: None

    nproc.process({}, MagicMock())

    assert captured == {'ptp': 0.1, 'grp': 0.1, 'cast': 0.1}, (
        'each receiver socket must be re-settimeout()d to '
        'NetworkProcess.socket_timeout in the worker subprocess')
