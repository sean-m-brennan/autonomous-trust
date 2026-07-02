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
# net_stats must (a) not raise "dictionary changed size during iteration" when
# the sender/receiver threads add peers mid-read, (b) compute a bytes/second
# rate (the timedelta needs .total_seconds(); int/timedelta is a TypeError), and
# (c) skip entries without a spannable interval. Surfaced 2026-06-26 by the
# two-node integration test ([node_b] UDPNetworkProcess: dictionary changed
# size during iteration).
# ---------------------------------------------------------------------------

def test_net_stats_rate_is_bytes_per_second_and_shape():
    from collections import deque
    from datetime import datetime, timedelta
    from autonomous_trust.core.network.netprocess import NetworkProcess, NetStat

    nproc = NetworkProcess.__new__(NetworkProcess)
    nproc.statistics = {}
    stat = NetStat()
    t0 = datetime(2026, 6, 26, 12, 0, 0)
    stat.times = deque([t0, t0 + timedelta(seconds=2)])  # 2 s span
    stat.send = deque([100, 100])
    stat.recv = deque([50, 50])
    stat.send_total, stat.recv_total = 200, 100
    stat.err_out, stat.err_in = 1, 2
    nproc.statistics['peer-1'] = stat

    stats = nproc.net_stats                       # must not raise TypeError
    up, down, send_total, recv_total, err_out, err_in = stats['peer-1']
    assert up == 100.0 and down == 50.0           # bytes / 2 s
    assert (send_total, recv_total, err_out, err_in) == (200, 100, 1, 2)


def test_net_stats_skips_insufficient_or_zero_span_entries():
    from collections import deque
    from datetime import datetime
    from autonomous_trust.core.network.netprocess import NetworkProcess, NetStat

    nproc = NetworkProcess.__new__(NetworkProcess)
    nproc.statistics = {}
    one = NetStat()
    one.sent(10)                                  # single sample -> no interval
    nproc.statistics['one-sample'] = one
    same = NetStat()
    t = datetime(2026, 6, 26, 12, 0, 0)
    same.times = deque([t, t])                    # zero-span -> no rate
    same.send, same.recv = deque([1, 1]), deque([1, 1])
    nproc.statistics['zero-span'] = same

    stats = nproc.net_stats                        # no IndexError / ZeroDivision
    assert 'one-sample' not in stats and 'zero-span' not in stats


def test_net_stats_safe_when_peer_added_mid_iteration():
    # Deterministically reproduce the reported failure: a peer is added to
    # statistics WHILE net_stats iterates it (as the sender/receiver threads
    # do). The injecting entry's .times access inserts a new key; with the old
    # `for uuid in self.statistics` this raised "dictionary changed size during
    # iteration", with the key snapshot it does not.
    from collections import deque
    from datetime import datetime, timedelta
    from autonomous_trust.core.network.netprocess import NetworkProcess, NetStat

    t0 = datetime(2026, 6, 26, 12, 0, 0)

    def _stat(send_total):
        s = NetStat()
        s.times = deque([t0, t0 + timedelta(seconds=1)])
        s.send = deque([send_total // 2, send_total // 2])
        s.recv = deque([0, 0])
        s.send_total = send_total
        return s

    class _InjectingStat:
        """Duck-typed NetStat whose .times read inserts a late peer."""
        def __init__(self, target):
            self._target = target
            self._fired = False
            self.send = deque([5, 5])
            self.recv = deque([0, 0])
            self.send_total, self.recv_total, self.err_out, self.err_in = 10, 0, 0, 0

        @property
        def times(self):
            if not self._fired:
                self._fired = True
                self._target['late-peer'] = _stat(99)   # mutate mid-iteration
            return deque([t0, t0 + timedelta(seconds=1)])

    nproc = NetworkProcess.__new__(NetworkProcess)
    nproc.statistics = {}
    nproc.statistics['inject'] = _InjectingStat(nproc.statistics)
    nproc.statistics['other'] = _stat(20)

    stats = nproc.net_stats          # must not raise
    # the two peers present at snapshot time are reported; the late insert is
    # simply picked up on the next call rather than crashing this one.
    assert 'inject' in stats and 'other' in stats
    assert nproc.net_stats.get('late-peer') is not None


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

# ---------------------------------------------------------------------------
# Drain-loop pacing must NOT be reverted to sleep_until(self.cadence).
# See project_proc_loop_throttle.md: the 0.5 s cadence + 1-msg-per-iter
# shape capped each subsystem at ~2 msgs/s. repproc was fixed first;
# idproc + negproc fixed in the same sweep. A static check is enough —
# the harness convergence tests catch any bootstrap-timing regression.
# ---------------------------------------------------------------------------

def test_drain_loop_pacing_not_reverted():
    import inspect
    import re
    from autonomous_trust.core.identity.idprocess import IdentityProcess
    from autonomous_trust.core.negotiation.negprocess import NegotiationProcess
    from autonomous_trust.core.reputation.repprocess import ReputationProcess
    # Strip comment lines so the historical mention in module-level
    # block comments doesn't trip this static check.
    code_only = lambda src: '\n'.join(
        ln for ln in src.splitlines()
        if not re.match(r'\s*#', ln))
    for cls in (IdentityProcess, NegotiationProcess, ReputationProcess):
        src = code_only(inspect.getsource(cls.process))
        assert 'self.sleep_until(self.cadence)' not in src, (
            f'{cls.__name__}.process re-introduced cadence-throttle '
            f'self.sleep_until(self.cadence) — see '
            f'project_proc_loop_throttle.md')
        assert 'DRAIN_BUDGET' in src, (
            f'{cls.__name__}.process should drain with DRAIN_BUDGET '
            f'(see repprocess.py for the canonical shape)')


def test_netproc_inbound_deques_are_drained_per_iter():
    """The three netproc inbound deques (peer_messages, group_messages,
    unknown_messages) used to be popleft'd once per iter — capping
    inbound throughput at ~6 msgs/s on a busy peer. The fix is a
    per-channel INBOUND_BUDGET drain loop. Pin the source shape so a
    revert that brings back the single popleft pattern fails here."""
    import inspect
    import re
    from autonomous_trust.core.network.netprocess import NetworkProcess
    code_only = '\n'.join(
        ln for ln in inspect.getsource(NetworkProcess.process).splitlines()
        if not re.match(r'\s*#', ln))
    assert 'INBOUND_BUDGET' in code_only, (
        'NetworkProcess.process should drain inbound deques with an '
        'INBOUND_BUDGET — see project_proc_loop_throttle.md')
    # All three deque names must appear inside while-drain blocks; the
    # while...popleft pattern is the load-bearing change. Counting
    # `while` occurrences is a proxy for "per-channel drain loop".
    while_count = len(re.findall(r'^\s*while\s', code_only, re.M))
    assert while_count >= 4, (
        f'NetworkProcess.process should have at least 4 while-loops '
        f'(outer keep_running + 3 inbound drains), found {while_count}')


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
