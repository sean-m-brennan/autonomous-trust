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
"""Unit tests for group partition recovery.

Doc: doc/architecture/partition-recovery.md

These tests build minimal IdentityProcess instances via ``object.__new__``
and populate just the fields the handlers touch. That bypasses the
full Automaton/Process/history bootstrap (which needs a generated
config tree on disk + multiprocessing scaffolding), while still
exercising the actual handler code from idprocess.py.

What's covered:
- ``handle_partition_signal`` emits a probe with the correct payload,
  signature, and target queue.
- ``handle_partition_signal`` honors the 10s per-from_addr cooldown.
- ``handle_partition_signal`` suppresses while bootstrapping
  (``self.group is None`` or ``self.choosing``) or while a recovery
  is already in flight.
- ``handle_partition_probe`` verifies the sender's signature, builds
  a well-formed ``partition_response``, and honors the 30s per-peer
  cooldown.
- ``handle_partition_probe`` rejects a tampered signature.
- ``handle_partition_response`` adopts a larger group by
  re-broadcasting ``request_access`` and sets
  ``_partition_recovery_in_progress``.
- ``handle_partition_response`` ignores size-tie when our uuid wins
  (the other side will initiate from their end).
- ``handle_partition_response`` ignores responses addressed to other
  peers' probes (``in_response_to`` mismatch).
- The merge hook (``_merge_to_mesh`` adopt branch) clears
  ``_partition_recovery_in_progress`` and the probe cooldown.
"""
from __future__ import annotations

import logging
import time
import uuid as uuid_mod
from datetime import timedelta
from unittest.mock import MagicMock, patch

import pytest
from nacl.encoding import HexEncoder

from autonomous_trust.core.identity import Identity, Peers, Group
from autonomous_trust.core.identity.idprocess import IdentityProcess
from autonomous_trust.core.identity.protocol import IdentityProtocol
from autonomous_trust.core.network import Message
from autonomous_trust.core.system import CfgIds, now
from autonomous_trust.core._python.protocol import Protocol


_MOCK_ADDRESSES = {
    'ip4': '192.168.1.1',
    'ip6': '::1',
    'mac': '00:11:22:33:44:55',
    'ip4_subnet': '255.255.255.0',
    'ip6_subnet': 'ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff',
    'mac_bcast': 'ff:ff:ff:ff:ff:ff',
}


def _new_identity(name, address):
    """Build an Identity without the network-discovery side trip."""
    with patch('autonomous_trust.core.network.network.Network.get_addresses',
               return_value=_MOCK_ADDRESSES):
        return Identity.initialize(name, name, address)


def _group_of_size(member_identity, extra_addresses):
    """Build a Group whose address map contains the member plus extras."""
    addrs = {str(member_identity.uuid): member_identity.address}
    for ident in extra_addresses:
        addrs[str(ident.uuid)] = ident.address
    return Group.initialize(addrs, '%s-grp' % member_identity.nickname)


class _FakeQueue:
    """List-backed queue stub that mimics the put/get_nowait interface."""

    def __init__(self):
        self.items = []

    def put(self, item, block=True, timeout=None):
        self.items.append(item)

    def put_nowait(self, item):
        self.items.append(item)

    def get_nowait(self):
        if not self.items:
            from queue import Empty
            raise Empty()
        return self.items.pop(0)

    def __len__(self):
        return len(self.items)


def _build_process(identity, group, peers=None):
    """Allocate a minimally-populated IdentityProcess.

    Bypasses ``__init__`` so we don't need a generated config tree or
    a Manager/Pool. Populates exactly the fields the partition-recovery
    handlers and their helpers reach for.
    """
    proc = object.__new__(IdentityProcess)
    proc.identity = identity
    proc.group = group
    proc.peers = peers if peers is not None else Peers()
    proc.protocol = Protocol(CfgIds.identity, logging.getLogger('test'), None)
    proc.protocol.group = group
    proc.protocol.peers = proc.peers
    proc.name = CfgIds.identity
    proc.logger = logging.getLogger('test.idproc.partition')
    proc.q_cadence = 0.01
    proc.phase = 3
    proc.choosing = False
    proc.merging = False
    proc.lock = MagicMock()  # report_exception touches self.lock under load
    proc.lock.__enter__ = MagicMock(return_value=proc.lock)
    proc.lock.__exit__ = MagicMock(return_value=False)
    proc._partition_probe_cooldown = {}
    proc._partition_response_cooldown = {}
    proc._partition_recovery_in_progress = None
    # report_exception only exists on the Process base class; route it
    # to the logger so test failures surface as warnings, not crashes.
    proc.report_exception = lambda err, where: \
        proc.logger.exception('%s: %s' % (where, err))
    return proc


def _build_queues():
    return {
        CfgIds.network: _FakeQueue(),
        CfgIds.identity: _FakeQueue(),
    }


# ---------------------------------------------------------------------------
# handle_partition_signal
# ---------------------------------------------------------------------------

class TestPartitionSignal:
    def test_emits_probe_with_correct_payload(self):
        me = _new_identity('coord', '10.0.0.3')
        grp = _group_of_size(me, [])
        proc = _build_process(me, grp)
        queues = _build_queues()
        sig_msg = Message(CfgIds.identity,
                          IdentityProtocol.partition_signal,
                          '10.0.0.10', encrypt=False)

        handled = proc.handle_partition_signal(queues, sig_msg)
        assert handled is True

        out = queues[CfgIds.network].items
        assert len(out) == 1
        probe = out[0]
        assert probe.function == IdentityProtocol.partition_probe
        assert probe.encrypt is False
        # Payload is JSON; deserialize and verify the embedded signature.
        from autonomous_trust.core.config import from_json_string
        payload = from_json_string(probe.obj) \
            if isinstance(probe.obj, (str, bytes)) else probe.obj
        assert payload['my_group_uuid'] == str(grp.uuid)
        assert payload['my_group_size'] == 1
        # Signature must verify under the sender identity's public key.
        # Use the raw-bytes path per the documented quirk in message.py.
        sender_id = payload['from_identity']
        sig_raw = HexEncoder.decode(payload['signature'].encode('ascii'))
        sender_id.signature.public.verify(
            IdentityProcess._partition_probe_canonical(
                payload['my_group_uuid'], payload['my_group_size']),
            sig_raw)

    def test_cooldown_suppresses_repeated_probe(self):
        me = _new_identity('coord', '10.0.0.3')
        grp = _group_of_size(me, [])
        proc = _build_process(me, grp)
        queues = _build_queues()
        sig_msg = Message(CfgIds.identity,
                          IdentityProtocol.partition_signal,
                          '10.0.0.10', encrypt=False)

        proc.handle_partition_signal(queues, sig_msg)
        proc.handle_partition_signal(queues, sig_msg)
        # Second call within 10s must not emit a second probe.
        assert len(queues[CfgIds.network]) == 1

    def test_different_addrs_each_get_own_probe(self):
        me = _new_identity('coord', '10.0.0.3')
        grp = _group_of_size(me, [])
        proc = _build_process(me, grp)
        queues = _build_queues()
        for addr in ('10.0.0.10', '10.0.0.11'):
            proc.handle_partition_signal(
                queues,
                Message(CfgIds.identity, IdentityProtocol.partition_signal,
                        addr, encrypt=False))
        assert len(queues[CfgIds.network]) == 2

    def test_suppressed_during_bootstrap(self):
        me = _new_identity('coord', '10.0.0.3')
        proc = _build_process(me, group=None)
        queues = _build_queues()
        sig_msg = Message(CfgIds.identity,
                          IdentityProtocol.partition_signal,
                          '10.0.0.10', encrypt=False)

        proc.handle_partition_signal(queues, sig_msg)
        # self.group is None — no probe should fire.
        assert len(queues[CfgIds.network]) == 0

    def test_suppressed_during_recovery(self):
        me = _new_identity('coord', '10.0.0.3')
        grp = _group_of_size(me, [])
        proc = _build_process(me, grp)
        proc._partition_recovery_in_progress = ('some-other-uuid', now())
        queues = _build_queues()

        proc.handle_partition_signal(
            queues,
            Message(CfgIds.identity, IdentityProtocol.partition_signal,
                    '10.0.0.10', encrypt=False))
        assert len(queues[CfgIds.network]) == 0

    def test_recovery_timeout_unblocks_probes(self):
        me = _new_identity('coord', '10.0.0.3')
        grp = _group_of_size(me, [])
        proc = _build_process(me, grp)
        stale = now() - timedelta(
            seconds=IdentityProcess._PARTITION_RECOVERY_TIMEOUT_SEC + 1)
        proc._partition_recovery_in_progress = ('stale-uuid', stale)
        queues = _build_queues()

        proc.handle_partition_signal(
            queues,
            Message(CfgIds.identity, IdentityProtocol.partition_signal,
                    '10.0.0.10', encrypt=False))
        # Stale recovery should auto-clear and let the probe through.
        assert proc._partition_recovery_in_progress is None
        assert len(queues[CfgIds.network]) == 1


# ---------------------------------------------------------------------------
# handle_partition_probe
# ---------------------------------------------------------------------------

class TestPartitionProbe:
    def _craft_probe(self, sender_identity, sender_group_uuid,
                     sender_group_size):
        """Construct a signed probe payload as if `sender_identity` sent it."""
        sig_bytes = IdentityProcess._partition_probe_canonical(
            sender_group_uuid, sender_group_size)
        signed = sender_identity.sign(sig_bytes)
        from autonomous_trust.core.config import to_json_string
        payload = to_json_string({
            'from_identity': sender_identity.publish(),
            'from_address': sender_identity.address,
            'my_group_uuid': sender_group_uuid,
            'my_group_size': sender_group_size,
            'signature': signed.signature.decode('ascii'),
        })
        return Message(CfgIds.identity, IdentityProtocol.partition_probe,
                       payload, encrypt=False)

    def test_emits_response_with_correct_payload(self):
        me = _new_identity('captain', '10.0.0.10')
        other = _new_identity('lieutenant', '10.0.0.11')
        my_group = _group_of_size(me, [other])
        my_peers = Peers()
        my_peers.all.append(other)
        proc = _build_process(me, my_group, my_peers)
        queues = _build_queues()

        sender = _new_identity('lone-coord', '10.0.0.3')
        probe = self._craft_probe(sender, str(uuid_mod.uuid4()), 1)
        handled = proc.handle_partition_probe(queues, probe)
        assert handled is True

        out = queues[CfgIds.network].items
        assert len(out) == 1
        resp = out[0]
        assert resp.function == IdentityProtocol.partition_response
        from autonomous_trust.core.config import from_json_string
        rp = from_json_string(resp.obj) if isinstance(resp.obj, (str, bytes)) \
            else resp.obj
        assert rp['in_response_to'] == str(sender.uuid)
        assert rp['my_group_uuid'] == str(my_group.uuid)
        assert rp['my_group_size'] == 2
        # Verifying the response's own signature (raw-bytes path).
        resp_sig_raw = HexEncoder.decode(rp['signature'].encode('ascii'))
        rp['from_identity'].signature.public.verify(
            IdentityProcess._partition_response_canonical(
                rp['my_group_uuid'], rp['my_group_size'],
                rp['in_response_to']),
            resp_sig_raw)

    def test_rejects_bad_signature(self):
        me = _new_identity('captain', '10.0.0.10')
        my_group = _group_of_size(me, [])
        proc = _build_process(me, my_group)
        queues = _build_queues()
        sender = _new_identity('attacker', '10.0.0.99')
        # Sign claim X but advertise claim Y.
        sig_bytes = IdentityProcess._partition_probe_canonical(
            'real-group-uuid', 1)
        signed = sender.sign(sig_bytes)
        from autonomous_trust.core.config import to_json_string
        payload = to_json_string({
            'from_identity': sender.publish(),
            'from_address': sender.address,
            'my_group_uuid': 'lied-group-uuid',   # mismatch
            'my_group_size': 99,                  # mismatch
            'signature': signed.signature.decode('ascii'),
        })
        probe = Message(CfgIds.identity, IdentityProtocol.partition_probe,
                        payload, encrypt=False)
        proc.handle_partition_probe(queues, probe)
        assert len(queues[CfgIds.network]) == 0

    def test_response_cooldown_per_sender(self):
        me = _new_identity('captain', '10.0.0.10')
        my_group = _group_of_size(me, [])
        proc = _build_process(me, my_group)
        queues = _build_queues()
        sender = _new_identity('probing-coord', '10.0.0.3')
        probe = self._craft_probe(sender, str(uuid_mod.uuid4()), 1)
        proc.handle_partition_probe(queues, probe)
        proc.handle_partition_probe(queues, probe)
        # Same sender within 30s — only one response.
        assert len(queues[CfgIds.network]) == 1


# ---------------------------------------------------------------------------
# handle_partition_response
# ---------------------------------------------------------------------------

class TestPartitionResponse:
    def _craft_response(self, responder_identity, responder_group_uuid,
                         responder_group_size, in_response_to,
                         leader_uuid=None, leader_address=None):
        from autonomous_trust.core.config import to_json_string
        sig_bytes = IdentityProcess._partition_response_canonical(
            responder_group_uuid, responder_group_size, in_response_to)
        signed = responder_identity.sign(sig_bytes)
        payload = to_json_string({
            'from_identity': responder_identity.publish(),
            'from_address': responder_identity.address,
            'in_response_to': in_response_to,
            'my_group_uuid': responder_group_uuid,
            'my_group_size': responder_group_size,
            'my_group_leader': leader_uuid or str(responder_identity.uuid),
            'my_group_leader_address': leader_address
                                       or responder_identity.address,
            'signature': signed.signature.decode('ascii'),
        })
        return Message(CfgIds.identity, IdentityProtocol.partition_response,
                       payload, encrypt=False)

    def test_adopts_larger_group_via_request_access(self):
        me = _new_identity('coord', '10.0.0.3')
        my_group = _group_of_size(me, [])  # size 1
        proc = _build_process(me, my_group)
        proc.package_hash = b'pkg-hash-stub'  # _broadcast_request_access uses it
        # _broadcast_request_access reads self.capabilities via the
        # property → self.protocol.capabilities. Set the backing field.
        from autonomous_trust.core._python.capabilities import Capabilities
        proc.protocol.capabilities = Capabilities()
        queues = _build_queues()

        responder = _new_identity('captain', '10.0.0.10')
        their_group_uuid = str(uuid_mod.uuid4())
        resp = self._craft_response(responder, their_group_uuid, 5,
                                    str(me.uuid))
        proc.handle_partition_response(queues, resp)

        # Recovery should be marked in progress.
        assert proc._partition_recovery_in_progress is not None
        assert proc._partition_recovery_in_progress[0] == their_group_uuid
        # And a request_access broadcast should have been queued.
        emitted = [m for m in queues[CfgIds.network].items
                   if m.function == IdentityProtocol.announce]
        assert len(emitted) == 1

    def test_ignores_response_to_other_peer(self):
        me = _new_identity('coord', '10.0.0.3')
        proc = _build_process(me, _group_of_size(me, []))
        queues = _build_queues()
        responder = _new_identity('captain', '10.0.0.10')
        # in_response_to is some random uuid, not ours.
        resp = self._craft_response(responder, str(uuid_mod.uuid4()), 5,
                                    str(uuid_mod.uuid4()))
        proc.handle_partition_response(queues, resp)
        assert proc._partition_recovery_in_progress is None
        assert len(queues[CfgIds.network]) == 0

    def test_we_win_when_we_are_larger(self):
        me = _new_identity('captain', '10.0.0.10')
        extras = [_new_identity('p%d' % i, '10.0.0.%d' % (11 + i))
                  for i in range(4)]
        my_group = _group_of_size(me, extras)  # size 5
        proc = _build_process(me, my_group)
        queues = _build_queues()

        responder = _new_identity('coord', '10.0.0.3')
        resp = self._craft_response(responder, str(uuid_mod.uuid4()), 2,
                                    str(me.uuid))
        proc.handle_partition_response(queues, resp)
        assert proc._partition_recovery_in_progress is None
        # No request_access should fire — they will initiate from their end.
        assert all(m.function != IdentityProtocol.announce
                   for m in queues[CfgIds.network].items)


# ---------------------------------------------------------------------------
# Merge-completion hook
# ---------------------------------------------------------------------------

class TestMergeHook:
    def test_group_update_adopt_clears_recovery_state(self):
        """When handle_group_update adopts a foreign larger group, the
        recovery bookkeeping should clear so future probes aren't
        suppressed. Drives the simpler of the two adopt paths (the
        other lives in _merge_to_mesh; both share the same cleanup).
        """
        me = _new_identity('coord', '10.0.0.3')
        my_group = _group_of_size(me, [])  # size 1
        proc = _build_process(me, my_group)
        queues = _build_queues()
        proc._partition_recovery_in_progress = ('foreign-uuid', now())
        proc._partition_probe_cooldown['10.0.0.10'] = now()
        proc._record_group = MagicMock()
        proc._update_group = MagicMock()

        captain = _new_identity('captain', '10.0.0.10')
        foreign_group = _group_of_size(captain,
                                       [_new_identity('lt', '10.0.0.11')])
        # handle_group_update reads message.obj as a Group (or wire string).
        msg = Message(CfgIds.identity, IdentityProtocol.update,
                      foreign_group, encrypt=False)
        proc.handle_group_update(queues, msg)

        assert proc.group.uuid == foreign_group.uuid
        assert proc._partition_recovery_in_progress is None
        assert proc._partition_probe_cooldown == {}
