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


def _public_only_twin(group, extra_addresses):
    """A PUBLIC-ONLY Group sharing ``group``'s uuid/nickname but with a larger
    address map — the on-the-wire shape of a membership-only group_key_update
    sent by a peer that holds only the public key (or one that survived a
    protobuf round-trip, which forces ``public_only=True``)."""
    from autonomous_trust.core.identity.encrypt import Encryptor
    addrs = dict(group._address_map)
    for ident in extra_addresses:
        addrs[str(ident.uuid)] = ident.address
    return Group(group.uuid, addrs, group.nickname,
                 Encryptor(group.encryptor.publish(), public_only=True),
                 _public_only=True)


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

    def test_c_originated_probe_canonical_identity(self):
        # A C / cross-runtime sender serializes from_identity as the flat
        # canonical form (no __type__), so from_json_string leaves it a
        # plain dict. The handler must normalize it to an Identity rather
        # than crash on `'dict' object has no attribute 'signature'`, which
        # otherwise strands cross-runtime group merges (the dod_mission
        # coordinator never merges and stays wedged in its size-1 group).
        from autonomous_trust.core.config import to_json_string
        from autonomous_trust.core.identity.identity import (
            public_identity_to_canonical)
        me = _new_identity('captain', '10.0.0.10')
        other = _new_identity('lieutenant', '10.0.0.11')
        my_group = _group_of_size(me, [other])
        my_peers = Peers()
        my_peers.all.append(other)
        proc = _build_process(me, my_group, my_peers)
        queues = _build_queues()

        sender = _new_identity('lone-coord', '10.0.0.3')
        sender_group_uuid = str(uuid_mod.uuid4())
        sig_bytes = IdentityProcess._partition_probe_canonical(
            sender_group_uuid, 1)
        signed = sender.sign(sig_bytes)
        payload = to_json_string({
            'from_identity': public_identity_to_canonical(sender.publish()),
            'from_address': sender.address,
            'my_group_uuid': sender_group_uuid,
            'my_group_size': 1,
            'signature': signed.signature.decode('ascii'),
        })
        probe = Message(CfgIds.identity, IdentityProtocol.partition_probe,
                        payload, encrypt=False)
        handled = proc.handle_partition_probe(queues, probe)
        assert handled is True
        # A well-formed response was emitted (signature verified, no crash).
        out = queues[CfgIds.network].items
        assert len(out) == 1
        assert out[0].function == IdentityProtocol.partition_response

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

    def test_adopts_when_prober_advertises_larger_group(self):
        # Symmetric adoption: a node that only ever RECEIVES probes — it
        # never gets the inbound foreign-group trigger, like the dod_mission
        # coordinator which is in no other group's address map — must still
        # initiate a merge when a probe advertises a larger group. Without
        # the fix it would only respond and stay wedged in its size-1 group.
        me = _new_identity('coord', '10.0.0.3')
        my_group = _group_of_size(me, [])  # size 1
        proc = _build_process(me, my_group)
        proc.package_hash = b'pkg-hash-stub'  # _broadcast_request_access uses it
        from autonomous_trust.core._python.capabilities import Capabilities
        proc.protocol.capabilities = Capabilities()
        queues = _build_queues()

        prober = _new_identity('captain', '10.0.0.10')
        their_group_uuid = str(uuid_mod.uuid4())
        probe = self._craft_probe(prober, their_group_uuid, 5)
        handled = proc.handle_partition_probe(queues, probe)
        assert handled is True

        # Recovery initiated toward the prober's (larger) group...
        assert proc._partition_recovery_in_progress is not None
        assert proc._partition_recovery_in_progress[0] == their_group_uuid
        # ...via a request_access (announce) broadcast,
        announces = [m for m in queues[CfgIds.network].items
                     if m.function == IdentityProtocol.announce]
        assert len(announces) == 1
        # ...and we still answer the probe so the prober can compare too.
        responses = [m for m in queues[CfgIds.network].items
                     if m.function == IdentityProtocol.partition_response]
        assert len(responses) == 1

    def test_no_adopt_when_prober_group_not_larger(self):
        # Prober is smaller: we do NOT adopt (they will, from our response).
        # Guards against accreting larger groups into smaller ones.
        me = _new_identity('captain', '10.0.0.10')
        extras = [_new_identity('p%d' % i, '10.0.0.%d' % (11 + i))
                  for i in range(4)]
        my_group = _group_of_size(me, extras)  # size 5
        proc = _build_process(me, my_group)
        queues = _build_queues()

        prober = _new_identity('coord', '10.0.0.3')
        probe = self._craft_probe(prober, str(uuid_mod.uuid4()), 1)
        proc.handle_partition_probe(queues, probe)

        assert proc._partition_recovery_in_progress is None
        assert all(m.function != IdentityProtocol.announce
                   for m in queues[CfgIds.network].items)
        # We still respond so the smaller prober can adopt us.
        assert any(m.function == IdentityProtocol.partition_response
                   for m in queues[CfgIds.network].items)

    def test_no_adopt_from_probe_while_recovery_in_flight(self):
        # The in-flight lock prevents double-initiation when another probe
        # arrives mid-recovery.
        me = _new_identity('coord', '10.0.0.3')
        proc = _build_process(me, _group_of_size(me, []))  # size 1
        proc.package_hash = b'pkg-hash-stub'
        from autonomous_trust.core._python.capabilities import Capabilities
        proc.protocol.capabilities = Capabilities()
        proc._partition_recovery_in_progress = ('in-flight-uuid', now())
        queues = _build_queues()

        prober = _new_identity('captain', '10.0.0.10')
        probe = self._craft_probe(prober, str(uuid_mod.uuid4()), 5)
        proc.handle_partition_probe(queues, probe)

        # Unchanged recovery target, no new request_access.
        assert proc._partition_recovery_in_progress[0] == 'in-flight-uuid'
        assert all(m.function != IdentityProtocol.announce
                   for m in queues[CfgIds.network].items)


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

    def test_membership_update_keeps_private_key_same_group(self):
        """A group_key_update for OUR group that carries a larger membership
        but only the PUBLIC key (the shape a peer without the shared private
        key — or a protobuf round-trip — puts on the wire) must NOT drop our
        private key. We adopt the larger membership but keep our encryptor.

        Regression for the live SG3 blocker: wholesale ``self.group = theirs``
        stripped the shared key, leaving cold-joining C nodes with the right
        group uuid but wrong/absent key bytes (group decrypt failed). C's
        handle_group_update already keeps its encryptor (id_proc.c:2113-2134).
        """
        from autonomous_trust.core.config import to_json_string

        me = _new_identity('coord', '10.0.0.3')
        my_group = _group_of_size(me, [])  # size 1, owns the private key
        assert my_group.owns_private_key
        key_before = my_group.encryptor.serialize()
        proc = _build_process(me, my_group)
        queues = _build_queues()
        proc._record_group = MagicMock()
        proc._update_group = MagicMock()

        # Same uuid, public-only, larger membership — arrives as the C-parsable
        # canonical wire string so we also exercise from_canonical reconstruction.
        twin = _public_only_twin(my_group,
                                 [_new_identity('lt', '10.0.0.11'),
                                  _new_identity('sgt', '10.0.0.12')])
        assert twin.uuid == my_group.uuid and not twin.owns_private_key
        msg = Message(CfgIds.identity, IdentityProtocol.update,
                      to_json_string(twin.to_canonical()), encrypt=False)
        assert proc.handle_group_update(queues, msg) is True

        # Key preserved (same object, same private bytes); membership grew.
        assert proc.group is my_group
        assert proc.group.owns_private_key
        assert proc.group.encryptor.serialize() == key_before
        assert len(list(proc.group.addresses)) == 3
        proc._record_group.assert_called_once()

    def test_refuse_public_only_foreign_group_over_keyed(self):
        """A DIFFERENT, public-only group with a larger membership must NOT
        replace our key-bearing group: adopting it would abandon a group we
        can decrypt for one we cannot. Refuse and wait for a private-bearing
        full_history / update to converge."""
        from autonomous_trust.core.config import to_json_string

        me = _new_identity('coord', '10.0.0.3')
        my_group = _group_of_size(me, [])  # size 1, owns the private key
        key_before = my_group.encryptor.serialize()
        proc = _build_process(me, my_group)
        queues = _build_queues()
        proc._record_group = MagicMock()
        proc._update_group = MagicMock()

        captain = _new_identity('captain', '10.0.0.10')
        foreign = _group_of_size(captain, [_new_identity('lt', '10.0.0.11')])
        foreign_pub = _public_only_twin(foreign, [])  # different uuid, no key
        assert foreign_pub.uuid != my_group.uuid and not foreign_pub.owns_private_key
        msg = Message(CfgIds.identity, IdentityProtocol.update,
                      to_json_string(foreign_pub.to_canonical()), encrypt=False)
        assert proc.handle_group_update(queues, msg) is True

        # Our group is untouched: same uuid, still owns the same private key.
        assert proc.group is my_group
        assert proc.group.uuid == my_group.uuid
        assert proc.group.owns_private_key
        assert proc.group.encryptor.serialize() == key_before
        proc._record_group.assert_not_called()

    def test_adopt_foreign_group_installs_its_key_when_keyless(self):
        """A DIFFERENT, larger group whose update carries the shared PRIVATE
        key is adopted wholesale, installing that key — we end with the foreign
        uuid AND its usable key. Here we start public-only (hold no key), so the
        install is directly observable. Pins parity with C, whose
        handle_group_update now reconstructs+installs theirs' encryptor on this
        path instead of keeping its own (id_proc.c)."""
        from autonomous_trust.core.config import to_json_string

        me = _new_identity('coord', '10.0.0.3')
        my_group = _public_only_twin(_group_of_size(me, []), [])  # size 1, NO key
        assert not my_group.owns_private_key
        proc = _build_process(me, my_group)
        queues = _build_queues()
        proc._record_group = MagicMock()
        proc._update_group = MagicMock()

        captain = _new_identity('captain', '10.0.0.10')
        theirs = _group_of_size(captain, [_new_identity('lt', '10.0.0.11')])
        assert theirs.uuid != my_group.uuid and theirs.owns_private_key
        msg = Message(CfgIds.identity, IdentityProtocol.update,
                      to_json_string(theirs.to_canonical()), encrypt=False)
        assert proc.handle_group_update(queues, msg) is True

        # Adopted theirs: their uuid, their membership, and their PRIVATE key.
        assert proc.group.uuid == theirs.uuid
        assert proc.group.owns_private_key
        assert proc.group.encryptor.serialize() == theirs.encryptor.serialize()
        assert len(list(proc.group.addresses)) == 2
        proc._record_group.assert_called_once()


# ---------------------------------------------------------------------------
# Identity resync (cold/late-joiner backfill) — dod layer 3
# ---------------------------------------------------------------------------

class TestIdentityResync:
    def _id_query(self, group_uuid, have):
        from autonomous_trust.core.config import to_json_string
        payload = to_json_string({'group_uuid': str(group_uuid),
                                  'have': [str(h) for h in have]})
        return Message(CfgIds.identity, IdentityProtocol.id_query,
                       payload, encrypt=False)

    def _id_response(self, member_identity):
        from autonomous_trust.core.config import to_json_string
        payload = to_json_string({'from_identity': member_identity.publish(),
                                  'from_address': member_identity.address})
        return Message(CfgIds.identity, IdentityProtocol.id_response,
                       payload, encrypt=False)

    def test_query_emitted_when_identities_sparse(self):
        # group has 3 members (by address) but self.peers is empty -> we lack
        # identities, so a query naming our group + have-list is broadcast.
        me = _new_identity('coord', '10.0.0.3')
        m1 = _new_identity('captain', '10.0.0.10')
        m2 = _new_identity('intel', '10.0.0.12')
        grp = _group_of_size(me, [m1, m2])  # 3 addresses
        proc = _build_process(me, grp, Peers())  # self.peers empty
        queues = _build_queues()

        proc._periodic_identity_resync(queues)

        from autonomous_trust.core.config import from_json_string
        qs = [m for m in queues[CfgIds.network].items
              if m.function == IdentityProtocol.id_query]
        assert len(qs) == 1
        payload = from_json_string(qs[0].obj)
        assert payload['group_uuid'] == str(grp.uuid)
        assert str(me.uuid) in set(payload['have'])  # we always "have" ourself

    def test_no_query_when_all_identities_present(self):
        me = _new_identity('coord', '10.0.0.3')
        m1 = _new_identity('captain', '10.0.0.10')
        grp = _group_of_size(me, [m1])
        peers = Peers()
        peers.add(m1)  # we already hold every other member's identity
        proc = _build_process(me, grp, peers)
        queues = _build_queues()

        proc._periodic_identity_resync(queues)

        assert not [m for m in queues[CfgIds.network].items
                    if m.function == IdentityProtocol.id_query]

    def test_responder_replies_when_in_group_and_not_in_have(self):
        # We are a group member; an asker in our group lacks us -> we reply.
        me = _new_identity('captain', '10.0.0.10')
        asker = _new_identity('coord', '10.0.0.3')
        grp = _group_of_size(me, [asker])
        proc = _build_process(me, grp)
        queues = _build_queues()

        proc.handle_identity_query(queues, self._id_query(grp.uuid, [asker.uuid]))

        resp = [m for m in queues[CfgIds.network].items
                if m.function == IdentityProtocol.id_response]
        assert len(resp) == 1

    def test_responder_silent_for_other_group(self):
        me = _new_identity('captain', '10.0.0.10')
        grp = _group_of_size(me, [])
        proc = _build_process(me, grp)
        queues = _build_queues()

        # Query naming a DIFFERENT group uuid -> no reply.
        proc.handle_identity_query(queues, self._id_query(uuid_mod.uuid4(), []))

        assert not [m for m in queues[CfgIds.network].items
                    if m.function == IdentityProtocol.id_response]

    def test_response_backfills_group_member(self):
        me = _new_identity('coord', '10.0.0.3')
        member = _new_identity('captain', '10.0.0.10')
        grp = _group_of_size(me, [member])  # member.address is in the group
        proc = _build_process(me, grp, Peers())  # but we lack its identity
        proc._record_peers = MagicMock()  # isolate from file I/O / main-put
        queues = _build_queues()

        proc.handle_identity_response(queues, self._id_response(member))

        assert proc.peers.find_by_uuid(member.uuid) is not None
        proc._record_peers.assert_called()  # propagates to main proc

    def test_response_rejects_non_group_address(self):
        me = _new_identity('coord', '10.0.0.3')
        grp = _group_of_size(me, [])  # group is just us
        stranger = _new_identity('stranger', '10.0.0.99')  # not in group
        proc = _build_process(me, grp, Peers())
        proc._record_peers = MagicMock()
        queues = _build_queues()

        proc.handle_identity_response(queues, self._id_response(stranger))

        assert proc.peers.find_by_uuid(stranger.uuid) is None
        proc._record_peers.assert_not_called()
