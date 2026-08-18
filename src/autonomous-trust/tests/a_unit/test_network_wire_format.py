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

"""The two network envelope encodings, and the group-carried choice between
them (doc/architecture/network-wire-format.md).

The Python mirror of ``src/c/test/net_message_test.c``'s proto half. Both sides
additionally run the same vectors through the conformance corpus
(``message-envelope-proto-*``, ``wire-format-mismatch-refused``,
``wire-mode-resolution``, ``group-wire-format-canonical``); these tests cover
what a corpus case cannot -- that the resolved format reaches the code that
SELECTS an encoding, which is the difference between a wire format and a
decorative one.

Design: ``doc/architecture/network-wire-format.md``. Format DETECTION is
deliberately unbuilt (doc/architecture/network-wire-format.md);
``test_no_sniffing_*`` below is what fails if it is
ever quietly added.
"""

import os

import pytest

from autonomous_trust.core._python import system as at_system
from autonomous_trust.core._python.config.configuration import (
    NET_WIRE_PROTO_MAGIC, NetWireFormat)
from autonomous_trust.core._python.identity.encrypt import Encryptor
from autonomous_trust.core._python.identity.group import Group
from autonomous_trust.core._python.identity.identity import Identity
from autonomous_trust.core._python.network.message import Message, WireFormatMismatch
from autonomous_trust.core._python.network.netprocess import NetworkProcess


@pytest.fixture
def signer():
    return Identity.initialize('nick', 'pet', '10.0.0.7')


def _msg(from_whom=None, obj='["hash",[]]'):
    return Message('identity', 'request_access', obj, from_whom=from_whom,
                   encrypt=False, trace_id='0123456789abcdef0123456789abcdef')


# --------------------------------------------------------------------------
# Encoding
# --------------------------------------------------------------------------

def test_proto_roundtrip_preserves_every_envelope_field(signer):
    msg = _msg(signer)
    wire = msg.to_wire(NetWireFormat.proto)
    got = Message.parse(wire, None, validate=False, wire_format=NetWireFormat.proto)

    assert got.process == msg.process
    assert got.function == msg.function
    assert str(got.obj) == str(msg.obj)
    assert got.encrypt == msg.encrypt
    # A trace that survives one encoding and not the other silently breaks the
    # correlation chain at that hop, which is worse than no trace.
    assert got.trace_id == msg.trace_id
    # Identity travels on the ENVELOPE (not the payload), which is how a peer we
    # do not yet know is admitted -- so it has to survive the binary encoding of
    # the uuid and the public keys.
    assert str(got.from_whom.uuid) == str(signer.uuid)
    assert got.from_whom.address == signer.address
    assert got.from_whom.signature.publish() == signer.signature.publish()
    assert got.from_whom.encryptor.publish() == signer.encryptor.publish()


def test_proto_frame_carries_the_format_marker(signer):
    wire = _msg(signer).to_wire(NetWireFormat.proto)
    assert wire[0] == NET_WIRE_PROTO_MAGIC
    # And the JSON form still begins '{', which is what makes one byte enough to
    # tell them apart without parsing either.
    assert _msg(signer).to_wire(NetWireFormat.json)[0:1] == b'{'


def test_proto_is_smaller_and_by_more_than_noise(signer):
    """The payload rides RAW in the proto form -- that saving is the entire
    reason the encoding exists, so it is measured rather than assumed. A
    regression that quietly base64'd the payload would pass every other test
    here."""
    payload = 'x' * 512
    msg = _msg(signer, obj=payload)
    j = msg.to_wire(NetWireFormat.json)
    p = msg.to_wire(NetWireFormat.proto)
    assert len(p) < len(j)
    # base64 costs 4 bytes per 3, and the keys/signature cost 320 bytes of hex,
    # so bound the saving instead of merely asserting "smaller".
    assert len(p) < len(j) - (len(payload) // 4)


def test_signature_is_identical_across_encodings(signer):
    """The load-bearing invariant: the pre-image is
    ``<process>|<function>|<base64(data)>`` in BOTH forms, so one message has one
    signature and re-encoding cannot invalidate it. Ed25519 is deterministic, so
    identical bytes prove identical pre-images rather than two self-consistent
    conventions."""
    msg = _msg(signer)
    j = Message.parse(msg.to_wire(NetWireFormat.json), None, validate=False,
                      wire_format=NetWireFormat.json)
    p = Message.parse(msg.to_wire(NetWireFormat.proto), None, validate=False,
                      wire_format=NetWireFormat.proto)
    assert j.verified and p.verified
    assert j.signature == p.signature


def test_empty_payload_verifies_in_both_forms(signer):
    """proto3 omits a default-valued field, so an empty payload means `data` is
    ABSENT here where JSON must emit "". base64("") == "" keeps the pre-image's
    trailing "|" present in both, so the signature still matches."""
    msg = Message('identity', 'noop', '', from_whom=signer, encrypt=False)
    for fmt in (NetWireFormat.json, NetWireFormat.proto):
        got = Message.parse(msg.to_wire(fmt), None, validate=False, wire_format=fmt)
        assert got.verified, fmt
        assert str(got.obj) == ''


# --------------------------------------------------------------------------
# The strict gate -- i.e. the absence of detection
# --------------------------------------------------------------------------

def test_no_sniffing_proto_frame_refused_on_json_path(signer):
    wire = _msg(signer).to_wire(NetWireFormat.proto)
    with pytest.raises(WireFormatMismatch):
        Message.parse(wire, None, validate=False, wire_format=NetWireFormat.json)


def test_no_sniffing_json_frame_refused_on_proto_path(signer):
    wire = _msg(signer).to_wire(NetWireFormat.json)
    with pytest.raises(WireFormatMismatch):
        Message.parse(wire, None, validate=False, wire_format=NetWireFormat.proto)


def test_mismatch_is_a_valueerror_subclass(signer):
    """`WireFormatMismatch` must stay a ValueError so every existing
    `except ValueError` around parse -- the conformance negative_runner among
    them -- keeps classifying it as a refusal rather than crashing."""
    assert issubclass(WireFormatMismatch, ValueError)


def test_garbage_behind_a_forged_marker_is_refused():
    """Protobuf decodes plenty of arbitrary byte strings into an all-defaults
    message. Without the non-empty process/function check that becomes a message
    addressed to process '' that routes nowhere with no diagnostic."""
    for frame in (bytes([NET_WIRE_PROTO_MAGIC]),
                  bytes([NET_WIRE_PROTO_MAGIC]) + b'\xff\xff\xff\xff',
                  bytes([NET_WIRE_PROTO_MAGIC]) + b'\x00'):
        with pytest.raises(ValueError):
            Message.parse(frame, None, validate=False,
                          wire_format=NetWireFormat.proto)


def test_unknown_format_is_refused(signer):
    with pytest.raises(ValueError):
        _msg(signer).to_wire('yaml')
    with pytest.raises(ValueError):
        Message.parse(b'{}', None, validate=False, wire_format='yaml')


# --------------------------------------------------------------------------
# The group carries the choice
# --------------------------------------------------------------------------

def _group(fmt=None):
    return Group('3f2504e0-4f89-11d3-9a0c-0305e82c3301', {'u': '10.0.0.1'}, '',
                 Encryptor.generate(), False, _wire_format=fmt)


def test_group_default_and_canonical_roundtrip():
    assert _group().wire_format == NetWireFormat.json
    canon = _group(NetWireFormat.proto).to_canonical()
    assert canon['wire_format'] == 'proto'
    assert Group.from_canonical(canon).wire_format == NetWireFormat.proto


def test_group_absent_field_reads_json():
    """A group from a peer predating this field, or a config written before it.
    Must read as json -- not error, not proto."""
    canon = _group(NetWireFormat.proto).to_canonical()
    del canon['wire_format']
    assert Group.from_canonical(canon).wire_format == NetWireFormat.json


def test_group_unknown_value_tightens_to_json():
    """A provisioning typo must tighten to the format every node can read rather
    than fail the load -- the same discipline as zta_policy.binding_mode falling
    back to `require`."""
    canon = _group(NetWireFormat.proto).to_canonical()
    canon['wire_format'] = 'yaml'
    assert Group.from_canonical(canon).wire_format == NetWireFormat.json


def test_group_published_view_keeps_the_format():
    """A member handed a public-only view still has to know which envelope the
    cohort speaks: the format is a property of the group, not of holding its
    private key."""
    assert _group(NetWireFormat.proto).publish().wire_format == NetWireFormat.proto


def test_group_proto_message_roundtrip():
    """The proto config path must carry it too, or a deployment running
    AT_SERIALIZE_MODE=proto would silently lose a proto cohort's format."""
    src = _group(NetWireFormat.proto)
    src.sync_to_message()
    blob = src.message.SerializeToString()
    dst = _group()
    dst.message.ParseFromString(blob)
    dst.sync_from_message()
    assert dst.wire_format == NetWireFormat.proto


def test_merge_adopts_the_surviving_groups_format():
    """The merge winner is decided by size -> age -> uuid; its format travels
    with its uuid and address map. Without this an absorbed node would keep
    talking in its old format inside its new group -- exactly the split a
    group-carried format exists to prevent."""
    ours = _group(NetWireFormat.json)
    theirs = _group(NetWireFormat.proto)
    ours.adopt_membership(theirs)
    assert ours.wire_format == NetWireFormat.proto


def test_minted_group_takes_the_env_knob(monkeypatch):
    """AT_NET_WIRE_MODE applies at the ONE moment a node decides a format rather
    than adopting one."""
    monkeypatch.delenv('AT_NET_WIRE_MODE', raising=False)
    assert Group.initialize({'u': '10.0.0.1'}, 'me').wire_format == NetWireFormat.json
    monkeypatch.setenv('AT_NET_WIRE_MODE', 'proto')
    assert Group.initialize({'u': '10.0.0.1'}, 'me').wire_format == NetWireFormat.proto


# --------------------------------------------------------------------------
# The knob
# --------------------------------------------------------------------------

@pytest.mark.parametrize('raw,want,src', [
    ('proto', 'proto', 'env'),
    ('json', 'json', 'env'),
    ('Proto', 'proto', 'env'),      # case is normalized, not refused
    ('  proto', 'proto', 'env'),    # so is surrounding whitespace
    (None, 'json', 'default'),
    ('', 'json', 'default'),        # empty is "not set", not a refusal
    ('yaml', 'json', 'default'),    # refused, default kept
    ('1', 'json', 'default'),
    ('prot', 'json', 'default'),
])
def test_wire_mode_resolution(monkeypatch, raw, want, src):
    if raw is None:
        monkeypatch.delenv('AT_NET_WIRE_MODE', raising=False)
    else:
        monkeypatch.setenv('AT_NET_WIRE_MODE', raw)
    assert at_system.resolve_net_wire_mode() == (want, src)


def test_wire_mode_default_matches_the_conformance_pin():
    """The scenario states these; a drift here would otherwise agree with a
    value neither runtime got from the other."""
    assert at_system.default_net_wire_mode == 'json'
    assert at_system.net_wire_modes == ('json', 'proto')


# --------------------------------------------------------------------------
# Selection reaches the send/receive path
# --------------------------------------------------------------------------

class _Stub:
    """Just enough NetworkProcess for the selection helpers: they are group
    lookups, so what matters is which group an address resolves to."""

    def __init__(self, groups):
        self._groups = groups

    def _group_for_sender(self, addr):
        return self._groups.get(addr)


def test_placed_peer_gets_its_groups_format():
    grp = _group(NetWireFormat.proto)
    stub = _Stub({'10.0.0.1': grp})
    assert NetworkProcess._wire_format_for_addr(stub, '10.0.0.1') == NetWireFormat.proto


def test_unplaced_peer_gets_json():
    """A sender we cannot place in any group is bootstrap traffic by definition,
    and JSON is the only format every AT node can read. This is what keeps a
    proto cohort joinable."""
    stub = _Stub({'10.0.0.1': _group(NetWireFormat.proto)})
    assert NetworkProcess._wire_format_for_addr(stub, '10.9.9.9') == NetWireFormat.json


def test_no_group_at_all_is_json():
    assert NetworkProcess._wire_format_for_group(None) == NetWireFormat.json
    assert NetworkProcess._wire_format_for_group(
        _group(NetWireFormat.proto)) == NetWireFormat.proto
