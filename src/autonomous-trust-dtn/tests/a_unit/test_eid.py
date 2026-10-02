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
"""EID formation and unicast resolution, against the strings C's dtn_eid.c and
net_transport_dtn.c build (src/c/extensions/dtn/test/dtn_eid_test.c)."""
import uuid

import pytest

from autonomous_trust.dtn import eid

NODE = uuid.UUID('aabbccdd-1122-4000-8000-000000000001')
GROUP = uuid.UUID('11223344-5566-7788-99aa-bbccddeeff00')


def test_node_eid_is_the_first_four_uuid_bytes():
    assert eid.eid_from_uuid(NODE) == 'dtn://at-aabbccdd/'
    assert eid.eid_from_uuid(str(NODE)) == 'dtn://at-aabbccdd/'
    assert eid.eid_from_uuid(NODE.bytes) == 'dtn://at-aabbccdd/'


def test_service_eid_trims_one_slash():
    assert eid.eid_for_service('dtn://at-aabbccdd/', '/peer') == 'dtn://at-aabbccdd/peer'
    assert eid.eid_for_service('dtn://at-aabbccdd/', 'peer') == 'dtn://at-aabbccdd/peer'


def test_group_eid_needs_eight_bytes():
    assert eid.eid_for_group(GROUP.bytes) == 'dtn://at-group-1122334455667788/'
    with pytest.raises(eid.EIDError):
        eid.eid_for_group(b'1234567')


def test_pre_join_hash_until_a_group_is_joined():
    for unjoined in (None, '', uuid.UUID(int=0), str(uuid.UUID(int=0))):
        assert eid.group_hash(unjoined) == (b'AT-boot\x00', False)
    assert eid.group_hash(GROUP) == (GROUP.bytes[:8], True)
    # Only the last byte set: joined, and the EID is the first eight bytes (zeros).
    tail = uuid.UUID(int=1)
    assert eid.group_hash(tail) == (bytes(8), True)


def test_endpoints_in_channel_order():
    assert eid.endpoints(NODE, None) == [
        ('dtn://at-aabbccdd/peer', '/peer'),
        ('dtn://at-group-41542d626f6f7400/bcast', '/bcast'),
        ('dtn://at-group-41542d626f6f7400/group', '/group'),
    ]
    assert eid.endpoints(None, GROUP)[0] == ('dtn://at-local/peer', '/peer')


def test_channel_service_mapping_round_trips():
    for ch in eid.CHANNELS:
        assert eid.service_to_channel(eid.channel_suffix(ch)) == ch
    assert eid.service_to_channel('/other') is None
    assert eid.service_to_channel(None) is None


def test_broadcast_eid_follows_the_group():
    assert eid.broadcast_eid(eid.CHAN_GROUP, GROUP) == 'dtn://at-group-1122334455667788/group'
    assert eid.broadcast_eid(eid.CHAN_BROADCAST, None) == 'dtn://at-group-41542d626f6f7400/bcast'
    with pytest.raises(eid.EIDError):
        eid.broadcast_eid(eid.CHAN_PEER, GROUP)


def test_peer_eid_resolution_order():
    lookup = {'10.0.0.5': NODE}.get
    # 1. an EID is used verbatim, even if an address matches
    assert eid.peer_eid('ipn:42.1', lookup) == 'ipn:42.1'
    assert eid.peer_eid('dtn://elsewhere/x', lookup) == 'dtn://elsewhere/x'
    # 2. the peer whose address is exactly the target
    assert eid.peer_eid('10.0.0.5', lookup) == 'dtn://at-aabbccdd/peer'
    # 3. the target as an opaque host
    assert eid.peer_eid('10.0.0.6', lookup) == 'dtn://at-10.0.0.6/peer'
    assert eid.peer_eid('host', None) == 'dtn://at-host/peer'
    with pytest.raises(eid.EIDError):
        eid.peer_eid('', lookup)


def test_eid_length_cap_is_cs():
    # dtn://at-<x>/peer is 14 bytes of frame: 113 fits in 127, 114 does not.
    assert len(eid.peer_eid('a' * 113)) == 127
    with pytest.raises(eid.EIDError):
        eid.peer_eid('a' * 114)
    assert eid.peer_eid('dtn:' + 'x' * 123) == 'dtn:' + 'x' * 123
    with pytest.raises(eid.EIDError):
        eid.peer_eid('dtn:' + 'x' * 124)
