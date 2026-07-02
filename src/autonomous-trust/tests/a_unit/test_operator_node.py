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
"""OperatorNode directory adapter tests (the pure `directory_from_state`)."""
from autonomous_trust.core.capabilities import Capabilities, PeerCapabilities
from autonomous_trust.core.operator.operator_node import directory_from_state
from autonomous_trust.core.operator.resource_directory import Reach


class _Peer:
    def __init__(self, uuid, petname='', tier=0):
        self.uuid = uuid
        self.petname = petname
        self.tier = tier


class _Peers:
    def __init__(self, peers):
        self._by_id = {str(p.uuid): p for p in peers}
        self.all = list(peers)

    def find_by_uuid(self, uuid):
        return self._by_id.get(str(uuid))


class _Rep:
    def __init__(self, score):
        self.score = score


def _local_caps():
    caps = Capabilities()
    caps.register_ability('analyze', None, required_tier=1,
                          description='image analysis', kind='compute',
                          arg_schema={'roi': 'bbox'})
    return caps


class TestDirectoryFromState:
    def test_local_descriptor_and_providers(self):
        caps = _local_caps()
        pc = PeerCapabilities()
        pc.register('drone-1', ['analyze'])
        pc.register('drone-2', ['analyze'])
        peers = _Peers([_Peer('drone-1', 'alpha', tier=2),
                        _Peer('drone-2', 'bravo', tier=1)])
        reps = {'drone-1': _Rep(0.9)}
        d = directory_from_state(caps, pc, peers, my_tier=2, reputations=reps)
        r = d.by_name('analyze')
        assert r.kind == 'compute'
        assert r.description == 'image analysis'
        assert r.required_tier == 1
        assert r.arg_schema == {'roi': 'bbox'}
        assert r.my_reach is Reach.INVOKABLE             # my_tier 2 >= 1
        provs = {p.peer: p for p in r.providers}
        assert provs['drone-1'].tier == 2
        assert provs['drone-1'].reputation == 0.9
        assert provs['drone-1'].name == 'alpha'
        assert provs['drone-2'].reputation is None       # no rep record

    def test_remote_only_cap_without_descriptor_is_bare(self):
        # A capability the operator doesn't locally know AND no wire descriptor:
        # listed with providers, required_tier unknown -> reach UNKNOWN.
        caps = Capabilities()
        pc = PeerCapabilities()
        pc.register('peerX', ['exotic_stream'])
        peers = _Peers([_Peer('peerX', 'x', tier=3)])
        d = directory_from_state(caps, pc, peers, my_tier=3)
        r = d.by_name('exotic_stream')
        assert r is not None
        assert r.required_tier is None
        assert r.my_reach is Reach.UNKNOWN
        assert [p.peer for p in r.providers] == ['peerX']

    def test_remote_cap_uses_wire_descriptor(self):
        # A descriptor learned from caps_response makes a remote-only cap
        # self-describing (required_tier known -> reach computed).
        caps = Capabilities()
        pc = PeerCapabilities()
        pc.register('peerX', ['exotic_stream'])
        pc.register_descriptor('exotic_stream', {
            'required_tier': 2, 'description': 'exotic feed',
            'kind': 'data_stream', 'arg_schema': {'rate': 'int'}})
        peers = _Peers([_Peer('peerX', 'x', tier=3)])
        d = directory_from_state(caps, pc, peers, my_tier=3)
        r = d.by_name('exotic_stream')
        assert r.required_tier == 2
        assert r.description == 'exotic feed'
        assert r.kind == 'data_stream'
        assert r.arg_schema == {'rate': 'int'}
        assert r.my_reach is Reach.INVOKABLE     # my_tier 3 >= 2

    def test_local_descriptor_takes_precedence_over_wire(self):
        # The operator's own registry wins over a peer-advertised descriptor.
        caps = _local_caps()  # 'analyze' required_tier=1
        pc = PeerCapabilities()
        pc.register('peerX', ['analyze'])
        pc.register_descriptor('analyze', {'required_tier': 4})  # peer claims 4
        d = directory_from_state(caps, pc, _Peers([_Peer('peerX')]), my_tier=2)
        assert d.by_name('analyze').required_tier == 1   # local wins

    def test_locked_resource_visible(self):
        caps = Capabilities()
        caps.register_ability('strike', None, required_tier=4, kind='service')
        pc = PeerCapabilities()
        pc.register('jet-1', ['strike'])
        peers = _Peers([_Peer('jet-1', 'jet', tier=4)])
        d = directory_from_state(caps, pc, peers, my_tier=1)
        r = d.by_name('strike')
        assert r.my_reach is Reach.LOCKED_BY_TIER
        assert r not in d.invokable()

    def test_online_filtering(self):
        caps = Capabilities()
        pc = PeerCapabilities()
        pc.register('p-on', ['data'])
        pc.register('p-off', ['data'])
        peers = _Peers([_Peer('p-on', tier=0), _Peer('p-off', tier=0)])
        d = directory_from_state(caps, pc, peers, my_tier=0,
                                 online_uuids={'p-on'})
        r = d.by_name('data')
        online = {p.peer: p.online for p in r.providers}
        assert online == {'p-on': True, 'p-off': False}
        assert r.online_provider_count == 1

    def test_arg_schema_from_arg_names_fallback(self):
        caps = Capabilities()
        caps.register_ability('q', None, arg_names=['a', 'b'], required_tier=0)
        pc = PeerCapabilities()
        pc.register('p', ['q'])
        d = directory_from_state(caps, pc, _Peers([_Peer('p')]), my_tier=0)
        assert d.by_name('q').arg_schema == {'a': 'any', 'b': 'any'}
