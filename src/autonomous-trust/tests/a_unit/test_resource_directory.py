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
"""ResourceDirectory read-model tests (PIV_MFA_OPERATOR_ACCESS_PLAN.md §3.5)."""
from autonomous_trust.core.operator.resource_directory import (
    build_directory, reach_for, CapabilityDescriptor, PeerInfo, Reach,
    ResourceKind)


def _peers(*infos):
    return {p.peer: p for p in infos}


class TestReach:
    def test_invokable_when_tier_meets(self):
        assert reach_for(2, 3) is Reach.INVOKABLE
        assert reach_for(2, 2) is Reach.INVOKABLE

    def test_locked_when_below(self):
        assert reach_for(3, 1) is Reach.LOCKED_BY_TIER

    def test_unknown_when_required_none(self):
        assert reach_for(None, 5) is Reach.UNKNOWN


class TestBuildDirectory:
    def test_lists_resource_with_providers_and_reach(self):
        descriptors = {
            'video': CapabilityDescriptor('video', kind=ResourceKind.DATA_STREAM.value,
                                          description='live video', required_tier=1,
                                          arg_schema={'fps': 'int'}),
        }
        providers = {'video': ['peerA', 'peerB']}
        peers = _peers(
            PeerInfo('peerA', name='drone', tier=2, reputation=0.8, online=True),
            PeerInfo('peerB', name='post', tier=1, reputation=0.6, online=False),
        )
        d = build_directory(descriptors, providers, peers, my_tier=2)
        r = d.by_name('video')
        assert r is not None
        assert r.kind == 'data_stream'
        assert r.description == 'live video'
        assert r.required_tier == 1
        assert r.arg_schema == {'fps': 'int'}
        assert {p.peer for p in r.providers} == {'peerA', 'peerB'}
        assert r.online_provider_count == 1
        assert r.my_reach is Reach.INVOKABLE          # my_tier 2 >= 1

    def test_locked_resource_still_listed(self):
        # Tier gating is execution-time only: show it, mark locked, never hide.
        descriptors = {'fire': CapabilityDescriptor('fire', required_tier=4)}
        d = build_directory(descriptors, {'fire': ['p1']},
                            _peers(PeerInfo('p1', tier=4)), my_tier=1)
        r = d.by_name('fire')
        assert r.my_reach is Reach.LOCKED_BY_TIER
        assert r not in d.invokable()
        assert r is not None  # listed despite being locked

    def test_provider_without_standing_shown_offline(self):
        # A provider id with no PeerInfo record is shown, not dropped.
        d = build_directory({}, {'data': ['ghost']}, {}, my_tier=0)
        r = d.by_name('data')
        assert [p.peer for p in r.providers] == ['ghost']
        assert r.providers[0].online is False
        assert r.my_reach is Reach.UNKNOWN            # no descriptor -> unknown tier

    def test_resource_with_no_providers_still_listed(self):
        # Locally-known capability with no current providers still appears.
        d = build_directory(
            {'compute': CapabilityDescriptor('compute', required_tier=0)},
            {}, {}, my_tier=0)
        r = d.by_name('compute')
        assert r is not None
        assert r.providers == []
        assert r.my_reach is Reach.INVOKABLE          # required 0, any tier

    def test_union_of_descriptor_and_provider_names(self):
        d = build_directory(
            {'a': CapabilityDescriptor('a', required_tier=0)},
            {'b': ['p1']}, _peers(PeerInfo('p1')), my_tier=0)
        assert {r.name for r in d.resources} == {'a', 'b'}

    def test_resources_sorted_by_name(self):
        d = build_directory(
            {}, {'zeta': ['p'], 'alpha': ['p'], 'mid': ['p']},
            _peers(PeerInfo('p')), my_tier=0)
        assert [r.name for r in d.resources] == ['alpha', 'mid', 'zeta']

    def test_invokable_filter(self):
        descriptors = {
            'lo': CapabilityDescriptor('lo', required_tier=0),
            'hi': CapabilityDescriptor('hi', required_tier=3),
        }
        d = build_directory(descriptors, {}, {}, my_tier=1)
        assert [r.name for r in d.invokable()] == ['lo']
