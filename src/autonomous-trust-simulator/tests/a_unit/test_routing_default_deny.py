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
"""Router._apply_reachability default-denies absent pairs.

The connectivity matrix is now sparse (reachable pairs only), so the router
must block every ordered pair of active peers that is NOT present-and-reachable,
and unblock those that are. Exercised with a mocked iptables/parse_chain so no
real firewall is touched.
"""
from types import SimpleNamespace
from unittest.mock import patch

from autonomous_trust.simulator.radio.routing import Router


def _peer(ip):
    return SimpleNamespace(ip4_addr=ip)


def _make_state(reachable):
    # three active peers a, b, c
    return SimpleNamespace(
        active=['a', 'b', 'c'],
        peers={'a': _peer('10.0.0.1'), 'b': _peer('10.0.0.2'), 'c': _peer('10.0.0.3')},
        reachable=reachable,
    )


def _run(reachable, rule_present=False):
    router = Router.__new__(Router)
    state = _make_state(reachable)
    with patch.object(Router, 'parse_chain', return_value=rule_present), \
            patch.object(Router, 'iptables') as mock_ipt:
        router._apply_reachability(state, 'OUTPUT')
        return [str(c) for c in mock_ipt.call_args_list]


def test_absent_pairs_are_blocked():
    """A sparse matrix with only a<->b reachable blocks every other ordered
    pair (default-deny), and does NOT block a<->b."""
    reachable = {'a': {'b': True}, 'b': {'a': True}}
    calls = _run(reachable, rule_present=False)
    # a<->b reachable: never a DROP add for them
    assert not any('-A OUTPUT -s 10.0.0.1 -d 10.0.0.2 -j DROP' in c for c in calls)
    assert not any('-A OUTPUT -s 10.0.0.2 -d 10.0.0.1 -j DROP' in c for c in calls)
    # every pair involving c is unreachable -> blocked (both directions)
    for pair in [('10.0.0.1', '10.0.0.3'), ('10.0.0.3', '10.0.0.1'),
                 ('10.0.0.2', '10.0.0.3'), ('10.0.0.3', '10.0.0.2')]:
        assert any('-A OUTPUT -s %s -d %s -j DROP' % pair in c for c in calls), pair


def test_reachable_pair_is_unblocked_when_rule_present():
    """When a stale DROP exists, a now-reachable pair gets it removed."""
    reachable = {'a': {'b': True}, 'b': {'a': True}}
    calls = _run(reachable, rule_present=True)
    assert any('-D OUTPUT -s 10.0.0.1 -d 10.0.0.2 -j DROP' in c for c in calls)
    assert any('-D OUTPUT -s 10.0.0.2 -d 10.0.0.1 -j DROP' in c for c in calls)


def test_empty_matrix_blocks_all_active_pairs():
    """No reachability at all -> every ordered active pair is blocked."""
    calls = _run({}, rule_present=False)
    # 3 active peers -> 6 ordered pairs, all blocked
    drops = [c for c in calls if '-A OUTPUT' in c and 'DROP' in c]
    assert len(drops) == 6
