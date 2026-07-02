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
from unittest.mock import MagicMock, patch

from autonomous_trust.core import CfgIds

from autonomous_trust.inspector.transitive_trust import (
    TransitiveTrustMixin, PEER_PAIR_QUERY_SEC,
)


def _peer(uuid):
    p = MagicMock()
    p.uuid = uuid
    return p


class _Host(TransitiveTrustMixin):
    """Minimal host exposing the attributes the mixin requires."""
    def __init__(self, peers_all, proc_name='monitor'):
        self.peers = MagicMock()
        self.peers.all = peers_all
        self.identity = MagicMock()
        self.proc_name = proc_name


class TestQueryPeerPairs:
    def test_cadence_constant(self):
        assert PEER_PAIR_QUERY_SEC > 0

    @patch('autonomous_trust.inspector.transitive_trust.Message')
    @patch('autonomous_trust.inspector.transitive_trust.to_json_string', return_value='{}')
    def test_sends_ordered_distinct_pairs(self, _tjs, _msg):
        # 3 peers -> 3*2 = 6 ordered (observer, subject) pairs, no self-pairs.
        host = _Host([_peer('a'), _peer('b'), _peer('c')])
        netq = MagicMock()
        sent = host.query_peer_pairs({CfgIds.network: netq})
        assert sent == 6
        assert netq.put.call_count == 6

    @patch('autonomous_trust.inspector.transitive_trust.Message')
    @patch('autonomous_trust.inspector.transitive_trust.to_json_string', return_value='{}')
    def test_single_peer_sends_nothing(self, _tjs, _msg):
        host = _Host([_peer('solo')])
        netq = MagicMock()
        assert host.query_peer_pairs({CfgIds.network: netq}) == 0
        assert netq.put.call_count == 0

    @patch('autonomous_trust.inspector.transitive_trust.Message')
    @patch('autonomous_trust.inspector.transitive_trust.to_json_string', return_value='{}')
    def test_put_errors_are_swallowed(self, _tjs, _msg):
        # A full/broken network queue must not crash the round; count reflects
        # only successful enqueues.
        host = _Host([_peer('a'), _peer('b')])
        netq = MagicMock()
        netq.put.side_effect = RuntimeError('queue full')
        sent = host.query_peer_pairs({CfgIds.network: netq}, logger=MagicMock())
        assert sent == 0
        assert netq.put.call_count == 2  # both attempts made
