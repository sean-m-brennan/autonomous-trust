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
    def test_one_request_per_observer_not_per_pair(self, _tjs, _msg):
        # 3 peers -> 3 requests, each naming every subject. The pre-batch form
        # sent 3*2 = 6, one per ordered pair; the coverage is the same.
        host = _Host([_peer('a'), _peer('b'), _peer('c')])
        netq = MagicMock()
        sent = host.query_peer_pairs({CfgIds.network: netq})
        assert sent == 3
        assert netq.put.call_count == 3

    @patch('autonomous_trust.inspector.transitive_trust.Message')
    @patch('autonomous_trust.inspector.transitive_trust.to_json_string', return_value='{}')
    def test_every_observer_is_addressed_exactly_once(self, _tjs, msg):
        peers = [_peer('a'), _peer('b'), _peer('c')]
        host = _Host(peers)
        host.query_peer_pairs({CfgIds.network: MagicMock()})
        # First message is constructed and signed; the rest are readdressed
        # copies of it, so the recipients are split across the two calls.
        addressed = [call.args[3].uuid for call in msg.call_args_list]
        addressed += [c.args[0].uuid for c in msg.return_value.for_recipient.call_args_list]
        assert sorted(addressed) == ['a', 'b', 'c']

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


class TestQueryPeerPairsCost:
    """What the round costs. The verb is batched, so a round is N requests with
    one shared body and one signature — not N(N-1) messages each serialized and
    signed on its own."""

    @patch('autonomous_trust.inspector.transitive_trust.Message')
    @patch('autonomous_trust.inspector.transitive_trust.to_json_string', return_value='{}')
    def test_body_is_serialized_once_per_round(self, tjs, _msg):
        host = _Host([_peer('a'), _peer('b'), _peer('c'), _peer('d')])
        host.query_peer_pairs({CfgIds.network: MagicMock()})
        # Once, not once per subject (4) and not once per pair (12).
        assert tjs.call_count == 1

    @patch('autonomous_trust.inspector.transitive_trust.Message')
    @patch('autonomous_trust.inspector.transitive_trust.to_json_string', return_value='{}')
    def test_body_names_every_peer_by_uuid(self, tjs, _msg):
        host = _Host([_peer('a'), _peer('b'), _peer('c')])
        host.query_peer_pairs({CfgIds.network: MagicMock()})
        body = tjs.call_args.args[0]
        assert body['peer_uuids'] == ['a', 'b', 'c'], body
        assert body['requesting_process'] == 'monitor'
        # uuids, not Identity objects: N identities to N observers would trade
        # N-squared messages for N-squared bytes.
        assert all(isinstance(u, str) for u in body['peer_uuids'])

    @patch('autonomous_trust.inspector.transitive_trust.Message')
    @patch('autonomous_trust.inspector.transitive_trust.to_json_string', return_value='{}')
    def test_only_one_message_is_signed_per_round(self, _tjs, msg):
        host = _Host([_peer('a'), _peer('b'), _peer('c'), _peer('d')])
        host.query_peer_pairs({CfgIds.network: MagicMock()})
        # One construction (which signs), three readdressed copies (which do not).
        assert msg.call_count == 1
        assert msg.return_value.for_recipient.call_count == 3

    @patch('autonomous_trust.inspector.transitive_trust.Message')
    @patch('autonomous_trust.inspector.transitive_trust.to_json_string')
    def test_unserializable_body_ends_the_round_quietly(self, tjs, _msg):
        """The body is shared by every request, so there is no partial round to
        salvage — but it must be logged rather than raised into the task loop."""
        tjs.side_effect = RuntimeError('cannot serialize')
        host = _Host([_peer('a'), _peer('b')])
        netq, logger = MagicMock(), MagicMock()
        assert host.query_peer_pairs({CfgIds.network: netq}, logger=logger) == 0
        assert netq.put.call_count == 0
        assert logger.exception.called

    @patch('autonomous_trust.inspector.transitive_trust.Message')
    @patch('autonomous_trust.inspector.transitive_trust.to_json_string', return_value='{}')
    def test_readdress_failure_costs_one_observer_not_the_round(self, _tjs, msg):
        msg.return_value.for_recipient.side_effect = RuntimeError('copy failed')
        host = _Host([_peer('a'), _peer('b'), _peer('c')])
        netq = MagicMock()
        sent = host.query_peer_pairs({CfgIds.network: netq}, logger=MagicMock())
        assert sent == 1, 'the signed original still went out'
