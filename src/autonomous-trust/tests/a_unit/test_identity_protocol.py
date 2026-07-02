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
from autonomous_trust.core.identity.protocol import IdentityProtocol


class TestIdentityProtocol:
    def test_protocol_values(self):
        assert IdentityProtocol.announce == 'request_access'
        assert IdentityProtocol.accept == 'access_granted'
        assert IdentityProtocol.history == 'full_history'
        assert IdentityProtocol.diff == 'history_diff'
        assert IdentityProtocol.propose == 'propose_peer'
        assert IdentityProtocol.vote == 'vote_on_peer'
        assert IdentityProtocol.confirm == 'peer_accepted'
        assert IdentityProtocol.update == 'group_key_update'

    def test_contains(self):
        # ClassEnumMeta __contains__ uses attribute names, not values
        assert 'announce' in IdentityProtocol
        assert 'accept' in IdentityProtocol
        assert 'nonexistent' not in IdentityProtocol

    def test_iter(self):
        """Iterates the full protocol enum.

        The set grew beyond the original 8 verbs to accommodate:
        - capability gossip recovery (caps_query, caps_response)
        - trust-tier change notifications (tier_update, tier_lost)
        - group-partition recovery (partition_signal,
          partition_probe, partition_response)
        - peer identity backfill (id_query, id_response)
        Asserting the exact count here pins the wire contract — a
        new verb without intent will fail this and force a deliberate
        update. Update the expected count alongside any new addition
        to ``IdentityProtocol``.
        """
        values = list(IdentityProtocol)
        assert len(values) == 17
        assert 'announce' in values
