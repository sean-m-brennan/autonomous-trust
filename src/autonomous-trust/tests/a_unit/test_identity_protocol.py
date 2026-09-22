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
        - subtree member-roster enumeration (roster_req, roster_resp)
        - operator-attended pull (attest_req, attest_resp), its
          local-only trigger (attest_trigger), and the local-only
          session round trip it needs
          (operator_state_req, operator_state_resp)
        - runtime hierarchy roots (hierarchy, hierarchy_req)
        - the OPTIONAL 1:1 first-contact handshake (hello, hello_ack;
          opt-in via AT_FIRST_CONTACT, see first-contact.md)
        - opt-in coarse position, the "with-distance" feature
          (position_query, position_response)
        - opt-in signed agora.profile, Increment 3
          (profile_query, profile_response)
        - explicit, revocable connection edges, Increment 5
          (connection_request, connection_response)
        - directed encrypted direct messages, Increment 6 (dm)
        - signed, content-addressed feed posts, Increment 7 (post)
        - directed encrypted post reactions, Increment 8 (reaction)
        - opt-in private proximity: two connected peers swap
          key-derived grid tags to learn only a coarse distance
          band (proximity_probe, proximity_reply, and its
          local-only trigger proximity_trigger)
        - business pages carried by their own customers, Phase 3
          (business_ad) — every ad on the wire is first-person, so
          one verb covers the business advertising itself and a
          happy customer re-advertising what it learned
        - detached co-signing of staff roll acts, Phase 3 P3.3
          (cosign_request, cosign_sig) — the record's bytes travel
          and the signers' private keys do not, so it takes two
          verbs: the ask carrying the exported payload, and the
          signature coming back. The human-legible description of
          what is being signed is deliberately NOT a field on
          either: the signer's own node derives it from the bytes.
        - business POSTS, Phase 3 P3.4 (business_post) — the polity
          speaking, where the page is what it is. One verb, not two:
          unlike an ad it IS relayed, and a relay forwards the
          publisher's own envelope untouched and bumps only the hop
          count, so a carried post is the same message rather than a
          second one. Its authority is the envoy signature sealed in
          the opaque bundle, which this tier never opens.
        - first-person reports, Phase 4 P4.1 (report) — directed and
          encrypted like a reaction, {seq, ts} only. No reason travels:
          on the wire it would make a score a published accusation.
        Asserting the exact count here pins the wire contract — a
        new verb without intent will fail this and force a deliberate
        update. Update the expected count alongside any new addition
        to ``IdentityProtocol``.
        """
        values = list(IdentityProtocol)
        assert len(values) == 45
        assert 'report' in values
        assert 'announce' in values
        assert 'business_ad' in values
        assert 'business_post' in values
        assert 'cosign_request' in values
        assert 'cosign_sig' in values
