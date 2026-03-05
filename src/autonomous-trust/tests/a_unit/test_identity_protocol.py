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
        values = list(IdentityProtocol)
        assert len(values) == 8
        assert 'announce' in values
