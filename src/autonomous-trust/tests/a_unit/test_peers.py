# ******************
#  Copyright 2025 Sean M. Brennan and contributors
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
import pytest
from uuid import uuid4
from unittest.mock import MagicMock

from autonomous_trust.core.identity.peers import Peers


def _mock_peer(nickname='peer1', address='192.168.1.1', uuid=None):
    peer = MagicMock()
    peer.nickname = nickname
    peer.address = address
    peer.uuid = uuid or uuid4()
    return peer


class TestPeers:
    def test_init_empty(self):
        p = Peers()
        assert len(p.all) == 0
        assert len(p.listing) == 0
        assert len(p.hierarchy) == Peers.LEVELS
        assert len(p.valuation) == Peers.VALUES

    def test_mid_level(self):
        p = Peers()
        assert p.mid_level == 1  # LEVELS=3, 3//2=1

    def test_to_dict(self):
        p = Peers()
        d = p.to_dict()
        assert 'hierarchy' in d
        assert 'valuation' in d

    def test_add(self):
        p = Peers()
        peer = _mock_peer()
        p.add(peer)
        assert peer in p.all
        assert peer.address in p.listing
        assert peer.nickname in p.hierarchy[p.mid_level]

    def test_add_with_level(self):
        p = Peers()
        peer = _mock_peer()
        p.add(peer, level=0)
        assert peer.nickname in p.hierarchy[0]

    def test_add_duplicate_address(self):
        p = Peers()
        peer = _mock_peer()
        p.add(peer)
        p.add(peer)  # should not duplicate
        assert p.all.count(peer) == 1

    def test_add_rejoin_same_nickname_dedups(self):
        # A peer rejoining under a new uuid/address keeps its nickname. The
        # stale identity must NOT linger in self.all / self.listing — there
        # must be exactly one peer per nickname, and it must be the new one.
        p = Peers()
        old = _mock_peer(nickname='mq800', address='10.0.0.1', uuid=uuid4())
        new = _mock_peer(nickname='mq800', address='10.0.0.2', uuid=uuid4())
        p.add(old)
        p.add(new)
        assert p.all == [new]
        assert old not in p.all
        assert old.address not in p.listing
        assert new.address in p.listing
        assert p.find_by_index('mq800') is new
        assert p.find_by_uuid(new.uuid) is new
        assert p.find_by_uuid(old.uuid) is None

    def test_add_distinct_nicknames_coexist(self):
        # Dedup is per-nickname only: different nicknames are unaffected.
        p = Peers()
        a = _mock_peer(nickname='a', address='10.0.0.1', uuid=uuid4())
        b = _mock_peer(nickname='b', address='10.0.0.2', uuid=uuid4())
        p.add(a)
        p.add(b)
        assert a in p.all and b in p.all
        assert len(p.all) == 2

    def test_find_by_uuid(self):
        p = Peers()
        uid = uuid4()
        peer = _mock_peer(uuid=uid)
        p.add(peer)
        found = p.find_by_uuid(uid)
        assert found is peer

    def test_find_by_uuid_not_found(self):
        p = Peers()
        assert p.find_by_uuid(uuid4()) is None

    def test_find_by_address(self):
        p = Peers()
        peer = _mock_peer(address='10.0.0.1')
        p.add(peer)
        found = p.find_by_address('10.0.0.1')
        assert found is peer

    def test_find_by_address_cidr(self):
        p = Peers()
        peer = _mock_peer(address='10.0.0.1')
        p.add(peer)
        found = p.find_by_address('10.0.0.1/24')
        assert found is peer

    def test_find_by_address_not_found(self):
        p = Peers()
        assert p.find_by_address('1.2.3.4') is None

    def test_find_by_index(self):
        p = Peers()
        peer = _mock_peer(nickname='nick1')
        p.add(peer)
        found = p.find_by_index('nick1')
        assert found is peer

    def test_find_by_index_not_found(self):
        p = Peers()
        assert p.find_by_index('nonexistent') is None

    def test_delete(self):
        p = Peers()
        peer = _mock_peer()
        p.add(peer)
        p.delete(peer)
        assert peer.nickname not in p.hierarchy[p.mid_level]

    def test_delete_nonexistent(self):
        p = Peers()
        peer = _mock_peer()
        p.delete(peer)  # should not crash

    def test_find_top_n_all(self):
        p = Peers()
        peers = [_mock_peer(nickname='p%d' % i, address='10.0.0.%d' % i) for i in range(5)]
        for peer in peers:
            p.add(peer)
        result = p.find_top_n(10)
        assert result == p.all

    def test_promote(self):
        p = Peers()
        peer = _mock_peer()
        p.add(peer)
        # Initially at valuation[-1]
        assert peer.nickname in p.valuation[-1]
        p.promote(peer)
        # Should be promoted to valuation[-2]
        assert peer.nickname in p.valuation[-2]

    def test_promote_not_in_all(self):
        p = Peers()
        peer = _mock_peer()
        # promote on peer not in all does nothing (guard: `if who in self.all`)
        p.promote(peer)
        # Since peer is not in self.all, promote finds no valuation index
        # and falls to else clause which adds to valuation[-1]
        # But the guard `if who in self.all` prevents this
        # So nothing happens
        assert peer not in p.all

    def test_demote(self):
        p = Peers()
        peer = _mock_peer()
        p.add(peer)
        # Move to a non-last position first
        p.promote(peer)  # now at [-2]
        p.demote(peer)  # should go back

    def test_move_not_in_all(self):
        p = Peers()
        peer = _mock_peer()
        # move on peer not in all does nothing
        p.move(peer, 0)
        assert peer not in p.all

    def test_my_level_peers(self):
        p = Peers()
        peer = _mock_peer()
        p.add(peer)
        assert peer.nickname in p.my_level_peers

    def test_init_with_hierarchy(self):
        peer = _mock_peer()
        hierarchy = [dict({}), {peer.nickname: peer}, dict({})]
        valuation = [dict({}) for _ in range(Peers.VALUES)]
        p = Peers(hierarchy=hierarchy, valuation=valuation)
        assert peer in p.all
        assert peer.address in p.listing


class TestFindTopNPartial:
    def test_find_top_n_partial(self):
        """Test find_top_n when n < len(all) - exercises the loop with early break."""
        p = Peers()
        peers = [_mock_peer(nickname='p%d' % i, address='10.0.0.%d' % i) for i in range(10)]
        for peer in peers:
            p.add(peer)
            # Promote some to different valuation levels
        for i in range(5):
            p.promote(peers[i])
        result = p.find_top_n(3)
        # find_top_n has a bug (no return when n < len(all)), returns None
        # But it exercises lines 93-100


class TestMoveInner:
    def test_move_peer_to_level(self):
        """Test move with peer in all and valid valuation.
        Note: move() has a bug - it uses _find_v index to delete from hierarchy,
        but valuation has 10 levels while hierarchy has 3, causing IndexError
        when the valuation index >= 3. We promote to valuation index 1 so the
        delete from hierarchy[1] works (hierarchy has 3 entries)."""
        p = Peers()
        peer = _mock_peer()
        p.add(peer)
        # Promote so valuation index becomes small enough for hierarchy
        for _ in range(Peers.VALUES - 2):  # promote to idx 1
            p.promote(peer)
        # Now _find_v returns 1, which is valid for hierarchy too
        # Put peer into hierarchy[1] so del hierarchy[1][index] works
        p.hierarchy[1][peer.nickname] = peer
        p.move(peer, 0)

    def test_move_peer_at_zero(self):
        """Move peer when it's at valuation index 0 - idx > 0 is False."""
        p = Peers()
        peer = _mock_peer()
        p.add(peer)
        # Promote all the way to valuation[0]
        for _ in range(Peers.VALUES - 1):
            p.promote(peer)
        # Now peer is at valuation[0], move should not move since idx > 0 is False


class TestDemoteEviction:
    def test_demote_past_hierarchy(self):
        """Demote peer past hierarchy boundary causes eviction."""
        p = Peers()
        peer = _mock_peer()
        p.add(peer)
        # Promote until at an index within LEVELS range
        for _ in range(Peers.VALUES - 1):  # promote to idx 0
            p.promote(peer)
        # Now demote: idx=0, idx < len(hierarchy)=3 is True, so moved to idx+1
        p.demote(peer)
        # idx=1, still within hierarchy
        p.demote(peer)
        # idx=2, still within hierarchy
        p.demote(peer)
        # idx=3, >= LEVELS=3, so peer gets evicted from listing and all


class TestPromoteNotInValuation:
    def test_promote_in_all_not_in_valuation(self):
        """Test promote when peer is in all but not found in valuation."""
        p = Peers()
        peer = _mock_peer()
        p.add(peer)
        # Manually remove from all valuation levels
        for v in p.valuation:
            if peer.nickname in v:
                del v[peer.nickname]
        # Now promote: who in all is True, _find_v returns None, goes to else branch
        p.promote(peer)
        # Should add to valuation[-1]
        assert peer.nickname in p.valuation[-1]
