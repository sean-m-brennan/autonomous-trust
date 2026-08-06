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
"""
The persistent-cohort save gate (`IdentityProcess._trusted_uuids_for_persist`).

Nothing tested this before, which is how the following shipped: the gate read
`peer._tier >= PERSIST_TIER_FLOOR`, but `_tier` is a CONSTRUCTOR DEFAULT of 0
(identity.py:63) that the protobuf wire form never carries, so an unscored peer
was indistinguishable from a demoted one. ReputationProcess only computes a score
when something asks, and on a quiet mesh nothing does -- measured 0 `rep.*` probe
events across a 40 s two-peer harness run -- so no tier was ever published, every
admitted peer sat at the default 0, and the saved roster came out EMPTY. Not
"empty until the peer earns trust" but empty permanently, which also means a node
forgot every legitimate group member across a restart. That is what made
`test_harness_two_peers_converge` read `Views={0: [], 1: []}` while the mesh had
in fact fully converged.

The gate now drops a peer only when it has been ASSESSED and found wanting.
Admission makes a peer a member; reputation can only take that away.
"""
from __future__ import annotations

from unittest.mock import MagicMock

from autonomous_trust.core.config import to_json_string
from autonomous_trust.core.identity import Peers
from autonomous_trust.core.identity.protocol import IdentityProtocol
from autonomous_trust.core._python.identity.idprocess import (
    IdentityProcess,
    PERSIST_TIER_FLOOR,
)
from autonomous_trust.core.reputation.repprocess import (
    ReputationProcess,
    REPUTATION_PERSIST_THRESHOLD,
)


class _Peer:
    """Minimal stand-in for a peer Identity. `_tier` is deliberately absent
    unless asked for, so a test can model 'never scored' faithfully."""

    def __init__(self, uuid, address, tier=None):
        self.uuid = uuid
        self.nickname = 'peer-' + uuid
        self.petname = self.nickname
        self.address = address
        if tier is not None:
            self._tier = tier


def _idproc(peers, tier_published=None):
    """An IdentityProcess stub carrying only what the gate reads."""
    proc = MagicMock(spec=IdentityProcess)
    proc.identity = _Peer('self-uuid', '127.0.0.1')
    proc.peers = peers
    proc._tier_published = set(tier_published or ())
    proc.logger = MagicMock()
    return proc


def _kept(proc):
    return IdentityProcess._trusted_uuids_for_persist(proc)


class TestUnscoredPeersSurvive:
    def test_never_scored_peer_is_kept(self):
        """The defect. Nobody has scored this peer, so it must persist."""
        peers = Peers()
        peers.add(_Peer('p1', '127.0.0.3'))
        kept = _kept(_idproc(peers))
        assert 'p1' in kept

    def test_never_scored_peer_reaches_the_saved_snapshot(self):
        """End to end through the filter the save path actually applies -- this
        is the file the diag harness reads to judge convergence."""
        peers = Peers()
        peers.add(_Peer('p1', '127.0.0.3'))
        snapshot = peers.filtered_for_persist(_kept(_idproc(peers)))
        assert len(snapshot.all) == 1
        assert [p.address for p in snapshot.all] == ['127.0.0.3']

    def test_default_tier_zero_is_not_treated_as_demotion(self):
        """`_tier` present and 0 is what a peer looks like straight off the
        wire; it is not evidence of a low score."""
        peers = Peers()
        peers.add(_Peer('p1', '127.0.0.3', tier=0))
        assert 'p1' in _kept(_idproc(peers))  # no tier published for it

    def test_self_is_always_kept(self):
        kept = _kept(_idproc(Peers()))
        assert 'self-uuid' in kept


class TestAssessedPeersAreGated:
    def test_assessed_below_floor_is_dropped(self):
        """The security intent, preserved: a peer scored down does not survive a
        restart."""
        peers = Peers()
        peers.add(_Peer('p1', '127.0.0.3', tier=0))
        kept = _kept(_idproc(peers, tier_published={'p1'}))
        assert 'p1' not in kept
        assert len(peers.filtered_for_persist(kept).all) == 0

    def test_assessed_at_or_above_floor_is_kept(self):
        peers = Peers()
        peers.add(_Peer('p1', '127.0.0.3', tier=PERSIST_TIER_FLOOR))
        assert 'p1' in _kept(_idproc(peers, tier_published={'p1'}))

    def test_neutral_prior_lands_above_the_floor(self):
        """The threshold comparison is `>=`, so a peer scored at exactly the
        neutral prior is tier 1 and persists. Guards against someone 'fixing'
        the comment's 'strictly above' wording into the code."""
        tier = ReputationProcess._trust_tier(REPUTATION_PERSIST_THRESHOLD)
        assert tier >= PERSIST_TIER_FLOOR
        peers = Peers()
        peers.add(_Peer('p1', '127.0.0.3', tier=tier))
        assert 'p1' in _kept(_idproc(peers, tier_published={'p1'}))

    def test_only_the_assessed_peer_is_gated(self):
        """A demotion must not take an unrelated unscored peer with it."""
        peers = Peers()
        peers.add(_Peer('p1', '127.0.0.3', tier=0))   # assessed, low
        peers.add(_Peer('p2', '127.0.0.4'))           # never scored
        kept = _kept(_idproc(peers, tier_published={'p1'}))
        assert 'p1' not in kept
        assert 'p2' in kept


class TestTierPublicationIsRecorded:
    def _msg(self, uuid, tier):
        msg = MagicMock()
        msg.function = IdentityProtocol.tier_update
        msg.obj = to_json_string((uuid, tier))
        return msg

    def _proc(self, peers):
        proc = MagicMock(spec=IdentityProcess)
        proc.identity = _Peer('self-uuid', '127.0.0.1')
        proc.peers = peers
        proc._tier_published = set()
        proc.logger = MagicMock()
        return proc

    def test_publication_is_recorded(self):
        peers = Peers()
        peers.add(_Peer('p1', '127.0.0.3'))
        proc = self._proc(peers)
        IdentityProcess.handle_tier_update(proc, None, self._msg('p1', 2))
        assert 'p1' in proc._tier_published

    def test_recorded_even_when_the_value_does_not_change(self):
        """A republished identical tier is still evidence the peer was assessed.
        Recording it only on change would leave a peer that was scored into
        tier 0 -- matching its default -- looking unscored forever, i.e. the
        original bug with extra steps."""
        peers = Peers()
        peers.add(_Peer('p1', '127.0.0.3', tier=0))
        proc = self._proc(peers)
        IdentityProcess.handle_tier_update(proc, None, self._msg('p1', 0))
        assert 'p1' in proc._tier_published
        # ...and it is now gated on that evidence
        assert 'p1' not in IdentityProcess._trusted_uuids_for_persist(proc)

    def test_unknown_peer_publication_does_not_gate_anything(self):
        """A tier for a peer we do not hold yet is dropped; it must not poison
        the set and later exclude that peer once it arrives."""
        peers = Peers()
        proc = self._proc(peers)
        IdentityProcess.handle_tier_update(proc, None, self._msg('ghost', 0))
        peers.add(_Peer('ghost', '127.0.0.9'))
        assert 'ghost' in IdentityProcess._trusted_uuids_for_persist(proc)
