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

"""Tests for the persistent-cohort feature.

Covers:
- Reputation save filters peers strictly above
  REPUTATION_PERSIST_THRESHOLD (=0.5); self always included.
- Peers/PeerCapabilities save filters by ``_tier >= PERSIST_TIER_FLOOR``
  (=1, matching rep > 0.5 per repprocess.TIER_FLOORS).
- tools/seed_dod_cohort.seed_cohort() writes mutually-consistent state
  for squad-*/microdrone-*/jet-* peers and leaves the rest empty.
- The seed is idempotent: re-run without --force preserves UUIDs.

Tests that need the live IdentityProcess/ReputationProcess wired up
(SIGTERM-triggered final-flush, ``choose_group`` warm-start) live as
integration tests in src/autonomous-trust/tests/b_integration/ — this
module stays at the a_unit-equivalent level so it runs fast.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from uuid import uuid4

import pytest

from autonomous_trust.core._python.capabilities import PeerCapabilities
from autonomous_trust.core._python.config.configuration import config_json_decoder
from autonomous_trust.core._python.identity import Peers
from autonomous_trust.core._python.identity.identity import Identity
from autonomous_trust.core._python.identity.sign import Signature
from autonomous_trust.core._python.identity.encrypt import Encryptor
from autonomous_trust.core._python.reputation.reputation import Reputations
from autonomous_trust.core._python.reputation.repprocess import (
    REPUTATION_PERSIST_THRESHOLD,
)


# ---------------------------------------------------------------- fixtures


def _mk_identity(name: str, tier: int = 0) -> Identity:
    """Build an Identity with a real keypair (deterministic-enough for
    test assertions). Address is the name itself."""
    ident = Identity(
        _uuid=uuid4(),
        address=name,
        _nickname=f"{name}@test",  # Zooko online name (decorated)
        _signature=Signature.generate(),
        _encryptor=Encryptor.generate(),
        petname=name,              # Zooko local name (bare roster label)
    )
    ident._tier = tier  # noqa: SLF001
    return ident


# ---------------------------------------------------------------- Reputations


def test_reputations_filtered_for_persist_drops_below_threshold():
    """Peers strictly above the threshold survive; at-threshold and
    below are pruned. Self is the caller's job (not the method's)."""
    u_high = uuid4()
    u_at = uuid4()
    u_low = uuid4()
    reps = Reputations(current={u_high: 0.75, u_at: 0.5, u_low: 0.3})
    keep = {u_high}  # caller's choice of who to keep
    filtered = reps.filtered_for_persist(keep)
    assert set(filtered.current.keys()) == {u_high}
    assert filtered.current[u_high] == pytest.approx(0.75)


def test_reputations_filtered_handles_string_uuids():
    """Round-trip through JSON gives back string keys; the filter must
    coerce keep_uuids to UUIDs before comparison."""
    u = uuid4()
    reps = Reputations(current={u: 0.9})
    # Pass the uuid as a string — what the JSON path produces.
    filtered = reps.filtered_for_persist({str(u)})
    assert filtered.current == {u: 0.9}


def test_reputation_persist_threshold_is_half():
    """The threshold has product implications (DoD demo's
    high-trust starting cohort). Pin it explicitly so it can't drift
    without an intentional test update."""
    assert REPUTATION_PERSIST_THRESHOLD == 0.5


# ---------------------------------------------------------------- Peers


def test_peers_filtered_for_persist_keeps_only_listed_uuids():
    alice = _mk_identity("alice", tier=2)
    bob = _mk_identity("bob", tier=2)
    carol = _mk_identity("carol", tier=0)
    peers = Peers()
    for ident in (alice, bob, carol):
        peers.add(ident)
    keep = {alice.uuid, bob.uuid}
    filtered = peers.filtered_for_persist(keep)
    assert {p.petname for p in filtered.all} == {"alice", "bob"}
    # Hierarchy + valuation both filtered
    assert all("carol" not in level for level in filtered.hierarchy)
    assert all("carol" not in tier for tier in filtered.valuation)


def test_peers_filtered_for_persist_empty_keep_returns_empty():
    alice = _mk_identity("alice")
    peers = Peers()
    peers.add(alice)
    filtered = peers.filtered_for_persist(set())
    assert filtered.all == []


# ---------------------------------------------------------------- PeerCapabilities


def test_peercapabilities_filtered_for_persist_drops_untrusted():
    alice = uuid4()
    bob = uuid4()
    pc = PeerCapabilities()
    pc.register(alice, ["cap.a", "cap.b"])
    pc.register(bob, ["cap.a"])
    filtered = pc.filtered_for_persist({alice})
    assert set(filtered._listing.keys()) == {"cap.a", "cap.b"}
    assert filtered._listing["cap.a"] == [alice]
    assert filtered._listing["cap.b"] == [alice]


def test_peercapabilities_filtered_drops_empty_cap_names():
    """A capability advertised by no surviving peer should not appear
    in the snapshot — keeps the file tight."""
    alice = uuid4()
    pc = PeerCapabilities()
    pc.register(alice, ["solo.cap"])
    filtered = pc.filtered_for_persist(set())  # alice not kept
    assert "solo.cap" not in filtered._listing


# ---------------------------------------------------------------- seed_dod_cohort


@pytest.fixture
def scenario_factory():
    from examples.dod_mission.scenario import DoDMissionScenario
    return lambda **kw: DoDMissionScenario(**kw)


def test_seed_cohort_writes_expected_files(tmp_path, scenario_factory):
    from tools.seed_dod_cohort import seed_cohort

    sc = scenario_factory(squad_size=3, swarm_size=2, sensor_count=2,
                          hacked_sensors=1, include_command=False)
    seeded = seed_cohort(tmp_path, sc, force=True)
    # squad-captain + 2 specialists + 2 microdrones + jet-1 = 6
    assert "jet-1" in seeded
    assert any(n.startswith("microdrone-") for n in seeded)
    assert any(n.startswith("squad-") for n in seeded)
    assert not any(n.startswith("mq-") for n in seeded)
    assert not any(n.startswith("ground-sensor-") for n in seeded)

    for peer in seeded:
        d = tmp_path / peer / "etc" / "at"
        for fn in ("identity.cfg.json", "group.cfg.json",
                   "peers.cfg.json", "reputation.cfg.json",
                   "reputation-history.cfg.json",
                   "peer-capabilities.cfg.json"):
            assert (d / fn).exists(), f"{peer} missing {fn}"


def test_seed_cohort_mutual_recognition(tmp_path, scenario_factory):
    """Every seeded peer's peers.cfg.json contains the OTHER seeded
    peers' Identities. The shared group UUID must match across all
    peers' group.cfg.json files."""
    from tools.seed_dod_cohort import seed_cohort

    sc = scenario_factory(squad_size=3, swarm_size=2, sensor_count=2,
                          hacked_sensors=1, include_command=False)
    seeded = seed_cohort(tmp_path, sc, force=True)

    group_uuids: set[str] = set()
    for peer in seeded:
        # Load peers.cfg.json; assert it contains every OTHER seeded peer.
        peers_file = tmp_path / peer / "etc" / "at" / "peers.cfg.json"
        with peers_file.open() as f:
            peers = json.load(f, object_hook=config_json_decoder)
        names = {p.petname for p in peers.all}  # bare roster label (Zooko local)
        for other in seeded:
            if other == peer:
                assert other not in names, "self should not be in peers"
            else:
                assert other in names, f"{peer} missing peer {other}"

        # Group UUID consistent across the cohort.
        grp_file = tmp_path / peer / "etc" / "at" / "group.cfg.json"
        with grp_file.open() as f:
            grp_payload = json.load(f, object_hook=config_json_decoder)
        group_uuids.add(grp_payload[0].uuid)

    assert len(group_uuids) == 1, "every seeded peer must share one group UUID"


def test_seed_cohort_group_history_loads_as_a_node_loads_it(tmp_path, scenario_factory):
    """Each seeded peer's group.cfg.json carries a history that peer can
    populate, the way IdentityProcess.choose_group reads it. An empty {}
    raised KeyError 'blacklist' there, and the node fell back to minting a
    group of its own, so the seeded cohort never formed."""
    import queue
    from autonomous_trust.core._python.identity.history.history import IdentityHistory
    from tools.seed_dod_cohort import seed_cohort

    sc = scenario_factory(squad_size=2, swarm_size=2, sensor_count=2,
                          hacked_sensors=1, include_command=False)
    seeded = seed_cohort(tmp_path, sc, force=True)

    for peer in seeded:
        d = tmp_path / peer / "etc" / "at"
        with (d / "identity.cfg.json").open() as f:
            identity = json.load(f, object_hook=config_json_decoder)
        with (d / "peers.cfg.json").open() as f:
            peers = json.load(f, object_hook=config_json_decoder)
        with (d / "group.cfg.json").open() as f:
            _group, hist_dict = json.load(f, object_hook=config_json_decoder)
        IdentityHistory(identity, peers, queue.Queue()).populate(hist_dict)


def test_seed_cohort_reputation_above_threshold(tmp_path, scenario_factory):
    """Every seeded peer's reputation snapshot has every OTHER seeded
    peer at >0.5 so they would all survive the rep-persist filter."""
    from tools.seed_dod_cohort import seed_cohort, SEED_REPUTATION

    sc = scenario_factory(squad_size=2, swarm_size=2, sensor_count=2,
                          hacked_sensors=1, include_command=False)
    seeded = seed_cohort(tmp_path, sc, force=True)

    for peer in seeded:
        rep_file = tmp_path / peer / "etc" / "at" / "reputation.cfg.json"
        with rep_file.open() as f:
            reps = json.load(f, object_hook=config_json_decoder)
        # All entries clearly above the threshold.
        assert all(r > REPUTATION_PERSIST_THRESHOLD
                   for r in reps.current.values())
        assert all(r == pytest.approx(SEED_REPUTATION)
                   for r in reps.current.values())
        # Count = seeded - 1 (no self entry).
        assert len(reps.current) == len(seeded) - 1


def test_seed_cohort_idempotent_without_force(tmp_path, scenario_factory):
    """Re-running the seed without --force preserves UUIDs so warm
    restarts see stable identities."""
    from tools.seed_dod_cohort import seed_cohort

    sc = scenario_factory(squad_size=2, swarm_size=1, sensor_count=2,
                          hacked_sensors=1, include_command=False)
    seed_cohort(tmp_path, sc, force=True)
    first_uuids = {}
    for peer in tmp_path.iterdir():
        if peer.is_dir() and peer.name != "_shared":
            ident_file = peer / "etc" / "at" / "identity.cfg.json"
            if ident_file.exists():
                with ident_file.open() as f:
                    ident = json.load(f, object_hook=config_json_decoder)
                first_uuids[peer.name] = ident.uuid

    # Second run without --force should not change the UUIDs.
    seed_cohort(tmp_path, sc, force=False)
    for peer_name, prior_uuid in first_uuids.items():
        ident_file = tmp_path / peer_name / "etc" / "at" / "identity.cfg.json"
        with ident_file.open() as f:
            ident = json.load(f, object_hook=config_json_decoder)
        assert ident.uuid == prior_uuid, f"{peer_name} UUID drifted on re-seed"


def test_seed_cohort_force_regenerates(tmp_path, scenario_factory):
    """--force blows away the dir and regenerates fresh keys (UUIDs
    change)."""
    from tools.seed_dod_cohort import seed_cohort

    sc = scenario_factory(squad_size=1, swarm_size=1, sensor_count=2,
                          hacked_sensors=1, include_command=False)
    seed_cohort(tmp_path, sc, force=True)
    ident_file = tmp_path / "jet-1" / "etc" / "at" / "identity.cfg.json"
    with ident_file.open() as f:
        first = json.load(f, object_hook=config_json_decoder)

    seed_cohort(tmp_path, sc, force=True)
    with ident_file.open() as f:
        second = json.load(f, object_hook=config_json_decoder)
    assert first.uuid != second.uuid, "--force should regenerate keys"


def test_seed_cohort_skips_mq800_and_sensors(tmp_path, scenario_factory):
    """The spec's pre-trusted set is strictly squad-*/microdrone-*/jet-*;
    everything else (mq-800, rq-86, ground-sensor-*, command-node)
    starts empty and cold-bootstraps."""
    from tools.seed_dod_cohort import seed_cohort

    sc = scenario_factory()
    seed_cohort(tmp_path, sc, force=True)
    # MQ-800 must not have been seeded — its compromise beat depends
    # on it joining late and being judged by handshake.
    assert not (tmp_path / "mq-800").exists() or \
           not any((tmp_path / "mq-800" / "etc" / "at").glob("*.cfg.json"))
    # Ground sensors likewise — the Sybil-rejection beat needs them
    # to handshake.
    sensors = list(tmp_path.glob("ground-sensor-*"))
    for s in sensors:
        assert not any(s.glob("etc/at/*.cfg.json")), \
            f"{s.name} should not be pre-seeded"


# ------------------------------------------------- seeded reputation evidence
#
# A seeded score with no evidence beside it restores clamped (ISSUES.md §10.3),
# which would gate the demo's tier-2 capabilities at t=0. These tests hold the
# seeder to the standard the runtime applies rather than to its own output
# format: the assertion that matters is that ReputationProcess ACCEPTS what was
# written, not that a file exists.


def _seeded_evidence(peer_dir: Path):
    from autonomous_trust.core._python.config import Configuration
    from autonomous_trust.core._python.reputation.reputation import (
        EVIDENCE_FILE, evidence_from_dict,
    )
    path = peer_dir / "etc" / "at" / (EVIDENCE_FILE + Configuration.file_ext)
    with path.open() as f:
        return evidence_from_dict(json.load(f))


def test_seed_cohort_writes_verifiable_evidence(tmp_path, scenario_factory):
    """Every seeded peer gets a hash-linked window whose Merkle root the
    checkpoint over it actually commits to."""
    from tools.seed_dod_cohort import seed_cohort
    from autonomous_trust.core._python.reputation.reputation import (
        TransactionHistory,
    )

    sc = scenario_factory(squad_size=3, swarm_size=2, sensor_count=2,
                          hacked_sensors=1, include_command=False)
    seeded = seed_cohort(tmp_path, sc, force=True)
    proposers = set()
    for peer in seeded:
        chain, signed = _seeded_evidence(tmp_path / peer)
        assert TransactionHistory.verify_chain_links(chain)
        assert TransactionHistory(_chain=chain).window_root() == signed.checkpoint.root
        assert signed.checkpoint.count == len(chain)
        # Each peer proposes its own checkpoint over the shared window, so the
        # signed designation differs per file even though the root does not.
        proposers.add(str(signed.checkpoint.proposer_uuid))
        assert signed.sigs
    assert len(proposers) == len(seeded)


def test_seed_cohort_evidence_signatures_verify(tmp_path, scenario_factory):
    """The co-signatures are real signatures by the cohort's own keys, and
    there are more of them than a reader's quorum requires -- which is the
    only reason the seeded scores survive restoration."""
    from tools.seed_dod_cohort import seed_cohort
    from nacl.encoding import HexEncoder

    sc = scenario_factory(squad_size=3, swarm_size=2, sensor_count=2,
                          hacked_sensors=1, include_command=False)
    seeded = seed_cohort(tmp_path, sc, force=True)
    peer = sorted(seeded)[0]
    chain, signed = _seeded_evidence(tmp_path / peer)
    peers_file = tmp_path / peer / "etc" / "at" / "peers.cfg.json"
    with peers_file.open() as f:
        roster = json.load(f, object_hook=config_json_decoder)
    known = {str(p.uuid): p for p in roster.all}
    verified = 0
    for voter, sig in signed.sigs.items():
        ident = known.get(str(voter))
        if ident is None:
            continue  # the viewer itself; its own key is not in its roster
        ident.signature.public.verify(signed.checkpoint.designation,
                                      HexEncoder.decode(sig.encode('ascii')))
        verified += 1
    assert verified > len(roster.all) // 2, "short of a reader's quorum"


def test_seed_cohort_evidence_is_founded_by_a_roster(tmp_path, scenario_factory):
    """The seeded window opens with the field group's genesis roster, listing
    every seeded member and gateway with its signing key, and every placement
    in it carries a certificate those keys verify. A chain with entries and no
    roster is reset at boot, whatever its checkpoint says."""
    from tools.seed_dod_cohort import seed_cohort
    from nacl.encoding import HexEncoder
    from nacl.signing import VerifyKey
    from autonomous_trust.core._python.reputation.reputation import (
        TransactionHistory, place_designation, place_value_digest,
        placement_entry,
    )

    sc = scenario_factory(squad_size=3, swarm_size=2, sensor_count=2,
                          hacked_sensors=1, include_command=False)
    seeded = seed_cohort(tmp_path, sc, force=True)
    peer = sorted(seeded)[0]
    chain, _signed = _seeded_evidence(tmp_path / peer)
    genesis = chain[0]
    assert genesis.index == 0 and genesis.roster_op == 'genesis'
    assert TransactionHistory(_chain=chain).latest_roster() is not None

    peers_file = tmp_path / peer / "etc" / "at" / "peers.cfg.json"
    with peers_file.open() as f:
        others = json.load(f, object_hook=config_json_decoder)
    with (tmp_path / peer / "etc" / "at" / "identity.cfg.json").open() as f:
        me = json.load(f, object_hook=config_json_decoder)
    expected = {str(p.uuid).lower() for p in others.all} | {str(me.uuid).lower()}
    keys = dict(map(tuple, genesis.roster_members))
    assert set(keys) == expected

    by_index = {tx.index: tx for tx in chain}
    certified = 0
    for tx in chain:
        if not tx.place_sigs:
            continue
        entries = [placement_entry(by_index[i])
                   for i in range(tx.place_from, tx.index + 1)]
        desig = place_designation(tx.place_from,
                                  by_index[tx.place_from].prev_hash,
                                  place_value_digest(entries, tx.place_from))
        for voter, sig in tx.place_sigs.items():
            VerifyKey(keys[voter].encode('ascii'), encoder=HexEncoder).verify(
                desig, HexEncoder.decode(sig.encode('ascii')))
        certified += tx.index - tx.place_from + 1
    assert certified == len(chain), "every entry is in a certified placement"


def test_seed_cohort_evidence_supports_the_seeded_tier(tmp_path,
                                                      scenario_factory):
    """The point of the whole exercise: a real ReputationProcess booting on
    the seeded state restores the cohort at SEED_TIER instead of clamping it.

    Asserted through the runtime, because the seeded window only clears the
    tier if it is LONG enough -- restoration bounds a score by its shrunk mean
    attested score -- and that coupling is exactly what a format-only test
    would miss."""
    import queue
    from unittest.mock import MagicMock
    from autonomous_trust.core.processes import ProcessTracker
    from autonomous_trust.core.system import CfgIds
    from autonomous_trust.core._python.config import Configuration
    from autonomous_trust.core._python.reputation.repprocess import (
        ReputationProcess,
    )
    from tools.seed_dod_cohort import seed_cohort
    from examples.dod_mission.reputation_warmstart import SEED_TIER

    sc = scenario_factory(squad_size=3, swarm_size=2, sensor_count=2,
                          hacked_sensors=1, include_command=False)
    seeded = seed_cohort(tmp_path, sc, force=True)
    peer = sorted(seeded)[0]
    root = tmp_path / peer

    def load(name):
        with (root / "etc" / "at" / name).open() as f:
            return json.load(f, object_hook=config_json_decoder)

    procs = []
    for nm in (CfgIds.network, CfgIds.identity, CfgIds.negotiation,
               CfgIds.reputation):
        p = MagicMock()
        p.name = nm
        procs.append(p)
    configs = {
        'processes': procs,
        CfgIds.identity: load("identity.cfg.json"),
        CfgIds.peers: load("peers.cfg.json"),
        CfgIds.group: load("group.cfg.json")[0],
        CfgIds.reputation: load("reputation.cfg.json"),
    }
    prior = os.environ.get(Configuration.ROOT_VARIABLE_NAME)
    os.environ[Configuration.ROOT_VARIABLE_NAME] = str(root)
    try:
        rp = ReputationProcess(configs, ProcessTracker(), queue.Queue(),
                               suppress_log=True)
    finally:
        if prior is None:
            del os.environ[Configuration.ROOT_VARIABLE_NAME]
        else:
            os.environ[Configuration.ROOT_VARIABLE_NAME] = prior
    # The evidence verified, so the attested history came up with it.
    assert rp._checkpoint is not None  # noqa: SLF001
    assert len(rp.history) == rp._checkpoint.count  # noqa: SLF001
    # It came up with its roster, so boot did not reset it as pre-roster.
    assert rp.history.latest_roster() is not None
    # ...and every seeded peer holds its seeded tier.
    assert rp.reputations.current
    for uuid, score in rp.reputations.current.items():
        assert rp._trust_tier(score) >= SEED_TIER, \
            f"{str(uuid)[:8]} restored at {score:.4f}, below tier {SEED_TIER}"


def test_seed_cohort_gateway_restores_field_evidence_as_its_child_chain(
        tmp_path, scenario_factory):
    """A gateway holds the field window as the CHILD chain it is, restored
    once its child group set arrives, with the field roster in force. Its
    primary chain stays empty for the command cohort it cold-bootstraps: a
    field-founded primary would give the field roster that cohort's
    decisions."""
    import queue
    from unittest.mock import MagicMock
    from autonomous_trust.core.processes import ProcessTracker
    from autonomous_trust.core.system import CfgIds
    from autonomous_trust.core._python.config import Configuration
    from autonomous_trust.core._python.reputation.repprocess import (
        ReputationProcess,
    )
    from tools.seed_dod_cohort import GROUP_NICKNAME, is_gateway, seed_cohort
    from examples.dod_mission.reputation_warmstart import SEED_TIER

    sc = scenario_factory(squad_size=3, swarm_size=2, sensor_count=2,
                          hacked_sensors=1, include_command=False)
    seed_cohort(tmp_path, sc, force=True)
    gws = sorted(n for n in sc.peers if is_gateway(n))
    assert gws, "the scenario has no gateway to check"
    root = tmp_path / gws[0]
    cfg = root / "etc" / "at"

    def load(name):
        with (cfg / name).open() as f:
            return json.load(f, object_hook=config_json_decoder)

    field = load("group_child_%s.cfg.json" % GROUP_NICKNAME)
    procs = []
    for nm in (CfgIds.network, CfgIds.identity, CfgIds.negotiation,
               CfgIds.reputation):
        p = MagicMock()
        p.name = nm
        procs.append(p)
    configs = {
        'processes': procs,
        CfgIds.identity: load("identity.cfg.json"),
        CfgIds.peers: load("peers.cfg.json"),
        CfgIds.reputation: load("reputation.cfg.json"),
    }
    prior = os.environ.get(Configuration.ROOT_VARIABLE_NAME)
    os.environ[Configuration.ROOT_VARIABLE_NAME] = str(root)
    try:
        rp = ReputationProcess(configs, ProcessTracker(), queue.Queue(),
                               suppress_log=True)
        assert len(rp.history) == 0
        rp.protocol.child_groups = {str(field.uuid): field}
        rp._restore_child_evidence({CfgIds.identity: queue.Queue(),  # noqa: SLF001
                                    CfgIds.negotiation: queue.Queue(),
                                    CfgIds.main: queue.Queue(),
                                    CfgIds.network: queue.Queue()})
    finally:
        if prior is None:
            del os.environ[Configuration.ROOT_VARIABLE_NAME]
        else:
            os.environ[Configuration.ROOT_VARIABLE_NAME] = prior
    child = rp._chain_for_group(str(field.uuid))  # noqa: SLF001
    assert len(child) == rp._checkpoints[str(field.uuid)].count  # noqa: SLF001
    assert child.latest_roster() is not None
    assert len(rp.history) == 0
    assert rp.reputations.current
    for uuid, score in rp.reputations.current.items():
        assert rp._trust_tier(score) >= SEED_TIER, \
            f"{str(uuid)[:8]} restored at {score:.4f}, below tier {SEED_TIER}"


# ------------------------------------------------- seeding the coordinator
# At 100 peers the coordinator's cold admission reached only one member, so a
# late joiner such as the MQ-800 never learned it and dropped every data
# subscribe it sent as undecryptable. --seed-coordinator makes it a seeded
# member from t=0; its capabilities are left for peers to learn at runtime.

def _small(scenario_factory):
    return scenario_factory(squad_size=2, swarm_size=2, sensor_count=2,
                            hacked_sensors=1, include_command=False)


def test_coordinator_not_seeded_by_default(tmp_path, scenario_factory):
    from tools.seed_dod_cohort import seed_cohort
    seeded = seed_cohort(tmp_path, _small(scenario_factory), force=True)
    assert "coordinator" not in seeded
    assert not (tmp_path / "coordinator").exists()


def test_seed_coordinator_writes_full_state(tmp_path, scenario_factory):
    from tools.seed_dod_cohort import seed_cohort
    seeded = seed_cohort(tmp_path, _small(scenario_factory), force=True,
                         seed_coordinator=True)
    assert "coordinator" in seeded
    d = tmp_path / "coordinator" / "etc" / "at"
    for fn in ("identity.cfg.json", "group.cfg.json", "peers.cfg.json",
               "reputation.cfg.json", "reputation-history.cfg.json",
               "peer-capabilities.cfg.json"):
        assert (d / fn).exists(), f"coordinator missing {fn}"


def test_seeded_peers_recognise_coordinator(tmp_path, scenario_factory):
    from tools.seed_dod_cohort import seed_cohort
    seeded = seed_cohort(tmp_path, _small(scenario_factory), force=True,
                         seed_coordinator=True)
    for peer in seeded:
        if peer == "coordinator":
            continue
        with (tmp_path / peer / "etc" / "at" / "peers.cfg.json").open() as f:
            peers = json.load(f, object_hook=config_json_decoder)
        assert "coordinator" in {p.petname for p in peers.all}, peer


def test_coordinator_capabilities_not_seeded(tmp_path, scenario_factory):
    from tools.seed_dod_cohort import seed_cohort
    seeded = seed_cohort(tmp_path, _small(scenario_factory), force=True,
                         seed_coordinator=True)
    coord_dir = tmp_path / "coordinator" / "etc" / "at"
    with (coord_dir / "identity.cfg.json").open() as f:
        coord_uuid = str(json.load(f, object_hook=config_json_decoder).uuid)
    for peer in seeded:
        if peer == "coordinator":
            continue
        with (tmp_path / peer / "etc" / "at" / "peer-capabilities.cfg.json").open() as f:
            pc = json.load(f, object_hook=config_json_decoder)
        listed = {str(u) for caps in pc._listing.values() for u in caps}
        assert coord_uuid not in listed, peer
