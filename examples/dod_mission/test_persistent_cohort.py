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
