from examples.dod_mission.scenario import DoDMissionScenario
from examples.dod_mission.deploy.hierarchy import (
    COMMAND_NETWORK, field_network, plan_layout)


def _sc(swarm=83, rq86=3):
    return DoDMissionScenario(squad_size=4, swarm_size=swarm, sensor_count=3,
                              hacked_sensors=2, rq86_count=rq86)


def test_96_peers_split_into_three_cohorts_of_at_most_32():
    sc = _sc()
    assert len(sc.peers) == 96
    lay = plan_layout(sc, max_cohort=32)
    assert len(lay.cohorts) == 3
    for c in lay.cohorts:
        assert len(c.members) + 1 <= 32          # members plus gateway
    assert sorted(lay.command) == sorted(
        ['squad-captain', 'squad-intel', 'squad-ops', 'squad-warrant',
         'jet-1', 'command', 'rq86-1', 'rq86-2', 'rq86-3'])


def test_every_field_peer_is_in_exactly_one_cohort():
    sc = _sc()
    lay = plan_layout(sc)
    field = [p for c in lay.cohorts for p in c.members]
    assert len(field) == len(set(field))
    assert set(field) | set(lay.command) == set(sc.peers)
    assert 'mq800' in lay.cohorts[0].members


def test_gateway_is_dual_homed_and_others_single_homed():
    lay = plan_layout(_sc())
    gw = lay.cohorts[1].gateway
    assert set(lay.addresses[gw]) == {COMMAND_NETWORK, field_network(2)}
    assert lay.ip(gw, field_network(2)).startswith('172.30.2.')
    assert lay.ip(gw, COMMAND_NETWORK).startswith('172.30.0.')
    member = lay.cohorts[1].members[0]
    assert set(lay.addresses[member]) == {field_network(2)}


def test_addresses_are_unique_per_network():
    lay = plan_layout(_sc())
    seen = {}
    for peer, nets in lay.addresses.items():
        for net, ip in nets.items():
            assert (net, ip) not in seen, (peer, seen.get((net, ip)))
            seen[(net, ip)] = peer


def test_each_cohort_has_a_python_anchor_microdrone():
    lay = plan_layout(_sc())
    for c in lay.cohorts:
        assert c.anchor.startswith('microdrone-') and c.anchor in c.members
        assert c.anchor not in lay.c_microdrones()
    assert len(lay.c_microdrones()) == 83 - 3


def test_48_peer_validation_point():
    lay = plan_layout(_sc(swarm=35))
    assert len(lay.cohorts) == 3
    assert all(len(c.members) + 1 <= 32 for c in lay.cohorts)


# --- compose generator, hierarchical mode ---------------------------------
import pytest
from examples.dod_mission.deploy import generate_compose as gc


@pytest.fixture
def hier(monkeypatch):
    monkeypatch.setenv("AT_COHORT_SIZE", "32")
    monkeypatch.setenv("AT_C_MICRODRONES", "all")
    return gc.build_compose(scenario_kwargs=dict(
        squad_size=4, swarm_size=83, sensor_count=3, hacked_sensors=2,
        rq86_count=3))


def test_compose_has_command_and_three_field_networks(hier):
    assert set(hier["networks"]) >= {"dod-net", "dod-field-1",
                                     "dod-field-2", "dod-field-3"}
    assert hier["networks"]["dod-field-2"]["ipam"]["config"][0]["subnet"] \
        == "172.30.2.0/24"


def test_gateway_service_is_dual_homed_with_hybrid_transport(hier):
    gw = hier["services"]["rq86-2"]
    assert set(gw["networks"]) == {"dod-net", "dod-field-2"}
    assert gw["networks"]["dod-field-2"]["ipv4_address"] == "172.30.2.10"
    env = gw["environment"]
    assert env["AT_TRANSPORT"].endswith("hybrid.HybridNetworkProcess")
    assert env["AT_BORDER_GUARD"] == "0"
    assert "mq800" not in env["AT_GATEWAY_FIELD_PEERS"].split(",")


def test_field_peer_only_on_its_field_network(hier):
    svc = hier["services"]["mq800"]
    assert set(svc["networks"]) == {"dod-field-1"}


def test_anchor_runs_python_and_others_run_c(hier):
    lay = plan_layout(_sc())
    anchor = lay.cohorts[0].anchor
    assert hier["services"][anchor]["image"] != gc.C_IMAGE
    other = lay.c_microdrones()[0]
    assert hier["services"][other]["image"] == gc.C_IMAGE


def test_flat_mode_unchanged(monkeypatch):
    monkeypatch.delenv("AT_COHORT_SIZE", raising=False)
    c = gc.build_compose(scenario_kwargs=dict(squad_size=4, swarm_size=4,
                                              sensor_count=3, hacked_sensors=2))
    assert list(c["networks"]) == ["dod-net"]


# --- every process builds the same scenario --------------------------------
def test_scenario_from_env_reads_gateway_count(monkeypatch):
    from examples.dod_mission.scenario import scenario_from_env
    monkeypatch.setenv("AT_RQ86_COUNT", "3")
    monkeypatch.setenv("AT_SWARM_SIZE", "35")
    sc = scenario_from_env()
    assert sum(1 for p in sc.peers if p.startswith("rq86-")) == 3


def test_compose_env_rebuilds_the_compose_scenario(hier, monkeypatch):
    """The environment the generator hands every container rebuilds the very
    roster the generator laid out."""
    from examples.dod_mission.scenario import scenario_from_env
    env = hier["services"]["rq86-1"]["environment"]
    for k, v in env.items():
        if k.startswith("AT_"):
            monkeypatch.setenv(k, v)
    assert len(scenario_from_env().peers) == 96


def test_field_joiners_wait_for_their_cohort_and_seeded_nodes_do_not(hier):
    """A field joiner has no group of its own to fall back on and its cohort's
    admitter can come up minutes after it, so it keeps asking (patience); a
    node seeded with its group loads it at once, and an anchor that waited
    would hold up every admission in its cohort."""
    lay = plan_layout(_sc())
    c = lay.cohorts[0]
    joiners = [m for m in c.members if m != c.anchor]
    for name in joiners:
        assert float(hier["services"][name]["environment"]["AT_JOIN_PATIENCE_SEC"]) > 0, name
    for name in [c.anchor, c.gateway, "squad-captain", "command"]:
        assert "AT_JOIN_PATIENCE_SEC" not in hier["services"][name]["environment"], name
