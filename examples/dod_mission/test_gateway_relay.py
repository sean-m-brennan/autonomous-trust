# ******************
#  Copyright 2026 TekFive, Inc., Sean M. Brennan, and contributors
#  Licensed under the Apache License, Version 2.0
# ******************
"""Gateway republisher: readings relayed from a field cohort to the command
cohort lose their batch task id, name the relaying gateway, and are never the
gateway's own."""
import queue

import pytest

from examples.dod_mission.gateway_relay import (
    field_producers_from_env, relay_readings)


def _r(peer, task="t1"):
    """A reading in its wire form, as DoDDataProcess ships it (Reading.to_dict:
    the producer is under "peer")."""
    from datetime import timedelta
    from autonomous_trust.services.data.reading import Reading
    return Reading(timestamp=timedelta(seconds=1), peer_name=peer,
                   data_type="target_position_x", value=1.0, unit="m",
                   metadata={"task_id": task}).to_dict()


def test_relay_strips_task_id_and_marks_relayer():
    out = relay_readings([_r("microdrone-7")], "rq86-1")
    assert "task_id" not in out[0]["metadata"]
    assert out[0]["metadata"]["relayed_by"] == "rq86-1"
    assert out[0]["peer"] == "microdrone-7"


def test_relay_does_not_echo_the_gateways_own_readings():
    assert relay_readings([_r("rq86-1")], "rq86-1") == []


def test_relay_does_not_mutate_the_input():
    src = [_r("microdrone-7")]
    relay_readings(src, "rq86-1")
    assert src[0]["metadata"]["task_id"] == "t1"


def test_relay_skips_non_dict_entries():
    assert relay_readings([None, "x", _r("mq800")], "rq86-1")[0]["peer"] == "mq800"


def test_field_producers_from_env(monkeypatch):
    monkeypatch.setenv("AT_GATEWAY_FIELD_PEERS", "mq800, microdrone-3,,sensor-1")
    assert field_producers_from_env() == ["mq800", "microdrone-3", "sensor-1"]
    monkeypatch.delenv("AT_GATEWAY_FIELD_PEERS")
    assert field_producers_from_env() == []


def test_data_process_drains_relayed_readings():
    participant = pytest.importorskip("examples.dod_mission.participant")
    q = queue.Queue()
    q.put(relay_readings([_r("microdrone-7")], "rq86-1"))
    proc = participant.DoDDataProcess.__new__(participant.DoDDataProcess)
    proc.relay_queue = q
    out = proc._drain_relay()
    assert [r["peer"] for r in out] == ["microdrone-7"]
    assert q.empty()


def test_data_process_emits_relayed_readings_without_a_bundle():
    """A gateway's relayed readings go out even when it produced none itself,
    and keep no task id (only the node's own batch is stamped)."""
    participant = pytest.importorskip("examples.dod_mission.participant")
    q = queue.Queue()
    q.put(relay_readings([_r("microdrone-7")], "rq86-1"))
    proc = participant.DoDDataProcess.__new__(participant.DoDDataProcess)
    proc.generators = None
    proc.relay_queue = q
    proc.clients = {}
    proc.active = True
    proc.t0_epoch = 0.0
    import logging
    proc.logger = logging.getLogger("test")
    out = proc.acquire()
    assert [r["peer"] for r in out] == ["microdrone-7"]
    assert "task_id" not in out[0]["metadata"]


def test_relay_ticks_follow_the_clock_not_the_loop():
    """The subscribe back-off counts ticks. Counted per loop pass, a gateway
    busy relaying ran thousands of passes a minute, and at 96 nodes it re-sent
    ~95,000 subscribes. A tick is one queue cadence of wall time."""
    from examples.dod_mission.gateway_relay import RELAY_TICK_SEC, relay_tick
    # A whole second: the queue cadence is a few milliseconds, so ticks of
    # that length re-sent subscribes nearly as fast as loop passes did.
    assert RELAY_TICK_SEC >= 1.0
    assert relay_tick(100.0, 100.0, 0.5) == 0
    assert relay_tick(100.0, 100.4, 0.5) == 0
    assert relay_tick(100.0, 103.0, 0.5) == 6


def test_relay_keeps_only_the_senders_own_readings():
    """A reading names its producer, and the gateway relays it under that name.
    A hacked field sensor could name squad-captain or a field peer it wanted to
    frame; the coordinator would attribute the reading to that peer."""
    out = relay_readings([_r("sensor-2"), _r("squad-captain"), _r("mq800")],
                         "rq86-1", producer="sensor-2")
    assert [r["peer"] for r in out] == ["sensor-2"]


def test_relay_ignores_data_from_a_sender_it_does_not_relay_for():
    from types import SimpleNamespace
    from examples.dod_mission.gateway_relay import GatewayRelay
    from autonomous_trust.services.data.server import DataProtocol
    relay = GatewayRelay.__new__(GatewayRelay)
    relay.field_producers = {"sensor-2"}
    relay.gateway_name = "rq86-1"
    relay.relay_queue = queue.Queue()
    relay.q_cadence = 0.01
    relay._received = set()
    relay._relayed = 0
    import logging
    relay.logger = logging.getLogger("test")
    from autonomous_trust.core import to_yaml_string
    def msg(nick):
        return SimpleNamespace(function=DataProtocol.data,
                               from_whom=SimpleNamespace(uuid="u-" + nick,
                                                         nickname=nick + "@x"),
                               obj=to_yaml_string([_r(nick)]))
    relay.handle_data(None, msg("stranger"))
    assert relay.relay_queue.empty()
    relay.handle_data(None, msg("sensor-2"))
    assert [r["peer"] for r in relay.relay_queue.get_nowait()] == ["sensor-2"]
