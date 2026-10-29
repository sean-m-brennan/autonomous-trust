# ******************
#  Copyright 2026 TekFive, Inc., Sean M. Brennan, and contributors
#  Licensed under the Apache License, Version 2.0
# ******************
"""Gateway republisher: carries a field cohort's readings up to the command
cohort.

A hierarchy gateway sits in both cohorts, and nobody in the command cohort can
reach a field producer, so the gateway subscribes to each field producer and
queues what arrives for its own data source, which the coordinator already
subscribes to. Each relayed reading keeps its producer's ``peer_name`` and
loses the batch ``task_id``: the producer's bilateral score pairs with ITS
subscriber (this gateway), and a coordinator scoring the gateway for a batch it
did not produce would pair with nothing. ``relayed_by`` names the gateway."""
import copy
import os
import sys
import time
from pathlib import Path
from queue import Empty, Full

from autonomous_trust.core import Process, ProcMeta, CfgIds, from_yaml_string
from autonomous_trust.core.network import Message
from autonomous_trust.services.data.server import DataProcess, DataProtocol

# Imported as examples.dod_mission.gateway_relay (tests) or by bare name from
# the participant script.
try:
    from .subscribe_policy import (
        pending_roster_subscriptions, resub_due, roster_name_of)
except ImportError:
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    from subscribe_policy import (  # noqa: E402
        pending_roster_subscriptions, resub_due, roster_name_of)

RELAY_FIELD_PEERS_ENV = "AT_GATEWAY_FIELD_PEERS"
# One subscribe back-off tick, in seconds (AT_DATA_RESUBSCRIBE_TICKS and
# _MAX_TICKS count these). The queue cadence is a few milliseconds, too short:
# at 96 nodes a gateway re-sent ~40,000 subscribes in a run.
RELAY_TICK_SEC = 1.0


def relay_readings(readings, gateway_name):
    """Copies of ``readings`` fit to republish: no ``task_id``, ``relayed_by``
    set, and none of the gateway's own (it already emits those itself)."""
    out = []
    for r in readings or []:
        if not isinstance(r, dict) or r.get("peer_name") == gateway_name:
            continue
        r = copy.deepcopy(r)
        meta = r.get("metadata")
        if not isinstance(meta, dict):
            meta = r["metadata"] = {}
        meta.pop("task_id", None)
        meta["relayed_by"] = gateway_name
        out.append(r)
    return out


def relay_tick(start, now, cadence):
    """Ticks of *cadence* seconds elapsed since *start*. The subscribe back-off
    counts these; counted per loop pass instead, a gateway busy relaying
    re-sent its subscribes many times a second."""
    return int((now - start) / cadence) if cadence > 0 else 0


def field_producers_from_env():
    """The field peers this gateway relays for, from AT_GATEWAY_FIELD_PEERS."""
    raw = os.environ.get(RELAY_FIELD_PEERS_ENV, "")
    return [n.strip() for n in raw.split(",") if n.strip()]


class GatewayRelay(Process, metaclass=ProcMeta, proc_name="gateway-relay",
                   description="Field-cohort data republisher"):
    def __init__(self, configurations, subsystems, log_queue, dependencies, **kwargs):
        self.relay_queue = kwargs.pop("relay_queue")
        self.field_producers = set(kwargs.pop("field_producers", ()) or ())
        super().__init__(configurations, subsystems, log_queue, dependencies=dependencies)
        self.protocol = DataProtocol(self.name, self.logger, configurations)
        self.protocol.register_handler(DataProtocol.data, self.handle_data)
        self.gateway_name = os.environ.get("AT_PEER_NAME", "")
        # Producers that have delivered at least once; the subscribe retry
        # stops for them, as the coordinator's does.
        self._received = set()
        self._schedule = {}
        self._started = None
        self._base = int(os.environ.get("AT_DATA_RESUBSCRIBE_TICKS", "6"))
        self._cap = max(self._base, int(
            os.environ.get("AT_DATA_RESUBSCRIBE_MAX_TICKS", "96")))
        self._relayed = 0

    def handle_data(self, _, message):
        if message.function != DataProtocol.data:
            return False
        self._received.add(str(getattr(message.from_whom, "uuid", "")))
        readings = []
        try:
            readings = relay_readings(from_yaml_string(message.obj), self.gateway_name)
            if readings:
                self.relay_queue.put(readings, block=True, timeout=self.q_cadence)
                if self._relayed == 0:
                    self.logger.info("Relaying field readings (first batch: %d from %s)",
                                     len(readings), readings[0].get("peer_name"))
                self._relayed += len(readings)
        except Full:
            self.logger.warning("Relay queue full; dropping %d reading(s)", len(readings))
        except Exception:
            self.logger.exception("Relay: undecodable data from %s",
                                  roster_name_of(message.from_whom) or "?")
        return True

    def process(self, queues, signal):
        self._started = time.monotonic()
        while self.keep_running(signal):
            tick = relay_tick(self._started, time.monotonic(), RELAY_TICK_SEC)
            for p in pending_roster_subscriptions(self.protocol.peers.all,
                                                  self._received, self.field_producers):
                uid = str(getattr(p, "uuid", ""))
                if not resub_due(self._schedule, uid, tick, self._base, self._cap):
                    continue
                queues[CfgIds.network].put(
                    Message(DataProcess.name, DataProtocol.request, self.name, p),
                    block=True, timeout=self.q_cadence)
                self.logger.debug("Relay: subscribed to field producer %s",
                                  roster_name_of(p) or uid)
            try:
                message = queues[self.name].get(block=True, timeout=self.q_cadence)
            except Empty:
                continue
            if not self.protocol.run_message_handlers(queues, message):
                self.logger.error("Unhandled message %s",
                                  getattr(message, "function", type(message).__name__))
