# ******************
#  Copyright 2026 TekFive, Inc., Sean M. Brennan, and contributors
#  Licensed under the Apache License, Version 2.0
# ******************
"""DoD mission demo participant node.

Each peer in the DoD scenario (squad member, microdrone, RQ-86, MQ-800,
leave-behind sensor, fighter jet, command) runs as one instance of this
class.  The peer's role is looked up in `DoDMissionScenario`, and the
right generator bundle is bound based on `PeerRole.kind`:

  Role kind         Generator bundle              Notes
  ----------------  ----------------------------  -------------------------
  soldier           (none)                        consumer-only
  command-node      (none)                        consumer-only
  microdrone        MicrodroneGenerators          target position + motion + audio
  recon-drone       OverheadISRGenerators         honest cross-validated ISR
  armed-drone       OverheadISRGenerators*        wrapped by contradictory_isr
  ground-sensor     GroundSensorGenerators        honest *or* ForgedIdentitySensor
  fighter-jet       (minimal)                     joins late; ISR not yet wired

Env-var selectors:
  AT_PEER_NAME            Peer roster name (overrides argv[1])
  AT_AGENCY               Agency label (informational)
  AT_COMPROMISED          "true" → MQ-800 wraps its OverheadISRGenerators
                          with the contradictory_isr compromise
  AT_COMPROMISE_MODE      "abrupt" | "gradual"
  AT_FORGERY_MODE         "unsigned" | "self_signed" | "sybil" — when set,
                          this peer's ground-sensor bundle is wrapped in
                          ForgedIdentitySensor.  Pairs with AT_SYBIL_TARGET
                          for sybil mode.
  AT_SYBIL_TARGET         Peer name to impersonate (sybil only)
  AT_JOIN_DELAY_SEC       Sleep before joining; used for MQ-800 (~240s),
                          leave-behind sensors (~120s), jet (~360s) so
                          their join times line up with scenario phases.

The generator bundle is pushed through ``DoDDataProcess.acquire()``
each tick; the coordinator's autonomous_tasking drains the resulting
readings from ``cohort.peers[*].data_stream`` and feeds them into the
sensor-comparison charts + cross-source validators.

Usage:
    python participant.py <peer-name> [--setup] [--log-level debug]
"""

from __future__ import annotations

import logging
import os
import random
import sys
import time
from datetime import timedelta
from pathlib import Path
from typing import Optional

from queue import Full
from uuid import uuid4

from autonomous_trust.core import (
    AutonomousTrust, CfgIds, Configuration, LogLevel, Process, ProcMeta,
    to_yaml_string,
)
from autonomous_trust.core.config.generate import (
    generate_identity, generate_worker_config,
)
from autonomous_trust.core.network import Message
from autonomous_trust.core.reputation.reputation import TransactionScore
from autonomous_trust.core.system import queue_cadence
from autonomous_trust.services.data.server import (
    DataProcess, DataConfig, DataProtocol,
)
from autonomous_trust.services.network_statistics import NetStatsSource

try:
    from autonomous_trust.simulator.peer.peer_metadata import (
        SimMetadataSource, SimMetadata,
    )
    HAS_SIMULATOR = True
except ImportError:
    HAS_SIMULATOR = False

# Sibling modules (dashed package layout — same trick as coordinator.py)
_HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(_HERE))
from scenario import DoDMissionScenario  # noqa: E402

sys.path.insert(0, str(_HERE / "generators"))
from isr import OverheadISRGenerators, MicrodroneGenerators  # noqa: E402
from ground_sensor import GroundSensorGenerators  # noqa: E402
from detection import (  # noqa: E402
    build_detection_source, DETECTION_VIEW_CENTER_OVERRIDE,
)

sys.path.insert(0, str(_HERE / "compromise"))
from contradictory_isr import (  # noqa: E402
    create_compromised_mq800_position_x,
    create_compromised_mq800_position_y,
    create_compromised_mq800_electronic_noise,
    wrap_detection_source_with_compromise,
    DEFAULT_ACTIVATE_AT,
)
from forged_identity import create_forged_identity_sensor  # noqa: E402


class _DetectionAugmentedBundle:
    """Wraps an existing generator bundle with a sibling DetectionSource.

    Implements the same ``tick(t) -> list[Reading]`` interface so
    DoDDataProcess.acquire() doesn't care which bundle it's running.
    Exposes the wrapped bundle's attributes for code that mutates
    ``bundle.target_x`` / ``bundle.electronic_noise`` etc. (see the
    contradictory_isr compromise).
    """

    def __init__(self, bundle, detection_source):
        self._bundle = bundle
        self._detection_source = detection_source

    def __getattr__(self, name):
        # Unpickle-safe delegation. When multiprocessing rehydrates this
        # object in a worker, __new__ runs without __init__ — `_bundle`
        # isn't in __dict__ yet, and a bare `getattr(self._bundle, name)`
        # would re-enter __getattr__ infinitely. Read via __dict__.get
        # so the unpickled-but-not-yet-populated state raises a clean
        # AttributeError that pickle handles.
        bundle = self.__dict__.get('_bundle')
        if bundle is None:
            raise AttributeError(name)
        return getattr(bundle, name)

    def tick(self, t):
        out = list(self._bundle.tick(t) or [])
        ds_out = self._detection_source.tick(t)
        if ds_out:
            out.extend(ds_out)
        return out

logger = logging.getLogger(__name__)


def _ts_keep(batch_id: str, denom: int) -> bool:
    """Deterministic per-batch decimation for TS submission.

    Both the sender (here) and the coordinator
    (DoDMissionCoordinator._maybe_submit_batch_scores) call this
    with the same batch_id and AT_TS_DECIMATION, so they always
    agree on which batches produce a TS.  This preserves the
    bilateral pairing that Transaction.add / TransactionHistory.update
    (reputation.py:209) requires before a Transaction is appended
    to the chain — without agreement, every Transaction would stay
    at len==1 and CTFT would never score anything.
    """
    if denom <= 1:
        return True
    # UUID4 is random; the first 8 hex chars are enough entropy for
    # uniform mod-denom selection without a hash function.
    return int(batch_id.replace('-', '')[:8], 16) % denom == 0


class DoDDataProcess(DataProcess, metaclass=ProcMeta,
                     proc_name='data-source',
                     description='DoD ISR / sensor data source'):
    """DataProcess subclass that drains a generator bundle each tick.

    The bare DataProcess is a generic stub: its ``acquire()`` warns
    "not implemented" and returns ``[None, None, None]``.  Here we
    override it to call ``self.generators.tick(t)`` and ship the
    resulting Readings to subscribers as a list of dicts (YAML-
    serialized over the wire by the base class).

    ``t`` is computed against ``self.t0_epoch`` so every peer's
    timestamps share a common origin -- the launcher exports
    ``AT_DEMO_T0_EPOCH`` (unix seconds at launch) and
    generate_compose plumbs it through ``common_env``, so the
    sensor charts on the coordinator can line up consensus across
    peers that joined at different real times.
    """

    def __init__(self, configurations, subsystems, log_queue,
                 dependencies, **kwargs):
        super().__init__(configurations, subsystems, log_queue,
                         dependencies)
        self.generators = kwargs.get('generators')
        self.t0_epoch = float(kwargs.get('t0_epoch') or time.time())
        # DataProcess.__init__ sets ``self.active`` from
        # ``self.name in configurations`` — i.e. only when a DataConfig
        # has been written.  Our generators don't need a DataConfig
        # (the bundle replaces the device_path/frame_size knobs), so
        # force-enable when there's a bundle attached.  Without this,
        # the parent process() loop skips acquire() and the data
        # stream is silent.
        if self.generators is not None:
            self.active = True

    _logged_first_acquire = False
    _logged_first_emit = False
    _logged_first_tx_submit = False
    _last_batch_id: Optional[str] = None

    def acquire(self):
        if self.generators is None:
            if not DoDDataProcess._logged_first_acquire:
                self.logger.info(
                    "DoDDataProcess.acquire: no generator bundle attached "
                    "(role has no continuous data source)")
                DoDDataProcess._logged_first_acquire = True
            return None
        t = timedelta(seconds=time.time() - self.t0_epoch)
        readings = self.generators.tick(t)
        if not DoDDataProcess._logged_first_acquire:
            self.logger.info(
                "DoDDataProcess.acquire: first call returned %d readings "
                "(t=%.1fs, active=%s, clients=%d)",
                len(readings or []), t.total_seconds(),
                self.active, len(self.clients))
            DoDDataProcess._logged_first_acquire = True
        if not readings:
            return None
        if not DoDDataProcess._logged_first_emit and self.clients:
            self.logger.info(
                "DoDDataProcess: emitting first batch of %d readings to "
                "%d subscriber(s)", len(readings), len(self.clients))
            DoDDataProcess._logged_first_emit = True
        # Stamp every reading in this tick with the same task_id so
        # the coordinator can identify which deliveries belong to the
        # same paxos round.  Both sides (sender here + coordinator)
        # submit a TransactionScore for batches selected by _ts_keep;
        # paired submissions form the bilateral Transaction that
        # CTFT scores against (reputation.py:209).
        batch_id = str(uuid4())
        emitted: list[dict] = []
        for r in readings:
            d = r.to_dict()
            meta = d.setdefault("metadata", {})
            meta["task_id"] = batch_id
            emitted.append(d)
        # Stash the task_id for process() to pick up after the
        # parent's broadcast loop runs.
        self._last_batch_id = batch_id
        return emitted

    def process(self, queues, signal):
        """Override the parent loop so we can submit a
        TransactionScore after each successful broadcast (subject
        to deterministic per-batch decimation, see _ts_keep) and
        log unhandled messages explicitly (the base
        DataProcess.process silently drops them).
        """
        from queue import Empty as _Empty
        while self.keep_running(signal):
            # mirror DataProcess.process_messages
            try:
                message = queues[self.name].get(
                    block=True, timeout=self.q_cadence)
            except _Empty:
                message = None
            if message:
                if not self.protocol.run_message_handlers(queues, message):
                    self.logger.error(
                        "Unhandled message %r",
                        getattr(message, "function", type(message).__name__))

            if self.active:
                data = self.acquire()
                if data is not None and self.clients:
                    msg_obj = to_yaml_string(data)
                    for client_id, (proc_name, peer) in self.clients.items():
                        msg = Message(proc_name, DataProtocol.data,
                                      msg_obj, peer)
                        try:
                            queues[CfgIds.network].put(
                                msg, block=True, timeout=self.q_cadence)
                        except Full:
                            self.logger.warning(
                                "Network queue full; dropping data for %s",
                                client_id)
                    batch_id = self._last_batch_id
                    self._last_batch_id = None
                    denom = int(os.environ.get("AT_TS_DECIMATION", "30"))
                    if (batch_id is not None and self.clients
                            and _ts_keep(batch_id, denom)):
                        # Sender's "I delivered" score for this
                        # batch.  Pinned to 0.9; pairs with the
                        # coordinator's verdict TS (0.8 clean / 0.3
                        # anomalous) on the same task_id to form
                        # the bilateral Transaction CTFT scores.
                        # Tagged with dod.sensor-report so the
                        # weighting math applies on both sides (see
                        # examples/dod_mission/trust_ladder.yaml).
                        ts = TransactionScore(task_id=batch_id, score=0.9,
                                              capability_name="dod.sensor-report")
                        try:
                            queues[CfgIds.reputation].put(
                                ts, block=True, timeout=self.q_cadence)
                            if not DoDDataProcess._logged_first_tx_submit:
                                self.logger.info(
                                    "DoDDataProcess: first "
                                    "TransactionScore submitted "
                                    "(batch=%s, score=0.9, denom=%d)",
                                    batch_id, denom)
                                DoDDataProcess._logged_first_tx_submit = True
                        except Full:
                            self.logger.warning(
                                "Reputation queue full; dropping "
                                "TransactionScore for batch %s",
                                batch_id)
            self.sleep_until(self.cadence)


class DoDMissionParticipant(AutonomousTrust):
    """A peer in the DoD squad infiltration scenario.

    Looks up its own role in the scenario, selects the appropriate
    generator bundle, and registers the standard AT workers
    (network stats, simulator metadata, data service).
    """

    def __init__(self, peer_name: str, scenario: DoDMissionScenario,
                 compromised: bool = False,
                 compromise_mode: str = "abrupt",
                 forgery_mode: Optional[str] = None,
                 sybil_target: Optional[str] = None,
                 **kwargs):
        self.peer_name = peer_name
        self.scenario = scenario
        self.role = scenario.peers.get(peer_name)
        if self.role is None:
            raise ValueError(
                f"Peer {peer_name!r} not defined in scenario {scenario.name!r}"
            )
        self.compromised = compromised
        self.compromise_mode = compromise_mode
        self.forgery_mode = forgery_mode
        self.sybil_target = sybil_target

        # silent=False so participant logs reach stdout / docker logs
        # (matches the coordinator).  Otherwise diagnostics are buried
        # in the per-container rotating logfile under /var/at/.
        super().__init__(silent=False, **kwargs)

        # Standard workers.
        self.add_worker(NetStatsSource)
        # SimMetadataSource intentionally NOT registered.  Its parent
        # MetadataSource.__init__ unconditionally reads
        # ``configurations['metadata-source']`` (see
        # services/peer/metadata.py:129), which would KeyError every
        # peer at startup unless we ran a separate setup pass to
        # pre-populate the config file.  SimMetadata.initialize() also
        # has non-default fields (type_of_peer, sim_host) so
        # generate_worker_config(..., defaults=True) can't write it
        # non-interactively.  The simulator integration drives
        # position/time updates; without it peers sit at their
        # scenario.py-defined coords forever, which is fine for the
        # data-stream/divergence demo — the ISR generators don't read
        # simulator state, they use the role's initial coords passed
        # in via sensor_xy.  Re-enable when a position-driven map
        # update is back on the critical path; will need to write a
        # SimMetadata config explicitly (not via setup_mode prompts).

        # Role-driven generator bundle.  Built before the DataProcess
        # worker is registered so the bundle can be passed in as a
        # kwarg -- DoDDataProcess.acquire() drains it each tick.  Peers
        # with no role-specific data source (soldier, command-node,
        # fighter-jet) still get a DataProcess so the service is
        # available, but with no bundle attached it just no-ops.
        # Shared epoch for cross-peer timestamp alignment in the
        # sensor-comparison charts.  See DoDDataProcess docstring. Computed
        # before _build_generators so the detection pose-provider closure
        # (_detection_pose_provider) can replay this peer's scenario path on
        # the same clock the emitted readings are stamped against.
        self._t0_epoch = float(os.environ.get("AT_DEMO_T0_EPOCH")
                               or time.time())

        self.generators = self._build_generators()

        self.add_worker(DoDDataProcess,
                        generators=self.generators,
                        t0_epoch=self._t0_epoch)

        logger.info("Participant %s initialized: role=%s, generators=%s, "
                    "compromised=%s, forgery_mode=%s",
                    peer_name, self.role.kind,
                    type(self.generators).__name__ if self.generators else "none",
                    compromised, forgery_mode)

    def _detection_pose_provider(self, kind, roster_latlon):
        """Return a callable ``() -> (lat, lon) | None`` yielding this peer's
        live pose each tick, or ``None`` to keep the stationary roster pose.

        Resolution order:

        1. An explicit ``self._pose_provider`` (e.g. a real simulator feed set
           on the instance) always wins.
        2. **Microdrones** get live motion *on by default*: a closure that
           replays this peer's own deterministic scenario path locally — no
           simulator dependency — so its ~350 m forward FOV sweeps onto the
           target compound as it advances from the insertion LZ to the
           objective (T+1:00..T+7:00). The pose is read from this
           participant's own ``scenario`` instance (built from the same roster
           knobs the coordinator uses), driven by ``self._t0_epoch`` — the
           shared demo clock the emitted readings are also stamped against, so
           visibility timing lines up with the rest of the timeline. Opt out
           with ``AT_DETECTION_LIVE_MOTION=0`` to restore the stationary v1.
        3. Every other role keeps the stationary roster pose (``None``); the
           RQ-86s orbit overhead (bearing-irrelevant) and the MQ-800 uses its
           DETECTION_VIEW_CENTER_OVERRIDE.
        """
        explicit = getattr(self, "_pose_provider", None)
        if explicit is not None:
            return explicit
        if kind != "microdrone":
            return None
        if os.environ.get("AT_DETECTION_LIVE_MOTION", "1") == "0":
            return None

        scenario = self.scenario
        peer_name = self.peer_name
        epoch = self._t0_epoch

        def _pose():
            # Replay the scenario movement model to this peer's live position.
            # _update_positions is pure movement (no phase-event side effects),
            # mutating scenario.peers[*].position in place; we read our own.
            try:
                t = timedelta(seconds=time.time() - epoch)
                scenario._update_positions(t)
                role = scenario.peers.get(peer_name)
                pos = getattr(role, "position", None)
                if pos is None:
                    return None
                return (pos.lat, pos.lon)
            except Exception:  # a flaky pose source must not crash the sensor
                logger.debug("detection pose provider failed for %s",
                             peer_name, exc_info=True)
                return None

        return _pose

    def _maybe_add_detection(self, bundle, kind, roster_latlon):
        """Attach a DetectionSource alongside a drone-role bundle.

        Silently returns the bare bundle if the catalogue file is
        missing (the demo runs even before tools/detection_prep.py
        has been executed). Compromised MQ-800 peers get the
        DetectionSource wrapped by the contradictory-ISR UID swap
        so the inspector panel shows the wrong building while the
        cross-source validator catches the position lie inside
        compound-alpha's bucket.
        """
        view_override = DETECTION_VIEW_CENTER_OVERRIDE.get(self.peer_name)
        # Arrival gate: a late joiner (the MQ-800 at join_phase 4 / T+4:00)
        # must not emit — or be cross-validated — before it is on the network.
        # Derive the threshold from the peer's join-phase start, mirroring
        # scenario.peer_arrived; pre-established emitters (join_phase 0) get
        # 0.0 and are unaffected.
        arrival_sec = 0.0
        jp = getattr(self.role, "join_phase", 0)
        phases = getattr(self.scenario, "_phases", None)
        if jp and phases and 0 <= jp < len(phases):
            arrival_sec = phases[jp].start.total_seconds()
        ds = build_detection_source(
            peer_name=self.peer_name,
            role=kind,
            roster_latlon=roster_latlon,
            view_center_override_latlon=view_override,
            active_after_sec=arrival_sec,
            pose_provider=self._detection_pose_provider(kind, roster_latlon),
        )
        if ds is None:
            return bundle
        if kind == "armed-drone" and self.compromised:
            ds = wrap_detection_source_with_compromise(
                ds, mode=self.compromise_mode)
            logger.info(
                "Wrapping %s detection source with CompromisedDetectionSource "
                "(mode=%s, visible=%s)",
                self.peer_name, self.compromise_mode, ds.visible_uids)
        else:
            logger.info(
                "DetectionSource for %s (%s): visible UIDs %s",
                self.peer_name, kind, ds.visible_uids)
        return _DetectionAugmentedBundle(bundle, ds)

    def _build_generators(self):
        """Pick the right generator bundle for this peer's role."""
        kind = self.role.kind
        # Microdrones / overhead ISR need a position to compute bearings
        # against.  Use the peer's roster position as a stand-in (the
        # simulator-side movement will overwrite it at runtime).
        sensor_xy = (self.role.position.lat, self.role.position.lon)

        if kind == "microdrone":
            return self._maybe_add_detection(
                MicrodroneGenerators(self.peer_name, sensor_xy), kind, sensor_xy)

        if kind == "recon-drone":
            return self._maybe_add_detection(
                OverheadISRGenerators(self.peer_name, sensor_xy), kind, sensor_xy)

        if kind == "armed-drone":
            # MQ-800: honest ISR generators, optionally wrapped by the
            # contradictory_isr compromise after activation.
            bundle = OverheadISRGenerators(self.peer_name, sensor_xy)
            if self.compromised:
                logger.info("Wrapping %s in contradictory_isr (mode=%s)",
                            self.peer_name, self.compromise_mode)
                # Replace each honest position / noise generator with its
                # compromised counterpart.  Bearing remains honest — even
                # a hostile platform cannot easily lie about its own
                # position-relative geometry without breaking the math.
                bundle.target_x = create_compromised_mq800_position_x(
                    peer_name=self.peer_name,
                    mode=self.compromise_mode,
                )
                bundle.target_y = create_compromised_mq800_position_y(
                    peer_name=self.peer_name,
                    mode=self.compromise_mode,
                )
                bundle.electronic_noise = create_compromised_mq800_electronic_noise(
                    peer_name=self.peer_name,
                    mode=self.compromise_mode,
                )
                bundle._generators = [
                    bundle.target_x, bundle.target_y,
                    bundle.bearing, bundle.electronic_noise,
                ]
            return self._maybe_add_detection(bundle, kind, sensor_xy)

        if kind == "ground-sensor":
            if self.forgery_mode:
                # ForgedIdentitySensor wraps a GroundSensorGenerators
                # bundle and adds the identity-layer attack marker.
                return create_forged_identity_sensor(
                    peer_name=self.peer_name,
                    forgery_mode=self.forgery_mode,
                    sybil_target=self.sybil_target,
                )
            return GroundSensorGenerators(self.peer_name)

        # soldier, command-node, fighter-jet: consumer-only or
        # event-driven; no continuous data sources yet.
        return None

    def autonomous_ability(self, queues):
        """Advertise this peer's data capability.

        ``self.capabilities`` is set on the AutonomousTrust instance but
        idprocess + DataRcvr live in worker subprocesses and only learn
        what they need via the queue.  Mirror the framework's testing-
        mode broadcast: register the ability, then put the
        ``Capabilities`` object onto every worker queue so
        ``Protocol.run_message_handlers`` updates their snapshots.
        Until this fires, the coordinator's DataRcvr never sees any
        peer advertise ``data`` and never subscribes — the per-peer
        ``data_stream`` queues stay empty and the sensor charts
        render blank.
        """
        if self.generators is not None:
            self.capabilities.register_ability(
                DataProcess.capability_name, None)
        # Register DoD trust-ladder caps so peer_capabilities advertised
        # to the cohort carries the right tier/weight metadata, and so
        # this participant's local reputation process finds the weights
        # when scoring TSs. Metadata-only (function=None); the actual
        # data flow still goes through DataProcess.
        # `participant.py` is invoked as a script (not a module), so we
        # use a bare-name import after sys.path.insert(_HERE) above —
        # same pattern as `from scenario import ...`.
        from trust_ladder import register_trust_ladder  # local import
        self._trust_ladder = register_trust_ladder(self.capabilities)
        logger.info(
            "autonomous_ability: peer=%s capabilities=%s — "
            "broadcasting to %d worker queue(s)",
            self.peer_name, self.capabilities.to_list(),
            len([q for q in queues if q != self.proc_name]))
        for q_name in queues:
            if q_name == self.proc_name:
                continue
            try:
                queues[q_name].put(self.capabilities,
                                   block=True, timeout=queue_cadence)
            except Exception:
                logger.warning("Failed to publish capabilities to %s",
                               q_name)

    def autonomous_tasking(self, queues):
        """Called each AT tick.  Data emission lives in DoDDataProcess
        (its own worker loop), so this hook stays a no-op for now."""
        pass


def _attach_zta_credential(cfg_dir: str) -> None:
    """Bind a provisioned ZTA credential to this peer's identity.

    ``tools/provision_zta_certs.py`` writes ``zta_credential.der`` into each
    peer's config dir — a mission-CA-signed cert for legitimate peers, or a
    rogue/absent credential for the hacked leave-behind sensors. Loading it
    onto the identity here means the peer's announce carries it, so the
    welcoming committee's ZTA gate (idprocess.welcoming_committee) verifies it
    at admission against the receiver's ``zta_policy`` — rejecting the forged
    sensors at the identity layer instead of merely flooring them on the
    dashboard. No-op when no credential file is present (ZTA-disabled runs).
    """
    cred_file = Path(cfg_dir) / "zta_credential.der"
    if not cred_file.is_file():
        return
    from autonomous_trust.core.identity import Identity  # local: heavy import
    id_file = Path(cfg_dir) / ("identity" + Identity.file_ext)
    if not id_file.is_file():
        return
    try:
        ident = Identity.from_file(str(id_file))
        ident.zta_credential = cred_file.read_bytes()
        ident.to_file(str(id_file))
        logger.info("Attached ZTA credential (%d bytes) to identity in %s",
                    len(ident.zta_credential), cfg_dir)
    except Exception:
        logger.warning("Failed to attach ZTA credential from %s", cred_file,
                       exc_info=True)


def _env_flag(name: str, default: bool = False) -> bool:
    raw = os.environ.get(name)
    if raw is None:
        return default
    return raw.strip().lower() in ("1", "true", "yes", "on")


def main():
    # See coordinator.py:main() for the rationale — AT only handler-binds
    # its own framework logger, so this module's `logger.info(...)` is
    # otherwise dropped by Python's lastResort handler.
    logging.basicConfig(
        level=logging.INFO,
        stream=sys.stderr,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )

    if len(sys.argv) < 2 and "AT_PEER_NAME" not in os.environ:
        print(f"Usage: {sys.argv[0]} <peer-name> [--setup] [--log-level LEVEL]")
        sys.exit(1)

    peer_name = os.environ.get("AT_PEER_NAME") or sys.argv[1]
    agency = os.environ.get("AT_AGENCY", "")
    setup_mode = "--setup" in sys.argv
    log_level = LogLevel.DEBUG
    for i, arg in enumerate(sys.argv):
        if arg == "--log-level" and i + 1 < len(sys.argv):
            log_level = LogLevel[sys.argv[i + 1].upper()]

    compromised = _env_flag("AT_COMPROMISED", default=False)
    compromise_mode = os.environ.get("AT_COMPROMISE_MODE", "abrupt")
    forgery_mode = os.environ.get("AT_FORGERY_MODE")  # None if not hacked
    sybil_target = os.environ.get("AT_SYBIL_TARGET")

    # Per-peer root directory.  AT derives etc/at + var/at from
    # AUTONOMOUS_TRUST_ROOT; mirror the mission/coordinator.py pattern.
    root_dir = os.environ.get(Configuration.ROOT_VARIABLE_NAME,
                              str(Path(__file__).parent / peer_name))
    os.environ[Configuration.ROOT_VARIABLE_NAME] = root_dir
    cfg_dir = Configuration.get_cfg_dir()
    dat_dir = Configuration.get_data_dir()
    os.makedirs(cfg_dir, exist_ok=True)
    os.makedirs(dat_dir, exist_ok=True)

    generate_identity(cfg_dir, preserve=True, defaults=True)
    _attach_zta_credential(cfg_dir)

    # Build the scenario from the same env-var knobs the coordinator uses,
    # so all peers agree on the peer roster (squad_size, swarm_size, ...).
    scenario = DoDMissionScenario(
        squad_size=int(os.environ.get("AT_SQUAD_SIZE", "4")),
        swarm_size=int(os.environ.get("AT_SWARM_SIZE", "4")),
        sensor_count=int(os.environ.get("AT_SENSOR_COUNT", "3")),
        hacked_sensors=int(os.environ.get("AT_HACKED_SENSORS", "2")),
        include_mq800=os.environ.get("AT_INCLUDE_MQ800", "1") != "0",
        include_jet=os.environ.get("AT_INCLUDE_JET", "1") != "0",
        include_command=os.environ.get("AT_INCLUDE_COMMAND", "1") != "0",
    )

    if setup_mode:
        # Signature: generate_worker_config(cfg_dir, proc_name, cfg_class, defaults).
        generate_worker_config(cfg_dir, DataProcess.name, DataConfig, True)
        if HAS_SIMULATOR:
            generate_worker_config(cfg_dir, SimMetadataSource.name, SimMetadata, True)
        print(f"Setup complete for {peer_name} ({agency or 'no-agency'})")
        return

    # Stagger startup — either explicitly via AT_JOIN_DELAY_SEC, or a
    # random 1-5s jitter to avoid thundering-herd identity exchanges.
    delay = int(os.environ.get("AT_JOIN_DELAY_SEC", "0"))
    if delay > 0:
        logger.info("Delaying startup by %ds (AT_JOIN_DELAY_SEC)", delay)
        time.sleep(delay)
    else:
        time.sleep(random.uniform(1.0, 5.0))

    logger.info("Starting DoD participant: %s (%s)", peer_name, agency)
    participant = DoDMissionParticipant(
        peer_name=peer_name,
        scenario=scenario,
        compromised=compromised,
        compromise_mode=compromise_mode,
        forgery_mode=forgery_mode,
        sybil_target=sybil_target,
        log_level=log_level,
    )
    participant.run_forever()


if __name__ == "__main__":
    # Default to forkserver: 'fork' (Linux default through 3.13) forks a
    # multi-threaded process and can deadlock the child. Harmless on 3.14+.
    import multiprocessing as _mp
    _mp.set_start_method('forkserver', force=True)
    main()
