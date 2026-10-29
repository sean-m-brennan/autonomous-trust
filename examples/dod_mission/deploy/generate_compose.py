#!/usr/bin/env python3
# ******************
#  Copyright 2025 Sean M. Brennan and contributors
#  Licensed under the Apache License, Version 2.0
# ******************
"""Generate docker-compose.yml for the DoD mission demo.

This is the DoD analogue of examples/multi_agency/deploy/docker-compose.yml,
which is hand-written.  We generate ours because the peer count is
parameterized — 16-peer baseline up through ~100-peer scale tests.

Per-role wiring (driven by `PeerRole.kind` and `metadata` flags from
scenario.py):

  Role kind         Env vars set on the container
  ----------------  ------------------------------------------------
  soldier           AT_AGENCY (informational)
  command-node      AT_AGENCY
  microdrone        AT_AGENCY
  recon-drone       AT_AGENCY
  armed-drone       AT_AGENCY, AT_COMPROMISED=true, AT_COMPROMISE_MODE
                    AT_JOIN_DELAY_SEC=240 (Phase 4 = T+4:00)
  ground-sensor     AT_AGENCY, AT_JOIN_DELAY_SEC=120 (Phase 2 = T+2:00),
                    (hacked only) AT_FORGERY_MODE=self_signed
  fighter-jet       AT_AGENCY, AT_JOIN_DELAY_SEC=360 (Phase 6 = T+6:00)

The scenario knobs (AT_SQUAD_SIZE, AT_SWARM_SIZE, etc.) are written
into every service so coordinator + participants agree on the roster.

Usage (module form, mirrors generate_k8s and multi-agency's
``disaster_response_compose``)::

    python -m examples.dod_mission.deploy.generate_compose                       # baseline
    python -m examples.dod_mission.deploy.generate_compose --swarm-size 24 \\
                                                           --sensor-count 20 \\
                                                           --hacked-sensors 8   # ~60-peer scale test

Requires the repo root on ``PYTHONPATH`` so ``examples`` resolves (the
Tiltfile and run-demo script set this up automatically). Cannot be
launched as a script (``python generate_compose.py``) — that breaks
the relative ``from ..scenario import`` below.
"""

from __future__ import annotations

import argparse
import os
import time
from pathlib import Path
from typing import Optional

from ..scenario import DoDMissionScenario  # noqa: E402
from .hierarchy import (COMMAND_NETWORK, cohort_size_from_env,  # noqa: E402
                        field_network, field_subnet, plan_layout)

_HERE = Path(__file__).resolve().parent

DEMO_IMAGE = "at-dod-mission-demo"
# C at_demo image for microdrones running the native node (Stretch Goal 3,
# Path B). Built from src/autonomous-trust/Dockerfile-c (which now ships the
# data-source service + --ingest-readings). Override via AT_C_IMAGE.
C_IMAGE = os.environ.get("AT_C_IMAGE", "autonomous-trust-c")
NETWORK_NAME = "dod-net"
# Per-container memory cap (compose mem_limit, e.g. "2g"); unset means no cap.
# Scale runs set it so one runaway peer is OOM-killed inside its container
# instead of starving the host.
MEM_LIMIT = os.environ.get("AT_COMPOSE_MEM_LIMIT", "")
# Peer log level (default debug) and the peers that keep debug regardless, as
# a comma list. Large runs lower the default because ~200 containers logging
# at debug saturate a spinning disk; the coordinator always logs at debug.
PEER_LOG_LEVEL = os.environ.get("AT_COMPOSE_LOG_LEVEL", "debug")
DEBUG_PEERS = frozenset(
    n.strip() for n in os.environ.get("AT_COMPOSE_DEBUG_PEERS", "").split(",")
    if n.strip())


def _peer_log_level(peer_name: str) -> str:
    return "debug" if peer_name in DEBUG_PEERS else PEER_LOG_LEVEL
# How long a hierarchy field joiner keeps asking to be admitted before founding
# a group of its own (AT_JOIN_PATIENCE_SEC). Bring-up of a 96-node stack on one
# host has spread over twenty minutes.
JOIN_PATIENCE_SEC = os.environ.get("AT_COMPOSE_JOIN_PATIENCE", "1800")
SUBNET = "172.30.0.0/24"
SUBNET_BASE = "172.30.0"  # ip suffix slots: 2=simulator, 3=coordinator, 10+=peers
BASE_PEER_OCTET = 10


def _microdrones_sorted(scenario) -> list:
    """All microdrone-* peer names ordered by numeric suffix (microdrone-2 <
    microdrone-10), so "first N" selects a stable, human-obvious prefix."""
    return sorted((n for n in scenario.peers if n.startswith("microdrone-")),
                  key=lambda n: int(n.rsplit("-", 1)[-1]))


def parse_c_microdrones(scenario, raw: Optional[str]) -> frozenset:
    """Resolve which microdrones run the C at_demo node from the AT_C_MICRODRONES
    knob. SPEC grammar (must stay in lockstep with
    seed_dod_cohort._resolve_c_microdrones, else a peer's identity format is
    cross-wired):

      * unset/""/"0"/"none"/"false"  -> none (fully Python, back-compat default)
      * "all"/"true"                 -> every microdrone-*
      * a bare integer N             -> the first N microdrones (by numeric
                                        suffix); N < total yields a MIXED
                                        Python+C swarm. NOTE: "1" now means
                                        "first 1", not "all" — use "all".
      * comma-separated peer names   -> exactly those peers
    """
    if raw is None:
        raw = os.environ.get("AT_C_MICRODRONES", "")
    raw = raw.strip()
    if raw in ("", "0", "none", "false"):
        return frozenset()
    if raw in ("all", "true"):
        return frozenset(_microdrones_sorted(scenario))
    if raw.isdigit():
        return frozenset(_microdrones_sorted(scenario)[:int(raw)])
    return frozenset(n.strip() for n in raw.split(",") if n.strip())

# Phase-index → seconds delay before the participant attempts to join.
# Matches Phase.start in scenario.py (60s per phase).
JOIN_DELAY_SEC = {
    0: 0,        # Setup
    1: 60,       # Approach
    2: 120,      # Contact (leave-behind sensors)
    3: 180,      # Intel
    4: 240,      # Rogue (MQ-800)
    5: 300,      # ECM
    6: 360,      # Strike (jet)
    7: 420,      # Exfil
}

# Per-peer-index startup stagger, additive to the phase delay above.
# Groups of STAGGER_GROUP_SIZE peers each get a 1-second offset, so
# at 100 peers the AT bootstrap traffic spreads over ~10 s instead of
# slamming the network all at once. Override via env at compose-gen
# time:
#   AT_PEER_STAGGER_GROUP=10    (peers per second; 0 disables)
# A coarse group-based stagger keeps AT_JOIN_DELAY_SEC integer-valued
# (the participant parses it as int).
STAGGER_GROUP_SIZE = int(os.environ.get("AT_PEER_STAGGER_GROUP", "10"))


# Per-peer persistent-state directory on the host. Bind-mounted into
# each container's $AUTONOMOUS_TRUST_ROOT so identity / group / peers /
# reputation / peer-capabilities .cfg.json files survive a
# docker-compose restart. Pre-populated by tools/seed_dod_cohort.py for
# squad-* / microdrone-* / jet-* peers (the high-trust starting set);
# empty for everyone else so they go through normal bootstrap.
#
# Override via AT_PERSIST_HOST_DIR; relative paths are resolved against
# the compose file's directory by docker-compose. Default sits next to
# the repo root so `.gitignore` already covers it.
PERSIST_HOST_DIR = os.environ.get(
    "AT_PERSIST_HOST_DIR",
    "../../../.demo-state/dod-mission")

# Recording: when enabled (build_compose(record_file=...) or the AT_RECORD env
# var), the coordinator is launched with `--record <RECORD_MOUNT>/<file>` and
# RECORD_HOST_DIR is bind-mounted there so the canned-playback log it flushes
# on shutdown lands on the host (no `docker cp` needed). Host path is
# compose-file-relative and MUST start with ./ or ../ — a bare name would be
# read as a *named volume*, not a bind mount. Default sits beside the compose
# file (examples/dod_mission/deploy/recording/); override via AT_RECORD_HOST_DIR.
RECORD_HOST_DIR = os.environ.get("AT_RECORD_HOST_DIR", "./recording")
RECORD_MOUNT = "/app/recording"


def _service_block(name: str, ip: str, *, image: str,
                   common_env: dict, extra_env: Optional[dict] = None,
                   volumes: Optional[list] = None,
                   ports: Optional[list] = None,
                   depends_on: Optional[list] = None,
                   cap_add: bool = True,
                   networks: Optional[dict] = None) -> dict:
    env = dict(common_env)
    if extra_env:
        env.update(extra_env)
    block = {
        "image": image,
        "container_name": name,
        "environment": env,
        # `networks` maps network name -> address for a node on several
        # networks (a hierarchy gateway); without it the node sits on dod-net.
        "networks": ({n: {"ipv4_address": a} for n, a in networks.items()}
                     if networks else {NETWORK_NAME: {"ipv4_address": ip}}),
        "restart": "unless-stopped",
    }
    if cap_add:
        block["cap_add"] = ["NET_ADMIN"]
    if MEM_LIMIT:
        block["mem_limit"] = MEM_LIMIT
    if volumes:
        block["volumes"] = volumes
    if ports:
        block["ports"] = ports
    if depends_on:
        block["depends_on"] = depends_on
    return block


def _add_c_microdrone(services: dict, ingest_volumes: set, peer_name: str,
                      ip: str, delay: int, common_env: dict,
                      c_image: str, demo_image: str,
                      networks: Optional[dict] = None,
                      extra_env: Optional[dict] = None) -> None:
    """Emit a C ``at_demo`` node + its Python flight-stub sidecar for one
    microdrone (Stretch Goal 3, Path B).

    The C node runs the trust fabric on dod-net (seeded identity bind-mounted at
    /etc/at with the default AUTONOMOUS_TRUST_ROOT=/, matching the interop test)
    and exposes an AF_UNIX ingest socket on a shared named volume. The stub
    (demo image) builds the microdrone generator bundle and streams Readings into
    that socket; it needs no dod-net IP, only the shared volume — so it joins the
    default compose network."""
    sock = f"/ingest/{peer_name}.sock"
    ingest_vol = f"ingest-{peer_name}"
    ingest_volumes.add(ingest_vol)

    # C node: entrypoint-c.sh reads LOG_LEVEL + STARTUP_DELAY; the data-source
    # process reads AT_INGEST_SOCKET. Scenario knobs ride in via common_env.
    c_env = {
        "LOG_LEVEL": _peer_log_level(peer_name),
        "AT_PEER_NAME": peer_name,
        "AT_INGEST_SOCKET": sock,
    }
    if delay > 0:
        c_env["STARTUP_DELAY"] = str(delay)
    if extra_env:
        c_env.update(extra_env)
    services[peer_name] = _service_block(
        peer_name, ip, image=c_image, common_env=common_env, extra_env=c_env,
        volumes=[f"{PERSIST_HOST_DIR}/{peer_name}/etc/at:/etc/at",
                 f"{ingest_vol}:/ingest"],
        depends_on=["simulator"], networks=networks)

    # Flight-stub sidecar: produces ISR readings; no fabric IP (default net).
    services[f"{peer_name}-stub"] = {
        "image": demo_image,
        "container_name": f"{peer_name}-stub",
        "environment": {
            **common_env,
            "AT_PEER_NAME": peer_name,
            "AT_INGEST_SOCKET": sock,
            "AUTONOMOUS_TRUST_EXE": "examples/pi_peer/pi_peer_main.py",
            "AUTONOMOUS_TRUST_ARGS": peer_name,
        },
        "restart": "unless-stopped",
        **({"mem_limit": MEM_LIMIT} if MEM_LIMIT else {}),
        "volumes": [f"{ingest_vol}:/ingest",
                    "../../pi_peer:/app/examples/pi_peer:ro"],
        "depends_on": [peer_name],
    }


def build_compose(scenario_kwargs: Optional[dict] = None,
                  image_name: str = DEMO_IMAGE,
                  record_file: Optional[str] = None,
                  c_microdrones: Optional[frozenset] = None,
                  c_image: str = C_IMAGE) -> dict:
    sc = DoDMissionScenario(**(scenario_kwargs or {}))
    # Hierarchical deployment (AT_COHORT_SIZE): the layout decides each peer's
    # cohort, networks and addresses, and which microdrones run C (all but one
    # Python anchor per field cohort).
    max_cohort = cohort_size_from_env()
    layout = plan_layout(sc, max_cohort) if max_cohort else None
    gateways = {c.gateway for c in layout.cohorts} if layout else set()
    if layout is not None:
        c_microdrones = frozenset(layout.c_microdrones())
    elif c_microdrones is None:
        c_microdrones = parse_c_microdrones(sc, None)
    ingest_volumes: set[str] = set()

    # Recording is opt-in: explicit record_file wins, else the AT_RECORD env
    # var (so the tilt path, which generates compose via the Tiltfile, enables
    # it just by inheriting the launcher's environment). basename-only so the
    # file always lands inside the bind-mounted RECORD_HOST_DIR.
    if record_file is None:
        record_file = os.environ.get("AT_RECORD") or None
    record_basename = os.path.basename(record_file) if record_file else None

    # Knobs all services need so they agree on the roster.
    sc_env = {
        "AT_SQUAD_SIZE": str(sc._squad_size),  # noqa: SLF001
        "AT_SWARM_SIZE": str(sc._swarm_size),  # noqa
        "AT_SENSOR_COUNT": str(sc._sensor_count),  # noqa
        "AT_HACKED_SENSORS": str(sc._hacked_sensors),  # noqa
        "AT_INCLUDE_MQ800": "1" if sc._include_mq800 else "0",  # noqa
        "AT_INCLUDE_JET": "1" if sc._include_jet else "0",  # noqa
        "AT_INCLUDE_COMMAND": "1" if sc._include_command else "0",  # noqa
        "AT_RQ86_COUNT": str(sc._rq86_count),  # noqa
    }
    if layout is not None:
        sc_env["AT_COHORT_SIZE"] = str(max_cohort)
    # Shared scenario epoch — DoDDataProcess uses this to anchor every
    # peer's reading timestamps to the same wall-clock origin, so the
    # sensor-comparison charts on the coordinator can line up consensus
    # across peers that joined at different real times (microdrones at
    # T+0s, ground sensors at T+120s, MQ-800 at T+240s, jet at T+360s).
    # Read from the launcher's environment; if unset, default to "now"
    # at compose-generation time.
    t0_epoch = os.environ.get("AT_DEMO_T0_EPOCH") or str(int(time.time()))

    # Do NOT set PYTHONPATH here. The base images already bake a
    # multi-root path covering /opt/at-{inspector,evaluation,services,
    # simulator}:/app (the AT subpackages are split across distros and
    # land at separate /opt roots). An override of `PYTHONPATH=/app`
    # silently shadows that, making
    # `from autonomous_trust.services import ...` ImportError at the
    # participant entrypoint. See Dockerfile + Dockerfile-peer.
    common_env = {
        "POSTMORTEM": "true",
        "AT_DEMO_T0_EPOCH": t0_epoch,
        **sc_env,
    }

    # Optional transport selection. Passed through from the launcher's
    # environment (run-demo.sh --tcp) so every AT node uses the same transport;
    # omitted (default UDP) when unset.
    _transport = os.environ.get("AT_TRANSPORT")
    if _transport:
        common_env["AT_TRANSPORT"] = _transport

    # Optional per-peer process-pool size (see system._max_concurrency).
    # Passed through so scale runs can shrink every peer's pool; omitted when
    # unset, leaving each node its default.
    _max_conc = os.environ.get("AT_MAX_CONCURRENCY")
    if _max_conc:
        common_env["AT_MAX_CONCURRENCY"] = _max_conc

    # Optional: enable persistent/pooled TCP connections cohort-wide. Passed
    # through from the launcher's environment (run-demo.sh --net-pool) so every
    # AT node reads the same setting; omitted (default off) when unset. Note
    # this only takes effect under the TCP transport (AT_TRANSPORT=tcp); the
    # default UDP transport has no connection pool. See
    # doc/architecture/network-connection-pooling.md.
    _net_pool = os.environ.get("AT_NET_POOL")
    if _net_pool:
        common_env["AT_NET_POOL"] = _net_pool

    services: dict[str, dict] = {}

    # Simulator
    services["simulator"] = _service_block(
        f"{sc.name}-simulator",
        f"{SUBNET_BASE}.2",
        image=image_name,
        common_env=common_env,
        extra_env={
            "AUTONOMOUS_TRUST_EXE": "-m autonomous_trust.simulator",
            # Absolute path: the simulator's positional config arg is
            # opened CWD-relative (WORKDIR=/app), and the bind mount
            # below lands the file at /app/config/scenario.yaml — not
            # /app/scenario.yaml. A bare "scenario.yaml" therefore
            # falls all the way through to the simulator module's own
            # /opt/at-simulator/.../scenario.yaml fallback, which
            # doesn't exist in the image, and the container crashes.
            "AUTONOMOUS_TRUST_ARGS":
                "--log simulator.log --log-level info "
                "--resolve-short-name /app/config/scenario.yaml",
            "AUTONOMOUS_TRUST_ROOT": "/app/config",
        },
        volumes=["../simulator/scenario.yaml:/app/config/scenario.yaml:ro"],
        ports=["8051:8051"],
        # In a hierarchy the simulator sits on every network, at .2 of each.
        networks=({COMMAND_NETWORK: f"{SUBNET_BASE}.2",
                   **{field_network(c.index): f"172.30.{c.index}.2"
                      for c in layout.cohorts}} if layout else None),
    )

    # Coordinator (dashboard + validators).
    #
    # NOTE on volume mounts: an earlier draft of this file bind-mounted the
    # generated per-peer configs at $AUTONOMOUS_TRUST_ROOT/etc/at/.  That
    # creates the intermediate dir as root inside the container (Docker
    # creates parents of a bind-mount target as root, regardless of the
    # in-image USER), so the AT runtime (running as `user`) then fails
    # with PermissionError when it tries to create the sibling var/at/
    # under the same root.  The generated peer.cfg.json files aren't read
    # at runtime anyway -- the participant looks up its role from the
    # in-memory DoDMissionScenario -- so we drop the mount and let
    # `os.makedirs(..., exist_ok=True)` build the tree fresh under
    # user-owned /app/.
    coord_args = "--log-level debug"
    coord_volumes = None
    # Seeded coordinator (tools/seed_dod_cohort.py --seed-coordinator): mount
    # its whole config root, as for the peers below, so it starts as a trusted
    # cohort member instead of cold-bootstrapping.
    if os.environ.get("AT_COMPOSE_SEED_COORDINATOR") == "1":
        coord_volumes = [f"{PERSIST_HOST_DIR}/coordinator:/app/config/coordinator"]
    if record_basename:
        # Recorder flushes on graceful shutdown (cleanup()); the bind mount
        # keeps the file after the container is removed. USER is root in this
        # image (Dockerfile), so the coordinator can write into the mount.
        coord_args += f" --record {RECORD_MOUNT}/{record_basename}"
        coord_volumes = (coord_volumes or []) + [
            f"{RECORD_HOST_DIR}:{RECORD_MOUNT}"]
    services["coordinator"] = _service_block(
        f"{sc.name}-coordinator",
        f"{SUBNET_BASE}.3",
        image=image_name,
        common_env=common_env,
        extra_env={
            "AUTONOMOUS_TRUST_EXE": "examples/dod_mission/coordinator.py",
            "AUTONOMOUS_TRUST_ARGS": coord_args,
            "AUTONOMOUS_TRUST_ROOT": "/app/config/coordinator",
        },
        volumes=coord_volumes,
        ports=["8050:8050", "8000:8000"],
        depends_on=["simulator"],
    )

    # Per-peer
    for i, (peer_name, role) in enumerate(sc.peers.items()):
        ip = f"{SUBNET_BASE}.{BASE_PEER_OCTET + i}"
        nets = (dict(layout.addresses[peer_name]) if layout is not None
                else None)
        # A field joiner has no seeded group to fall back on, and its cohort's
        # admitter can come up long after it on a loaded host, so it keeps
        # asking to be admitted instead of founding a group of one. Anchors,
        # gateways and command members load their seeded group and do not wait.
        joiner_env = {}
        if layout is not None:
            coh = layout.cohort_of(peer_name)
            if coh is not None and peer_name not in (coh.anchor, coh.gateway):
                joiner_env["AT_JOIN_PATIENCE_SEC"] = JOIN_PATIENCE_SEC

        # Late joiners — phase-index drives the join delay.
        # Per-peer index stagger stacks on top: peers in group `g`
        # (g = i // STAGGER_GROUP_SIZE) wait an extra `g` seconds.
        # Keeps the AT-bootstrap broadcast burst from arriving at all
        # peers in one network tick when peer count is high.
        delay = JOIN_DELAY_SEC.get(role.join_phase, 0)
        if STAGGER_GROUP_SIZE > 0:
            delay += i // STAGGER_GROUP_SIZE

        # --- C at_demo microdrone: native node + Python flight-stub sidecar ---
        if peer_name in c_microdrones:
            _add_c_microdrone(services, ingest_volumes, peer_name, ip, delay,
                              common_env, c_image, image_name, networks=nets,
                              extra_env=joiner_env)
            continue

        extra: dict[str, str] = {
            "AUTONOMOUS_TRUST_EXE": "examples/dod_mission/participant.py",
            "AUTONOMOUS_TRUST_ARGS": f"{peer_name} --log-level {_peer_log_level(peer_name)}",
            "AUTONOMOUS_TRUST_ROOT": f"/app/config/{peer_name}",
            "AT_PEER_NAME": peer_name,
            "AT_AGENCY": role.agency,
        }
        if delay > 0:
            extra["AT_JOIN_DELAY_SEC"] = str(delay)
        extra.update(joiner_env)

        # Role-specific compromise wiring.  The scenario marks these in
        # PeerRole.metadata; we translate to env vars the participant reads.
        if role.metadata.get("rogue"):
            extra["AT_COMPROMISED"] = "true"
            extra["AT_COMPROMISE_MODE"] = "abrupt"  # overridable at run-demo.sh
        if role.metadata.get("forged_identity"):
            extra["AT_FORGERY_MODE"] = "self_signed"

        # Hierarchy gateway: one hybrid-transport leg per network. It stays
        # out of admission, since as a border guard it would propose field
        # joiners into its primary (command) group, and it relays readings
        # from the field peers it is given.
        if peer_name in gateways:
            extra["AT_TRANSPORT"] = ("autonomous_trust.core.network.hybrid."
                                     "HybridNetworkProcess")
            extra["AT_BORDER_GUARD"] = "0"
            extra["AT_GATEWAY_FIELD_PEERS"] = ",".join(
                layout.cohort_of(peer_name).members)

        # Persistent-state mount. The full $AUTONOMOUS_TRUST_ROOT
        # (parent of etc/at and var/at) is bind-mounted so AT — running
        # as root in this image (see Dockerfile USER root) — can create
        # both subtrees itself, sidestepping the root-creates-parent
        # bug noted on the coordinator service. The host-side dir is
        # pre-populated by tools/seed_dod_cohort.py for the high-trust
        # cohort (squad-*/microdrone-*/jet-*) and empty for the rest.
        services[peer_name] = _service_block(
            peer_name, ip,
            image=image_name,
            common_env=common_env,
            extra_env=extra,
            volumes=[f"{PERSIST_HOST_DIR}/{peer_name}:/app/config/{peer_name}"],
            depends_on=["simulator"],
            networks=nets,
        )

    networks = {
        NETWORK_NAME: {
            "driver": "bridge",
            "ipam": {"config": [{"subnet": SUBNET}]},
        },
    }
    if layout is not None:
        for c in layout.cohorts:
            networks[field_network(c.index)] = {
                "driver": "bridge",
                "ipam": {"config": [{"subnet": field_subnet(c.index)}]},
            }
    compose = {"services": services, "networks": networks}
    # Named volumes carrying the AF_UNIX ingest socket shared by each C
    # microdrone and its flight-stub sidecar.
    if ingest_volumes:
        compose["volumes"] = {v: None for v in sorted(ingest_volumes)}
    return compose


def write_compose(compose: dict, output_path: Path,
                  description: str = "") -> None:
    import yaml
    output_path.parent.mkdir(parents=True, exist_ok=True)
    n_peers = len(compose["services"]) - 2  # minus simulator + coordinator
    with output_path.open("w") as f:
        f.write("# Auto-generated by examples/dod_mission/deploy/generate_compose.py\n")
        f.write(f"# {n_peers} peers + simulator + coordinator\n")
        if description:
            f.write(f"# {description}\n")
        f.write("\n")
        yaml.dump(compose, f, default_flow_style=False, sort_keys=False)


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument("output", nargs="?",
                   default=str(_HERE / "docker-compose.yml"),
                   help="Path to write compose YAML")
    p.add_argument("--image", default=DEMO_IMAGE)
    p.add_argument("--c-image", default=C_IMAGE,
                   help="Image for C at_demo microdrones (default %(default)s).")
    p.add_argument("--c-microdrones", metavar="SPEC", default=None,
                   help="Run microdrones as C at_demo nodes: 'all', a comma-list "
                        "of peer names, or unset (default: $AT_C_MICRODRONES). "
                        "Pair with: python -m tools.seed_dod_cohort --c-microdrones.")
    p.add_argument("--squad-size", type=int, default=4)
    p.add_argument("--swarm-size", type=int, default=4)
    p.add_argument("--sensor-count", type=int, default=3)
    p.add_argument("--hacked-sensors", type=int, default=2)
    p.add_argument("--no-mq800", action="store_true")
    p.add_argument("--no-jet", action="store_true")
    p.add_argument("--no-command", action="store_true")
    p.add_argument("--rq86-count", type=int,
                   default=int(os.environ.get("AT_RQ86_COUNT", "2")),
                   help="RQ-86 gateways; with AT_COHORT_SIZE set, one per "
                        "field cohort (default: $AT_RQ86_COUNT, else 2).")
    p.add_argument("--record", metavar="FILE", default=None,
                   help="Record the run to FILE (basename; written under "
                        f"{RECORD_HOST_DIR}/ on the host via a coordinator "
                        "bind mount). Defaults to the AT_RECORD env var.")
    args = p.parse_args(argv)

    scenario_kwargs = dict(
        squad_size=args.squad_size,
        swarm_size=args.swarm_size,
        sensor_count=args.sensor_count,
        hacked_sensors=args.hacked_sensors,
        include_mq800=not args.no_mq800,
        include_jet=not args.no_jet,
        include_command=not args.no_command,
        rq86_count=args.rq86_count,
    )
    c_microdrones = parse_c_microdrones(DoDMissionScenario(**scenario_kwargs),
                                        args.c_microdrones)
    compose = build_compose(image_name=args.image, record_file=args.record,
                            scenario_kwargs=scenario_kwargs,
                            c_microdrones=c_microdrones, c_image=args.c_image)
    write_compose(compose, Path(args.output))
    n_peers = len(compose["services"]) - 2
    print(f"Wrote {args.output}  ({n_peers} peers + simulator + coordinator)")
    if c_microdrones:
        print(f"  C at_demo microdrones ({args.c_image}): "
              + ", ".join(sorted(c_microdrones))
              + "\n  -> first run: python -m tools.seed_dod_cohort --c-microdrones")
    rec = args.record or os.environ.get("AT_RECORD")
    if rec:
        print(f"  recording ENABLED -> coordinator writes "
              f"{RECORD_HOST_DIR}/{os.path.basename(rec)} on graceful "
              f"shutdown (docker compose down / docker stop)")


if __name__ == "__main__":
    main()
