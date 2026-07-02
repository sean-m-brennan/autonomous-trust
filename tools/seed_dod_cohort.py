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

"""Seed per-peer persistent state for the high-trust dod-mission cohort.

Generates ``./.demo-state/dod-mission/<peer>/etc/at/{identity,group,
peers,reputation,peer-capabilities}.cfg.json`` for every pre-trusted peer
in the scenario (squad-* / microdrone-* / jet-* — see PRE_TRUSTED_PREFIXES
in examples/dod_mission/reputation_warmstart.py). The state encodes mutual
recognition + reputation = 0.7 so the cohort starts trusting each other
from t=0. The jet is included because its strike window is too brief to
build consensus. Everyone else (rq-86 recon, mq-800 armed, ground sensors,
command-node) cold-bootstraps normally so the existing demo beats (Sybil
rejection on hacked sensors, MQ-800 contradiction detection) stay intact.

(``command`` was briefly seeded too, but that made it a mutual-trust field
member and churned the gateway-reputation tree — reverted; it cold-boots.)

Output layout::

    .demo-state/dod-mission/
      _shared/                          # not bind-mounted; the canonical
        group.cfg.json                  # group + group_key shared by
        peers_template.json             # all seeded peers
      squad-captain/etc/at/
        identity.cfg.json               # this peer's own identity (keys)
        group.cfg.json                  # copy of _shared/group.cfg.json
        peers.cfg.json                  # the OTHER seeded peers' Identities
        reputation.cfg.json             # rep = 0.7 for each OTHER peer
        peer-capabilities.cfg.json      # advertised cap list per peer
      microdrone-1/etc/at/              # ... same structure ...
      ...

Usage::

    python -m tools.seed_dod_cohort                    # default: .demo-state/dod-mission
    python -m tools.seed_dod_cohort --out /tmp/seed    # explicit path
    python -m tools.seed_dod_cohort --force            # regenerate identities
    python -m tools.seed_dod_cohort --swarm-size 24    # larger swarm

By default the script is *idempotent*: a re-run on an already-seeded
directory preserves the previously-generated identity keys so a warm
restart sees the same UUIDs/pubkeys it did before. ``--force`` blows
the directory away and regenerates fresh keys.
"""

from __future__ import annotations

import argparse
import copy
import json
import os
import shutil
import sys
from pathlib import Path

# Repo-relative imports — works when invoked via
# ``python -m tools.seed_dod_cohort`` from the repo root (PYTHONPATH
# set up by the surrounding runner script or Tiltfile).
from examples.dod_mission.scenario import DoDMissionScenario  # noqa: E402
from autonomous_trust.core._python.config import Configuration  # noqa: E402
from autonomous_trust.core._python.config.configuration import (  # noqa: E402
    ConfigJSONEncoder, config_json_decoder,
)
from autonomous_trust.core._python.identity import Identity, Peers  # noqa: E402
from autonomous_trust.core._python.identity.group import Group  # noqa: E402
from autonomous_trust.core._python.identity.history.history import (  # noqa: E402
    IdentityHistory,
)
from autonomous_trust.core._python.reputation.reputation import Reputations  # noqa: E402
from autonomous_trust.core._python.capabilities import PeerCapabilities  # noqa: E402
from autonomous_trust.core._python.system import CfgIds  # noqa: E402


# Seed reputation / tier / pre-trusted set: single source of truth shared
# with the coordinator's dashboard warm-start (see the module docstring).
# 0.7 sits above the 0.5 rep-persist threshold but under 1.0 -> tier 2
# ("affirmed") per TIER_FLOORS in repprocess.py:57-62.
from examples.dod_mission.reputation_warmstart import (  # noqa: E402
    SEED_REPUTATION, SEED_TIER, PRE_TRUSTED_PREFIXES,
)
# Compose IP scheme — single source of truth so a pre-seeded C node's stored
# address matches the IP the compose generator assigns it (the C node preserves
# its seeded identity and does not re-discover the interface; the announce
# envelope's from_address derives from this).
from examples.dod_mission.deploy.generate_compose import (  # noqa: E402
    SUBNET_BASE, BASE_PEER_OCTET,
)
from tools.c_identity import (  # noqa: E402
    make_c_node_identity, public_identity_from_c_json,
)

# Capability list each seeded peer advertises in its peer-capabilities
# snapshot. Matches the canonical bootstrap set every AT peer registers
# via autonomous_ability() at startup (see participant.py:466-506);
# we duplicate it here so the seeded cohort knows what it's signed up
# for before the first announce/handshake round.
SEEDED_PEER_CAPABILITIES: list[str] = [
    "data.publish",
    "data.subscribe",
    "trust.handshake",
    "telemetry.report",
]

GROUP_NICKNAME = "odazone"

# Gateways (rank > 1 "peer leaders") bridge the command cohort above them
# to the field cohort below. For seed-assisted dual membership they are
# given the field group as a CHILD group (group_child_*.cfg.json) and are
# added to the field group's address map so field members deliver
# field-group traffic to them — but they are NOT given a primary
# group.cfg.json, so they still cold-bootstrap their command cohort with
# the coordinator. Runtime rank governs the reputation roster/routing;
# this only hands them the child key at t=0. See
# doc/architecture/gateway-reputation-tree.md.
GATEWAY_PREFIXES = ("rq86-",)


def is_seeded(peer_name: str) -> bool:
    """The pre-trusted set: squad-*, microdrone-*, jet-*."""
    return peer_name.startswith(PRE_TRUSTED_PREFIXES)


def is_gateway(peer_name: str) -> bool:
    """Gateways that get the field cohort as a seeded child group."""
    return peer_name.startswith(GATEWAY_PREFIXES)


def _compose_ip(scenario: DoDMissionScenario, peer_name: str) -> str:
    """The IP generate_compose.py assigns this peer (same enumerate order)."""
    idx = list(scenario.peers).index(peer_name)
    return f"{SUBNET_BASE}.{BASE_PEER_OCTET + idx}"


def _read_or_init_c_identity(ident_file: Path, peer_name: str, address: str,
                             force: bool) -> tuple[dict, Identity]:
    """C-node analog of _read_or_init_identity: emit a seed-based C-format
    identity (so the C ``at_demo`` node loads it via its preserve path) and the
    matching public-only cohort view. Idempotent: a re-run without ``--force``
    reuses the stored seeds so the C node keeps its UUID/pubkeys.
    """
    if ident_file.exists() and not force:
        with ident_file.open("r") as f:
            c_json = json.load(f)  # plain C JSON, NOT ConfigJSONEncoder
        if isinstance(c_json, dict) and "hex_seed" in c_json.get("signature", {}):
            return c_json, public_identity_from_c_json(c_json)
        # Format mismatch: a Python-format identity (ConfigJSONEncoder output,
        # ``__type__``/``signature`` as a nested Configuration) sits on disk but
        # this run treats the peer as a C node — i.e. ``--c-microdrones`` gained
        # this peer since the prior seed. The Python schema can't be loaded by
        # the C runtime, so regenerate a fresh C-format seed rather than KeyError
        # on the missing ``hex_seed``. Fresh keys are fine: the cohort views are
        # all rebuilt in this same seed run, so every peer still agrees.
        print(f"  warning: {peer_name} has a Python-format identity on disk but "
              f"is being seeded as a C node; regenerating a fresh C identity "
              f"(drop --c-microdrones to keep it Python, or --force to silence).")
    return make_c_node_identity(peer_name, address)


def _read_or_init_identity(ident_file: Path, peer_name: str,
                           force: bool) -> Identity:
    """Load the peer's prior identity if present (and ``--force`` not
    set), else generate a fresh keypair. The address is a placeholder —
    the runtime overwrites it from the actual network interface on
    first announce; the only thing the seed must stabilise is the
    UUID + pubkeys so warm-start peers recognise each other.
    """
    if ident_file.exists() and not force:
        with ident_file.open("r") as f:
            loaded = json.load(f, object_hook=config_json_decoder)
        if isinstance(loaded, Identity):
            return loaded
        # Format mismatch: the file is a C-runtime identity (flat jansson
        # schema, no ``__type__``), so the Python decoder handed back a plain
        # dict. This run is seeding the peer as Python but a prior run seeded it
        # as a C ``at_demo`` node (the ``--c-microdrones`` SPEC was dropped or
        # changed). A C seed carries only public material in the wrong schema
        # and can't be loaded as a Python identity, so regenerate a fresh Python
        # keypair instead of letting the dict crash _peer_view_of() downstream.
        # Fresh keys are fine: the whole cohort's views are rebuilt in this same
        # seed run, so every peer still recognises every other.
        print(f"  warning: {peer_name} has a C-format identity on disk but is "
              f"being seeded as a Python peer; regenerating a fresh Python "
              f"identity (pass --c-microdrones to keep it a C node, or --force "
              f"to silence).")
    return Identity.initialize(
        my_name=f"{peer_name}@dod-demo",
        my_nickname=peer_name,
        my_address=peer_name,  # placeholder; runtime re-resolves.
    )


def _save_json(path: Path, obj) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w") as f:
        json.dump(obj, f, cls=ConfigJSONEncoder, indent=2)


def _peer_view_of(ident: Identity) -> Identity:
    """Return a copy of ``ident`` with ``_tier`` bumped to ``SEED_TIER``
    so any peer that loads this Identity from its peers.cfg.json sees
    the seeded peer as already-affirmed. ``_tier`` is a local-view
    attribute (not part of the protobuf wire form) so each peer's copy
    of every other peer can hold a different tier value, which is
    exactly what the per-peer save semantics need.
    """
    view = copy.deepcopy(ident)
    view._tier = SEED_TIER  # noqa: SLF001
    return view


def seed_cohort(out_root: Path, scenario: DoDMissionScenario,
                force: bool = False,
                c_nodes: frozenset[str] = frozenset()) -> list[str]:
    """Write seeded state under ``out_root``. Returns the list of seeded
    peer names (squad-*/microdrone-*/jet-*).

    ``c_nodes`` names peers that run the C ``at_demo`` binary instead of the
    Python participant. They get a seed-based **C-format** ``identity.cfg.json``
    (no Python-format group/peers/reputation in their own dir — they cold-join
    for the group key via the live handshake) while still being registered, at
    seed tier, in every *other* peer's view so the cohort recognises them at t=0.
    """
    seeded = [name for name in scenario.peers.keys() if is_seeded(name)]
    if not seeded:
        return seeded
    gateways = [name for name in scenario.peers.keys() if is_gateway(name)]

    if force and out_root.exists():
        # Best-effort wipe. We OWN and must refresh the seeded identities under
        # each peer's etc/at; the sibling var/at is *runtime* state the live
        # node/container writes — and when peers ran in Docker as root, those
        # files come back owned by uid 0 (and on a virtiofs-backed checkout not
        # even host sudo can unlink them). A plain rmtree() aborts the whole
        # reseed on the first such file. Skip what we can't remove (the node
        # overwrites/append its own var/at on boot) and keep going; the ETC/AT
        # identities we do own get cleared here and regenerated below.
        undeletable = []

        def _keep_going(func, path, exc):  # onexc(3.12+)/onerror(<3.12) callback
            undeletable.append(path)

        try:
            shutil.rmtree(out_root, onexc=_keep_going)        # Python >= 3.12
        except TypeError:
            shutil.rmtree(out_root, onerror=_keep_going)      # Python < 3.12
        if undeletable:
            print(f"  warning: {len(undeletable)} container-owned runtime "
                  f"file(s) under {out_root} could not be removed "
                  f"(e.g. {undeletable[0]}); seeded identities are still "
                  f"regenerated. To fully reset, delete the dir as the owner "
                  f"(e.g. a root `docker run --rm -v ...:/s alpine rm -rf /s`).")
    out_root.mkdir(parents=True, exist_ok=True)

    # Phase 1: per-peer identities (load existing on re-run unless --force).
    # Gateways get a seeded identity too so their UUID/address is stable
    # and can be carried in the field group's address map; they are NOT
    # added to `seeded` (no primary group / mutual-trust seeding) — only
    # the field group as a child.
    identities: dict[str, Identity] = {}
    for peer in seeded + gateways:
        ident_file = out_root / peer / "etc" / "at" / "identity.cfg.json"
        if peer in c_nodes:
            # C node: write the C-runtime schema verbatim (json.dump, not
            # ConfigJSONEncoder); register the public-only view for the cohort.
            c_json, identities[peer] = _read_or_init_c_identity(
                ident_file, peer, _compose_ip(scenario, peer), force)
            ident_file.parent.mkdir(parents=True, exist_ok=True)
            with ident_file.open("w") as f:
                json.dump(c_json, f, indent=2)
        else:
            identities[peer] = _read_or_init_identity(ident_file, peer, force)
            _save_json(ident_file, identities[peer])

    # Phase 2: shared field Group. Its address map spans the seeded field
    # members AND the gateways, so field members unicast field-group
    # traffic (incl. reputation `committed` broadcasts) to the gateways,
    # which hold the field key as a child group and accumulate the field
    # reputation chain. Same group UUID + key for every member.
    shared_dir = out_root / "_shared"
    shared_grp_file = shared_dir / "group.cfg.json"
    if shared_grp_file.exists() and not force:
        with shared_grp_file.open("r") as f:
            grp_payload = json.load(f, object_hook=config_json_decoder)
            group, hist_dict = grp_payload
        # Re-run: make sure the gateways are present in the loaded map.
        for gw in gateways:
            group.add_address(identities[gw].uuid, identities[gw].address)
    else:
        address_map = {ident.uuid: ident.address
                       for ident in identities.values()}  # seeded + gateways
        group = Group.initialize(address_map, GROUP_NICKNAME)
        # Empty IdentityHistory for v1 — the bootstrap flow's
        # ``self_bootstrapped=True`` branch in idprocess.choose_group()
        # tolerates a fresh history; peers will start exchanging
        # diffs from the empty baseline.
        hist_dict = {}
        _save_json(shared_grp_file, (group, hist_dict))

    # Phase 3a: field members — primary group + mutual peers/rep/caps.
    # Each field member's peer view includes the OTHER field members AND
    # the gateways (so it recognises and unicasts to them).
    field_and_gw = seeded + gateways
    for peer in seeded:
        if peer in c_nodes:
            # C node loads only its C-format identity; it cold-joins for the
            # group key + peer set via the live admission handshake (the cohort
            # already trusts its seeded pubkey). Writing Python-format group/
            # peers/reputation into its dir would just be unparsed noise to the
            # C loader, so skip — it stays in *other* peers' views via `seeded`.
            continue
        peer_cfg_dir = out_root / peer / "etc" / "at"

        # Group: shared content, one file per peer (each container
        # bind-mounts only its own peer dir, so the file must be there).
        peer_group_file = peer_cfg_dir / "group.cfg.json"
        _save_json(peer_group_file, (group, hist_dict))

        # Peers: the OTHER field members + gateways, each tier-bumped.
        peers = Peers()
        for other in field_and_gw:
            if other == peer:
                continue
            peers.add(_peer_view_of(identities[other]))
        _save_json(peer_cfg_dir / "peers.cfg.json", peers)

        # Reputation: rep = SEED_REPUTATION for each OTHER field member.
        # Self is implicit (the rep engine seeds self at first compute).
        rep_dict = {identities[other].uuid: SEED_REPUTATION
                    for other in seeded if other != peer}
        reputations = Reputations(current=rep_dict)
        _save_json(peer_cfg_dir / "reputation.cfg.json", reputations)

        # Peer capabilities: every OTHER peer is recorded as offering
        # the seeded capability list.
        pc = PeerCapabilities()
        for other in seeded:
            if other == peer:
                continue
            pc.register(identities[other].uuid, SEEDED_PEER_CAPABILITIES)
        _save_json(peer_cfg_dir / "peer-capabilities.cfg.json", pc)

    # Phase 3b: gateways — the field group as a CHILD group only. No
    # primary group.cfg.json (they cold-bootstrap their command cohort).
    # idprocess._load_child_groups picks up group_child_*.cfg.json at
    # startup and calls _adopt_child_group. The gateway's peer view holds
    # the field members so it can resolve field-group senders on decrypt.
    for gw in gateways:
        gw_cfg_dir = out_root / gw / "etc" / "at"
        child_file = gw_cfg_dir / ("group_child_%s.cfg.json" % GROUP_NICKNAME)
        _save_json(child_file, (group, hist_dict))

        peers = Peers()
        for other in seeded:
            peers.add(_peer_view_of(identities[other]))
        _save_json(gw_cfg_dir / "peers.cfg.json", peers)

        # Reputation priors for the field members. These feed the
        # gateway's consensus-baseline fallback (_consensus_baseline),
        # so its subtree roster reports the field cohort at its primed
        # rep until real field-chain transactions accumulate — instead
        # of a flat 0.5. See repprocess._consensus_reputation.
        rep_dict = {identities[other].uuid: SEED_REPUTATION
                    for other in seeded}
        _save_json(gw_cfg_dir / "reputation.cfg.json",
                   Reputations(current=rep_dict))

        pc = PeerCapabilities()
        for other in seeded:
            pc.register(identities[other].uuid, SEEDED_PEER_CAPABILITIES)
        _save_json(gw_cfg_dir / "peer-capabilities.cfg.json", pc)

    return seeded


def _microdrones_sorted(scenario):
    """microdrone-* peer names ordered by numeric suffix (microdrone-2 <
    microdrone-10) so a "first N" SPEC selects a stable, obvious prefix."""
    return sorted((n for n in scenario.peers if n.startswith("microdrone-")),
                  key=lambda n: int(n.rsplit("-", 1)[-1]))


def _resolve_c_microdrones(scenario, raw):
    """Resolve which microdrones run the C at_demo node from a SPEC string.
    Kept in LOCKSTEP with generate_compose.parse_c_microdrones so seeding and
    compose agree on the exact set (a mismatch cross-wires a peer's identity
    format). Grammar:

      * unset/""/"0"/"none"/"false"  -> none
      * "all"/"true"                 -> every microdrone-*
      * a bare integer N             -> the first N microdrones (by numeric
                                        suffix); N < total -> mixed Python+C.
                                        "1" means "first 1", not "all".
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


def main(argv=None) -> int:
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument("--out", type=Path,
                   default=Path(".demo-state/dod-mission"),
                   help="Output root directory. Each peer gets a "
                        "subdir named after itself.")
    p.add_argument("--force", action="store_true",
                   help="Blow away the output dir and regenerate "
                        "fresh keys. Default is to preserve existing "
                        "identities so warm restarts stay consistent.")
    p.add_argument("--squad-size", type=int, default=4)
    p.add_argument("--swarm-size", type=int, default=4)
    p.add_argument("--sensor-count", type=int, default=3)
    p.add_argument("--hacked-sensors", type=int, default=2)
    p.add_argument("--no-mq800", action="store_true")
    p.add_argument("--no-jet", action="store_true")
    p.add_argument("--no-command", action="store_true")
    p.add_argument("--c-microdrones", metavar="SPEC", nargs="?",
                   const="all", default=None,
                   help="Seed microdrone-* peers as C at_demo nodes (C-format "
                        "identity; they cold-join for the group key). SPEC is "
                        "'all' (the default when the flag is given bare), a bare "
                        "integer N for the first N microdrones (N < total -> a "
                        "mixed Python+C swarm), a comma-separated list of peer "
                        "names, or unset. MUST match the SPEC passed to "
                        "generate_compose.py --c-microdrones, else a peer gets a "
                        "C-format identity but runs as Python (or vice-versa) "
                        "and fails to load its own identity.")
    args = p.parse_args(argv)

    scenario = DoDMissionScenario(
        squad_size=args.squad_size,
        swarm_size=args.swarm_size,
        sensor_count=args.sensor_count,
        hacked_sensors=args.hacked_sensors,
        include_mq800=not args.no_mq800,
        include_jet=not args.no_jet,
        include_command=not args.no_command,
    )
    c_nodes = _resolve_c_microdrones(scenario, args.c_microdrones)
    seeded = seed_cohort(args.out, scenario, force=args.force, c_nodes=c_nodes)
    n_skipped = len(scenario.peers) - len(seeded)
    print(f"Seeded {len(seeded)} peers under {args.out} "
          f"({n_skipped} peers left to cold-bootstrap)")
    if seeded:
        print("  Trusted cohort: " + ", ".join(sorted(seeded)))
    if c_nodes:
        print("  C at_demo nodes: " + ", ".join(sorted(c_nodes)))
    return 0


if __name__ == "__main__":
    sys.exit(main())
