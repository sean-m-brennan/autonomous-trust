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

"""Docker Compose + Kubernetes manifest generation for the civilian demo.

Takes a DisasterResponseScenario (or any Scenario subclass whose peers
have agency/kind metadata) and emits:

  - docker-compose.yaml: one service per peer with named container,
    stable subnet IP, agency/role/capability env vars.
  - kubernetes/: one Deployment (or StatefulSet) per peer grouped into
    per-agency YAML files, plus a ConfigMap carrying the scenario
    timeline so late-joiner schedulers can delay pod start.

The compose pattern is adapted from /gen_compose.py but replaces the
numbered at-1..at-N clones with role-specific names that the UI can
key on directly (noaa-1, fema-fusion, etc.).
"""

from __future__ import annotations

import argparse
import json
import os
from dataclasses import dataclass, field
from typing import Optional


# Default subnet for the demo (isolated from other compose networks).
_DEMO_SUBNET = "10.27.4.0/24"
_DEMO_ROUTER = "10.27.4.1"
_DEMO_FIRST_IP = 10   # first peer gets .10, peers assigned in order


@dataclass
class ComposeOptions:
    """Knobs for compose/k8s emission."""
    image: str = "autonomous-trust"
    registry: str = ""                   # e.g. "ghcr.io/tekfive/"
    image_tag: str = ""                  # e.g. ":demo" or "@sha256:..."
    log_level: str = "info"
    exclude_logs: str = "none"  # "network"
    backend: str = "native"
    subnet: str = _DEMO_SUBNET
    router: str = _DEMO_ROUTER
    first_ip: int = _DEMO_FIRST_IP
    scenario_mount: str = "/app/scenario"  # path where scenario.json is mounted
    metrics_mount: Optional[str] = None    # host path for metrics-collector dir
    extra_env: dict[str, str] = field(default_factory=dict)
    # Civilian-demo inspector container. Runs the Dash server + bridge
    # on the same demo-net so it can observe peer traffic. Shares the
    # registry/image_tag of the peer image.
    inspector_image: str = "autonomous-trust-inspector"
    inspector_last_octet: int = 250        # subnet host byte for the inspector
    inspector_host_port: int = 8050        # published to host
    include_inspector: bool = True         # set False to suppress the service


# ----------------------------------------------------------------------
# Compose emission
# ----------------------------------------------------------------------

def _peer_entry(peer_name: str, role, ip: str, delay_sec: int,
                opts: ComposeOptions) -> list[str]:
    """Build the YAML lines for a single compose service."""
    image = f"{opts.registry}{opts.image}{opts.image_tag}"
    caps = ",".join(role.capabilities) if role.capabilities else ""
    at_args = f"--live --test --exclude-logs {opts.exclude_logs} " \
              f"--log-level {opts.log_level}"

    env = {
        "ROUTER": opts.router,
        "AUTONOMOUS_TRUST_ARGS": at_args,
        "AUTONOMOUS_TRUST_BACKEND": opts.backend,
        "AT_TRANSPORT": "autonomous_trust.core.network.TCPNetworkProcess",
        "AT_PEER_NAME": peer_name,
        "AT_AGENCY": role.agency,
        "AT_ROLE_KIND": role.kind,
        "AT_CAPABILITIES": caps,
        "AT_JOIN_PHASE": str(role.join_phase),
        "AT_POSITION_LAT": f"{role.position.lat:.6f}",
        "AT_POSITION_LON": f"{role.position.lon:.6f}",
        "LOG_LEVEL": opts.log_level,
        "STARTUP_DELAY": str(delay_sec),
    }
    env.update(opts.extra_env)

    # Compromised-sensor plumbing: the envdata service reads these flags
    # to know whether it's the rogue peer and when to flip.
    if role.metadata.get("compromised"):
        env["AT_COMPROMISED"] = "1"
        env["AT_COMPROMISE_ONSET_SEC"] = str(role.metadata.get(
            "compromise_onset_sec", 240))
        modes = role.metadata.get("compromise_modes") or []
        env["AT_COMPROMISE_MODES"] = ",".join(modes)

    lines = [
        f"  {peer_name}:",
        f"    image: {image}",
        f"    container_name: {peer_name}",
        f"    hostname: {peer_name}",
        f"    cap_add:",
        f"      - NET_ADMIN",
        f"    environment:",
    ]
    for k, v in env.items():
        # Escape double-quotes conservatively; values here are all simple.
        safe = str(v).replace('"', '\\"')
        lines.append(f'      {k}: "{safe}"')

    volumes = []
    if opts.scenario_mount:
        volumes.append(f"./scenario:{opts.scenario_mount}:ro")
    if opts.metrics_mount:
        volumes.append(f"{opts.metrics_mount}:/metrics")
    if volumes:
        lines.append("    volumes:")
        for v in volumes:
            lines.append(f"      - {v}")

    lines.extend([
        f"    networks:",
        f"      demo-net:",
        f"        ipv4_address: {ip}",
        "",
    ])
    return lines


def _inspector_entry(opts: ComposeOptions) -> list[str]:
    """Build the compose service for the civilian inspector container."""
    image = f"{opts.registry}{opts.inspector_image}{opts.image_tag}"
    ip = f"{opts.subnet.rsplit('.', 1)[0]}.{opts.inspector_last_octet}"
    env_lines = [
        f'      AT_PEER_NAME: "inspector"',
        f'      AUTONOMOUS_TRUST_BACKEND: "{opts.backend}"',
        f'      AT_TRANSPORT: "autonomous_trust.core.network.TCPNetworkProcess"',
        f'      LOG_LEVEL: "{opts.log_level}"',
        # The inspector joins a peer mesh that's already bootstrapping;
        # the default 5s choose_group window loses the race against UDP
        # broadcast + vote + finalize. 30s gives the existing peers
        # time to vote-and-respond. Peers themselves keep the default.
        f'      AT_INIT_TIMEOUT_SEC: "30"',
        # Hold inspector startup until peer TCP listeners are bound.
        # Peer 5s stagger × 9 = 40s for the synchronous batch (epa-1
        # joins at scenario T+360s regardless). 45s gives a safety
        # margin so the inspector's single request_access multicast
        # doesn't race peers' socket bind().
        f'      STARTUP_DELAY: "45"',
    ]
    # Forward Mapbox-related host env so the dashboard can opt into
    # tiled basemaps. MAPBOX is a truthy feature toggle (and may also
    # carry an access token for branded styles); MAPBOX_STYLE picks
    # the style. Only emitted when set on the host running the
    # compose generator.
    for var in ("MAPBOX", "MAPBOX_STYLE"):
        val = os.environ.get(var)
        if val:
            safe = val.replace('"', '\\"')
            env_lines.append(f'      {var}: "{safe}"')
    # Override the Dockerfile CMD so the inspector log level tracks
    # opts.log_level (the Dockerfile bakes in --log-level info).
    return [
        "  inspector:",
        f"    image: {image}",
        "    container_name: civilian-inspector",
        "    hostname: civilian-inspector",
        "    environment:",
        *env_lines,
        "    command:",
        '      - "python3"',
        '      - "-m"',
        '      - "autonomous_trust.inspector"',
        '      - "--demo-civilian"',
        '      - "--port"',
        '      - "8050"',
        '      - "--log-level"',
        f'      - "{opts.log_level}"',
        "    ports:",
        f'      - "{opts.inspector_host_port}:8050"',
        "    volumes:",
        f"      - ./scenario:{opts.scenario_mount}:ro",
        "    networks:",
        "      demo-net:",
        f"        ipv4_address: {ip}",
        "",
    ]


def generate_compose(scenario, opts: Optional[ComposeOptions] = None) -> str:
    """Return a docker-compose.yaml body for the given scenario."""
    opts = opts or ComposeOptions()
    lines: list[str] = ["services:"]

    # Deterministic IP assignment follows scenario peer order.
    for i, (name, role) in enumerate(scenario.peers.items()):
        ip = f"{opts.subnet.rsplit('.', 1)[0]}.{opts.first_ip + i}"
        # 5s stagger so early peers finish identity before later ones join.
        # Late joiners (epa-1) need a much longer stagger so they arrive
        # at the scenario's Onboarding phase (T+6:00 = 360s).
        if role.join_phase > 0 and scenario.phases \
                and role.join_phase < len(scenario.phases):
            delay = int(scenario.phases[role.join_phase].start.total_seconds())
        else:
            delay = i * 5
        lines.extend(_peer_entry(name, role, ip, delay, opts))

    if opts.include_inspector:
        lines.extend(_inspector_entry(opts))

    lines.extend([
        "networks:",
        "  demo-net:",
        "    driver: bridge",
        "    ipam:",
        "      config:",
        f"        - subnet: {opts.subnet}",
        "",
    ])
    return "\n".join(lines)


# ----------------------------------------------------------------------
# Kubernetes emission
# ----------------------------------------------------------------------

_K8S_DEPLOYMENT_TEMPLATE = """---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: {peer_name}
  namespace: {namespace}
  labels:
    app: {peer_name}
    agency: {agency_lower}
    kind: {role_kind}
    scenario: disaster-response
spec:
  replicas: 1
  selector:
    matchLabels:
      app: {peer_name}
  template:
    metadata:
      labels:
        app: {peer_name}
        agency: {agency_lower}
        kind: {role_kind}
        scenario: disaster-response
    spec:
      containers:
        - name: at
          image: {image}
          imagePullPolicy: IfNotPresent
          env:
{env_block}
          volumeMounts:
            - name: scenario-cfg
              mountPath: {scenario_mount}
              readOnly: true
          securityContext:
            capabilities:
              add: [NET_ADMIN]
      volumes:
        - name: scenario-cfg
          configMap:
            name: disaster-response-scenario
      restartPolicy: Always
"""


def _env_block(env: dict[str, str], indent: str = "            ") -> str:
    out = []
    for k, v in env.items():
        safe = str(v).replace('"', '\\"')
        out.append(f'{indent}- name: {k}')
        out.append(f'{indent}  value: "{safe}"')
    return "\n".join(out)


def generate_k8s_manifests(scenario, namespace: str = "disaster-demo",
                           opts: Optional[ComposeOptions] = None
                           ) -> dict[str, str]:
    """Return {filename: yaml_content} for per-agency manifests + ConfigMap.

    Late-joiner scheduling is handled by the init-container sleep pattern:
    peers whose scenario join_phase > 0 get a STARTUP_DELAY env that the
    container's entrypoint honors. (K8s has no native "start at T+N"
    mechanism; an operator controller would be overkill for a demo.)
    """
    opts = opts or ComposeOptions()
    image = f"{opts.registry}{opts.image}{opts.image_tag}"

    files: dict[str, str] = {}

    # Group peers by agency for file-per-agency layout the plan asks for.
    by_agency: dict[str, list[tuple[str, object]]] = {}
    for name, role in scenario.peers.items():
        by_agency.setdefault(role.agency, []).append((name, role))

    for agency, peers in by_agency.items():
        sections: list[str] = []
        for name, role in peers:
            env: dict[str, str] = {
                "ROUTER": opts.router,
                "AUTONOMOUS_TRUST_ARGS": (
                    f"--live --test --exclude-logs {opts.exclude_logs} "
                    f"--log-level {opts.log_level}"),
                "AUTONOMOUS_TRUST_BACKEND": opts.backend,
                "AT_TRANSPORT": "autonomous_trust.core.network.TCPNetworkProcess",
                "AT_PEER_NAME": name,
                "AT_AGENCY": role.agency,
                "AT_ROLE_KIND": role.kind,
                "AT_CAPABILITIES": ",".join(role.capabilities),
                "AT_JOIN_PHASE": str(role.join_phase),
                "AT_POSITION_LAT": f"{role.position.lat:.6f}",
                "AT_POSITION_LON": f"{role.position.lon:.6f}",
                "LOG_LEVEL": opts.log_level,
            }
            if role.join_phase > 0 and role.join_phase < len(scenario.phases):
                delay = int(scenario.phases[role.join_phase].start.total_seconds())
                env["STARTUP_DELAY"] = str(delay)
            if role.metadata.get("compromised"):
                env["AT_COMPROMISED"] = "1"
                env["AT_COMPROMISE_ONSET_SEC"] = str(role.metadata.get(
                    "compromise_onset_sec", 240))
                env["AT_COMPROMISE_MODES"] = ",".join(
                    role.metadata.get("compromise_modes") or [])
            env.update(opts.extra_env)

            sections.append(_K8S_DEPLOYMENT_TEMPLATE.format(
                peer_name=name,
                namespace=namespace,
                agency_lower=agency.lower(),
                role_kind=role.kind,
                image=image,
                env_block=_env_block(env),
                scenario_mount=opts.scenario_mount,
            ))
        files[f"{agency.lower()}.yaml"] = "".join(sections)

    # ConfigMap carrying the scenario definition (peers + phases) for any
    # consumer that needs to know the timeline at runtime.
    scenario_json = json.dumps(scenario.export_scenario_def(), indent=2)
    # Indent each line of scenario JSON by four spaces for YAML block scalar.
    indented = "\n".join("    " + line for line in scenario_json.splitlines())
    files["scenario-config.yaml"] = (
        f"---\n"
        f"apiVersion: v1\n"
        f"kind: ConfigMap\n"
        f"metadata:\n"
        f"  name: disaster-response-scenario\n"
        f"  namespace: {namespace}\n"
        f"data:\n"
        f"  scenario.json: |\n"
        f"{indented}\n"
    )

    # Namespace manifest (convenience for one-command apply).
    files["namespace.yaml"] = (
        f"---\n"
        f"apiVersion: v1\n"
        f"kind: Namespace\n"
        f"metadata:\n"
        f"  name: {namespace}\n"
    )

    return files


# ----------------------------------------------------------------------
# Top-level write helper + CLI
# ----------------------------------------------------------------------

def write_all(scenario, out_dir: str, namespace: str = "disaster-demo",
              opts: Optional[ComposeOptions] = None) -> dict[str, str]:
    """Write compose + k8s + scenario JSON under out_dir.

    Layout:
        out_dir/docker-compose.yaml
        out_dir/scenario/scenario.json   (for volume-mount from compose)
        out_dir/kubernetes/namespace.yaml
        out_dir/kubernetes/scenario-config.yaml
        out_dir/kubernetes/<agency>.yaml
    """
    os.makedirs(out_dir, exist_ok=True)
    os.makedirs(os.path.join(out_dir, "scenario"), exist_ok=True)
    os.makedirs(os.path.join(out_dir, "kubernetes"), exist_ok=True)

    written: dict[str, str] = {}

    compose = generate_compose(scenario, opts)
    compose_path = os.path.join(out_dir, "docker-compose.yaml")
    with open(compose_path, "w") as f:
        f.write(compose)
    written[compose_path] = compose

    scenario_path = os.path.join(out_dir, "scenario", "scenario.json")
    scenario_json = json.dumps(scenario.export_scenario_def(), indent=2)
    with open(scenario_path, "w") as f:
        f.write(scenario_json + "\n")
    written[scenario_path] = scenario_json

    k8s = generate_k8s_manifests(scenario, namespace, opts)
    for fname, body in k8s.items():
        p = os.path.join(out_dir, "kubernetes", fname)
        with open(p, "w") as f:
            f.write(body)
        written[p] = body

    return written


def _main(argv=None):
    p = argparse.ArgumentParser(description=(
        "Generate docker-compose and kubernetes manifests for the "
        "disaster-response civilian demo."))
    p.add_argument("--out", required=True,
                   help="Output directory (will be created).")
    p.add_argument("--namespace", default="disaster-demo",
                   help="Kubernetes namespace (default: disaster-demo).")
    p.add_argument("--image", default="autonomous-trust",
                   help="Container image name.")
    p.add_argument("--registry", default="",
                   help="Registry prefix (include trailing /).")
    p.add_argument("--image-tag", default="",
                   help="Image tag (include leading :).")
    p.add_argument("--log-level", default="info")
    p.add_argument("--backend", default="native")
    args = p.parse_args(argv)

    from .disaster_response import DisasterResponseScenario

    opts = ComposeOptions(
        image=args.image,
        registry=args.registry,
        image_tag=args.image_tag,
        log_level=args.log_level,
        backend=args.backend,
    )
    written = write_all(DisasterResponseScenario(), args.out,
                        namespace=args.namespace, opts=opts)
    for path in sorted(written):
        print(path)


if __name__ == "__main__":
    _main()
