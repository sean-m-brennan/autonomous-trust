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

"""Docker Compose + Kubernetes manifest generation for the multi-agency demo.

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
    # Peer image must include autonomous_trust.evaluation + .services so
    # the disaster_response_demo entrypoint can import. The bare
    # autonomous-trust image only ships .core; see
    # src/autonomous-trust-evaluation/Dockerfile for the overlay that
    # produces this image.
    image: str = "autonomous-trust-disaster"
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
    # Multi-agency-demo inspector container. Runs the Dash server + bridge
    # on the same demo-net so it can observe peer traffic. Shares the
    # registry/image_tag of the peer image.
    inspector_image: str = "autonomous-trust-inspector"
    inspector_last_octet: int = 250        # subnet host byte for the inspector
    inspector_host_port: int = 8050        # published to host
    include_inspector: bool = True         # set False to suppress the service
    # Debug-probes wiring (see core/_python/_probes/). When `probes` is
    # true, every container gets AT_PROBES=1 and the host directory
    # `probes_host_dir` is bind-mounted at `probes_container_dir`. Defaults
    # honor host env so callers can flip probes on with
    # `AT_PROBES=1 ./scripts/run-demo.sh --variant=multi-agency` without code changes.
    probes: bool = field(default_factory=lambda: bool(os.environ.get('AT_PROBES')))
    probes_host_dir: str = field(default_factory=lambda: os.environ.get('AT_PROBES_HOST_DIR', './at-probes'))
    probes_container_dir: str = '/var/at-probes'


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
        # Boot the peer via the disaster-response entrypoint instead of
        # the stock `autonomous_trust` module so DisasterResponseDemoAT
        # is instantiated. That subclass adds the EnvData* worker matching
        # AT_ROLE_KIND and writes the per-role envdata config so the
        # service activates and starts publishing readings.
        "AUTONOMOUS_TRUST_EXE": (
            "-m autonomous_trust.evaluation.scenarios.disaster_response_demo"),
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
    if opts.probes:
        env["AT_PROBES"] = "1"
        env["AT_PROBES_DIR"] = opts.probes_container_dir
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
    if opts.probes:
        # Shared host-bind so `scripts/probe-tail.py --dir <host_dir>`
        # can read every peer's JSONL without docker volume cp.
        volumes.append(f"{opts.probes_host_dir}:{opts.probes_container_dir}")
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
    """Build the compose service for the multi-agency inspector container."""
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
    if opts.probes:
        env_lines.append(f'      AT_PROBES: "1"')
        env_lines.append(f'      AT_PROBES_DIR: "{opts.probes_container_dir}"')
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
    volume_lines = [f"      - ./scenario:{opts.scenario_mount}:ro"]
    if opts.probes:
        volume_lines.append(f"      - {opts.probes_host_dir}:{opts.probes_container_dir}")
    # Override the Dockerfile CMD so the inspector log level tracks
    # opts.log_level (the Dockerfile bakes in --log-level info).
    return [
        "  inspector:",
        f"    image: {image}",
        "    container_name: multi-agency-inspector",
        "    hostname: multi-agency-inspector",
        "    environment:",
        *env_lines,
        "    command:",
        '      - "python3"',
        '      - "-m"',
        '      - "examples.multi_agency"',
        '      - "--port"',
        '      - "8050"',
        '      - "--log-level"',
        f'      - "{opts.log_level}"',
        "    ports:",
        f'      - "{opts.inspector_host_port}:8050"',
        "    volumes:",
        *volume_lines,
        "    networks:",
        "      demo-net:",
        f"        ipv4_address: {ip}",
        "",
    ]


def generate_compose(scenario, opts: Optional[ComposeOptions] = None) -> str:
    """Return a docker-compose.yaml body for the given scenario."""
    opts = opts or ComposeOptions()
    lines: list[str] = ["services:"]

    # Per-peer setup-phase stagger. Default keeps the historical
    # `i * 5s` behaviour (group_size=1, sec=5 → 5 s per peer). At
    # scale this becomes painful — 100 peers compounds to ~8 min of
    # accumulated startup delay — so callers can override with env:
    #   AT_PEER_STAGGER_GROUP=10   peers per group (default 1)
    #   AT_PEER_STAGGER_SEC=1      seconds per group (default 5)
    # E.g. GROUP=10 SEC=1 spreads 100 peers over ~10 s instead of
    # ~500 s. Matches the DoD generator's pattern; see
    # examples/dod_mission/deploy/generate_compose.py.
    stagger_group = max(1, int(os.environ.get("AT_PEER_STAGGER_GROUP", "1")))
    stagger_sec = max(0, int(os.environ.get("AT_PEER_STAGGER_SEC", "5")))

    # Deterministic IP assignment follows scenario peer order.
    for i, (name, role) in enumerate(scenario.peers.items()):
        ip = f"{opts.subnet.rsplit('.', 1)[0]}.{opts.first_ip + i}"
        # Late joiners (epa-1) need a much longer stagger so they arrive
        # at the scenario's Onboarding phase (T+6:00 = 360s).
        if role.join_phase > 0 and scenario.phases \
                and role.join_phase < len(scenario.phases):
            delay = int(scenario.phases[role.join_phase].start.total_seconds())
        else:
            delay = (i // stagger_group) * stagger_sec
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
            - name: AT_K8S_NAMESPACE
              valueFrom:
                fieldRef:
                  fieldPath: metadata.namespace
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


# NodePort for the in-cluster inspector. Falls in the standard
# 30000-32767 range that k8s reserves for NodePort services.
_INSPECTOR_NODE_PORT = 30850


def _inspector_k8s_yaml(opts: ComposeOptions, namespace: str) -> str:
    """Deployment + NodePort Service for the multi-agency inspector.

    Mirrors `_inspector_entry` (compose) so behavior is identical
    across backends. The inspector pod sits on the regular cluster
    network, talks to peers in the same namespace via TCP, and exposes
    its Dash UI on NodePort 30850 so `minikube service` yields a
    browser-ready URL."""
    image = f"{opts.registry}{opts.inspector_image}{opts.image_tag}"

    env: dict[str, str] = {
        "ROUTER": opts.router,
        "AUTONOMOUS_TRUST_BACKEND": opts.backend,
        "AT_TRANSPORT": "autonomous_trust.core.network.TCPNetworkProcess",
        "AT_PEER_NAME": "inspector",
        # Same race-margin tuning as the compose bridge — inspector joins
        # an already-bootstrapping mesh, so the choose_group window and
        # startup delay are both lengthened.
        "AT_INIT_TIMEOUT_SEC": "30",
        "STARTUP_DELAY": "45",
        "LOG_LEVEL": opts.log_level,
    }
    # Forward Mapbox env (host → cluster) when present, identical to the
    # compose path. Skipped silently when unset.
    for var in ("MAPBOX", "MAPBOX_STYLE"):
        val = os.environ.get(var)
        if val:
            env[var] = val
    env.update(opts.extra_env)

    return f"""---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: multi-agency-inspector
  namespace: {namespace}
  labels:
    app: multi-agency-inspector
    role: inspector
    scenario: disaster-response
spec:
  replicas: 1
  selector:
    matchLabels:
      app: multi-agency-inspector
  template:
    metadata:
      labels:
        app: multi-agency-inspector
        role: inspector
        scenario: disaster-response
    spec:
      containers:
        - name: inspector
          image: {image}
          imagePullPolicy: IfNotPresent
          command:
            - "python3"
            - "-m"
            - "examples.multi_agency"
            - "--port"
            - "8050"
            - "--namespace"
            - "{namespace}"
            - "--log-level"
            - "{opts.log_level}"
          ports:
            - name: http
              containerPort: 8050
          env:
            - name: AT_K8S_NAMESPACE
              valueFrom:
                fieldRef:
                  fieldPath: metadata.namespace
{_env_block(env)}
          volumeMounts:
            - name: scenario-cfg
              mountPath: {opts.scenario_mount}
              readOnly: true
          readinessProbe:
            httpGet:
              path: /
              port: 8050
            initialDelaySeconds: 60
            periodSeconds: 5
            failureThreshold: 12
      volumes:
        - name: scenario-cfg
          configMap:
            name: disaster-response-scenario
      restartPolicy: Always
---
apiVersion: v1
kind: Service
metadata:
  name: multi-agency-inspector
  namespace: {namespace}
  labels:
    app: multi-agency-inspector
    role: inspector
    scenario: disaster-response
spec:
  type: NodePort
  selector:
    app: multi-agency-inspector
  ports:
    - name: http
      port: 8050
      targetPort: 8050
      nodePort: {_INSPECTOR_NODE_PORT}
"""


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
                "AUTONOMOUS_TRUST_EXE": (
                    "-m autonomous_trust.evaluation.scenarios.disaster_response_demo"),
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

    if opts.include_inspector:
        files["inspector.yaml"] = _inspector_k8s_yaml(opts, namespace)

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
        out_dir/kubernetes/inspector.yaml   (Deployment + NodePort, when
                                             include_inspector=True)
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
        "disaster-response multi-agency demo."))
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
