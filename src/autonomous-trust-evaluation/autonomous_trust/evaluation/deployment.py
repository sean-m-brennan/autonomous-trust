"""
Docker Compose generation helpers for AutonomousTrust demo scenarios.

Generates a docker-compose.yml from a Scenario definition, creating one
container per peer plus supporting services (simulator, inspector).

Docker limitations to be aware of (for future K8s migration):
  - Docker Compose networks are flat (no per-link bandwidth/latency shaping
    without tc/netem, which requires --cap-add NET_ADMIN).
  - No native support for node failure injection — must use docker pause/stop.
  - DNS-based service discovery is simple but doesn't support multicast.
  - Volume mounts for per-peer configs can get unwieldy at 20+ peers.
  - Docker Swarm mode adds overlay networking but complicates local dev.
"""

from __future__ import annotations

import textwrap
from pathlib import Path
from typing import Optional

import yaml

from .scenarios.scenario import Scenario, PeerRole


def generate_compose(
    scenario: Scenario,
    image_name: str,
    output_path: str | Path,
    inspector_port: int = 8050,
    simulator_port: int = 8051,
    network_subnet: str = "172.29.0.0/24",
    network_name: str = "demo-net",
    base_ip_offset: int = 10,
    extra_services: Optional[dict] = None,
) -> Path:
    """Generate a docker-compose.yml from a scenario definition.

    Each peer gets its own container with a static IP.  The inspector
    and simulator get dedicated containers.

    Args:
        scenario:        Scenario instance defining peers and phases
        image_name:      Docker image name for AT nodes
        output_path:     Where to write docker-compose.yml
        inspector_port:  Host port for the dashboard
        simulator_port:  Host port for the simulator API
        network_subnet:  Docker bridge network CIDR
        network_name:    Docker network name
        base_ip_offset:  First peer gets .10+offset, second .11+offset, etc.
        extra_services:  Additional services to merge into compose

    Returns:
        Path to the generated file
    """
    output_path = Path(output_path)

    subnet_base = network_subnet.rsplit(".", 2)[0]  # e.g. "172.29.0"

    services = {}

    # Simulator service
    services["simulator"] = {
        "image": image_name,
        "container_name": f"{scenario.name}-simulator",
        "command": ["python", "-m", "autonomous_trust.simulator",
                    "--config", "/etc/at/scenario.yml"],
        "ports": [f"{simulator_port}:8051"],
        "volumes": ["./scenario.yml:/etc/at/scenario.yml:ro"],
        "networks": {
            network_name: {
                "ipv4_address": f"{subnet_base}.2",
            }
        },
    }

    # Inspector / dashboard service
    services["inspector"] = {
        "image": image_name,
        "container_name": f"{scenario.name}-inspector",
        "command": ["python", "-m", "autonomous_trust.inspector",
                    "--port", str(inspector_port)],
        "ports": [f"{inspector_port}:8050"],
        "depends_on": ["simulator"],
        "networks": {
            network_name: {
                "ipv4_address": f"{subnet_base}.3",
            }
        },
    }

    # Per-peer services
    for i, (name, role) in enumerate(scenario.peers.items()):
        ip = f"{subnet_base}.{base_ip_offset + i}"
        peer_service = {
            "image": image_name,
            "container_name": _sanitize_container_name(name),
            "command": _peer_command(name, role),
            "environment": {
                "AUTONOMOUS_TRUST_ROOT": "/",
                "AT_PEER_NAME": name,
                "AT_AGENCY": role.agency,
            },
            "volumes": [
                f"./configs/{name}/:/etc/at/:ro",
            ],
            "depends_on": ["simulator"],
            "networks": {
                network_name: {
                    "ipv4_address": ip,
                }
            },
        }
        services[_sanitize_service_name(name)] = peer_service

    # Extra services (e.g. mock OCSP)
    if extra_services:
        services.update(extra_services)

    compose = {
        "services": services,
        "networks": {
            network_name: {
                "driver": "bridge",
                "ipam": {
                    "config": [{"subnet": network_subnet}],
                },
            }
        },
    }

    output_path.parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, "w") as f:
        f.write(f"# Auto-generated for scenario: {scenario.name}\n")
        f.write(f"# {scenario.description}\n\n")
        yaml.dump(compose, f, default_flow_style=False, sort_keys=False)

    return output_path


def generate_peer_configs(
    scenario: Scenario,
    output_dir: str | Path,
) -> Path:
    """Generate per-peer configuration directories.

    Creates output_dir/configs/<peer_name>/ with identity and
    subsystem configs for each peer.

    Returns:
        Path to the configs directory
    """
    output_dir = Path(output_dir)
    configs_dir = output_dir / "configs"

    for name, role in scenario.peers.items():
        peer_dir = configs_dir / name
        peer_dir.mkdir(parents=True, exist_ok=True)

        # Minimal peer config (AT's generate.py fills in the rest at runtime)
        peer_config = {
            "name": name,
            "agency": role.agency,
            "kind": role.kind,
            "capabilities": role.capabilities,
            "position": {
                "lat": role.position.lat,
                "lon": role.position.lon,
                "alt": role.position.alt,
            },
        }

        import json
        with open(peer_dir / "peer.cfg.json", "w") as f:
            json.dump(peer_config, f, indent=2)

    return configs_dir


def _sanitize_container_name(name: str) -> str:
    """Docker container names: lowercase, alphanumeric + hyphens."""
    return name.lower().replace("_", "-").replace(" ", "-")


def _sanitize_service_name(name: str) -> str:
    """Docker Compose service names: lowercase, alphanumeric + hyphens + underscores."""
    return name.lower().replace(" ", "-")


def _peer_command(name: str, role: PeerRole) -> list[str]:
    """Generate the command for a peer container."""
    return [
        "python", "-m", "autonomous_trust",
        "--name", name,
        "--config-dir", "/etc/at/",
    ]
