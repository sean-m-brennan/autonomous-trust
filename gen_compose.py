#!/usr/bin/env python3
"""Generate docker-compose.tilt.yaml for N AutonomousTrust peer nodes."""

import sys


def generate_compose(num_nodes: int, exclude_logs: str = "network") -> str:
    lines = ["services:"]
    for i in range(1, num_nodes + 1):
        delay = (i - 1) * 10
        ip = f"172.27.3.{10 + i}"
        exclude_arg = f"--exclude-logs {exclude_logs}" if exclude_logs else ""
        args = f"--live --test {exclude_arg}".strip()
        lines.extend([
            f"  at-{i}:",
            f"    image: autonomous-trust",
            f"    container_name: at-{i}",
            f"    hostname: at-{i}",
            f"    cap_add:",
            f"      - NET_ADMIN",
            f"    environment:",
            f"      ROUTER: \"172.27.3.1\"",
            f"      AUTONOMOUS_TRUST_ARGS: \"{args}\"",
            f"      STARTUP_DELAY: \"{delay}\"",
            f"    networks:",
            f"      at-net:",
            f"        ipv4_address: {ip}",
            "",
        ])

    lines.extend([
        "networks:",
        "  at-net:",
        "    driver: bridge",
        "    ipam:",
        "      config:",
        "        - subnet: 172.27.3.0/24",
        "",
    ])
    return "\n".join(lines)


def main():
    num_nodes = int(sys.argv[1]) if len(sys.argv) > 1 else 2
    exclude_logs = sys.argv[2] if len(sys.argv) > 2 else "network"
    content = generate_compose(num_nodes, exclude_logs)
    with open("docker-compose.tilt.yaml", "w") as f:
        f.write(content)
    print(f"Generated docker-compose.tilt.yaml for {num_nodes} nodes")


if __name__ == "__main__":
    main()
