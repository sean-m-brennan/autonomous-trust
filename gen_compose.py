#!/usr/bin/env python3
"""Generate docker-compose.tilt.yaml for N AutonomousTrust peer nodes."""

import sys


def generate_compose(num_nodes: int, exclude_logs: str = "network",
                     log_level: str = "info", backend: str = "native") -> str:
    lines = ["services:"]
    for i in range(1, num_nodes + 1):
        delay = (i - 1) * 10
        ip = f"172.27.3.{10 + i}"
        exclude_arg = f"--exclude-logs {exclude_logs}" if exclude_logs else ""
        log_arg = f"--log-level {log_level}" if log_level else ""
        args = f"--live --test {exclude_arg} {log_arg}".strip()
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
            f"      AUTONOMOUS_TRUST_BACKEND: \"{backend}\"",
            f"      LOG_LEVEL: \"{log_level}\"",
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
    log_level = sys.argv[3] if len(sys.argv) > 3 else "info"
    backend = sys.argv[4] if len(sys.argv) > 4 else "native"
    content = generate_compose(num_nodes, exclude_logs, log_level, backend)
    with open("docker-compose.tilt.yaml", "w") as f:
        f.write(content)
    print(f"Generated docker-compose.tilt.yaml for {num_nodes} nodes (backend={backend})")


if __name__ == "__main__":
    main()
