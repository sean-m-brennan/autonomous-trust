#!/usr/bin/env python3
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
"""Generate docker-compose.tilt.yaml for N AutonomousTrust peer nodes."""

import sys


def generate_compose(num_nodes: int, exclude_logs: str = "network",
                     log_level: str = "info", backend: str = "native",
                     metrics_dir: str = "") -> str:
    lines = ["services:"]
    for i in range(1, num_nodes + 1):
        delay = (i - 1) * 5
        ip = f"10.27.3.{10 + i}"
        exclude_arg = f"--exclude-logs {exclude_logs}" if exclude_logs else ""
        log_arg = f"--log-level {log_level}" if log_level else ""
        args = f"--live --test {exclude_arg} {log_arg}".strip()
        # First node runs instrumented entry point for metrics collection.
        # When metrics_dir is set, ALL nodes must use the same image so that
        # PackageHash digests match (otherwise peers reject each other as
        # "counterfeit").
        collect_metrics = metrics_dir and i == 1
        if collect_metrics:
            exe = "-m autonomous_trust.evaluation.instrumented"
            metrics_args = f"--metrics-output /metrics/metrics.json {args}"
        else:
            exe = "-m autonomous_trust"
            metrics_args = args
        image = "autonomous-trust-full-devel" if metrics_dir else "autonomous-trust"
        lines.extend([
            f"  at-{i}:",
            f"    image: {image}",
            f"    container_name: at-{i}",
            f"    hostname: at-{i}",
            f"    cap_add:",
            f"      - NET_ADMIN",
            f"    environment:",
            f"      ROUTER: \"10.27.3.1\"",
            f"      AUTONOMOUS_TRUST_ARGS: \"{metrics_args}\"",
            f"      AUTONOMOUS_TRUST_BACKEND: \"{backend}\"",
            f"      LOG_LEVEL: \"{log_level}\"",
            f"      STARTUP_DELAY: \"{delay}\"",
        ])
        if collect_metrics:
            lines.extend([
                f"      AUTONOMOUS_TRUST_EXE: \"{exe}\"",
                f"    volumes:",
                f"      - {metrics_dir}:/metrics",
            ])
        lines.extend([
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
        "        - subnet: 10.27.3.0/24",
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
