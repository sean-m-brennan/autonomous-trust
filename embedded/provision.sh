#!/usr/bin/env bash
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
#
# Generate provisioning configs for a fleet of Autonomous Trust nodes.
#
# Default mode: creates lightweight bootstrap configs (peer addresses, subnet,
# node names) that each device fleshes out on first boot via --generate-config.
#
# With --full-identity: uses at_demo to pre-generate complete identity and
# network configs, so devices are fully configured before deployment.
#
# Usage:
#   ./provision.sh --nodes 5 --subnet 192.168.1.0/24
#   ./provision.sh --nodes 3 --subnet 10.0.0.0/24 --start-ip 10.0.0.10
#   ./provision.sh --nodes 5 --subnet 192.168.1.0/24 --full-identity

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OUTPUT_DIR="$SCRIPT_DIR/fleet-configs"

NODE_COUNT=""
SUBNET=""
START_IP=""
NODE_PREFIX="at-node"
FULL_IDENTITY=false
STAGGER_DELAY=2  # seconds between node startups

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
RESET='\033[0m'

info()  { echo -e "${GREEN}[provision]${RESET} $*"; }
warn()  { echo -e "${YELLOW}[provision]${RESET} $*"; }
error() { echo -e "${RED}[provision]${RESET} $*" >&2; }

usage() {
    cat <<EOF
Usage: $0 --nodes N --subnet CIDR [OPTIONS]

Required:
  --nodes N            Number of nodes to provision
  --subnet CIDR        Network subnet (e.g., 192.168.1.0/24)

Options:
  --start-ip IP        First node IP (default: derived from subnet + 10)
  --prefix NAME        Node name prefix (default: at-node)
  --stagger-delay S    Seconds between node startups (default: 2)
  --full-identity      Pre-generate full identity configs via at_demo
  --output DIR         Output directory (default: ./fleet-configs)
  -h, --help           Show this help
EOF
    exit 0
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --nodes)          NODE_COUNT="$2"; shift 2 ;;
        --subnet)         SUBNET="$2"; shift 2 ;;
        --start-ip)       START_IP="$2"; shift 2 ;;
        --prefix)         NODE_PREFIX="$2"; shift 2 ;;
        --stagger-delay)  STAGGER_DELAY="$2"; shift 2 ;;
        --full-identity)  FULL_IDENTITY=true; shift ;;
        --output)         OUTPUT_DIR="$2"; shift 2 ;;
        -h|--help)        usage ;;
        *)                error "Unknown option: $1"; exit 1 ;;
    esac
done

if [ -z "$NODE_COUNT" ] || [ -z "$SUBNET" ]; then
    error "Both --nodes and --subnet are required"
    usage
fi

# Parse subnet to derive start IP if not provided
SUBNET_BASE="${SUBNET%/*}"
if [ -z "$START_IP" ]; then
    # Take the base and add .10 (skip .0-.9 for gateways/infrastructure)
    IFS='.' read -r a b c _d <<< "$SUBNET_BASE"
    START_IP="${a}.${b}.${c}.10"
fi

# Increment an IPv4 address by N
ip_add() {
    local ip="$1" n="$2"
    IFS='.' read -r a b c d <<< "$ip"
    local num=$(( (a << 24) + (b << 16) + (c << 8) + d + n ))
    echo "$(( (num >> 24) & 255 )).$(( (num >> 16) & 255 )).$(( (num >> 8) & 255 )).$(( num & 255 ))"
}

info "Provisioning $NODE_COUNT nodes on $SUBNET (starting at $START_IP)"
rm -rf "$OUTPUT_DIR"
mkdir -p "$OUTPUT_DIR"

# Collect all peer IPs
PEER_IPS=()
for i in $(seq 0 $((NODE_COUNT - 1))); do
    PEER_IPS+=("$(ip_add "$START_IP" "$i")")
done

for i in $(seq 0 $((NODE_COUNT - 1))); do
    node_name="${NODE_PREFIX}-$((i + 1))"
    node_ip="${PEER_IPS[$i]}"
    node_dir="$OUTPUT_DIR/$node_name"
    config_dir="$node_dir/opt/autonomous-trust/etc/at"
    bootstrap_dir="$node_dir/opt/autonomous-trust/etc/at/bootstrap"
    mkdir -p "$config_dir" "$bootstrap_dir"

    info "  $node_name ($node_ip)"

    # Build peer list (all nodes except self)
    peer_list="[]"
    for j in $(seq 0 $((NODE_COUNT - 1))); do
        if [ "$j" -ne "$i" ]; then
            peer_entry="{\"address\": \"${PEER_IPS[$j]}\", \"name\": \"${NODE_PREFIX}-$((j + 1))\"}"
            if [ "$peer_list" = "[]" ]; then
                peer_list="[$peer_entry"
            else
                peer_list="$peer_list, $peer_entry"
            fi
        fi
    done
    [ "$peer_list" != "[]" ] && peer_list="$peer_list]"

    # Write bootstrap config (in subdirectory to avoid at_demo config scan)
    cat > "$bootstrap_dir/bootstrap.cfg.json" <<BOOTSTRAP
{
    "node_name": "$node_name",
    "node_address": "$node_ip",
    "subnet": "$SUBNET",
    "peers": $peer_list
}
BOOTSTRAP

    # Write environment overrides
    cat > "$config_dir/environment" <<ENV
LOG_LEVEL=info
STARTUP_DELAY=$((i * STAGGER_DELAY))
AUTONOMOUS_TRUST_ARGS=
ENV

    if $FULL_IDENTITY; then
        if ! command -v at_demo &>/dev/null; then
            error "at_demo not found in PATH (required for --full-identity)"
            error "Install it first, or omit --full-identity for bootstrap-only configs"
            exit 1
        fi
        info "    Generating full identity for $node_name ..."
        AUTONOMOUS_TRUST_ROOT="$node_dir/opt/autonomous-trust" \
            at_demo --generate-config --log-level error 2>/dev/null || \
            warn "    at_demo config generation returned non-zero for $node_name"
    fi

    # Package per-node tarball
    tar -czf "$OUTPUT_DIR/${node_name}.tar.gz" -C "$node_dir" .
done

# Clean up staging directories
for i in $(seq 0 $((NODE_COUNT - 1))); do
    rm -rf "$OUTPUT_DIR/${NODE_PREFIX}-$((i + 1))"
done

info ""
info "Fleet configs written to $OUTPUT_DIR/"
ls -lh "$OUTPUT_DIR"/*.tar.gz
info ""
info "Deploy to each device with:"
info "  scp $OUTPUT_DIR/<node>.tar.gz pi@<device>:/tmp/"
info "  ssh pi@<device> 'sudo tar -xzf /tmp/<node>.tar.gz -C /'"
info "  ssh pi@<device> 'sudo systemctl restart autonomous-trust'"
