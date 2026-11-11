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
# Run several AutonomousTrust C nodes on this host, each in its own network
# namespace with an ipvlan link on a Wi-Fi interface, so that they sit on the
# same wireless LAN as a hardware node (a Raspberry Pi 4) and discover it
# directly.
#
# AT finds peers by broadcast and multicast on the local segment, so every node
# needs an address on the Wi-Fi subnet itself. A Wi-Fi client link cannot be
# bridged and cannot carry macvlan, because the access point drops frames from
# MAC addresses that never associated with it. ipvlan gives each namespace its
# own IP address while sharing the parent's MAC, which the access point accepts.
#
# ipvlan isolates its namespaces from the parent interface: this host cannot
# reach the nodes' addresses over the Wi-Fi link, and they cannot reach it.
# `status` therefore reads each node's configuration from disk, and traffic is
# watched with: sudo tcpdump -ni wlan0 udp portrange 27787-27788
#
# The node binary should be a static x86_64 build from the same commit as the
# Pi's arm64 build (build-arm.sh --static --all-arch), so that both ends speak
# the same wire protocol.
#
# Usage:
#   sudo ./wifi-fleet.sh up [--nodes N] [--iface IF] [--first-ip ADDR] [--tarball PATH]
#   ./wifi-fleet.sh status [--pi USER@HOST]
#   sudo ./wifi-fleet.sh logs N
#   sudo ./wifi-fleet.sh down [--purge]

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
STATE_DIR="$SCRIPT_DIR/.wifi-fleet"
FLEET_ENV="$STATE_DIR/fleet.env"
NS_PREFIX="atwifi"
UNIT_PREFIX="at-wifi-node"
PI_AT_ROOT="/opt/autonomous-trust"

NODE_COUNT=4
IFACE="wlan0"
FIRST_IP=""
TARBALL="$SCRIPT_DIR/dist/autonomous-trust-amd64-static.tar.gz"
PI_HOST=""
PURGE=false

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
RESET='\033[0m'

info()  { echo -e "${YELLOW}[wifi-fleet]${RESET} $*"; }
pass()  { echo -e "${GREEN}[PASS]${RESET} $*"; }
fail()  { echo -e "${RED}[FAIL]${RESET} $*"; }
error() { echo -e "${RED}[wifi-fleet] ERROR:${RESET} $*" >&2; }

usage() {
    sed -n '/^# Usage:/,/^$/p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'
    echo "Defaults: --nodes $NODE_COUNT --iface $IFACE --first-ip <subnet>.201 (for a /24)"
    echo "          --tarball $TARBALL"
    exit "${1:-0}"
}

require_root() {
    if [ "$(id -u)" -ne 0 ]; then
        error "'$1' needs root for network namespaces and system units (use sudo)"
        exit 1
    fi
}

# Address arithmetic: add an offset to an IPv4 address.
ip_add() {
    python3 -I -c 'import ipaddress,sys; print(ipaddress.IPv4Address(sys.argv[1]) + int(sys.argv[2]))' "$1" "$2"
}

# Whether ADDR lies in the network of CIDR (an interface address with prefix).
ip_in_net() {
    python3 -I -c 'import ipaddress,sys; sys.exit(0 if ipaddress.IPv4Address(sys.argv[1]) in ipaddress.IPv4Interface(sys.argv[2]).network else 1)' "$1" "$2"
}

load_env() {
    if [ ! -f "$FLEET_ENV" ]; then
        error "No fleet recorded at $FLEET_ENV (run 'up' first)"
        exit 1
    fi
    # shellcheck source=/dev/null
    . "$FLEET_ENV"
}

node_root() { echo "$STATE_DIR/node-$1"; }

cmd_up() {
    require_root up
    local owner_uid="${SUDO_UID:-0}" owner_gid="${SUDO_GID:-0}"

    if [ -f "$FLEET_ENV" ] && ip netns list | grep -q "^${NS_PREFIX}"; then
        error "A fleet is already up; run 'down' first"
        exit 1
    fi
    if ! ip link show "$IFACE" &>/dev/null; then
        error "Interface $IFACE not found"
        exit 1
    fi
    local cidr
    cidr="$(ip -o -4 addr show dev "$IFACE" | awk '{print $4; exit}')"
    if [ -z "$cidr" ]; then
        error "$IFACE has no IPv4 address; connect it to the Wi-Fi network first"
        exit 1
    fi
    local prefix="${cidr#*/}"
    if [ -z "$FIRST_IP" ]; then
        if [ "$prefix" != "24" ]; then
            error "$IFACE is on a /$prefix network; pass --first-ip explicitly"
            exit 1
        fi
        FIRST_IP="$(echo "${cidr%/*}" | cut -d. -f1-3).201"
    fi
    info "Wi-Fi interface $IFACE is $cidr; nodes take $NODE_COUNT addresses from $FIRST_IP"

    # Pick addresses nobody answers on. Static addresses on a DHCP network can
    # collide with a lease, so choose a range outside the router's DHCP pool.
    local ips=() i ip
    for i in $(seq 0 $((NODE_COUNT - 1))); do
        ip="$(ip_add "$FIRST_IP" "$i")"
        if ! ip_in_net "$ip" "$cidr"; then
            error "$ip is outside $cidr"
            exit 1
        fi
        ping -c 1 -W 1 -I "$IFACE" "$ip" &>/dev/null || true
        if ip neigh show dev "$IFACE" "$ip" | grep -q lladdr; then
            error "$ip is already in use on $IFACE (answered ARP); choose another --first-ip"
            exit 1
        fi
        ips+=("$ip")
    done

    if [ ! -f "$TARBALL" ]; then
        error "Tarball not found: $TARBALL (build it with build-arm.sh --static --all-arch)"
        exit 1
    fi
    mkdir -p "$STATE_DIR/pkg"
    tar -xzf "$TARBALL" -C "$STATE_DIR/pkg"
    local bin="$STATE_DIR/pkg/opt/autonomous-trust/bin/at_demo"
    if [ ! -x "$bin" ]; then
        error "Tarball has no opt/autonomous-trust/bin/at_demo"
        exit 1
    fi
    if ldd "$bin" &>/dev/null; then
        info "WARNING: $bin is dynamically linked; it needs its libraries on this host"
    fi
    # The units drop to the invoking user, who must be able to reach the binary
    # and the node directories.
    chown -R "$owner_uid:$owner_gid" "$STATE_DIR"

    {
        echo "NODE_COUNT=$NODE_COUNT"
        echo "IFACE=$IFACE"
        echo "PREFIX=$prefix"
        echo "IPS=\"${ips[*]}\""
    } > "$FLEET_ENV"
    chown "$owner_uid:$owner_gid" "$FLEET_ENV"

    for i in $(seq 1 "$NODE_COUNT"); do
        local ns="${NS_PREFIX}${i}" link="atw${i}" root
        root="$(node_root "$i")"
        ip="${ips[$((i - 1))]}"
        ip netns add "$ns"
        ip link add link "$IFACE" name "$link" type ipvlan mode l2
        ip link set "$link" netns "$ns"
        ip -n "$ns" link set lo up
        ip -n "$ns" addr add "$ip/$prefix" dev "$link"
        ip -n "$ns" link set "$link" up
        mkdir -p "$root/etc/at" "$root/var/at"
        chown -R "$owner_uid:$owner_gid" "$root"

        # A transient system unit per node: restarts on failure, and survives
        # the desktop session that started it.
        systemd-run --quiet --unit="${UNIT_PREFIX}${i}" --collect \
            -p Restart=on-failure -p RestartSec=5 -p UMask=0077 \
            -E AUTONOMOUS_TRUST_ROOT="$root" \
            ip netns exec "$ns" \
            setpriv --reuid="$owner_uid" --regid="$owner_gid" --init-groups -- \
            "$bin" --generate-config --log-level info
        info "node $i: $ip in namespace $ns, unit ${UNIT_PREFIX}${i}"
        sleep 1
    done

    info "Started $NODE_COUNT nodes. Give them a minute, then:"
    info "  $0 status --pi <user>@<pi-address>"
}

# Print "uuid count addr,addr,..." for one node's group config on stdin.
group_summary() {
    jq -r '.[0] | "\(._uuid) \(._address_map | length) \([._address_map[]] | sort | join(","))"' 2>/dev/null \
        || echo "none 0 -"
}

cmd_status() {
    load_env
    local ok=true i uuid count addrs ref_uuid="" expect
    expect="$NODE_COUNT"
    [ -n "$PI_HOST" ] && expect=$((NODE_COUNT + 1))
    read -r -a ips <<< "$IPS"

    printf '%-6s %-16s %-9s %-10s %s\n' node address unit group members
    for i in $(seq 1 "$NODE_COUNT"); do
        local cfg state
        cfg="$(node_root "$i")/etc/at/group.cfg.json"
        state="$(systemctl is-active "${UNIT_PREFIX}${i}" 2>/dev/null || true)"
        read -r uuid count addrs < <(group_summary < "$cfg" 2>/dev/null || echo "none 0 -")
        printf '%-6s %-16s %-9s %-10s %s\n' "$i" "${ips[$((i - 1))]}" "$state" "${uuid:0:8}" "$count"
        [ "$state" = active ] || ok=false
        [ -z "$ref_uuid" ] && ref_uuid="$uuid"
        [ "$uuid" = "$ref_uuid" ] && [ "$uuid" != none ] || ok=false
        [ "$count" -ge "$expect" ] || ok=false
    done

    if [ -n "$PI_HOST" ]; then
        local pi_json pi_ip
        pi_json="$(ssh -o BatchMode=yes -o ConnectTimeout=5 "$PI_HOST" \
            "cat $PI_AT_ROOT/etc/at/group.cfg.json 2>/dev/null || sudo -n cat $PI_AT_ROOT/etc/at/group.cfg.json" 2>/dev/null || true)"
        pi_ip="$(ssh -o BatchMode=yes -o ConnectTimeout=5 "$PI_HOST" \
            "cat $PI_AT_ROOT/etc/at/network.cfg.json 2>/dev/null || sudo -n cat $PI_AT_ROOT/etc/at/network.cfg.json" 2>/dev/null \
            | jq -r '.ip4_cidr // empty' || true)"
        read -r uuid count addrs < <(echo "$pi_json" | group_summary)
        printf '%-6s %-16s %-9s %-10s %s\n' pi "${pi_ip%/*}" "$( [ -n "$pi_json" ] && echo reached || echo unreached)" "${uuid:0:8}" "$count"
        [ "$uuid" = "$ref_uuid" ] && [ "$uuid" != none ] || ok=false
        [ "$count" -ge "$expect" ] || ok=false
        for ip in "${ips[@]}"; do
            [[ ",$addrs," == *",$ip,"* ]] || { ok=false; info "the Pi's group does not list $ip"; }
        done
    fi

    if $ok; then
        pass "All nodes$( [ -n "$PI_HOST" ] && echo " and the Pi") share group ${ref_uuid:0:8} with at least $expect members"
    else
        fail "Not one cohort yet (want one group UUID, $expect members everywhere, all units active)"
        return 1
    fi
}

cmd_logs() {
    local n="${1:-}"
    [ -n "$n" ] || { error "logs needs a node number"; exit 1; }
    journalctl -u "${UNIT_PREFIX}${n}" -f
}

cmd_down() {
    require_root down
    local unit ns
    for unit in $(systemctl list-units --plain --no-legend --all "${UNIT_PREFIX}*" | awk '{print $1}'); do
        systemctl stop "$unit" || true
    done
    for ns in $(ip netns list | awk '{print $1}' | grep "^${NS_PREFIX}" || true); do
        ip netns delete "$ns"   # removes the ipvlan link inside it
    done
    if $PURGE; then
        rm -rf "$STATE_DIR"
        info "Stopped the fleet and removed $STATE_DIR (node identities are gone)"
    else
        rm -f "$FLEET_ENV"
        info "Stopped the fleet; node identities stay in $STATE_DIR for the next 'up'"
    fi
}

CMD="${1:-}"
[ -n "$CMD" ] || usage 1
shift
LOGS_NODE=""
while [[ $# -gt 0 ]]; do
    case "$1" in
        --nodes|-n)  NODE_COUNT="$2"; shift 2 ;;
        --iface)     IFACE="$2"; shift 2 ;;
        --first-ip)  FIRST_IP="$2"; shift 2 ;;
        --tarball)   TARBALL="$(realpath "$2")"; shift 2 ;;
        --pi)        PI_HOST="$2"; shift 2 ;;
        --purge)     PURGE=true; shift ;;
        -h|--help)   usage 0 ;;
        [0-9]*)      LOGS_NODE="$1"; shift ;;
        *)           error "Unknown option: $1"; usage 1 ;;
    esac
done

case "$CMD" in
    up)     cmd_up ;;
    status) cmd_status ;;
    logs)   cmd_logs "$LOGS_NODE" ;;
    down)   cmd_down ;;
    -h|--help|help) usage 0 ;;
    *)      error "Unknown command: $CMD"; usage 1 ;;
esac
