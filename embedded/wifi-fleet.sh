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
# `status` therefore reads each node's group from disk and its peers from its
# journal, and traffic is watched with:
#   sudo tcpdump -ni wlan0 udp portrange 27787-27788
#
# The node binary should be a static x86_64 build from the same commit as the
# Pi's arm64 build (build-arm.sh --static --all-arch), so that both ends speak
# the same wire protocol.
#
# Usage:
#   sudo ./wifi-fleet.sh up [--nodes N] [--iface IF] [--first-ip ADDR] [--tarball PATH]
#                           [--bad-node N --bad-bin PATH [--defect-after SECONDS]]
#   ./wifi-fleet.sh status [--pi USER@HOST | --pi-addr ADDR]
#   ./wifi-fleet.sh latency [--pi USER@HOST]
#   sudo ./wifi-fleet.sh logs N
#   sudo ./wifi-fleet.sh down [--purge]

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
STATE_DIR="$SCRIPT_DIR/.wifi-fleet"
FLEET_ENV="$STATE_DIR/fleet.env"
# Each node's root as AT sees it: a short symlink to its directory under
# STATE_DIR. AT puts its unix sockets under the root, and a socket path holds
# 108 bytes, which the checkout's own path already nearly fills.
LINK_DIR="/run/at-wifi"
NS_PREFIX="atwifi"
UNIT_PREFIX="at-wifi-node"
PI_AT_ROOT="/opt/autonomous-trust"

NODE_COUNT=4
IFACE="wlan0"
FIRST_IP=""
TARBALL="$SCRIPT_DIR/dist/autonomous-trust-amd64-static.tar.gz"
PI_HOST=""
PI_ADDR=""
BAD_NODE=""
BAD_BIN=""
DEFECT_AFTER=180
DEFECT_AT=""          # set by up, read back from fleet.env
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

    # A bad node runs a red-team build (cmake -DAT_REDTEAM=ON), which answers
    # the handshake and echo probes wrongly from AT_REDTEAM_DEFECT_AT on. A
    # release build ignores that variable, so refuse one rather than run a
    # "bad" node that never misbehaves.
    local bad_bin="" defect_at=""
    if [ -n "$BAD_NODE" ]; then
        if [ -z "$BAD_BIN" ] || [ ! -x "$BAD_BIN" ]; then
            error "--bad-node needs --bad-bin PATH to a red-team at_demo"
            exit 1
        fi
        if ! grep -qa AT_REDTEAM_DEFECT_AT "$BAD_BIN"; then
            error "$BAD_BIN is not a red-team build (configure it with -DAT_REDTEAM=ON)"
            exit 1
        fi
        if [ "$BAD_NODE" -lt 1 ] || [ "$BAD_NODE" -gt "$NODE_COUNT" ]; then
            error "--bad-node must be between 1 and $NODE_COUNT"
            exit 1
        fi
        mkdir -p "$STATE_DIR/redteam"
        cp "$BAD_BIN" "$STATE_DIR/redteam/at_demo"
        bad_bin="$STATE_DIR/redteam/at_demo"
        defect_at=$(( $(date +%s) + DEFECT_AFTER ))
    fi
    # The units drop to the invoking user, who must be able to reach the binary
    # and the node directories.
    chown -R "$owner_uid:$owner_gid" "$STATE_DIR"

    {
        echo "NODE_COUNT=$NODE_COUNT"
        echo "IFACE=$IFACE"
        echo "PREFIX=$prefix"
        echo "IPS=\"${ips[*]}\""
        echo "BAD_NODE=$BAD_NODE"
        echo "DEFECT_AT=$defect_at"
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
        mkdir -p "$LINK_DIR"
        ln -sfn "$root" "$LINK_DIR/$i"

        local node_bin="$bin" node_env=()
        if [ "$i" = "$BAD_NODE" ]; then
            node_bin="$bad_bin"
            node_env=(-E "AT_REDTEAM_DEFECT_AT=$defect_at")
        fi

        # A transient system unit per node: restarts on failure, and survives
        # the desktop session that started it.
        systemd-run --quiet --unit="${UNIT_PREFIX}${i}" --collect \
            -p Restart=on-failure -p RestartSec=5 -p UMask=0077 \
            -E AUTONOMOUS_TRUST_ROOT="$LINK_DIR/$i" "${node_env[@]}" \
            ip netns exec "$ns" \
            setpriv --reuid="$owner_uid" --regid="$owner_gid" --init-groups -- \
            "$node_bin" --generate-config --log-level info
        info "node $i: $ip in namespace $ns, unit ${UNIT_PREFIX}${i}$( [ "$i" = "$BAD_NODE" ] && echo ", red team: defects at $(date -d "@$defect_at" +%T)")"
        sleep 1
    done

    info "Started $NODE_COUNT nodes. Give them a minute, then:"
    info "  $0 status --pi <user>@<pi-address>   (or --pi-addr <pi-address> without SSH)"
}

# Print "uuid" for one node's group config on stdin. The group's address map
# is not a member list (a member can hold the group key without appearing in
# it), so membership is read from the peers each node has added instead.
group_uuid() {
    jq -r '.[0]._uuid // "none"' 2>/dev/null || echo none
}

# Print the addresses node N has added as peers since its unit last started,
# one per line, from net_proc's "Network: added peer NAME (ADDR)" log line.
node_peers() {
    local unit="${UNIT_PREFIX}$1" since
    since="$(systemctl show -p ActiveEnterTimestamp --value "$unit" 2>/dev/null || true)"
    [ -n "$since" ] || return 0
    journalctl -q --no-pager -u "$unit" --since "$since" -o cat 2>/dev/null \
        | sed -n 's/.*Network: added peer [^ ]* (\([^)]*\)).*/\1/p' | sort -u
}

cmd_status() {
    load_env
    local ok=true i uuid ref_uuid="" expect state
    read -r -a ips <<< "$IPS"

    # The Pi's address: given, or read over SSH from the Pi's network config
    if [ -n "$PI_HOST" ]; then
        local pi_json
        pi_json="$(ssh -o BatchMode=yes -o ConnectTimeout=5 "$PI_HOST" \
            "cat $PI_AT_ROOT/etc/at/network.cfg.json 2>/dev/null || sudo -n cat $PI_AT_ROOT/etc/at/network.cfg.json" 2>/dev/null || true)"
        [ -n "$PI_ADDR" ] || PI_ADDR="$(echo "$pi_json" | jq -r '.ip4_cidr // empty' 2>/dev/null || true)"
        PI_ADDR="${PI_ADDR%/*}"
        [ -n "$PI_ADDR" ] || { ok=false; info "could not read the Pi's address over SSH from $PI_HOST"; }
    fi
    # Every other host node, plus the Pi when one is named
    expect=$((NODE_COUNT - 1))
    [ -n "$PI_HOST$PI_ADDR" ] && expect=$((expect + 1))

    printf '%-6s %-16s %-9s %-10s %-6s %s\n' node address unit group peers pi
    for i in $(seq 1 "$NODE_COUNT"); do
        local peers count has_pi="-"
        state="$(systemctl is-active "${UNIT_PREFIX}${i}" 2>/dev/null || true)"
        uuid="$(group_uuid < "$(node_root "$i")/etc/at/group.cfg.json" 2>/dev/null || echo none)"
        peers="$(node_peers "$i")"
        count="$(grep -c . <<< "$peers" || true)"
        if [ -n "$PI_ADDR" ]; then
            if grep -qxF "$PI_ADDR" <<< "$peers"; then has_pi=yes; else has_pi=no; ok=false; fi
        fi
        printf '%-6s %-16s %-9s %-10s %-6s %s\n' "$i" "${ips[$((i - 1))]}" "$state" "${uuid:0:8}" "$count" "$has_pi"
        [ "$state" = active ] || ok=false
        [ -z "$ref_uuid" ] && ref_uuid="$uuid"
        [ "$uuid" = "$ref_uuid" ] && [ "$uuid" != none ] || ok=false
        [ "$count" -ge "$expect" ] || ok=false
    done

    # Over SSH, the Pi's own group must be the same one
    if [ -n "$PI_HOST" ]; then
        local pi_group
        pi_group="$(ssh -o BatchMode=yes -o ConnectTimeout=5 "$PI_HOST" \
            "cat $PI_AT_ROOT/etc/at/group.cfg.json 2>/dev/null || sudo -n cat $PI_AT_ROOT/etc/at/group.cfg.json" 2>/dev/null || true)"
        uuid="$(echo "$pi_group" | group_uuid)"
        printf '%-6s %-16s %-9s %-10s\n' pi "$PI_ADDR" "$( [ -n "$pi_group" ] && echo reached || echo unreached)" "${uuid:0:8}"
        [ "$uuid" = "$ref_uuid" ] && [ "$uuid" != none ] || ok=false
    fi

    if $ok; then
        pass "All nodes share group ${ref_uuid:0:8} and have each added at least $expect peers$( [ -n "$PI_ADDR" ] && echo ", the Pi ($PI_ADDR) among them")"
    else
        fail "Not one cohort yet (want one group UUID, $expect peers added by every node$( [ -n "$PI_ADDR" ] && echo " including $PI_ADDR"), all units active)"
        return 1
    fi
}

# Print "<detected> <tier0> <excluded>" for one observer's AT log on stdin:
# the timestamps (AT's own ISO time, which leads each line) of its first 0.10
# probe score for the bad node, of its first score for it below 0.5 after one
# at or above (the fall to tier 0, where every gate above tier 0 closes; a
# peer scored with no evidence starts at the 0.2 prior, already in tier 0, so
# only a fall from earned trust counts), and of its excluding the bad node at
# the network layer, or "-" for any it has not logged. Wrong probe answers
# alone cannot exclude: each scores 0.1, and the average is drawn toward the
# 0.2 prior, so only a slash puts a peer below the 0.1 cut-off.
observer_times() {
    awk -v nick="$1" -v uuid8="$2" '
        det == "" && index($0, "scored 0.10 for " nick " ") && index($0, "via probe") { det = substr($0, 1, 23) }
        t0 == "" && index($0, "peer reputation: " uuid8) && match($0, /score=[0-9.]+/) {
            score = substr($0, RSTART + 6, RLENGTH - 6) + 0
            if (score >= 0.5) high = 1
            else if (high) t0 = substr($0, 1, 23)
        }
        exc == "" && index($0, "Reputation: excluded " uuid8 " ") { exc = substr($0, 1, 23) }
        END { print (det == "" ? "-" : det), (t0 == "" ? "-" : t0), (exc == "" ? "-" : exc) }'
}

# Seconds from Unix time $2 to ISO time $1, or "-" for "-"
seconds_after() {
    if [ "$1" = - ]; then
        echo -
        return
    fi
    local t
    t="$(date -u -d "${1/T/ }" +%s.%N)"
    awk -v t="$t" -v t0="$2" 'BEGIN { printf "%.1f s\n", t - t0 }'
}

# One row of the latency table, for an observer's log on stdin
latency_row() {
    local det t0 exc
    read -r det t0 exc < <(observer_times "$3" "$4")
    printf '%-14s %-16s %12s %12s %12s\n' "$1" "$2" \
        "$(seconds_after "$det" "$DEFECT_AT")" "$(seconds_after "$t0" "$DEFECT_AT")" \
        "$(seconds_after "$exc" "$DEFECT_AT")"
}

# Seconds from the bad node's defection to each observer's detection of it,
# its fall to tier 0 and its exclusion, from that observer's log
cmd_latency() {
    load_env
    if [ -z "${BAD_NODE:-}" ] || [ -z "${DEFECT_AT:-}" ]; then
        error "This fleet has no bad node; start it with: up --bad-node N --bad-bin PATH"
        exit 1
    fi
    local ident nick uuid8 i
    ident="$(node_root "$BAD_NODE")/etc/at/identity.cfg.json"
    nick="$(jq -r .nickname "$ident")"
    uuid8="$(jq -r .uuid "$ident" | cut -c1-8)"
    info "bad node $BAD_NODE ($nick, $uuid8) defects at $(date -d "@$DEFECT_AT" '+%F %T %Z')"
    if [ "$(date +%s)" -lt "$DEFECT_AT" ]; then
        info "it has not defected yet"
        return 0
    fi

    read -r -a ips <<< "$IPS"
    printf '%-14s %-16s %12s %12s %12s\n' observer address detected "tier 0" excluded
    for i in $(seq 1 "$NODE_COUNT"); do
        [ "$i" = "$BAD_NODE" ] && continue
        journalctl -q --no-pager -o cat -u "${UNIT_PREFIX}${i}" --since "@$DEFECT_AT" 2>/dev/null \
            | latency_row "node $i" "${ips[$((i - 1))]}" "$nick" "$uuid8"
    done
    if [ -n "$PI_HOST" ]; then
        ssh -o BatchMode=yes -o ConnectTimeout=5 "$PI_HOST" \
            "journalctl -q --no-pager -o cat -u autonomous-trust --since @$DEFECT_AT" 2>/dev/null \
            | latency_row pi "${PI_HOST#*@}" "$nick" "$uuid8"
    fi
    info "detected: the observer's first 0.10 probe score for the bad node"
    info "tier 0: its score for the bad node first fell below 0.5 after reaching 0.5"
    info "excluded: its reputation for the bad node fell below the communication cut-off"
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
    rm -f "$LINK_DIR"/*
    [ ! -d "$LINK_DIR" ] || rmdir "$LINK_DIR"
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
        --pi-addr)   PI_ADDR="$2"; shift 2 ;;
        --bad-node)  BAD_NODE="$2"; shift 2 ;;
        --bad-bin)   BAD_BIN="$(realpath "$2")"; shift 2 ;;
        --defect-after) DEFECT_AFTER="$2"; shift 2 ;;
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
    latency) cmd_latency ;;
    down)   cmd_down ;;
    -h|--help|help) usage 0 ;;
    *)      error "Unknown command: $CMD"; usage 1 ;;
esac
