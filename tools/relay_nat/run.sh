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
# First contact across REAL NAT through a rendezvous relay (FIRST_CONTACT_PLAN
# Phase 0). Needs root (network namespaces + iptables); run on a Linux host:
#
#     sudo PYTHON="$(which python3)" tools/relay_nat/run.sh
#
# sudo resets PATH, so a bare python3 under sudo is the system interpreter,
# which usually lacks AT's dependencies; PYTHON names yours.
#
# Topology: Alice and Bob each sit on a private network behind their own
# masquerading router, which forwards only outbound flows and their replies --
# nothing can open a connection TO them. The relay has the one public address.
#
#     rn_alice 192.168.10.2 -- rn_nata (MASQ) --+
#                                               +-- rn_pub bridge -- rn_relay 10.99.0.1
#     rn_bob   192.168.20.2 -- rn_natb (MASQ) --+
#
# Alice registers with the relay; the link she mints names it; Bob, who has
# never seen Alice's network, adds her from the link alone. Pass = both write
# "ok" to their result file.
#
#     tools/relay_nat/run.sh --loopback
#
# runs the same three roles on loopback with no namespaces (no root needed): the
# check of this script and its driver where namespaces are unavailable.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(cd "$HERE/../.." && pwd)"
PY="${PYTHON:-python3}"
TIMEOUT="${RELAY_NAT_TIMEOUT:-120}"
MODE="nat"
[[ "${1:-}" == "--loopback" ]] && MODE="loopback"

export PYTHONPATH="$(ls -d "$REPO"/src/autonomous-trust* | tr '\n' ':')${PYTHONPATH:-}"
# Fail in seconds, not after the timeout: every node would die on this import.
if ! err="$("$PY" -c 'import autonomous_trust.core' 2>&1)"; then
    echo "FAIL: $PY cannot import autonomous_trust.core:" >&2
    echo "$err" | tail -n 1 >&2
    [[ -n "${SUDO_USER:-}" && -z "${PYTHON:-}" ]] && \
        echo "under sudo, pass your interpreter: sudo PYTHON=\"\$(which python3)\" $0 $*" >&2
    exit 2
fi
WORK="$(mktemp -d /tmp/relay-nat.XXXXXX)"
SHARE="$WORK/share"
mkdir -p "$SHARE"
PIDS=()

cleanup() {
    touch "$SHARE/done" 2>/dev/null || true
    for p in "${PIDS[@]:-}"; do [[ -n "$p" ]] && kill "$p" 2>/dev/null || true; done
    if [[ "$MODE" == "nat" ]]; then
        for ns in rn_alice rn_bob rn_nata rn_natb rn_relay; do
            ip netns del "$ns" 2>/dev/null || true
        done
        ip link del rn_br0 2>/dev/null || true
    fi
}
trap cleanup EXIT

node() {   # node <netns|-> <role> [args...]
    local ns="$1"; shift
    local role="$1"; shift
    local cmd=("$PY" "$HERE/node.py" "$role" --root "$WORK/$role" --share "$SHARE"
               --timeout "$TIMEOUT" "$@")
    if [[ "$ns" == "-" ]]; then
        "${cmd[@]}" >"$SHARE/$role.out" 2>&1 &
    else
        ip netns exec "$ns" "${cmd[@]}" >"$SHARE/$role.out" 2>&1 &
    fi
    PIDS+=("$!")
}

if [[ "$MODE" == "nat" ]]; then
    [[ $EUID -eq 0 ]] || { echo "run as root (or use --loopback)" >&2; exit 2; }
    for ns in rn_alice rn_bob rn_nata rn_natb rn_relay; do ip netns add "$ns"; done
    ip link add rn_br0 type bridge && ip link set rn_br0 up

    # The public segment: the relay and both routers' outside legs.
    pub() {   # pub <ns> <addr>
        ip link add "$1_o" type veth peer name "$1_b"
        ip link set "$1_b" master rn_br0 up
        ip link set "$1_o" netns "$1"
        ip -n "$1" addr add "$2/24" dev "$1_o"
        ip -n "$1" link set "$1_o" up
        ip -n "$1" link set lo up
    }
    pub rn_relay 10.99.0.1
    pub rn_nata  10.99.0.2
    pub rn_natb  10.99.0.3

    # Each private network behind its router, which masquerades outbound and
    # forwards back only replies (ESTABLISHED,RELATED): no inbound path.
    private() {   # private <host-ns> <router-ns> <net-prefix>
        ip link add "$1_i" type veth peer name "$2_i"
        ip link set "$1_i" netns "$1"
        ip link set "$2_i" netns "$2"
        ip -n "$1" addr add "$3.2/24" dev "$1_i"
        ip -n "$2" addr add "$3.1/24" dev "$2_i"
        ip -n "$1" link set "$1_i" up
        ip -n "$2" link set "$2_i" up
        ip -n "$1" link set lo up
        ip -n "$1" route add default via "$3.1"
        ip netns exec "$2" sysctl -qw net.ipv4.ip_forward=1
        ip netns exec "$2" iptables -t nat -A POSTROUTING -o "$2_o" -j MASQUERADE
        ip netns exec "$2" iptables -P FORWARD DROP
        ip netns exec "$2" iptables -A FORWARD -i "$2_i" -o "$2_o" -j ACCEPT
        ip netns exec "$2" iptables -A FORWARD -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
    }
    private rn_alice rn_nata 192.168.10
    private rn_bob   rn_natb 192.168.20

    # Sanity: Bob cannot reach Alice at all; both can reach the relay.
    if ip netns exec rn_bob ping -c1 -W1 192.168.10.2 >/dev/null 2>&1; then
        echo "FAIL: topology leaks -- bob reaches alice directly" >&2; exit 1
    fi
    ip netns exec rn_alice ping -c1 -W2 10.99.0.1 >/dev/null
    ip netns exec rn_bob   ping -c1 -W2 10.99.0.1 >/dev/null

    node rn_relay relay --relay-port 27790
    node rn_alice alice --relay 10.99.0.1:27790
    node rn_bob   bob
else
    node - relay --loopback 127.0.0.3 --port 31203 --relay-port 31290
    node - alice --loopback 127.0.0.1 --port 31201 --relay 127.0.0.3:31290
    node - bob   --loopback 127.0.0.2 --port 31202
fi

# Each node's own deadline starts after its startup delay (node.py --startup,
# 10 s) and ends in a "fail <reason>" result; outwait it so that reason lands.
deadline=$((SECONDS + TIMEOUT + 30))
while (( SECONDS < deadline )); do
    [[ -f "$SHARE/alice.result" && -f "$SHARE/bob.result" ]] && break
    sleep 1
done
status=0
for role in alice bob; do
    if [[ -f "$SHARE/$role.result" ]]; then
        echo "$role: $(cat "$SHARE/$role.result")"
        grep -q '^ok' "$SHARE/$role.result" || status=1
    else
        echo "$role: no result within $((TIMEOUT + 30))s"; status=1
    fi
done
if (( status != 0 )); then
    for role in relay alice bob; do
        echo "--- $role.out (tail) ---"
        tail -n 20 "$SHARE/$role.out" 2>/dev/null || echo "(missing)"
    done
fi
echo "logs: $SHARE"
exit $status
