#!/usr/bin/env bash
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
#
# End-to-end test of the embedded deployment using QEMU VMs.
#
# Spins up N Debian VMs on a shared virtual LAN, deploys the at_demo binary
# via install.sh + provision.sh, starts the systemd service, and verifies
# multi-node discovery.
#
# Prerequisites:
#   apt install qemu-system-x86 qemu-utils cloud-image-utils openssh-client wget
#
# Usage:
#   ./test-qemu.sh                # 2 nodes (default)
#   ./test-qemu.sh --nodes 3      # 3 nodes
#   ./test-qemu.sh --keep         # don't tear down VMs on exit
#   ./test-qemu.sh --skip-build   # reuse existing dist/autonomous-trust-amd64.tar.gz
#   ./test-qemu.sh --fleet-test  # also test fleet update protocol after deployment

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WORK_DIR="$SCRIPT_DIR/.test-qemu"

NODE_COUNT=2
KEEP=false
SKIP_BUILD=false
FLEET_TEST=false
SUBNET="10.0.2.0/24"  # QEMU user-mode default; VMs use socket mcast for inter-VM
VM_NET_SUBNET="192.168.100"
SSH_BASE_PORT=10022
MCAST_ADDR="230.0.0.1"
MCAST_PORT=1234
VM_RAM=512   # MB
VM_CPUS=1
CLOUD_IMAGE_URL="https://cloud.debian.org/images/cloud/bookworm/latest/debian-12-genericcloud-amd64.qcow2"
CLOUD_IMAGE_FILE="debian-12-genericcloud-amd64.qcow2"
SSH_KEY=""
SSH_OPTS="-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=5 -o LogLevel=ERROR"

# Timeout settings (seconds)
BOOT_TIMEOUT=180
SSH_TIMEOUT=300
SERVICE_TIMEOUT=30

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
CYAN='\033[0;36m'
RESET='\033[0m'

info()  { echo -e "${GREEN}[test]${RESET} $*"; }
warn()  { echo -e "${YELLOW}[test]${RESET} $*"; }
error() { echo -e "${RED}[test]${RESET} $*" >&2; }
step()  { echo -e "${CYAN}[test]${RESET} === $* ==="; }

VM_PIDS=()

cleanup() {
    if $KEEP; then
        info "VMs kept running (--keep). PIDs: ${VM_PIDS[*]}"
        info "Work dir: $WORK_DIR"
        info "Kill manually: kill ${VM_PIDS[*]}"
        return
    fi
    info "Cleaning up ..."
    for pid in "${VM_PIDS[@]}"; do
        kill "$pid" 2>/dev/null || true
        wait "$pid" 2>/dev/null || true
    done
    # Leave work dir for debugging; remove with: rm -rf embedded/.test-qemu
    info "VMs stopped. Work dir preserved at $WORK_DIR"
}
trap cleanup EXIT

usage() {
    cat <<EOF
Usage: $0 [OPTIONS]

Options:
  --nodes N       Number of VMs to launch (default: 2, min: 2)
  --keep          Don't kill VMs on exit
  --skip-build    Reuse existing amd64 tarball (skip build-arm.sh)
  --ram MB        RAM per VM in MB (default: 512)
  -h, --help      Show this help
EOF
    exit 0
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --nodes)      NODE_COUNT="$2"; shift 2 ;;
        --keep)       KEEP=true; shift ;;
        --skip-build) SKIP_BUILD=true; shift ;;
        --fleet-test) FLEET_TEST=true; shift ;;
        --ram)        VM_RAM="$2"; shift 2 ;;
        -h|--help)    usage ;;
        *)            error "Unknown option: $1"; exit 1 ;;
    esac
done

if [ "$NODE_COUNT" -lt 2 ]; then
    error "Need at least 2 nodes for a multi-node test"
    exit 1
fi

# -----------------------------------------------------------------------
# Step 0: Preflight
# -----------------------------------------------------------------------
step "Preflight checks"

for cmd in qemu-system-x86_64 qemu-img cloud-localds ssh ssh-keygen wget; do
    if ! command -v "$cmd" &>/dev/null; then
        error "Required command not found: $cmd"
        exit 1
    fi
done

mkdir -p "$WORK_DIR"

# Generate ephemeral SSH key for test
if [ ! -f "$WORK_DIR/test_key" ]; then
    info "Generating ephemeral SSH key ..."
    ssh-keygen -t ed25519 -f "$WORK_DIR/test_key" -N "" -q
fi
SSH_KEY="$(cat "$WORK_DIR/test_key.pub")"

# -----------------------------------------------------------------------
# Step 1: Build the amd64 tarball
# -----------------------------------------------------------------------
step "Build amd64 tarball"

TARBALL="$SCRIPT_DIR/dist/autonomous-trust-amd64.tar.gz"
if $SKIP_BUILD && [ -f "$TARBALL" ]; then
    info "Reusing existing tarball: $TARBALL"
else
    info "Building via build-arm.sh (amd64 only) ..."
    "$SCRIPT_DIR/build-arm.sh" --all-arch
    if [ ! -f "$TARBALL" ]; then
        error "Build did not produce $TARBALL"
        exit 1
    fi
fi
info "Tarball: $(ls -lh "$TARBALL" | awk '{print $5, $9}')"

# -----------------------------------------------------------------------
# Step 2: Provision fleet configs
# -----------------------------------------------------------------------
step "Provision fleet configs for $NODE_COUNT nodes"

"$SCRIPT_DIR/provision.sh" \
    --nodes "$NODE_COUNT" \
    --subnet "${VM_NET_SUBNET}.0/24" \
    --start-ip "${VM_NET_SUBNET}.10" \
    --output "$WORK_DIR/fleet-configs"

# -----------------------------------------------------------------------
# Step 3: Download cloud image
# -----------------------------------------------------------------------
step "Prepare cloud image"

BASE_IMAGE="$WORK_DIR/$CLOUD_IMAGE_FILE"
if [ -f "$BASE_IMAGE" ]; then
    info "Reusing cached image: $BASE_IMAGE"
else
    info "Downloading Debian 12 cloud image ..."
    wget -q --show-progress -O "$BASE_IMAGE" "$CLOUD_IMAGE_URL"
fi

# -----------------------------------------------------------------------
# Step 4: Create and boot VMs
# -----------------------------------------------------------------------
step "Launching $NODE_COUNT VMs"

for i in $(seq 1 "$NODE_COUNT"); do
    node_name="at-node-$i"
    node_ip="${VM_NET_SUBNET}.$((9 + i))"
    ssh_port=$((SSH_BASE_PORT + i - 1))
    vm_dir="$WORK_DIR/$node_name"
    mkdir -p "$vm_dir"

    # Create per-VM disk (COW overlay on base image)
    disk="$vm_dir/disk.qcow2"
    if [ ! -f "$disk" ]; then
        qemu-img create -f qcow2 -b "$BASE_IMAGE" -F qcow2 "$disk" 4G >/dev/null
    fi

    # Create cloud-init user-data
    #
    # The LAN NIC (second virtio-net, MAC 52:54:00:00:02:XX) is configured
    # via a persistent systemd-networkd .network file rather than a transient
    # "ip addr add" in runcmd.  This survives networkd restarts and avoids
    # the race where networkd reconfigures the interface after runcmd.
    LAN_MAC_FULL="52:54:00:00:02:$(printf '%02x' "$i")"
    cat > "$vm_dir/user-data" <<USERDATA
#cloud-config
hostname: $node_name
manage_etc_hosts: true
users:
  - name: test
    sudo: ALL=(ALL) NOPASSWD:ALL
    shell: /bin/bash
    ssh_authorized_keys:
      - $SSH_KEY
write_files:
  - path: /etc/systemd/network/10-at-lan.network
    content: |
      [Match]
      MACAddress=$LAN_MAC_FULL

      [Network]
      Address=$node_ip/24
runcmd:
  - ssh-keygen -A
  - systemctl restart ssh
  - networkctl reload
USERDATA

    # Create seed ISO for cloud-init
    seed="$vm_dir/seed.iso"
    cloud-localds "$seed" "$vm_dir/user-data"

    info "Starting $node_name (ssh port $ssh_port, LAN IP $node_ip) ..."
    qemu-system-x86_64 \
        -name "$node_name" \
        -m "$VM_RAM" -smp "$VM_CPUS" \
        -cpu max -machine accel=kvm:tcg \
        -display none \
        -drive file="$disk",if=virtio \
        -drive file="$seed",if=virtio,format=raw \
        -netdev user,id=mgmt,hostfwd=tcp::"$ssh_port"-:22 \
        -device virtio-net-pci,netdev=mgmt,mac="52:54:00:00:01:$(printf '%02x' "$i")" \
        -netdev socket,id=lan,mcast="${MCAST_ADDR}:${MCAST_PORT}" \
        -device virtio-net-pci,netdev=lan,mac="52:54:00:00:02:$(printf '%02x' "$i")" \
        -serial "file:$vm_dir/console.log" \
        -pidfile "$vm_dir/qemu.pid" \
        -daemonize

    pid="$(cat "$vm_dir/qemu.pid")"
    VM_PIDS+=("$pid")
    info "  $node_name PID=$pid"
done

# -----------------------------------------------------------------------
# Step 5: Wait for VMs to boot and accept SSH
# -----------------------------------------------------------------------
step "Waiting for VMs to boot (timeout: ${SSH_TIMEOUT}s per VM)"

wait_for_ssh() {
    local port="$1" name="$2"
    local elapsed=0
    while [ $elapsed -lt $SSH_TIMEOUT ]; do
        if ssh $SSH_OPTS -i "$WORK_DIR/test_key" -p "$port" test@localhost "echo ok" &>/dev/null; then
            return 0
        fi
        sleep 5
        elapsed=$((elapsed + 5))
        printf "."
    done
    return 1
}

for i in $(seq 1 "$NODE_COUNT"); do
    node_name="at-node-$i"
    ssh_port=$((SSH_BASE_PORT + i - 1))
    printf "  Waiting for %s (port %d) " "$node_name" "$ssh_port"
    if wait_for_ssh "$ssh_port" "$node_name"; then
        echo " ready"
    else
        echo " TIMEOUT"
        error "$node_name did not become reachable. Console log:"
        tail -30 "$WORK_DIR/$node_name/console.log" || true
        exit 1
    fi
done

# -----------------------------------------------------------------------
# Step 6: Deploy tarball + install.sh + service file to each VM
# -----------------------------------------------------------------------
step "Deploying to $NODE_COUNT VMs"

for i in $(seq 1 "$NODE_COUNT"); do
    node_name="at-node-$i"
    ssh_port=$((SSH_BASE_PORT + i - 1))
    ssh_cmd="ssh $SSH_OPTS -i $WORK_DIR/test_key -p $ssh_port test@localhost"
    scp_cmd="scp $SSH_OPTS -i $WORK_DIR/test_key -P $ssh_port"

    info "Deploying to $node_name ..."

    # Wait for cloud-init to finish (releases apt lock)
    $ssh_cmd "sudo cloud-init status --wait" || true

    # Upload artifacts
    $scp_cmd "$TARBALL" test@localhost:/tmp/autonomous-trust-amd64.tar.gz
    $scp_cmd "$SCRIPT_DIR/install.sh" test@localhost:/tmp/install.sh
    $scp_cmd "$SCRIPT_DIR/autonomous-trust.service" test@localhost:/tmp/autonomous-trust.service
    $scp_cmd "$WORK_DIR/fleet-configs/${node_name}.tar.gz" test@localhost:/tmp/node-config.tar.gz

    # Run install (install.sh finds service file via $SCRIPT_DIR = /tmp/)
    $ssh_cmd "sudo bash /tmp/install.sh --tarball /tmp/autonomous-trust-amd64.tar.gz"

    # Deploy provisioned config
    $ssh_cmd "sudo tar -xzf /tmp/node-config.tar.gz -C /"

    info "  $node_name: installed"
done

# -----------------------------------------------------------------------
# Step 7: Start services
# -----------------------------------------------------------------------
step "Starting autonomous-trust on all nodes"

for i in $(seq 1 "$NODE_COUNT"); do
    node_name="at-node-$i"
    ssh_port=$((SSH_BASE_PORT + i - 1))
    ssh_cmd="ssh $SSH_OPTS -i $WORK_DIR/test_key -p $ssh_port test@localhost"

    $ssh_cmd "sudo systemctl start autonomous-trust"
    info "  $node_name: service started"
done

# Give services time to start and discover each other
info "Waiting ${SERVICE_TIMEOUT}s for nodes to discover each other ..."
sleep "$SERVICE_TIMEOUT"

# -----------------------------------------------------------------------
# Step 8: Verify
# -----------------------------------------------------------------------
step "Verification"

PASS=0
FAIL=0

check() {
    local desc="$1" result="$2"
    if [ "$result" -eq 0 ]; then
        info "  PASS: $desc"
        PASS=$((PASS + 1))
    else
        error "  FAIL: $desc"
        FAIL=$((FAIL + 1))
    fi
}

for i in $(seq 1 "$NODE_COUNT"); do
    node_name="at-node-$i"
    ssh_port=$((SSH_BASE_PORT + i - 1))
    ssh_cmd="ssh $SSH_OPTS -i $WORK_DIR/test_key -p $ssh_port test@localhost"

    # Check 1: at_demo binary is installed
    $ssh_cmd "test -x /usr/local/bin/at_demo" 2>/dev/null && rc=0 || rc=$?
    check "$node_name: at_demo binary installed" $rc

    # Check 2: shared library is present
    $ssh_cmd "test -f /usr/local/lib/libautonomous_trust.so" 2>/dev/null && rc=0 || rc=$?
    check "$node_name: libautonomous_trust.so present" $rc

    # Check 3: systemd service is active
    $ssh_cmd "systemctl is-active autonomous-trust" &>/dev/null && rc=0 || rc=$?
    check "$node_name: systemd service active" $rc

    # Check 4: bootstrap config was deployed
    $ssh_cmd "test -f /opt/autonomous-trust/etc/at/bootstrap/bootstrap.cfg.json" 2>/dev/null && rc=0 || rc=$?
    check "$node_name: bootstrap config deployed" $rc

    # Check 5: config directory was created
    $ssh_cmd "test -d /opt/autonomous-trust/var/at" 2>/dev/null && rc=0 || rc=$?
    check "$node_name: data directory exists" $rc

    # Check 6: service is producing output (journalctl)
    log_lines=$($ssh_cmd "sudo journalctl -u autonomous-trust --no-pager -n 5 2>/dev/null" | wc -l) || log_lines=0
    [ "$log_lines" -gt 0 ] 2>/dev/null && rc=0 || rc=$?
    check "$node_name: service producing log output" $rc

    # Dump recent logs for inspection
    info "  $node_name recent logs:"
    $ssh_cmd "sudo journalctl -u autonomous-trust --no-pager -n 10 2>/dev/null" | sed 's/^/    /' || true
    echo
done

# Check inter-VM LAN connectivity
step "Inter-VM LAN connectivity"
for i in $(seq 1 "$NODE_COUNT"); do
    ssh_port=$((SSH_BASE_PORT + i - 1))
    ssh_cmd="ssh $SSH_OPTS -i $WORK_DIR/test_key -p $ssh_port test@localhost"
    for j in $(seq 1 "$NODE_COUNT"); do
        [ "$i" -eq "$j" ] && continue
        peer_ip="${VM_NET_SUBNET}.$((9 + j))"
        $ssh_cmd "ping -c 1 -W 2 $peer_ip" &>/dev/null && rc=0 || rc=$?
        check "at-node-$i -> at-node-$j ($peer_ip) ping" $rc
    done
done

# -----------------------------------------------------------------------
# Fleet management integration test (optional)
# -----------------------------------------------------------------------
if [ "$FLEET_TEST" = true ]; then
    info "=== Fleet management integration test ==="

    node1_port=$((SSH_BASE_PORT + 0))
    node2_port=$((SSH_BASE_PORT + 1))
    ssh_node1="ssh $SSH_OPTS -i $WORK_DIR/test_key -p $node1_port test@localhost"
    ssh_node2="ssh $SSH_OPTS -i $WORK_DIR/test_key -p $node2_port test@localhost"

    # Reconfigure node-1 with --inject-update
    info "Reconfiguring node-1 with --inject-update ..."
    $ssh_node1 "sudo systemctl stop autonomous-trust"
    $ssh_node1 "sudo sed -i 's|AUTONOMOUS_TRUST_ARGS=.*|AUTONOMOUS_TRUST_ARGS=\"--inject-update --log-level debug\"|' /opt/autonomous-trust/etc/at/environment"
    $ssh_node1 "sudo systemctl start autonomous-trust"

    # Wait for node-2 artifact download (poll logs)
    info "Waiting for node-2 artifact download (up to 120s) ..."
    FLEET_ELAPSED=0
    FLEET_TIMEOUT=120
    while [ $FLEET_ELAPSED -lt $FLEET_TIMEOUT ]; do
        if $ssh_node2 "journalctl -u autonomous-trust --no-pager" 2>/dev/null | grep -q "download complete"; then
            info "Node-2: artifact download complete after ${FLEET_ELAPSED}s"
            break
        fi
        sleep 5
        FLEET_ELAPSED=$((FLEET_ELAPSED + 5))
    done

    if [ $FLEET_ELAPSED -ge $FLEET_TIMEOUT ]; then
        error "  FAIL: Node-2: artifact download did not complete within ${FLEET_TIMEOUT}s"
        FAIL=$((FAIL + 1))
    else
        $ssh_node2 "test -n ok" 2>/dev/null && rc=0 || rc=$?
        check "Node-2: artifact download" 0

        # Wait for node-2 restart
        info "Waiting for node-2 restart (up to 30s) ..."
        sleep 10
        RECONNECT_ELAPSED=0
        RECONNECT_TIMEOUT=30
        while [ $RECONNECT_ELAPSED -lt $RECONNECT_TIMEOUT ]; do
            if $ssh_node2 "echo ok" >/dev/null 2>&1; then
                info "Node-2: SSH reconnected after restart"
                break
            fi
            sleep 3
            RECONNECT_ELAPSED=$((RECONNECT_ELAPSED + 3))
        done

        # Verify post-restart state
        $ssh_node2 "systemctl is-active autonomous-trust" &>/dev/null && rc=0 || rc=$?
        check "Node-2: service active after restart" $rc

        $ssh_node2 "! test -f /opt/autonomous-trust/var/at/update/state.json" 2>/dev/null && rc=0 || rc=$?
        check "Node-2: state file cleaned up" $rc

        $ssh_node2 "journalctl -u autonomous-trust --no-pager" 2>/dev/null | grep -q "health check PASSED" && rc=0 || rc=$?
        check "Node-2: health check passed in logs" $rc

        $ssh_node2 "ls /opt/autonomous-trust/var/at/artifacts/*/complete >/dev/null 2>&1" && rc=0 || rc=$?
        check "Node-2: artifact store has complete marker" $rc
    fi

    info "=== Fleet test complete ==="
fi

# -----------------------------------------------------------------------
# Summary
# -----------------------------------------------------------------------
echo
step "Results: $PASS passed, $FAIL failed"

if [ "$FAIL" -gt 0 ]; then
    error "Some checks failed. Inspect logs in $WORK_DIR/<node>/console.log"
    error "SSH into a VM: ssh $SSH_OPTS -i $WORK_DIR/test_key -p $SSH_BASE_PORT test@localhost"
    exit 1
fi

info "All checks passed!"
info "SSH into a VM: ssh $SSH_OPTS -i $WORK_DIR/test_key -p $SSH_BASE_PORT test@localhost"
