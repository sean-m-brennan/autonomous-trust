#!/usr/bin/env bash
# ******************
#  Copyright 2025 Sean M. Brennan and contributors
#  Licensed under the Apache License, Version 2.0
# ******************
#
# Live C <-> Python interop test for the request_access discovery + identity
# admission handshake (Stretch Goal 3 / on-ramp #1, task #10).
#
# Brings up ONE C at_demo node and ONE pure-Python node on a shared Docker
# bridge and verifies they discover + mutually admit each other over live UDP,
# then that the C node obtains the shared GROUP KEY (group-key sync). A SECOND
# Python node is then staggered in (after the C node settles) so the authority
# fans a membership update out to the already-present C node -- the only way a
# group_key_update crosses the wire (see the group_key_update block below).
# Topology: C @ .21, Python @ .11, 2nd Python @ .12.
#
# What is checked:
#   * C -> Python : the Python node reconstructs the C node's identity from the
#                   envelope from_* fields and admits it (access_granted).
#   * Python -> C : the C node processes the Python node's announce and unicasts
#                   a peer_caps_query back.
#   * group-key  : the C node parses Python's full_history group payload (the
#                   DRY canonical form) and ADOPTS the shared group key, so it
#                   can decrypt/emit encrypted group traffic. This exercises
#                   SG3 blockers 1/2/3 + slot-2 (accept/confirm/history canonical).
#   * group_key_update : a membership-propagation update (IdentityProtocol.update),
#                   distinct from the full_history bootstrap above. Python's
#                   _update_group now emits the canonical flat group so the C
#                   co-member's handle_group_update can parse it (pre-fix Python
#                   sent the ConfigJSONEncoder form, which C silently dropped).
#
# Why this script exists: the standard Docker image build (Dockerfile-c) needs
# apt access to the Debian repos, which is firewalled in the dev sandbox. So we
# build the C at_demo natively (host toolchain) and bundle it into a glibc-
# matched base image. In CI / any apt-reachable environment, prefer building
# `autonomous-trust-c` via Dockerfile-c instead (see .github/workflows/
# arm64-build.yml) and skip the native build with --c-image autonomous-trust-c.
#
# Usage:
#   ./test-interop-cpython.sh                 # build C node + run, ~120s (3 nodes)
#   ./test-interop-cpython.sh --skip-build    # reuse existing at-cnode-cur image
#   ./test-interop-cpython.sh --c-image NAME  # use a prebuilt C image (e.g. from Dockerfile-c)
#   ./test-interop-cpython.sh --keep          # leave containers running
#   ./test-interop-cpython.sh --duration 120  # run longer

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(cd "$SCRIPT_DIR/.." && pwd)"
WORK="$SCRIPT_DIR/.interop-cpython"
NET=interop-cpy-net
SUBNET=172.31.0.0/24
C_IP=172.31.0.21
PY_IP=172.31.0.11
PY2_IP=172.31.0.12
PY_IMAGE=autonomous-trust:dev
C_IMAGE=at-cnode-cur
DURATION=120
STAGGER=40          # seconds to let C settle before the 2nd Python node joins
SKIP_BUILD=false
KEEP=false

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[0;33m'; RST='\033[0m'
pass(){ echo -e "${GREEN}[PASS]${RST} $*"; }
fail(){ echo -e "${RED}[FAIL]${RST} $*"; }
info(){ echo -e "${YELLOW}[interop]${RST} $*"; }

while [[ $# -gt 0 ]]; do case "$1" in
  --skip-build) SKIP_BUILD=true; shift;;
  --c-image)    C_IMAGE="$2"; SKIP_BUILD=true; shift 2;;
  --py-image)   PY_IMAGE="$2"; shift 2;;
  --duration)   DURATION="$2"; shift 2;;
  --keep)       KEEP=true; shift;;
  -h|--help)    sed -n '2,40p' "$0"; exit 0;;
  *) echo "unknown option: $1"; exit 1;;
esac; done

cleanup(){
  if $KEEP; then info "leaving containers up (--keep); 'docker rm -f interop-c interop-py interop-py2'"; return; fi
  docker rm -f interop-c interop-py interop-py2 >/dev/null 2>&1 || true
  docker network rm "$NET" >/dev/null 2>&1 || true
}
trap cleanup EXIT

# ----------------------------------------------------------------------------
# Build the current C at_demo into a glibc-matched runtime image (native build)
# ----------------------------------------------------------------------------
if ! $SKIP_BUILD; then
  # Codegen is `protoc --c_out` (see src/c/CMakeLists.txt), which discovers the
  # protoc-gen-c plugin on PATH. protobuf-c >= 1.5 drops the legacy `protoc-c`
  # wrapper, shipping only protoc-gen-c -- so require the plugin, not the wrapper.
  for t in gcc g++ cmake protoc protoc-gen-c; do
    command -v "$t" >/dev/null || { fail "missing build tool: $t (apt: build-essential cmake protobuf-compiler protobuf-c-compiler libsodium-dev libjansson-dev uuid-dev libprotobuf-c-dev libprotobuf-dev | conda-forge: cmake protobuf protobuf-c libsodium jansson libuuid + a gcc)"; exit 1; }
  done
  info "Building current at_demo from source (gcc) ..."
  # Drop any stale find_library() results so dependency paths (esp. protobuf-c)
  # re-resolve against the *current* toolchain/env. CMake never re-searches a
  # cached find var, so a cache from an earlier setup can pin a system lib whose
  # dev symlink is absent on the host -> "No rule to make target .../libprotobuf-c.so".
  rm -f "$REPO/examples/build-gcc/CMakeCache.txt"
  CC=gcc CXX=g++ cmake -S "$REPO/examples" -B "$REPO/examples/build-gcc" \
    -DCMAKE_BUILD_TYPE=Release -DCMAKE_C_FLAGS="-Wno-unknown-warning-option" \
    -DCMAKE_CXX_FLAGS="-Wno-unknown-warning-option" >/dev/null
  cmake --build "$REPO/examples/build-gcc" --target autonomous_trust -j"$(nproc)" >/dev/null
  PB="$REPO/examples/build-gcc/lib/protobuf/autonomous_trust/core/protobuf"
  # at_demo links the static lib via --whole-archive under clang; gcc trips on a
  # relocation there, so link dynamically against the freshly-built .so instead.
  # Inside a conda env, a bare gcc doesn't search the env's include/lib dirs, so
  # the generated headers' `#include <protobuf-c/protobuf-c.h>` and the -l libs
  # won't resolve. Add them explicitly; the conda rpath also lets the ldd step
  # below resolve the env's libs on the host so they get bundled into the image.
  CONDA_CFLAGS=(); CONDA_LDFLAGS=()
  if [ -n "${CONDA_PREFIX:-}" ]; then
    CONDA_CFLAGS=(-I "${CONDA_PREFIX}/include")
    CONDA_LDFLAGS=(-L "${CONDA_PREFIX}/lib" -Wl,-rpath,"${CONDA_PREFIX}/lib")
  fi
  # -fms-extensions is required: the AT headers embed anonymous typedef'd
  # members (smrt_ptr_t etc.) at offset 0; without it gcc drops those members
  # ("declaration does not declare anything") and diverges the struct layout
  # from the .so it links against. The library is built with it; match here.
  gcc -fms-extensions "$REPO/examples/demo/src/at_demo.c" \
    "${CONDA_CFLAGS[@]}" \
    -I "$REPO/src/c" -I "$REPO/src/c/autonomous_trust" -I "$PB" -I "$REPO/examples/build-gcc/lib/protobuf" \
    -L "$REPO/examples/build-gcc/lib" "${CONDA_LDFLAGS[@]}" -lautonomous_trust \
    -lsodium -ljansson -luuid -lprotobuf-c -lprotobuf -lstdc++ -lpthread -lm \
    -Wl,-rpath,'$ORIGIN/lib' -o "$REPO/examples/build-gcc/at_demo_cur"

  info "Packaging C node image ($C_IMAGE), base matched to host glibc ..."
  # Pick a runtime base whose glibc matches the host so the natively-built
  # at_demo runs. Map the host distro to a real image tag: Ubuntu -> ubuntu:VER,
  # Debian and its derivatives (e.g. MX Linux: ID=mx, ID_LIKE=debian, which would
  # otherwise yield a nonexistent ubuntu:12) -> debian:<major>. Fall back to ubuntu.
  BASE="$(
    ID=""; VERSION_ID=""; ID_LIKE=""
    [ -r /etc/os-release ] && . /etc/os-release
    case "$ID" in
      ubuntu) echo "ubuntu:${VERSION_ID:-24.04}";;
      debian) echo "debian:${VERSION_ID:-12}";;
      *) case "$ID_LIKE" in
           *ubuntu*) echo "ubuntu:${VERSION_ID:-24.04}";;
           *debian*) echo "debian:$(cut -d. -f1 /etc/debian_version 2>/dev/null || echo 12)";;
           *)        echo "ubuntu:24.04";;
         esac;;
    esac
  )"
  info "Using base image: $BASE"
  rm -rf "$WORK"; mkdir -p "$WORK/libs"
  cp "$REPO/examples/build-gcc/at_demo_cur" "$WORK/at_demo"
  cp "$REPO/examples/build-gcc/lib/libautonomous_trust.so" "$WORK/libs/"
  # Bundle at_demo's full shared-lib closure. ldd has already resolved the whole
  # transitive set (via the conda/$ORIGIN rpaths), so copy every dep that lives
  # under the conda prefix -- these are exactly the libs absent from the base
  # image. A name-only filter is NOT enough: conda's libprotobuf 6.x drags in
  # Abseil (libabsl_*) and a newer libstdc++, and missing those is what caused
  # "error while loading shared libraries: libabsl_die_if_null.so...". The
  # name-match arm covers the non-conda/system build (sodium/jansson/protobuf-c
  # aren't in a minimal debian/ubuntu base either).
  CONDA_LIBROOT="${CONDA_PREFIX:-/__no_conda__}"
  ldd "$REPO/examples/build-gcc/at_demo_cur" | awk '/=>/{print $3}' \
    | while read -r l; do
        [ -e "$l" ] || continue
        case "$l" in
          "$CONDA_LIBROOT"/*)                  cp -L "$l" "$WORK/libs/";;
          *sodium*|*jansson*|*uuid*|*protobuf*) cp -L "$l" "$WORK/libs/";;
        esac
      done
  cat > "$WORK/entrypoint.sh" <<'EOF'
#!/bin/sh
mkdir -p "${AUTONOMOUS_TRUST_ROOT}/etc/at" "${AUTONOMOUS_TRUST_ROOT}/var/at" 2>/dev/null || true
export LD_LIBRARY_PATH=/usr/local/lib
exec /usr/local/bin/at_demo --generate-config --log-level "${LOG_LEVEL:-debug}" "$@"
EOF
  chmod +x "$WORK/entrypoint.sh"
  cat > "$WORK/Dockerfile" <<EOF
FROM $BASE
COPY libs/ /usr/local/lib/
COPY at_demo /usr/local/bin/at_demo
COPY entrypoint.sh /entrypoint.sh
ENV AUTONOMOUS_TRUST_ROOT=/ LD_LIBRARY_PATH=/usr/local/lib
ENTRYPOINT ["/entrypoint.sh"]
EOF
  docker build -t "$C_IMAGE" "$WORK" >/dev/null
fi

# ----------------------------------------------------------------------------
# Bring up the mixed fleet
# ----------------------------------------------------------------------------
docker rm -f interop-c interop-py interop-py2 >/dev/null 2>&1 || true
docker network rm "$NET" >/dev/null 2>&1 || true
docker network create --subnet "$SUBNET" "$NET" >/dev/null

info "Starting C node ($C_IMAGE @ $C_IP) and Python node ($PY_IMAGE @ $PY_IP) ..."
docker run -d --name interop-c --network "$NET" --ip "$C_IP" \
  -e LOG_LEVEL=debug "$C_IMAGE" >/dev/null
# Mount the WHOLE current package so the interop fix (and its sibling modules)
# are present, then run the pure-Python backend (the hardest interop case).
docker run -d --name interop-py --network "$NET" --ip "$PY_IP" \
  -e AUTONOMOUS_TRUST_BACKEND=python -e AUTONOMOUS_TRUST_EXE="-m autonomous_trust" \
  -e AUTONOMOUS_TRUST_ARGS="--live --log-level debug" -e POSTMORTEM=false \
  -v "$REPO/src/autonomous-trust/autonomous_trust:/app/autonomous_trust:ro" \
  "$PY_IMAGE" >/dev/null

# group_key_update needs an admission that fans out to an ALREADY-admitted
# peer: Python's _update_group (idprocess.py) only sends the group to PRE-
# existing group members (self.peers.hierarchy[level]), so the very first
# peer's own admission has an empty fan-out target and emits nothing. We let
# the C node settle, then bring up a SECOND Python node; when the established
# authority admits it, its _update_group fans the (now larger) group to the
# already-present C node -- the cross-runtime group_key_update under test.
REMAIN="$DURATION"
if [ "$DURATION" -gt "$((STAGGER + 20))" ]; then
  info "Settling ${STAGGER}s before adding the 2nd Python node ($PY2_IP) ..."
  sleep "$STAGGER"
  info "Starting 2nd Python node ($PY_IMAGE @ $PY2_IP) to trigger a group_key_update fan-out ..."
  docker run -d --name interop-py2 --network "$NET" --ip "$PY2_IP" \
    -e AUTONOMOUS_TRUST_BACKEND=python -e AUTONOMOUS_TRUST_EXE="-m autonomous_trust" \
    -e AUTONOMOUS_TRUST_ARGS="--live --log-level debug" -e POSTMORTEM=false \
    -v "$REPO/src/autonomous-trust/autonomous_trust:/app/autonomous_trust:ro" \
    "$PY_IMAGE" >/dev/null
  REMAIN="$((DURATION - STAGGER))"
else
  info "DURATION ($DURATION) too short to stagger a 2nd node (need > $((STAGGER + 20))); group_key_update will NOT fire."
fi
info "Running ${REMAIN}s more ..."
sleep "$REMAIN"
PYLOG="$(docker logs interop-py 2>&1)"
CLOG="$(docker logs interop-c 2>&1)"
PY2LOG="$(docker logs interop-py2 2>&1 || true)"
# Did the C node survive, or did it exit (e.g. a bundled-lib/glibc mismatch)?
C_STATE="$(docker inspect -f '{{.State.Status}} (exit {{.State.ExitCode}})' interop-c 2>/dev/null || echo unknown)"
info "C node container state: ${C_STATE}"

# ----------------------------------------------------------------------------
# Verify
# ----------------------------------------------------------------------------
echo; echo "=============================="
P=0; F=0
chk(){ if echo "$PYLOG" | grep -qiE "$2"; then pass "$1"; P=$((P+1)); else fail "$1"; F=$((F+1)); fi; }
chkc(){ if echo "$CLOG" | grep -qiE "$2"; then pass "$1"; P=$((P+1)); else fail "$1"; F=$((F+1)); fi; }

# C -> Python: Python reconstructed the C identity and admitted it
# Anchor on the C node's IP: the Python node's own outgoing announce also logs
# "request_access", so match a genuine *receive* from the C addr instead
# (netprocess "Recvd ... from <addr>" or the identity-reconstruction line).
chk "Python received the C node's announce"            "Recvd .* from ${C_IP}|Received new identity: .* - ${C_IP} -"
chk "Python reconstructed C identity (not rejected)"   "Received new identity: .* - ${C_IP} -"
chk "Python skipped counterfeit (heterogeneous C node)" "skipping counterfeit check"
chk "Python admitted the C node (access_granted)"      "access_granted"
chk "Python added the C node as a peer"                "Add peers"
# Python -> C: the C node processed Python's announce and queried its caps
chk "C node processed Python + replied (caps_query)"   "peer_caps_query from ${C_IP}"

# ----------------------------------------------------------------------------
# Group-key sync (SG3 blockers 1/2/3 + slot-2): the C node must obtain and
# install the Python mesh's shared group key so it can exchange ENCRYPTED group
# traffic — the layer past admission. The key travels in `full_history` slot 0
# as the DRY canonical group form; the C node parses it (group_from_json) and
# adopts it during the self-bootstrap → mesh merge. The "adopted mesh group"
# line fires ONLY when group_from_json successfully parses Python's canonical
# group (raw private key + public_only) — before the canonical fix Python's
# ConfigJSONEncoder group was unparseable by C and this never appeared.
echo "------ group-key sync ------"
chk  "Python sent full_history (group key) to the C node" "Send full history"
chkc "C node received full_history from Python"           "received history from"
chkc "C node parsed + ADOPTED the Python group key"       "adopted mesh group .* during merge"

# ----------------------------------------------------------------------------
# group_key_update (membership propagation, IdentityProtocol.update): distinct
# from the full_history bootstrap adoption above. Python's _update_group now
# emits the DRY canonical flat group (to_canonical), so the C co-member's
# handle_group_update can parse it -- pre-fix Python sent the ConfigJSONEncoder
# form, which C could not parse and silently dropped.
#
# This message ONLY crosses the wire once a NEW peer is admitted while an
# earlier peer is already in the group (_update_group fans out to pre-existing
# members only). Hence the staggered 2nd Python node above: its admission is
# what makes the authority fan the group to the already-present C node. With
# only the original two nodes, Python emits no group_key_update at all and
# these checks (correctly) cannot pass.
#
# The C "parsed incoming group update (uuid <real-uuid>, addresses N>=1)" line
# is the cross-runtime proof: it fires on a successful canonical parse
# regardless of the adopt/no-op outcome (a same-group equal-size no-op leaves
# no other trace, so the older "adopting incoming group" line alone is too
# timing-dependent to assert on). A pre-fix / non-canonical payload would
# instead log "uuid ?, addresses 0".
echo "------ group_key_update (membership) ------"
chk  "Python fanned out a group_key_update (_update_group)" "Sent group .* to "
chkc "C node received a group_key_update from Python"      "received group update from"
chkc "C parsed Python's canonical group_key_update"        "parsed incoming group update \(uuid [0-9a-fA-F-]{36}, addresses [1-9]"

echo "=============================="
echo "  $P passed, $F failed"
echo "=============================="
if [ "$F" -gt 0 ]; then
  info "C node container state: ${C_STATE}"
  info "C node log (last 40 lines):";  echo "$CLOG"  | sed 's/\x1b\[[0-9;]*m//g' | tail -40
  info "Python log (last 40 lines):"; echo "$PYLOG" | sed 's/\x1b\[[0-9;]*m//g' | tail -40
  info "2nd Python node log (last 20 lines):"; echo "${PY2LOG:-<not started>}" | sed 's/\x1b\[[0-9;]*m//g' | tail -20
  exit 1
fi
info "C <-> Python discovery + identity admission interoperate."
exit 0
