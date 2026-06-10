#!/usr/bin/env bash
# ******************
#  Copyright 2025 Sean M. Brennan and contributors
#  Licensed under the Apache License, Version 2.0
# ******************
#
# Run the GitHub Actions CI workflows locally, so you can gain confidence a
# push will go green BEFORE you push. This does NOT use `act`; it executes the
# same underlying commands each workflow job runs, in the same way, with the
# same environment variables -- just on your host instead of a runner.
#
# Jobs mirrored (1:1 with .github/workflows/):
#   conformance   (conformance.yml)         BLOCKING
#       Runs inside a Miniforge container by default (condaforge/miniforge3,
#       mirrors the workflow's setup-miniconda; NO host conda needed). Builds
#       the env from config/cfg/environment.yml + devel_environ.yml — cached in
#       $CI_LOCAL_CACHE (default ~/.cache/ci-local) so the heavy solve happens
#       once — then runs the Python harness and the C harness + cross-language
#       diff with the exact CI env (CONFORMANCE_SKIP_TOX=1, CC=clang,
#       CMAKE_PREFIX_PATH/LD_LIBRARY_PATH -> $CONDA_PREFIX). Use --host-conda to
#       run against a local conda install instead, --conda-image NAME to pin the
#       image, --recreate-env for a fresh (CI-faithful) env.
#   arm64-build   (arm64-build.yml job 1)   BLOCKING
#       Registers QEMU binfmt (the CI's setup-qemu-action), then
#       `embedded/build-arm.sh` (dynamic) + `--static`. Needs docker + buildx.
#   qemu-smoke    (arm64-build.yml job 2)   NON-BLOCKING (continue-on-error)
#       `embedded/test-qemu.sh --nodes 2`. Heavy (QEMU VMs); opt-in. A failure
#       here is reported but does NOT fail the overall run, matching CI.
#
# Usage:
#   scripts/ci-local.sh                 # default: conformance + arm64-build
#   scripts/ci-local.sh --all           # + qemu-smoke (heavy, non-blocking)
#   scripts/ci-local.sh --conformance   # just one job (repeatable flags)
#   scripts/ci-local.sh --arm64
#   scripts/ci-local.sh --qemu
#   scripts/ci-local.sh --conformance --recreate-env   # match CI's fresh env
#   scripts/ci-local.sh --conformance --update-env      # layer yml changes in
#   scripts/ci-local.sh --list          # show jobs and exit
#
# Exit codes: 0 all selected blocking jobs passed; 1 a blocking job FAILED;
#             2 a blocking job was SKIPPED for missing prereqs (inconclusive).
#
# NOTE: arm64-build and qemu-smoke drive Docker. Run this on your host, never
# inside the Claude sandbox (Docker there crashes the agent -- see CLAUDE.md).

set -uo pipefail   # intentionally NOT -e: we capture each job's status and continue

REPO="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
CENV=autonomous_trust
# Conformance runs in a Miniforge container by default (matches conformance.yml's
# setup-miniconda, and needs no host conda). Override the tag with --conda-image
# or CI_LOCAL_CONDA_IMAGE; force the host's conda instead with --host-conda.
CONDA_IMAGE="${CI_LOCAL_CONDA_IMAGE:-condaforge/miniforge3:latest}"
# Persisted across runs so the (heavy) env solve happens once. Override with
# CI_LOCAL_CACHE. Holds the conda envs + package cache used by the container.
CI_CACHE="${CI_LOCAL_CACHE:-$HOME/.cache/ci-local}"

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[0;33m'; BLUE='\033[0;34m'; RST='\033[0m'
info(){ echo -e "${BLUE}[ci-local]${RST} $*"; }
ok(){   echo -e "${GREEN}[ci-local]${RST} $*"; }
warn(){ echo -e "${YELLOW}[ci-local]${RST} $*"; }
err(){  echo -e "${RED}[ci-local]${RST} $*" >&2; }
hr(){   echo "------------------------------------------------------------------"; }

RECREATE_ENV=false
UPDATE_ENV=false
USE_HOST_CONDA=false
declare -a SELECTED=()

while [[ $# -gt 0 ]]; do case "$1" in
  --conformance) SELECTED+=(conformance); shift;;
  --arm64)       SELECTED+=(arm64);       shift;;
  --qemu)        SELECTED+=(qemu);        shift;;
  --all)         SELECTED=(conformance arm64 qemu); shift;;
  --recreate-env) RECREATE_ENV=true; shift;;
  --update-env)   UPDATE_ENV=true;   shift;;
  --host-conda)   USE_HOST_CONDA=true; shift;;
  --conda-image)  CONDA_IMAGE="$2"; shift 2;;
  --conda-image=*) CONDA_IMAGE="${1#*=}"; shift;;
  --list) echo "jobs: conformance (blocking), arm64 (blocking), qemu (non-blocking)"; exit 0;;
  -h|--help) awk 'NR>=2 && /^#/{sub(/^# ?/,"");print;next} NR>=2{exit}' "$0"; exit 0;;
  *) err "unknown option: $1"; exit 1;;
esac; done

# Default selection mirrors the blocking CI jobs (qemu is opt-in / non-blocking).
if [[ ${#SELECTED[@]} -eq 0 ]]; then SELECTED=(conformance arm64); fi

# ---------------------------------------------------------------------------
# Job: conformance  (conformance.yml)
#
# Default path runs inside a Miniforge container (mirrors the workflow's
# setup-miniconda and needs no host conda). --host-conda uses a local conda
# instead. Docker is preferred when both are available; falls back to host
# conda only if Docker is absent.
# ---------------------------------------------------------------------------
job_conformance() {
  if $USE_HOST_CONDA; then
    command -v conda >/dev/null 2>&1 || { err "--host-conda set but conda not on PATH"; return 3; }
    _conformance_host_conda
  elif command -v docker >/dev/null 2>&1; then
    _conformance_docker
  elif command -v conda >/dev/null 2>&1; then
    warn "docker not found; falling back to host conda."
    _conformance_host_conda
  else
    err "need docker (preferred; pulls $CONDA_IMAGE) or conda on PATH for the conformance job."
    return 3
  fi
}

# Run the conformance harnesses inside a Miniforge container. The conda envs +
# package cache live in host-side cache dirs ($CI_CACHE) mounted into the
# container, so the heavy env solve happens once and the container runs as the
# invoking user (no root-owned build artifacts left in the repo).
_conformance_docker() {
  info "Using Miniforge image: $CONDA_IMAGE  (cache: $CI_CACHE)"
  mkdir -p "$CI_CACHE/conda-envs" "$CI_CACHE/conda-pkgs" "$CI_CACHE/home" || { err "cannot create cache dirs"; return 1; }

  # Inner script runs in the container. Single-quoted heredoc: all $VARS expand
  # INSIDE the container, not on the host. RECREATE_ENV/UPDATE_ENV arrive via -e.
  local inner
  inner=$(cat <<'INNER'
set -euo pipefail
source /opt/conda/etc/profile.d/conda.sh
MGR=conda; command -v mamba >/dev/null 2>&1 && MGR=mamba
echo "[ci-local] env manager: $MGR ; $(python --version 2>&1 || true)"
if [ "${RECREATE_ENV:-false}" = true ]; then
  echo "[ci-local] removing cached env for a fresh CI-faithful build ..."
  conda env remove -n autonomous_trust -y >/dev/null 2>&1 || true
fi
if ! conda env list | awk '{print $1}' | grep -qx autonomous_trust; then
  echo "[ci-local] creating env from environment.yml (slow on first run) ..."
  "$MGR" env create -n autonomous_trust -f config/cfg/environment.yml
  echo "[ci-local] layering devel_environ.yml ..."
  "$MGR" env update -n autonomous_trust -f config/cfg/devel_environ.yml
elif [ "${UPDATE_ENV:-false}" = true ]; then
  echo "[ci-local] updating cached env from both yml files ..."
  "$MGR" env update -n autonomous_trust -f config/cfg/environment.yml
  "$MGR" env update -n autonomous_trust -f config/cfg/devel_environ.yml
else
  echo "[ci-local] reusing cached env autonomous_trust"
fi
conda activate autonomous_trust
export CONFORMANCE_SKIP_TOX=1 CC=clang CXX=clang++
export CMAKE_PREFIX_PATH="$CONDA_PREFIX${CMAKE_PREFIX_PATH:+:$CMAKE_PREFIX_PATH}"
export LD_LIBRARY_PATH="$CONDA_PREFIX/lib${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
echo "[ci-local] Python conformance harness ..."
bash scripts/test-conformance.sh --python --strict-coverage
echo "[ci-local] C conformance harness + cross-language diff ..."
bash scripts/test-conformance.sh --c --strict-coverage
INNER
)

  docker run --rm \
    -v "$REPO:/work" -w /work \
    -v "$CI_CACHE/conda-envs:/cache/envs" \
    -v "$CI_CACHE/conda-pkgs:/cache/pkgs" \
    -v "$CI_CACHE/home:/cihome" \
    --user "$(id -u):$(id -g)" \
    -e HOME=/cihome \
    -e CONDA_ENVS_DIRS=/cache/envs \
    -e CONDA_PKGS_DIRS=/cache/pkgs \
    -e RECREATE_ENV="$RECREATE_ENV" \
    -e UPDATE_ENV="$UPDATE_ENV" \
    "$CONDA_IMAGE" \
    bash -c "$inner" || { err "conformance (containerized) failed"; return 1; }
}

# Run the conformance harnesses against a local conda install.
_conformance_host_conda() {
  local conda_base; conda_base="$(conda info --base 2>/dev/null)" || { err "conda info --base failed"; return 3; }
  # shellcheck disable=SC1091
  source "$conda_base/etc/profile.d/conda.sh" || { err "could not source conda.sh"; return 3; }

  local mgr=conda
  command -v mamba >/dev/null 2>&1 && mgr=mamba
  info "env manager: $mgr"

  if $RECREATE_ENV; then
    warn "Removing env '$CENV' for a fresh CI-faithful rebuild ..."
    conda env remove -n "$CENV" -y >/dev/null 2>&1 || true
  fi

  if ! conda env list | awk '{print $1}' | grep -qx "$CENV"; then
    info "Creating env '$CENV' from config/cfg/environment.yml (this is slow on first run) ..."
    "$mgr" env create -n "$CENV" -f config/cfg/environment.yml || { err "env create failed"; return 1; }
    info "Layering config/cfg/devel_environ.yml ..."
    "$mgr" env update -n "$CENV" -f config/cfg/devel_environ.yml || { err "env update failed"; return 1; }
  elif $UPDATE_ENV; then
    info "Updating env '$CENV' from both yml files ..."
    "$mgr" env update -n "$CENV" -f config/cfg/environment.yml   || { err "env update (environment.yml) failed"; return 1; }
    "$mgr" env update -n "$CENV" -f config/cfg/devel_environ.yml || { err "env update (devel_environ.yml) failed"; return 1; }
  else
    info "Reusing existing env '$CENV' (use --recreate-env to match CI's fresh build, or --update-env to layer yml changes)."
  fi

  conda activate "$CENV" || { err "could not activate '$CENV'"; return 1; }
  info "active python: $(command -v python)  ($(python --version 2>&1))"

  # Exactly the env the workflow's run step exports.
  export CONFORMANCE_SKIP_TOX=1
  export CC=clang CXX=clang++
  export CMAKE_PREFIX_PATH="${CONDA_PREFIX}${CMAKE_PREFIX_PATH:+:${CMAKE_PREFIX_PATH}}"
  export LD_LIBRARY_PATH="${CONDA_PREFIX}/lib${LD_LIBRARY_PATH:+:${LD_LIBRARY_PATH}}"

  info "Python conformance harness (produces python-*.json) ..."
  bash scripts/test-conformance.sh --python --strict-coverage || { err "python harness failed"; conda deactivate || true; return 1; }
  info "C conformance harness + cross-language diff ..."
  bash scripts/test-conformance.sh --c --strict-coverage || { err "C harness / diff failed"; conda deactivate || true; return 1; }
  conda deactivate || true
}

# ---------------------------------------------------------------------------
# Job: arm64-build  (arm64-build.yml job 1)
# ---------------------------------------------------------------------------
job_arm64() {
  command -v docker >/dev/null 2>&1 || { err "docker not found"; return 3; }
  docker buildx version >/dev/null 2>&1 || { err "docker buildx not available"; return 3; }

  # The CI registers QEMU emulation via docker/setup-qemu-action; do the same
  # so the amd64 host can run aarch64 build steps. Idempotent.
  info "Registering QEMU binfmt handlers (arm64) ..."
  docker run --privileged --rm tonistiigi/binfmt --install arm64 >/dev/null 2>&1 \
    || warn "binfmt registration returned nonzero (may already be installed)."

  cd "$REPO/embedded" || return 1
  info "Cross-building at_demo arm64 (dynamic) -> autonomous-trust-arm64.tar.gz ..."
  ./build-arm.sh          || { err "build-arm.sh (dynamic) failed"; cd "$REPO" || true; return 1; }
  info "Cross-building at_demo arm64 (static) -> autonomous-trust-arm64-static.tar.gz ..."
  ./build-arm.sh --static || { err "build-arm.sh --static failed"; cd "$REPO" || true; return 1; }
  cd "$REPO" || return 1

  info "Artifacts:"
  ls -lh embedded/dist/*arm64* 2>/dev/null || warn "no arm64 artifacts found in embedded/dist/"
}

# ---------------------------------------------------------------------------
# Job: qemu-smoke  (arm64-build.yml job 2; continue-on-error -> non-blocking)
# ---------------------------------------------------------------------------
job_qemu() {
  command -v docker >/dev/null 2>&1 || { err "docker not found"; return 3; }
  local miss=0
  for t in qemu-system-x86_64 qemu-img cloud-localds; do
    command -v "$t" >/dev/null 2>&1 || { warn "missing $t"; miss=1; }
  done
  [[ $miss -eq 1 ]] && warn "Install: sudo apt-get install -y qemu-system-x86 qemu-utils cloud-image-utils openssh-client wget"

  cd "$REPO/embedded" || return 1
  info "Two-node QEMU discovery smoke test (heavy) ..."
  ./test-qemu.sh --nodes 2 || { err "test-qemu.sh failed"; cd "$REPO" || true; return 1; }
  cd "$REPO" || return 1
}

# ---------------------------------------------------------------------------
# Driver
# ---------------------------------------------------------------------------
declare -A RESULT DURATION BLOCKING
declare -a ORDER=()
OVERALL=0

run_job() {
  local label=$1 fn=$2 blocking=$3
  ORDER+=("$label"); BLOCKING[$label]=$blocking
  hr; info "▶ JOB: $label  ($([ "$blocking" = yes ] && echo blocking || echo non-blocking))"
  cd "$REPO" || { err "cannot cd to repo root"; RESULT[$label]=FAIL; OVERALL=1; return; }
  local start=$SECONDS rc=0
  "$fn" || rc=$?
  DURATION[$label]=$(( SECONDS - start ))
  if   [[ $rc -eq 0 ]]; then RESULT[$label]=PASS; ok "✔ $label PASSED (${DURATION[$label]}s)"
  elif [[ $rc -eq 3 ]]; then RESULT[$label]=SKIP; warn "⊘ $label SKIPPED — missing prerequisites (${DURATION[$label]}s)"
                             [[ $blocking == yes ]] && OVERALL=$(( OVERALL < 2 ? 2 : OVERALL ))
  else                       RESULT[$label]=FAIL; err "✘ $label FAILED (rc=$rc, ${DURATION[$label]}s)"
                             [[ $blocking == yes ]] && OVERALL=1
  fi
}

info "Repo: $REPO"
info "Selected jobs: ${SELECTED[*]}"
for j in "${SELECTED[@]}"; do case "$j" in
  conformance) run_job conformance job_conformance yes;;
  arm64)       run_job arm64       job_arm64       yes;;
  qemu)        run_job qemu        job_qemu        no;;
esac; done

hr; echo; echo "================== CI-LOCAL SUMMARY =================="
for label in "${ORDER[@]}"; do
  printf "  %-13s %-5s  %4ss  (%s)\n" "$label" "${RESULT[$label]}" "${DURATION[$label]}" \
    "$([ "${BLOCKING[$label]}" = yes ] && echo blocking || echo non-blocking)"
done
echo "======================================================"
case $OVERALL in
  0) ok   "All selected BLOCKING jobs passed. GitHub CI should go green for these workflows.";;
  1) err  "A blocking job FAILED — fix before pushing.";;
  2) warn "A blocking job was SKIPPED (missing prereqs) — result is INCONCLUSIVE; install the tools and re-run.";;
esac
exit "$OVERALL"
