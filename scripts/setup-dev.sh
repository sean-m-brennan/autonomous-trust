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
# Development environment setup for autonomous-trust.
# Installs miniforge (conda-forge only), creates the conda environment,
# installs Rust toolchain inside it, and verifies Docker.
#
# Usage:
#   ./setup-dev.sh            # full setup
#   ./setup-dev.sh --update   # update existing environment

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
CONFIG_DIR="$REPO_DIR/config"
CFG_DIR="$CONFIG_DIR/cfg"

ENV_NAME="autonomous_trust"
MINIFORGE_HOME="$HOME/.miniforge3"

# Pinned conda toolchain (config/cfg/toolchain-pins.env). MINIFORGE_VERSION selects the
# installer release below; the file also carries the container-image pin the
# Dockerfiles use. Fall back to `latest` only if the file is missing, and say so
# -- a floating installer is exactly the drift that file exists to prevent.
TOOLCHAIN_PINS="$CFG_DIR/toolchain-pins.env"
if [ -f "$TOOLCHAIN_PINS" ]; then
    # shellcheck source=../config/cfg/toolchain-pins.env
    source "$TOOLCHAIN_PINS"
fi
MINIFORGE_VERSION="${MINIFORGE_VERSION:-}"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
RESET='\033[0m'

info()  { echo -e "${GREEN}[setup]${RESET} $*"; }
warn()  { echo -e "${YELLOW}[setup]${RESET} $*"; }
error() { echo -e "${RED}[setup]${RESET} $*" >&2; }

# Detect platform
OS="$(uname -s)"
ARCH="$(uname -m)"

case "$OS" in
    Linux)  PLATFORM="Linux" ;;
    Darwin) PLATFORM="MacOSX" ;;
    *)      error "Unsupported OS: $OS"; exit 1 ;;
esac

# Miniforge (conda-forge only — no Anaconda defaults channel)
install_miniforge() {
    if command -v conda &>/dev/null; then
        info "conda already available: $(conda --version)"
        return 0
    fi

    if [ -x "$MINIFORGE_HOME/bin/conda" ]; then
        info "Miniforge found at $MINIFORGE_HOME but not on PATH"
        eval "$("$MINIFORGE_HOME/bin/conda" shell.bash hook)"
        return 0
    fi

    local url
    if [ -n "$MINIFORGE_VERSION" ]; then
        info "Installing Miniforge $MINIFORGE_VERSION (pinned) to $MINIFORGE_HOME ..."
        url="https://github.com/conda-forge/miniforge/releases/download/${MINIFORGE_VERSION}/Miniforge3-${PLATFORM}-${ARCH}.sh"
    else
        warn "No MINIFORGE_VERSION in $TOOLCHAIN_PINS -- falling back to the" \
             "floating latest release (want config/cfg/toolchain-pins.env)"
        info "Installing Miniforge to $MINIFORGE_HOME ..."
        url="https://github.com/conda-forge/miniforge/releases/latest/download/Miniforge3-${PLATFORM}-${ARCH}.sh"
    fi
    local installer="/tmp/miniforge-installer.sh"
    curl -fsSL "$url" -o "$installer"
    bash "$installer" -b -p "$MINIFORGE_HOME"
    rm -f "$installer"

    eval "$("$MINIFORGE_HOME/bin/conda" shell.bash hook)"
    # Ensure only conda-forge is configured (miniforge default, but be explicit)
    conda config --system --set auto_update_conda false
    conda config --system --add channels conda-forge
    conda config --system --set channel_priority strict
    info "Miniforge installed"
}

activate_conda() {
    if ! command -v conda &>/dev/null; then
        if [ -x "$MINIFORGE_HOME/bin/conda" ]; then
            eval "$("$MINIFORGE_HOME/bin/conda" shell.bash hook)"
        else
            error "conda not found after install"
            exit 1
        fi
    fi
}

# Conda environment
create_conda_env() {
    activate_conda

    if conda env list | grep -q "/${ENV_NAME}\$"; then
        info "Conda environment '$ENV_NAME' already exists"
        return 0
    fi

    info "Creating conda environment '$ENV_NAME' ..."
    conda env create -n "$ENV_NAME" --file "$REPO_DIR/environment.yml"

    # Overlay development dependencies
    if [ -f "$CFG_DIR/devel_environ.yml" ]; then
        info "Installing development dependencies ..."
        conda env update -n "$ENV_NAME" --file "$CFG_DIR/devel_environ.yml"
    fi

    # Platform-specific compiler packages
    local platform_yaml
    case "$PLATFORM-$ARCH" in
        Linux-x86_64)   platform_yaml="$CFG_DIR/linux-64/platform.yaml" ;;
        Linux-aarch64)  platform_yaml="$CFG_DIR/linux-64/platform.yaml" ;;
        MacOSX-x86_64)  platform_yaml="$CFG_DIR/osx-64/platform.yaml" ;;
        MacOSX-arm64)   platform_yaml="$CFG_DIR/osx-64/platform.yaml" ;;
    esac
    if [ -n "${platform_yaml:-}" ] && [ -f "$platform_yaml" ]; then
        info "Installing platform compiler packages ..."
        conda env update -n "$ENV_NAME" --file "$platform_yaml"
    fi

    info "Conda environment '$ENV_NAME' created"
}

update_conda_env() {
    # No `conda update -n base conda` here: it floats base conda to whatever
    # conda-forge published today, which defeats the pinned installer above and
    # is one of the drifts that broke a working build. To move conda, move the pin in
    # config/cfg/toolchain-pins.env and re-run the install path.
    activate_conda
    info "Updating conda environment '$ENV_NAME' ..."
    conda env update -n "$ENV_NAME" --file "$REPO_DIR/environment.yml" --prune
    if [ -f "$CFG_DIR/devel_environ.yml" ]; then
        conda env update -n "$ENV_NAME" --file "$CFG_DIR/devel_environ.yml"
    fi
    info "Environment updated"
}

# Rust toolchain (installed into the conda env)
install_rust() {
    activate_conda
    conda activate "$ENV_NAME"

    local env_prefix
    env_prefix="$(conda info --json | python3 -c "
import sys, json
info = json.load(sys.stdin)
for p in info['envs']:
    if p.endswith('/$ENV_NAME') or '/$ENV_NAME' in p:
        print(p); break
" 2>/dev/null || echo "$CONDA_PREFIX")"

    if [ -z "$env_prefix" ]; then
        env_prefix="$CONDA_PREFIX"
    fi

    export RUSTUP_HOME="$env_prefix"
    export CARGO_HOME="$env_prefix"
    export PATH="$env_prefix/bin:$PATH"

    if [ -x "$env_prefix/bin/rustc" ]; then
        info "Rust already installed: $(rustc --version)"
    else
        info "Installing Rust toolchain into conda env ..."
        curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --no-modify-path
        info "Rust installed: $("$env_prefix/bin/rustc" --version)"
    fi

    # Conda activate/deactivate hooks so RUSTUP_HOME/CARGO_HOME are set
    local activate_dir="$env_prefix/etc/conda/activate.d"
    local deactivate_dir="$env_prefix/etc/conda/deactivate.d"
    mkdir -p "$activate_dir" "$deactivate_dir"

    cat > "$activate_dir/rust.sh" << EOF
#!/bin/sh
export RUSTUP_HOME="$env_prefix"
export CARGO_HOME="$env_prefix"
export PATH="$env_prefix/bin:\$PATH"
EOF
    chmod +x "$activate_dir/rust.sh"

    cat > "$deactivate_dir/rust.sh" << 'EOF'
#!/bin/sh
unset RUSTUP_HOME
unset CARGO_HOME
EOF
    chmod +x "$deactivate_dir/rust.sh"

    info "Rust conda hooks configured"
}

# Download a pre-built SMT solver binary from a GitHub release.
#   $1 - repo (owner/name)      e.g. "Z3Prover/z3"
#   $2 - release tag            e.g. "z3-4.13.4"
#   $3 - binary name            e.g. "z3"
#   $4 - destination directory  e.g. "/path/to/env/bin"
install_smt_from_github() {
    local repo="$1" tag="$2" binary="$3" dest="$4"

    if [ -x "$dest/$binary" ]; then
        info "$binary already installed: $("$dest/$binary" --version 2>&1 | head -1)"
        return 0
    fi

    # Query the GitHub Releases API for the asset matching this platform
    local api_url="https://api.github.com/repos/${repo}/releases/tags/${tag}"
    local asset_url
    asset_url=$(curl -fsSL "$api_url" | python3 -c "
import json, platform, sys
release = json.load(sys.stdin)
machine, system = platform.machine(), platform.system()
arch_tags = {
    ('Linux',  'x86_64'):  ['x64', 'x86_64', 'amd64'],
    ('Linux',  'aarch64'): ['arm64', 'aarch64'],
    ('Darwin', 'x86_64'):  ['x64', 'x86_64'],
    ('Darwin', 'arm64'):   ['arm64', 'aarch64'],
}
os_tags = {'Linux': ['linux', 'glibc'], 'Darwin': ['osx', 'macos', 'darwin']}
arch_keys = arch_tags.get((system, machine), [])
os_keys = os_tags.get(system, [])
candidates = []
for asset in release.get('assets', []):
    name = asset['name'].lower()
    if name.endswith(('.sha256', '.sig', '.asc', '.txt')):
        continue
    if not (any(k in name for k in os_keys) and any(k in name for k in arch_keys)):
        continue
    if not (name.endswith('.zip') or 'static' in name):
        continue
    # Rank: prefer static over shared, non-GPL over GPL
    rank = ('static' in name) * 2 + ('gpl' not in name)
    candidates.append((rank, asset['browser_download_url']))
if candidates:
    candidates.sort(reverse=True)
    print(candidates[0][1])
" 2>/dev/null) || true

    if [ -z "$asset_url" ]; then
        warn "Could not find $binary release asset for $PLATFORM-$ARCH"
        warn "Install manually from: https://github.com/${repo}/releases/tag/${tag}"
        return 0
    fi

    info "Downloading $binary from GitHub ($tag) ..."
    local dl_tmp
    dl_tmp=$(mktemp -d)
    curl -fsSL -L "$asset_url" -o "$dl_tmp/artifact"

    # Determine whether this is a zip archive or a standalone binary
    if file -b "$dl_tmp/artifact" | grep -qi zip; then
        unzip -q "$dl_tmp/artifact" -d "$dl_tmp/unpacked"
        local found
        found=$(find "$dl_tmp/unpacked" -name "$binary" -type f | head -1)
        if [ -n "$found" ]; then
            install -m 755 "$found" "$dest/$binary"
        else
            warn "$binary binary not found inside downloaded archive"
            rm -rf "$dl_tmp"
            return 0
        fi
    else
        # Standalone static binary
        install -m 755 "$dl_tmp/artifact" "$dest/$binary"
    fi

    rm -rf "$dl_tmp"
    info "$binary installed to $dest/$binary"
}

# Frama-C (installed into the conda env)
install_frama_c() {
    activate_conda
    conda activate "$ENV_NAME"

    local env_prefix
    env_prefix="$(conda info --json | python3 -c "
import sys, json
info = json.load(sys.stdin)
for p in info['envs']:
    if p.endswith('/$ENV_NAME') or '/$ENV_NAME' in p:
        print(p); break
" 2>/dev/null || echo "$CONDA_PREFIX")"

    if [ -z "$env_prefix" ]; then
        env_prefix="$CONDA_PREFIX"
    fi

    export OPAMROOT="$env_prefix/share/opam"

    info "Initializing opam at $OPAMROOT ..."
    opam init -n --root="$OPAMROOT" --compiler=4.14.1  # may take a while
    eval $(opam env --root="$OPAMROOT" --switch=4.14.1)

    if command -v frama-c &>/dev/null; then
        info "Frama-C already installed: $(frama-c -version 2>&1 | head -1)"
    else
        # Frama-C lists lablgtk3 as a hard dependency on Linux, but the build
        # system (dune) treats the GUI as optional.  Download the source, strip
        # the GTK dependencies from the opam metadata, then pin-install so opam
        # never tries to build lablgtk3.
        info "Downloading Frama-C source ..."
        local tmpdir
        tmpdir=$(mktemp -d)
        trap "rm -rf '$tmpdir'" EXIT
        opam source frama-c --dir="$tmpdir/frama-c"

        info "Patching Frama-C opam file to remove GUI (lablgtk3) dependencies ..."
        local opam_file="$tmpdir/frama-c/opam"
        if [ ! -f "$opam_file" ]; then
            opam_file="$tmpdir/frama-c/frama-c.opam"
        fi
        sed -i '/"lablgtk3/d'          "$opam_file"
        sed -i '/"conf-gtksourceview3/d' "$opam_file"

        info "Installing Frama-C (CLI only, no GUI) — this may take a while ..."
        opam pin add frama-c "$tmpdir/frama-c" -y --assume-depexts
    fi

    if command -v alt-ergo &>/dev/null; then
        info "Alt-Ergo already installed: $(alt-ergo --version 2>&1 | head -1)"
    else
        info "Installing Alt-Ergo SMT solver ..."
        opam install -y alt-ergo
    fi

    info "Installing Z3 SMT solver ..."
    install_smt_from_github "Z3Prover/z3" "z3-4.13.4" "z3" "$env_prefix/bin"

    info "Installing CVC5 SMT solver ..."
    install_smt_from_github "cvc5/cvc5" "cvc5-1.2.0" "cvc5" "$env_prefix/bin"

    why3 config detect

    # Conda activate/deactivate hooks so OPAMROOT and opam PATH are set
    local activate_dir="$env_prefix/etc/conda/activate.d"
    local deactivate_dir="$env_prefix/etc/conda/deactivate.d"
    mkdir -p "$activate_dir" "$deactivate_dir"

    cat > "$activate_dir/frama-c.sh" << EOF
#!/bin/sh
export OPAMROOT="$env_prefix/share/opam"
eval \$(opam env --root="\$OPAMROOT" --switch=4.14.1)
EOF
    chmod +x "$activate_dir/frama-c.sh"

    cat > "$deactivate_dir/frama-c.sh" << 'EOF'
#!/bin/sh
unset OPAMROOT
unset OPAM_SWITCH_PREFIX
unset CAML_LD_LIBRARY_PATH
unset OCAML_TOPLEVEL_PATH
EOF
    chmod +x "$deactivate_dir/frama-c.sh"

    info "Frama-C installed. Reactivate the conda environment to pick up PATH changes:"
    info "  conda deactivate && conda activate $ENV_NAME"
}

# ---------------------------------------------------------------------------
# Docker
# ---------------------------------------------------------------------------
check_docker() {
    if command -v docker &>/dev/null; then
        info "Docker available: $(docker --version)"
    else
        warn "Docker not found. Install it separately if needed."
        warn "  See: https://docs.docker.com/engine/install/"
    fi
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
usage() {
    cat <<'EOF'
Usage: setup-dev.sh [OPTIONS]

Set up the autonomous-trust development environment: install miniforge
(conda-forge only), create the conda environment, install the Rust toolchain
and Frama-C inside it, and verify Docker.

Options:
  --update      Update the existing conda environment instead of full setup.
  -h, --help    Show this help message and exit.
EOF
}

main() {
    case "${1:-}" in
        -h|--help)
            usage
            exit 0
            ;;
    esac

    if [[ "${1:-}" == "--update" ]]; then
        update_conda_env
        exit 0
    fi

    info "Setting up autonomous-trust development environment"
    echo

    install_miniforge
    create_conda_env
    install_rust
    install_frama_c
    check_docker

    echo
    info "Setup complete. Activate with:"
    info "  conda activate $ENV_NAME"
}

main "$@"
