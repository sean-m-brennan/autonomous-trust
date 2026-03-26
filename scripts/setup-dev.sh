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

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
RESET='\033[0m'

info()  { echo -e "${GREEN}[setup]${RESET} $*"; }
warn()  { echo -e "${YELLOW}[setup]${RESET} $*"; }
error() { echo -e "${RED}[setup]${RESET} $*" >&2; }

# ---------------------------------------------------------------------------
# Detect platform
# ---------------------------------------------------------------------------
OS="$(uname -s)"
ARCH="$(uname -m)"

case "$OS" in
    Linux)  PLATFORM="Linux" ;;
    Darwin) PLATFORM="MacOSX" ;;
    *)      error "Unsupported OS: $OS"; exit 1 ;;
esac

# ---------------------------------------------------------------------------
# 1. Miniforge (conda-forge only — no Anaconda defaults channel)
# ---------------------------------------------------------------------------
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

    info "Installing Miniforge to $MINIFORGE_HOME ..."
    local installer="/tmp/miniforge-installer.sh"
    local url="https://github.com/conda-forge/miniforge/releases/latest/download/Miniforge3-${PLATFORM}-${ARCH}.sh"
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

# ---------------------------------------------------------------------------
# 2. Conda environment
# ---------------------------------------------------------------------------
create_conda_env() {
    activate_conda

    if conda env list | grep -q "/${ENV_NAME}\$"; then
        info "Conda environment '$ENV_NAME' already exists"
        return 0
    fi

    info "Creating conda environment '$ENV_NAME' ..."
    conda env create -n "$ENV_NAME" --file "$REPO_DIR/environment.yaml"

    # Overlay development dependencies
    if [ -f "$CFG_DIR/devel_environ.yaml" ]; then
        info "Installing development dependencies ..."
        conda env update -n "$ENV_NAME" --file "$CFG_DIR/devel_environ.yaml"
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
    conda update -n base -c conda-forge conda
    activate_conda
    info "Updating conda environment '$ENV_NAME' ..."
    conda env update -n "$ENV_NAME" --file "$REPO_DIR/environment.yaml" --prune
    if [ -f "$CFG_DIR/devel_environ.yaml" ]; then
        conda env update -n "$ENV_NAME" --file "$CFG_DIR/devel_environ.yaml"
    fi
    info "Environment updated"
}

# ---------------------------------------------------------------------------
# 3. Rust toolchain (installed into the conda env)
# ---------------------------------------------------------------------------
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

# ---------------------------------------------------------------------------
# 4. Docker
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
main() {
    if [[ "${1:-}" == "--update" ]]; then
        update_conda_env
        exit 0
    fi

    info "Setting up autonomous-trust development environment"
    echo

    install_miniforge
    create_conda_env
    install_rust
    check_docker

    echo
    info "Setup complete. Activate with:"
    info "  conda activate $ENV_NAME"
}

main "$@"
