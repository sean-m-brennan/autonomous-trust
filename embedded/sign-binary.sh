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
# Sign an at_demo binary with an Ed25519 key.
#
# Usage:
#   ./sign-binary.sh --binary at_demo --key signing.key
#   ./sign-binary.sh --binary at_demo --generate-key  # first-time setup
#
# Produces: at_demo.sig (detached signature)

set -euo pipefail

BINARY=""
KEY_FILE=""
GENERATE_KEY=false

RED='\033[0;31m'
GREEN='\033[0;32m'
RESET='\033[0m'

info()  { echo -e "${GREEN}[sign]${RESET} $*"; }
error() { echo -e "${RED}[sign]${RESET} $*" >&2; }

while [[ $# -gt 0 ]]; do
    case "$1" in
        --binary)        BINARY="$2"; shift 2 ;;
        --key)           KEY_FILE="$2"; shift 2 ;;
        --generate-key)  GENERATE_KEY=true; shift ;;
        -h|--help)
            echo "Usage: $0 --binary FILE [--key KEYFILE | --generate-key]"
            echo
            echo "Options:"
            echo "  --binary FILE       Binary to sign"
            echo "  --key KEYFILE       Ed25519 private key (PEM)"
            echo "  --generate-key      Generate a new signing keypair"
            exit 0 ;;
        *) error "Unknown option: $1"; exit 1 ;;
    esac
done

if [ -z "$BINARY" ]; then
    error "--binary is required"
    exit 1
fi

if ! command -v openssl &>/dev/null; then
    error "openssl is required but not found"
    exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

if $GENERATE_KEY; then
    KEY_FILE="${KEY_FILE:-$SCRIPT_DIR/signing.key}"
    PUB_FILE="${KEY_FILE%.key}.pub"
    if [ -f "$KEY_FILE" ]; then
        error "Key file already exists: $KEY_FILE"
        error "Remove it first if you want to regenerate."
        exit 1
    fi
    info "Generating Ed25519 signing keypair ..."
    openssl genpkey -algorithm Ed25519 -out "$KEY_FILE"
    openssl pkey -in "$KEY_FILE" -pubout -out "$PUB_FILE"
    chmod 600 "$KEY_FILE"
    info "Private key: $KEY_FILE"
    info "Public key:  $PUB_FILE"
fi

if [ -z "$KEY_FILE" ]; then
    KEY_FILE="$SCRIPT_DIR/signing.key"
fi

if [ ! -f "$KEY_FILE" ]; then
    error "Signing key not found: $KEY_FILE"
    error "Run with --generate-key first, or specify --key"
    exit 1
fi

if [ ! -f "$BINARY" ]; then
    error "Binary not found: $BINARY"
    exit 1
fi

SIG_FILE="${BINARY}.sig"

info "Signing $BINARY ..."
openssl pkeyutl -sign -inkey "$KEY_FILE" \
    -rawin -in "$BINARY" \
    -out "$SIG_FILE"

info "Signature written to $SIG_FILE"
info "Verify with: ./verify-binary.sh --binary $BINARY --pubkey ${KEY_FILE%.key}.pub"
