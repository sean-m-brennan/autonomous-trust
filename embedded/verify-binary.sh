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
# Verify an at_demo binary signature.
#
# Usage:
#   ./verify-binary.sh --binary at_demo --pubkey signing.pub

set -euo pipefail

BINARY=""
PUBKEY=""

RED='\033[0;31m'
GREEN='\033[0;32m'
RESET='\033[0m'

info()  { echo -e "${GREEN}[verify]${RESET} $*"; }
error() { echo -e "${RED}[verify]${RESET} $*" >&2; }

while [[ $# -gt 0 ]]; do
    case "$1" in
        --binary) BINARY="$2"; shift 2 ;;
        --pubkey) PUBKEY="$2"; shift 2 ;;
        -h|--help)
            echo "Usage: $0 --binary FILE --pubkey PUBKEYFILE"
            exit 0 ;;
        *) error "Unknown option: $1"; exit 1 ;;
    esac
done

if [ -z "$BINARY" ] || [ -z "$PUBKEY" ]; then
    error "Both --binary and --pubkey are required"
    exit 1
fi

SIG_FILE="${BINARY}.sig"

if [ ! -f "$BINARY" ]; then
    error "Binary not found: $BINARY"
    exit 1
fi

if [ ! -f "$SIG_FILE" ]; then
    error "Signature not found: $SIG_FILE"
    exit 1
fi

if [ ! -f "$PUBKEY" ]; then
    error "Public key not found: $PUBKEY"
    exit 1
fi

info "Verifying $BINARY ..."
if openssl pkeyutl -verify -pubin -inkey "$PUBKEY" \
    -rawin -in "$BINARY" \
    -sigfile "$SIG_FILE" 2>/dev/null; then
    info "PASS: Signature is valid"
    exit 0
else
    error "FAIL: Signature verification failed"
    exit 1
fi
