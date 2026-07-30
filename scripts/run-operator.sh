#!/bin/bash
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
# Launch the AutonomousTrust Operator console (PIV+MFA terminal UI).

# Run everything relative to the repo root
here=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
cd "$here" || exit 1

usage() {
  cat <<'EOF'
Usage: run-operator.sh [--demo] [operator args...] [-h|--help]

Launch the AutonomousTrust Operator console (the PIV+MFA Textual TUI in
src/autonomous-trust-operator). All arguments are forwarded verbatim to
`python -m autonomous_trust.operator`:

  run-operator.sh --demo                 # seeded directory, no live node
  run-operator.sh                        # real node bridge; card presence only
  run-operator.sh --software-cert C.pem --software-key K.pem --ca-bundle CA.pem
                                         # dev activator (software token, no card)

The console needs a TTY, so run it in an interactive terminal (not piped).

Activation ("--ca-bundle")
  Activate returns "UNAVAILABLE - no PIV token configured" until an activator is
  wired, because verifying a PIV credential needs the issuing-CA chain to check
  it against. --ca-bundle is that chain: concatenated PEM, a single DER cert, or a
  PKCS#7 .p7b/.p7c (DER or PEM-wrapped) -- no conversion needed.

  Live PIV card (the card in the reader is the token):

    run-operator.sh --ca-bundle CA.p7b

  The PIN you enter opens a PKCS#11 session, the card signs the challenge, and its
  cert chain is verified against CA.p7b -- which must be the chain that actually
  issued the card's cert, or activation REJECTS with a chain error. The session is
  closed as soon as activation returns; the PIN is never stored. Use
  --pkcs11-module / --slot if the module is not autodetected.

  Software token instead of a card (dev/CI), all three together:

    --software-cert C.pem   the operator leaf certificate
    --software-key K.pem    its private key
    --ca-bundle CA.pem      chain of the CA(s) that issued C.pem

  These take precedence over the live card. For a throwaway set, run --demo (it
  mints its own CA+leaf) or copy the leaf files --demo writes to its temp dir. Add
  --totp-secret <base32> to enforce a TOTP second factor, and --crl-path (PEM or
  DER) for a revocation check.

  A CRL is NOT a CA bundle (it lists revoked serials, carries no trust anchor):
  pass it as --crl-path. Handing a CRL, private key, or CSR to --ca-bundle reports
  which file and what it is, instead of an unknown-issuer error against the
  credential.

Card presence
  With no token flags, presence comes from a PIN-less PKCS#11 probe against an
  autodetected opensc-pkcs11.so. If the Activate tab says "no token detected"
  with a card inserted, the parenthetical reason names the cause; the usual fixes
  are installing the binding (pip install pykcs11), starting pcscd, or pointing
  AUTONOMOUS_TRUST_PKCS11_MODULE at vendor/CACKey middleware.

Environment:
  PYTHON                      interpreter to use (default: autodetected — an
                              active env's python, else src/autonomous-trust/.venv).
  AUTONOMOUS_TRUST_BACKEND    core backend (default: python; the operator core
                              modules are python-only).
  AUTONOMOUS_TRUST_PKCS11_MODULE
                              PKCS#11 module for live PIV/CAC cards (default:
                              autodetected opensc-pkcs11.so).

Options:
  -h, --help    Show this help message and exit.
EOF
}

case "${1:-}" in
  -h|--help) usage; exit 0 ;;
esac

src="$here/src"
# Namespace-package roots the operator imports from (core + services + operator);
# prepended so a working tree runs without an editable install.
export PYTHONPATH="$src/autonomous-trust:$src/autonomous-trust-services:$src/autonomous-trust-operator${PYTHONPATH:+:$PYTHONPATH}"
# Operator core (session/activate/resource_directory/operator_node) is python-only.
export AUTONOMOUS_TRUST_BACKEND="${AUTONOMOUS_TRUST_BACKEND:-python}"

# Pick an interpreter: explicit $PYTHON, else the active env's python if it has
# Textual, else the repo's autonomous-trust venv.
pick_python() {
  if [ -n "${PYTHON:-}" ]; then echo "$PYTHON"; return; fi
  if command -v python >/dev/null 2>&1 && \
     python -c 'import textual' >/dev/null 2>&1; then
    echo python; return
  fi
  if [ -x "$src/autonomous-trust/.venv/bin/python" ]; then
    echo "$src/autonomous-trust/.venv/bin/python"; return
  fi
  echo python
}
PY="$(pick_python)"

if ! "$PY" -c 'import textual' >/dev/null 2>&1; then
  echo "error: 'textual' is not importable with '$PY'." >&2
  echo "       Activate the dev env (conda activate autonomous_trust) or set" >&2
  echo "       PYTHON=/path/to/python, then re-run. (pip install textual pyotp)" >&2
  exit 1
fi

exec "$PY" -m autonomous_trust.operator "$@"
